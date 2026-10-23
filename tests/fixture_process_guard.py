"""Test-only direct-child supervision. Never discover or signal indirect PIDs."""
import math
import os
import signal
import subprocess
import time
from pathlib import Path


def process_identity(pid):
    """Read only the explicitly launched synthetic child's nonsecret identity."""
    try:
        fields = Path('/proc/%d/stat' % pid).read_text().rpartition(')')[2].split()
        argv = Path('/proc/%d/cmdline' % pid).read_bytes().rstrip(b'\0').split(b'\0')
        return {'pid': pid, 'ppid': int(fields[1]), 'pgrp': int(fields[2]),
                'session': int(fields[3]), 'start': fields[19],
                'argv': [os.fsdecode(value) for value in argv]}
    except (OSError, ValueError, IndexError):
        return None


def own_fixture(proc, argv, identity_reader=process_identity, parent_pid=None):
    """Capture ownership immediately after Popen(start_new_session=True)."""
    parent_pid = os.getpid() if parent_pid is None else parent_pid
    identity = identity_reader(proc.pid) if proc.poll() is None else None
    expected = list(argv)
    valid = (identity is not None and identity['pid'] == proc.pid
             and identity['ppid'] == parent_pid and identity['pgrp'] == proc.pid
             and identity['session'] == proc.pid and identity['argv'] == expected)
    proc._fixture_ownership = {'identity': dict(identity) if valid else None,
                              'argv': expected, 'parent': parent_pid}
    return proc


def spawn_fixture(argv, **kwargs):
    if not isinstance(argv,(list,tuple)) or not argv or not all(isinstance(value,str) for value in argv) or kwargs.get('shell'):
        raise ValueError('Explicit argv list without a shell required')
    if 'start_new_session' in kwargs:
        raise ValueError('Fixture supervisor owns the new-session option')
    return own_fixture(subprocess.Popen(argv, start_new_session=True, **kwargs), argv)


def capture_fixture(proc, timeout, cleanup_budget=3, force_stop=None,
                    clock=time.monotonic, identity_reader=process_identity,
                    signal_group=os.killpg, parent_pid=None):
    """One bounded capture plus one finite cleanup budget, including reap.

    A reaped/exited parent can leave unknown pipe writers. Those numeric PIDs
    and groups are never signaled. Partial captures and all cleanup errors stay
    in the returned evidence; failure does not become a successful test.
    """
    parent_pid = os.getpid() if parent_pid is None else parent_pid
    if (not all(isinstance(value,(int,float)) and math.isfinite(value) for value in [timeout,cleanup_budget])
            or timeout < 0 or cleanup_budget <= 0):
        raise ValueError('Finite nonnegative capture and positive cleanup budget required')
    result = {'stdout': '', 'stderr': '', 'returncode': None, 'error': None,
              'partialCaptures': [], 'cleanup': {'captureComplete': True,
                  'pipeWritersUnknown': False, 'directChildReaped': False,
                  'signals': [], 'errors': []}}
    cleanup = result['cleanup']

    def partial(exc):
        entry = {}
        for field in ['stdout', 'stderr']:
            value = getattr(exc, field, None)
            if value is not None:
                value = value.decode(errors='replace') if isinstance(value, bytes) else value
                result[field] = value
                entry[field] = value
        if entry:
            result['partialCaptures'].append(entry)

    try:
        if force_stop is not None:
            raise RuntimeError(force_stop)
        result['stdout'], result['stderr'] = proc.communicate(timeout=timeout)
    except BaseException as exc:
        result['error'] = type(exc).__name__ + ': ' + str(exc)
        partial(exc)
        deadline = clock() + cleanup_budget
        cleanup['captureComplete'] = False

        def signal_owned(sig):
            try:
                # poll may reap an exited child; its group is then ineligible.
                # A still-unreaped direct child reserves its PID across the
                # final identity check and signal, even if it exits meanwhile.
                if proc.poll() is not None:
                    return
                owned = getattr(proc, '_fixture_ownership', None)
                current = identity_reader(proc.pid)
                if (not owned or owned['identity'] is None
                        or owned['parent'] != parent_pid
                        or current != owned['identity']
                        or current['ppid'] != parent_pid
                        or current['argv'] != owned['argv']
                        or current['pgrp'] != proc.pid
                        or current['session'] != proc.pid):
                    raise RuntimeError('Unreaped direct fixture identity/argv/group changed; no signal')
                signal_group(proc.pid, sig)
                cleanup['signals'].append({'pid': proc.pid, 'signal': int(sig)})
            except BaseException as failure:
                cleanup['errors'].append('owned signal: ' + type(failure).__name__ + ': ' + str(failure))

        def capture(seconds):
            left = min(seconds, deadline - clock())
            if left <= 0:
                cleanup['errors'].append('finite cleanup capture deadline exhausted')
                return False
            try:
                result['stdout'], result['stderr'] = proc.communicate(timeout=left)
                return True
            except BaseException as failure:
                partial(failure)
                cleanup['errors'].append('bounded capture: ' + type(failure).__name__ + ': ' + str(failure))
                return False

        signal_owned(signal.SIGTERM)
        drained = capture(min(1, cleanup_budget))
        if not drained:
            signal_owned(signal.SIGKILL)
            drained = capture(deadline - clock())
        cleanup['captureComplete'] = drained
        if not drained:
            cleanup['pipeWritersUnknown'] = True
            cleanup['errors'].append('Pipe capture incomplete; unknown writers retained, never signal indirect PIDs')
            for stream in [proc.stdin, proc.stdout, proc.stderr]:
                if stream is not None:
                    try:
                        stream.close()
                    except BaseException as failure:
                        cleanup['errors'].append('pipe close: ' + type(failure).__name__ + ': ' + str(failure))
            remaining = deadline - clock()
            if remaining > 0:
                try:
                    proc.wait(timeout=remaining)
                except BaseException as failure:
                    cleanup['errors'].append('bounded direct reap: ' + type(failure).__name__ + ': ' + str(failure))
            else:
                cleanup['errors'].append('finite direct-child reap deadline exhausted')
    cleanup['directChildReaped'] = proc.poll() is not None
    result['returncode'] = proc.returncode
    return result


def run_fixture(argv, timeout, **kwargs):
    """CompletedProcess-compatible result for isolated run-style fixtures."""
    proc = spawn_fixture(argv, **kwargs)
    result = capture_fixture(proc, timeout)
    if result['error']:
        raise AssertionError('Private fixture capture failed: ' + repr(result))
    completed = subprocess.CompletedProcess(argv, result['returncode'], result['stdout'], result['stderr'])
    completed.fixture_receipt = result
    return completed
