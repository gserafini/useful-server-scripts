#!/bin/bash
# Restart sshd by killing all old / stale connections

screen -D -m -S RestartSSHD bash -c 'killall sshd; sleep 5; /etc/init.d/sshd restart'

