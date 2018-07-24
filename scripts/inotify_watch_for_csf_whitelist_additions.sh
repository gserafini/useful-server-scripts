#!/bin/bash
# Watch /etc/csf/csf.allow for new whitelist additions, restart apache whenever a new one is added

# Watch this script using chkserv
# echo 'service[inotify_watch_for_csf_whitelist_additions]=x,x,x,/root/inotify_watch_for_csf_whitelist_additions.sh,inotify_watch_for_csf_whitelist_additions.sh,root' > /etc/chkserv.d/inotify_csf_whitelist_monitor
# /scripts/restartsrv_chkservd

while true; do
  inotifywait -e modify /etc/csf/csf.allow; logger -s 'Restarting Apache...'; service httpd restart; logger -s 'Apache restarted!'
done



