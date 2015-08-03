#!/bin/bash
# Watch /etc/csf/csf.allow for new whitelist additions, restart apache whenever a new one is added
while true; do
  inotifywait -e modify /etc/csf/csf.allow && echo 'Restarting Apache...'; service httpd restart
done



