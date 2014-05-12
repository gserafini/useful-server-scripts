#!/bin/bash

# This script will kill all php processes that have been running longer than 1 hour.

ps -eo uid,pid,command,etime | grep php | egrep ' ([0-9]+-)?([0-9]{2}:?){3}' | awk '{print $2}' | xargs -I{} kill {}


