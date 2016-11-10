#! /bin/bash

# Run as root

# Get list of all modified .htaccess files on server and commit them to the repository
echo 'Finding modified .htaccess files and commiting them to Subversion...'
find /home/*/public_html/.htaccess | xargs svn st -q | grep M | sed 's/M *//' | xargs -I FILE svn ci FILE -m "Auto-committing .htaccess on server to repository"

#Fix permissions
echo 'Fixing permissions...'
while read p; do
  echo $p | sed "s/#.*//" | sed "s/:.*//" | xargs -I LOCALDIROWNER find /home/LOCALDIROWNER/public_html/ -user root -exec chown LOCALDIROWNER:LOCALDIROWNER {} \; 
done < /etc/trueuserowners


