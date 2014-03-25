Gabriel's Useful Server Scripts
=====================

Useful scripts for server administration.  You will most likely need root access to install
these.


Installation
-----
1. ``$ git clone https://github.com/gserafini/useful-server-scripts.git``
2. ``$ cd useful-server-scripts/``
3. ``$ for f in `ls scripts/` ; do sudo ln -s $PWD/scripts/$f /usr/local/bin/$f ; done``

### svn\_add\_remove
Run this script in a directory you are managing using svn. It will ask you if you would like
to svn add new files and svn remove missing files.  It is particularly useful if a 
WordPress installation has been automatically upgraded and files have been added / removed
that you would like to then check in.