# Installation instructions #
  1. Download the latest Metasploit Framework (MSF) release: http://www.metasploit.com/download/
  1. Install Metasploit Framework
  1. Update Ruby to 1.9 if not already done
  1. Download XSSF from the SVN (svn export http://xssf.googlecode.com/svn/trunk/ XSSF) or from the last packaged version
  1. Copy and paste all downloaded files into the Metasploit ~/msf3/ folder
  1. Note that you can directly use 'svn export' command within ~/msf3/ folder. Please don't use 'svn checkout' command for XSSF within ~/msf3/ directory, that would break MSF legitimate '.svn' files, and break futures MSF updates !
  1. Enjoy!