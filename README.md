This script will debug Policy Installation.<br />
It will also gather basic information from the machine (disk space,<br />
free memory, running processes, hotfixes, etc.) and other files relevant.<br />

The script will save the debugs to /tmp/policy-debug if the root partition<br />
has 2GB of space or more. Otherwise if will save it to /var/log/policy-debug<br />
if it has 2GB of space or more. There is a also a function that will monitor<br />
the disk space of the partition used. If the free space gets less than 500MB<br />
the debugs will stop and will be deleted.<br />

When the script is finished running, all the files will be compressed<br />
and will then print the location of the tgz.<br />
