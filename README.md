This script will debug Policy Installation.<br />
It will also gather basic information from the machine (disk space, free memory, running processes, hotfixes, etc.) and other files relevant.

The script will save the debugs to /tmp/policy-debug if the root partition has 2GB of space or more.<br />
Otherwise if will save it to /var/log/policy-debug if it has 2GB of space or more.<br />
There is a also a function that will monitor the disk space of the partition used.<br />
If the free space gets less than 500MB the debugs will stop and will be deleted.

When the script is finished running, all the files will be compressed and will then print the location of the tgz.<br />
