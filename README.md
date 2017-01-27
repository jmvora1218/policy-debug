# policy-debug

These debug scripts will debug the relevant processes for which they are named after.<br />
The scripts will also gather basic information from the server (disk space, free memory, running processes, hotfixes, etc.)<br />
All the relevant debug files and information will be compressed into a tgz file.


# Instructions

1. Upload debug script file to a temporary directory.

2. Convert the script to Unix.<br />
  \# dos2unix SCRIPT_NAME

3. Give execute permissions.<br />
  \# chmod +x SCRIPT_NAME

4. Run the script.<br />
  \# ./SCRIPT_NAME

  Note - Do NOT install policy from Dashboard while the debug is running.

5. Answer the questions if asked.

6. The script will stop automatically when it is finished.
