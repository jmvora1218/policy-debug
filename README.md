# policy-debug

These debug scripts will debug the relevant processes for which they are named after.
The scripts will also gather basic information from the server (disk space, free memory, running processes, hotfixes, etc.)
All the relevant debug files and information will be compressed into a tgz file.


# instructions
policy_gw
policy_mgmt

1. Install policy from Dashboard and verify the error is seen.
2. Upload debug script tar file to a temporary directory.

3. Extract the script.
  tar xvf SCRIPT_NAME.tar

4. Run the script.
  ./SCRIPT_NAME

5. Answer the questions if asked.
6. The script will stop automatically when it is finished.
7. Upload the compressed file using Check Point Uploader on sk108152.
