###############################################################################<br />
POLICY INSTALLATION DEBUG SCRIPT DOCUMENTATION
###############################################################################

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
<br />

###############################################################################<br />
SUPPORTED VERSIONS
###############################################################################

Management servers:<br />
R65 and up<br />
Gaia and SecurePlatform<br />
SmartCenter and MDS/Provider-1 which includes Domain/CMA<br />

Gateways:<br />
R65 and up for regular Gateways<br />
R75.40VS and up for VSX<br />
61k/41k<br />
1100, 1400 and other SG80's<br />
<br />

###############################################################################<br />
INSTRUCTIONS TO RUN
###############################################################################

1. Upload policy_debug.tar file to a temporary directory.<br />

2. Extract the script.<br />
  [Expert@HostName]# tar xvf policy_debug.tar<br />

3. Run the script.<br />
  [Expert@HostName]# ./policy_debug.sh<br />

Note - Do NOT install policy from SmartConsole while the debug is running.

4. Answer the questions if asked.<br />
5. The script will stop automatically when it is finished.<br />
6. Upload the tgz file using Check Point Uploader on sk108152.<br />
<br />

###############################################################################<br />
OPTIONAL FLAGS
###############################################################################

\# ./policy_debug.sh -h

A help menu that shows the optional flags available.
<br />

\# ./policy_debug -b

Manually define the kernel debug buffer.<br />
The script will use 32000 for the buffer by default.<br />
If the Gateway fails to allocate a 32MB buffer, it can be manually defined.
<br />

\# ./policy_debug -d

If the script itself is failing or not working, it can be debugged.<br />
Debug output will be on the screen and in a log file named, 'script_debug.txt'.<br />
The log file will be created same directory as the script.
<br />

\# ./policy_debug -f

This will enable more debugging flags.<br />
Management debugs will have "export TDERROR_ALL_ALL=5" on all<br />
debugs except slow policy installation.

Gateway debugs will enable more kernel flags.<br />
See Gateway Debug Syntax section for flags enabled.
<br />

\# ./policy_debug -s

The minimum disk space check will be disabled and all debug files will be<br />
written to /var/log/policy-debug or /logs/policy-debug if SG80.<br />
This option is not recommended to be enabled, but is available in case it is needed.
<br />

\# ./policy_debug -v

Display the version information of the script.
<br />

###############################################################################<br />
RELEVANT FILES<br />
###############################################################################

session.log - script log showing any options chosen and debug syntax used.<br />
general.txt - basic information from the machine.
<br />

###############################################################################<br />
MANAGEMENT DEBUG SYNTAX
###############################################################################

Database Installation:<br />
fwm -d dbload "MGMT_NAME" &> install_database_debug.txt

Policy Verification:<br />
fwm -d verify "POLICY_NAME" &> policy_verify_debug.txt
<br />

Policy Installation:

Network Security:<br />
fwm -d load "POLICY_NAME" "GATEWAY_NAME" &> security_policy_install_debug.txt

Threat Prevention:<br />
fwm -d load -p threatprevention "POLICY_NAME" "GATEWAY_NAME" &> threat_prevention_policy_install_debug.txt

QoS:<br />
fgate -d load "POLICY_NAME".F "GATEWAY_NAME" &> qos_policy_install_debug.txt

Desktop Security:<br />
fwm -d psload "$FWDIR/conf/POLICY_NAME".S "GATEWAY_NAME" &> desktop_policy_install_debug.txt

Slow Policy Install:<br />
export TDERROR_ALL_PLCY_INST_TIMING=5<br />
fwm load "POLICY_NAME" "GATEWAY_NAME" &> policy_install_timing_debug.txt

Assign Global Policy for R80 and up:<br />
$MDS_FWDIR/scripts/cpm_debug.sh -t Assign_Global_Policy -s DEBUG<br />
mgmt_cli assign-global-assignment global-domains "Global" dependent-domains "DOMAIN_NAME" -r true

Assign Global Policy for R77 and below:<br />
export TDERROR_ALL_ALL=5<br />
fwm -d mds fwmconnect -assign -n 10 -g "##GLOBAL_POLICY_NAME" -l "CMA_NAME_._._DOMAIN_NAME" &> global_policy_assign_debug.txt
<br />

###############################################################################<br />
GATEWAY DEBUG SYNTAX
###############################################################################

fw ctl debug -m fw + filter ioctl<br />
fw ctl debug -m kiss + salloc<br />
fw ctl kdebug -T -f &> kernel_atomic_debug.txt

export TDERROR_ALL_ALL=5<br />
fw -d fetchlocal -d $FWDIR/state/__tmp/FW1 &> fetch_local_debug.txt

If this script is run with the "-f" flag, the below kernel flags are enabled.<br />
These additional flags will use more CPU and memory to run.<br />
This may cause some loaded Gateways to stop responding or crash.<br />
Run this flag only in a maintenance window.

fw ctl debug -m fw + filter ioctl cmi<br />
fw ctl debug -m WS + error warning<br />
fw ctl debug -m cmi_loader + error warning policy info<br />
fw ctl debug -m kiss + error warning htab ghtab mtctx salloc pm

If the Gateway is R80.10 or higher, this flag is enabled.<br />
fw ctl debug -m UP + error warning
