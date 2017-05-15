###############################################################################
POLICY INSTALLATION DEBUG SCRIPT DOCUMENTATION
###############################################################################

This script will debug Policy Installation.
It will also gather basic information from the machine (disk space,
free memory, running processes, hotfixes, etc.) and other files relevant.

The script will save the debugs to /tmp/policy-debug if the root partition
has 2GB of space or more. Otherwise if will save it to /var/log/policy-debug
if it has 2GB of space or more. There is a also a function that will monitor
the disk space of the partition used. If the free space gets less than 500MB
the debugs will stop and will be deleted.

When the script is finished running, all the files will be compressed
and will then print the location of the tgz.


###############################################################################
SUPPORTED VERSIONS
###############################################################################

Management servers:
R65 and up
Gaia and SecurePlatform
SmartCenter and MDS/Provider-1 which includes Domain/CMA

Gateways:
R65 and up for regular Gateways
R75.40VS and up for VSX
61k/41k
1100, 1400 and other SG80's


###############################################################################
INSTRUCTIONS TO RUN
###############################################################################

1. Upload policy_debug.tar file to a temporary directory.

2. Extract the script.
  [Expert@HostName]# tar xvf policy_debug.tar

3. Run the script.
  [Expert@HostName]# ./policy_debug.sh

Note - Do NOT install policy from SmartConsole while the debug is running.

4. Answer the questions if asked.
5. The script will stop automatically when it is finished.
6. Upload the tgz file using Check Point Uploader on sk108152.


###############################################################################
OPTIONAL FLAGS
###############################################################################

# ./policy_debug.sh -h

A help menu that shows the optional flags available.


# ./policy_debug -b

Manually define the kernel debug buffer.
The script will use 32000 for the buffer by default.
If the Gateway fails to allocate a 32MB buffer, it can be manually defined.


# ./policy_debug -d

If the script itself is failing or not working, it can be debugged.
Debug output will be on the screen and in a log file named, 'script_debug.txt'.
The log file will be created same directory as the script.


# ./policy_debug -f

This will enable more debugging flags.
Management debugs will have "export TDERROR_ALL_ALL=5" on all
debugs except slow policy installation.

Gateway debugs will enable more kernel flags.
See Gateway Debug Syntax section for flags enabled.


# ./policy_debug -s

The minimum disk space check will be disabled and all debug files will be
written to /var/log/policy-debug or /logs/policy-debug if SG80.
This option is not recommended to be enabled, but is available in case it is needed.


# ./policy_debug -v

Display the version information of the script.


###############################################################################
RELEVANT FILES:
###############################################################################

session.log - script log showing any options chosen and debug syntax used.
general.txt - basic information from the machine.


###############################################################################
MANAGEMENT DEBUG SYNTAX:
###############################################################################

Database Installation:
fwm -d dbload "MGMT_NAME" &> install_database_debug.txt

Policy Verification:
fwm -d verify "POLICY_NAME" &> policy_verify_debug.txt


Policy Installation:

Network Security:
fwm -d load "POLICY_NAME" "GATEWAY_NAME" &> security_policy_install_debug.txt

Threat Prevention:
fwm -d load -p threatprevention "POLICY_NAME" "GATEWAY_NAME" &> threat_prevention_policy_install_debug.txt

QoS:
fgate -d load "POLICY_NAME".F "GATEWAY_NAME" &> qos_policy_install_debug.txt

Desktop Security:
fwm -d psload "$FWDIR/conf/POLICY_NAME".S "GATEWAY_NAME" &> desktop_policy_install_debug.txt

Slow Policy Install:
export TDERROR_ALL_PLCY_INST_TIMING=5
fwm load "POLICY_NAME" "GATEWAY_NAME" &> policy_install_timing_debug.txt

Assign Global Policy for R80 and up:
$MDS_FWDIR/scripts/cpm_debug.sh -t Assign_Global_Policy -s DEBUG
mgmt_cli assign-global-assignment global-domains "Global" dependent-domains "DOMAIN_NAME" -r true

Assign Global Policy for R77 and below:
export TDERROR_ALL_ALL=5
fwm -d mds fwmconnect -assign -n 10 -g "##GLOBAL_POLICY_NAME" -l "CMA_NAME_._._DOMAIN_NAME" &> global_policy_assign_debug.txt


###############################################################################
GATEWAY DEBUG SYNTAX
###############################################################################

fw ctl debug -m fw + filter ioctl
fw ctl debug -m kiss + salloc
fw ctl kdebug -T -f &> kernel_atomic_debug.txt

export TDERROR_ALL_ALL=5
fw -d fetchlocal -d $FWDIR/state/__tmp/FW1 &> fetch_local_debug.txt

If this script is run with the "-f" flag, the below kernel flags are enabled.
These additional flags will use more CPU and memory to run.
This may cause some loaded Gateways to stop responding or crash.
Run this flag only in a maintenance window.

fw ctl debug -m fw + filter ioctl cmi
fw ctl debug -m WS + error warning
fw ctl debug -m cmi_loader + error warning policy info
fw ctl debug -m kiss + error warning htab ghtab mtctx salloc pm

If the Gateway is R80.10 or higher, this flag is enabled.
fw ctl debug -m UP + error warning
