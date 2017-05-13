#!/bin/bash

# Russell Seifert
# Escalation Engineer
# Check Point Software Technologies Ltd.

###############################################################################
# HELP SCREEN
###############################################################################
HELP_USAGE="
Usage: $0 [OPTIONS]

   -h    display this help
   -b    define the kernel debug buffer (Gateway debug only)
   -d    debug this script. a log file named 'script_debug.txt' will be
           created in the current working directory
   -f    enable more debug flags
   -s    disable minimum disk space check
   -v    version information
"

HELP_VERSION="
Policy Installation Debug Script
Version 3.5 BETA
"

OPTIND=1
while getopts ':h-:b-:d-:f-:s-:v-:' HELP_OPTION; do
    case "$HELP_OPTION" in
        h) echo "$HELP_USAGE" ; exit ;;
        b) DEBUG_BUFFER_ON=1 ;;
        d) set -vx ; exec &> >(tee script_debug.txt) ;;
        f) MORE_DEBUG_FLAGS=1 ;;
        s) SPACE_CHECK_OFF=1 ;;
        v) echo "$HELP_VERSION" ; exit ;;
        \?) printf "Invalid option: -%s\n" "$OPTARG" >&2
            echo "$HELP_USAGE" >&2 ; exit 1 ;;
    esac
done
shift $(( OPTIND - 1 ))

if [[ "$#" -gt "0" ]]; then
    echo -e "Error: Illegal number of parameters\\n$HELP_USAGE"
    exit 1
fi

###############################################################################
# INTRODUCTION
###############################################################################
clear
echo -e "\033[1m************************************************"
echo -e "Welcome to the Policy Installation Debug Script"
echo -e "************************************************\\n\033[0m"
echo -e "This script will debug Policy Installation problems"
echo -e "Please answer the following questions if asked\\n"
unset TMOUT

###############################################################################
# VERIFY ENVIRONMENT AND IMPORT CHECKPOINT VARIABLES
###############################################################################
if [[ $(uname -s) != "Linux" ]]; then
    echo -e "\\nError: This is not running on Linux"
    echo -e "This script is designed to run on a Linux OS"
    echo -e "Please find an alternate method to debug Policy Installation\\n"
    exit 1
fi

if [[ -r /etc/profile.d/CP.sh ]]; then
    source /etc/profile.d/CP.sh
elif [[ -r /opt/CPshared/5.0/tmp/.CPprofile.sh ]]; then
    source /opt/CPshared/5.0/tmp/.CPprofile.sh
elif [[ -r $CPDIR/tmp/.CPprofile.sh ]]; then
    source $CPDIR/tmp/.CPprofile.sh
else
    echo -e "\\nError: Unable to find \$CPDIR/tmp/.CPprofile.sh"
    echo -e "Verify this file exists and you can read it\\n"
    exit 1
fi

if [[ $($CPDIR/bin/cpprod_util FwIsVSX 2> /dev/null) == *"1"* ]]; then
    if [[ -r /etc/profile.d/vsenv.sh ]]; then
        source /etc/profile.d/vsenv.sh
    elif [[ -r $FWDIR/scripts/vsenv.sh ]]; then
        source $FWDIR/scripts/vsenv.sh
    else
        if [[ $($CPDIR/bin/cpprod_util CPPROD_GetValue CPshared VersionText 1) == *"R6"* ]]; then
            echo -e "\\nError: This is a VSX Gateway on a version lower than R75.40VS"
            echo -e "This script is not supported on this version"
            echo -e "Please follow sk84700 to debug Policy Installation\\n"
            exit 1
        else
            echo -e "\\nError: Unable to find /etc/profile.d/vsenv.sh or \$FWDIR/scripts/vsenv.sh"
            echo -e "Verify this file exists in either directory and you can read it\\n"
            exit 1
        fi
    fi
fi

IS_MGMT=$($CPDIR/bin/cpprod_util FwIsFirewallMgmt)
IS_MDS=$($CPDIR/bin/cpprod_util CPPROD_GetValue PROVIDER-1 IsConfigured 1 2> /dev/null)
IS_FW=$($CPDIR/bin/cpprod_util FwIsFirewallModule)
IS_VSX=$($CPDIR/bin/cpprod_util FwIsVSX 2> /dev/null)
IS_SG80=$($CPDIR/bin/cpprod_util CPPROD_GetValue Products SG80 1 2> /dev/null)
IS_61K=$($CPDIR/bin/cpprod_util CPPROD_GetValue ASG_CHASSIS ChassisID 1 2> /dev/null)

MAJOR_VERSION=$($CPDIR/bin/cpprod_util CPPROD_GetValue CPshared VersionText 1)

###############################################################################
# BASIC VARIABLES
###############################################################################
ECHO="/bin/echo -e"
SCRIPT_NAME=($(basename $0))
FILES="$SCRIPT_NAME"_files.$$

###############################################################################
# CREATE TEMPORARY DIRECTORIES
###############################################################################
if [[ "$IS_SG80" == "Failed to find the value" ]]; then
    if [[ "$SPACE_CHECK_OFF" == "1" ]]; then
        DBGDIR=/var/log/policy-debug
        DBGDIR_FILES=/var/log/policy-debug/"$FILES"
    else
        if [[ $(df -P | grep /$ | awk '{ print $4 }') -lt "2000000" ]]; then
            if [[ $(df -P | egrep "/var$|/var/log$" | awk '{ print $4 }') -lt "2000000" ]]; then
                $ECHO "\\nError: There is not enough disk space available"
                $ECHO "Please follow sk60080 to clear disk space\\n"
                exit 1
            else
                DBGDIR=/var/log/policy-debug
                DBGDIR_FILES=/var/log/policy-debug/"$FILES"
            fi
        else
            DBGDIR=/tmp/policy-debug
            DBGDIR_FILES=/tmp/policy-debug/"$FILES"
        fi
    fi
else
    if [[ "$SPACE_CHECK_OFF" == "1" ]]; then
        DBGDIR=/logs/policy-debug
        DBGDIR_FILES=/logs/policy-debug/"$FILES"
    else
        if [[ $(df | grep "/logs" | awk '{ print $4 }') -lt "10000" ]]; then
            if [[ $(df | grep "/storage" | awk '{ print $4 }') -lt "10000" ]]; then
                $ECHO "\\nError: There is not enough disk space available"
                $ECHO "Please follow sk60080 to clear disk space\\n"
                exit 1
            else
                DBGDIR=/storage/tmp/policy-debug
                DBGDIR_FILES=/storage/tmp/policy-debug/"$FILES"
            fi
        else
            DBGDIR=/logs/policy-debug
            DBGDIR_FILES=/logs/policy-debug/"$FILES"
        fi
    fi
fi

if [[ ! -d "$DBGDIR_FILES" ]]; then
    mkdir -p "$DBGDIR_FILES"
else
    rm -rf "$DBGDIR_FILES"
    mkdir -p "$DBGDIR_FILES"
fi

###############################################################################
# PROCESS CLEANUP AND TERMINATION SIGNALS
###############################################################################
if [[ "$IS_SG80" == "Failed to find the value" ]]; then
    interrupted()
    {
        $ECHO "\\n\\nError: Script interrupted, cleaning temporary files..."

        if [[ "$IS_FW" == *"1"* ]]; then
            fw ctl debug 0 1> /dev/null
        fi

        unset TDERROR_ALL_ALL
        unset TDERROR_ALL_PLCY_INST_TIMING

        if [[ "$MAJOR_VERSION" == "R80" ]]; then
            if [[ $(grep \#TOPIC-DEBUG:assign_global_policy:SEVERITY $MDS_FWDIR/conf/tdlog.cpm) == "#TOPIC-DEBUG:assign_global_policy:SEVERITY"* ]]; then
                $MDS_FWDIR/scripts/cpm_debug.sh -t Assign_Global_Policy -s INFO
                $MDS_FWDIR/scripts/cpm_debug.sh -r
            fi
        fi

        pkill -P $$
        rm -rf "$DBGDIR_FILES"

        $ECHO "Completed\\n"
        exit 1
    }
    trap interrupted SIGHUP SIGINT SIGTERM # 1 2 15

    clean_up()
    {
        pkill -P $$
        rm -rf "$DBGDIR_FILES"
    }
    trap clean_up EXIT # 0
fi

###############################################################################
# MONITOR DISK SPACE USAGE
###############################################################################
if [[ "$IS_SG80" == "Failed to find the value" ]]; then
    disk_space_check()
    {
        while true; do
            DISKCHECK=$(df -P $DBGDIR | grep / | awk '{print $4}')
            if [[ "$DISKCHECK" -lt "500000" ]]; then
                $ECHO -n "\\n\\nError: Disk space is less than 500MB. Stopping debug..."
                kill -15 $$
            fi
        sleep 20
        done
    }
    disk_space_check &
fi

###############################################################################
# START SCRIPT SESSION LOG
###############################################################################
GENERAL_LOG="$DBGDIR_FILES"/general.txt
SESSION_LOG="$DBGDIR_FILES"/session.log
START_DATE=$(/bin/date "+%d %b %Y %H:%M:%S %z")

echo_log()
{
    $ECHO "$1" >> "$SESSION_LOG"
}

echo_shell_log()
{
    $ECHO "$1" | tee -a "$SESSION_LOG"
}

echo_log "$HELP_VERSION"
echo_log "Script Started at $START_DATE\\n"

if [[ "$SPACE_CHECK_OFF" == "1" ]]; then
    echo_shell_log "\\nWARNING: Minimum disk space check is disabled"
fi

if [[ "$MORE_DEBUG_FLAGS" == "1" ]]; then
    echo_shell_log "\\nINFO: More debug flags is enabled"
fi

###############################################################################
# CHANGE TO CMA CONTEXT IF MDS
###############################################################################
change_to_cma()
{
    if [[ "$IS_MDS" == "1" ]]; then
        echo_shell_log "\\nThis is a Multi-Domain Management Server"
        echo_shell_log "\\n--------DOMAINS DETECTED--------\\n"

        OBJECT_ARRAY=($($MDSVERUTIL AllCMAs | sort | tee -a "$SESSION_LOG"))
        display_objects "Domains"

        while true; do
            $ECHO "\\nWhat is the number of the Domain you want to debug?"
            $ECHO -n "(1-${OBJECT_ARRAY_NUMBER_OPTION}): "
            read CMA_NUMBER

            case "$CMA_NUMBER" in
                [1-9]|[1-9][0-9]|[1-9][0-9][0-9])
                    CMA_NAME="${OBJECT_ARRAY[$((CMA_NUMBER-1))]}"
                    CMA_NAME_EXIST=$($MDSVERUTIL AllCMAs | grep ^"$CMA_NAME"$)
                    ;;
                *)
                    not_valid
                    continue ;;
            esac

            case "$CMA_NAME" in
                "")
                    not_valid
                    continue ;;

                "$CMA_NAME_EXIST")
                    CMA_IP=$($MDSVERUTIL CMAIp -n $CMA_NAME)
                    if [[ "$?" != "0" ]]; then
                        $ECHO "\\nError: There is no Domain Management Server with Name: $CMA_NAME"
                        $ECHO "Run the script again and specify a valid Domain\\n"
                        clean_up
                        exit 1
                    fi

                    mdsenv "$CMA_NAME"
                    DOMAIN_NAME=$($CPDIR/bin/cpprod_util CPPROD_GetValue FW1 CustomerName 1)
                    if [[ -z "$DOMAIN_NAME" ]]; then
                        $ECHO "\\nError: Failed to retrieve Domain name"
                        $ECHO "Consider running this script again with verbose output\\n"
                        clean_up
                        exit 1
                    fi

                    echo_log "\\nSelected CMA: $CMA_NAME"
                    echo_log "Domain: $DOMAIN_NAME"
                    echo_shell_log ""
                    break ;;
            esac
        done
    fi
}

###############################################################################
# CHECK FWM STATUS
###############################################################################
check_fwm()
{
    if [[ "$IS_MDS" == "1" ]]; then
        FWM_STATUS=$(ps aux | grep $CMA_NAME | grep fwm | grep -v grep)
    else
        FWM_STATUS=$(ps aux | grep fwm | grep -v grep)
    fi

    if [[ -z "$FWM_STATUS" ]]; then
        $ECHO "\\nError: FWM is not running"
        $ECHO "Verify FWM is up and running\\n"
        clean_up
        exit 1
    fi
}

###############################################################################
# VERIFY 61K/41K CHASSIS AND BLADE
###############################################################################
verify_61k()
{
    BLADEID=$($CPDIR/bin/cpprod_util CPPROD_GetValue ASG_CHASSIS BladeID 1)
    echo_shell_log "\\nThis is a 61k/41k Gateway"
    read -p "Do you want to run the debug on Chassis $IS_61K Blade $BLADEID? (y/n) [n]? " CORRECT_61K

        case "$CORRECT_61K" in
            [yY][eE][sS]|[yY])
                echo_log "Selected: Chassis $IS_61K Blade $BLADEID"
                ;;
            *)
                $ECHO "Please change to the correct Chassis and Blade\\n"
                clean_up
                exit 1
                ;;
        esac
}

###############################################################################
# VERIFY VSX CONTEXT
###############################################################################
verify_vsx()
{
    VSID_SCRIPT=$(cat /proc/self/vrf)
    echo_shell_log "\\nThis is a VSX Gateway"
    read -p "Do you want to run the debug on VS $VSID_SCRIPT? (y/n) [n]? " CORRECT_VS

        case "$CORRECT_VS" in
            [yY][eE][sS]|[yY])
                echo_log "Selected: VS $VSID_SCRIPT"
                ;;
            *)
                $ECHO "Please change to the correct Virtual System\\n"
                clean_up
                exit 1
                ;;
        esac

    vsenv "$VSID_SCRIPT" > /dev/null
}

###############################################################################
# VERIFY KERNEL DEBUG BUFFER
###############################################################################
verify_buffer()
{
    if [[ "$DEBUG_BUFFER_ON" == "1" ]]; then
        while true; do
            $ECHO "\\nWhat size in kilobytes do you want the kernel debug buffer? [4000-32768]"
            read DEBUG_BUFFER

            case "$DEBUG_BUFFER" in
                [4-9][0-9][0-9][0-9]|[1-9][0-9][0-9][0-9][0-9])
                    if (( "$DEBUG_BUFFER" < 16384 )); then
                        $ECHO "\\nInfo: The kernel debug buffer is defined less than 16384"
                        $ECHO "The debug may not show the error with a buffer of $DEBUG_BUFFER"
                        read -p "Do you want to continue running the debug? (y/n) [n]? " LOW_BUFFER

                        case "$LOW_BUFFER" in
                            [yY][eE][sS]|[yY])
                                ;;
                            *)
                                $ECHO "\\nPlease define a larger buffer"
                                $ECHO "Press CTRL-C to exit the script if needed"
                                continue
                                ;;
                        esac
                    fi

                    if (( "$DEBUG_BUFFER" > 32768 )); then
                        $ECHO "\\nError: Kernel debug buffer can only be up to 32768"
                        $ECHO "Please define a valid buffer between 4000-32768"
                        $ECHO "Press CTRL-C to exit the script if needed"
                        continue
                    fi

                    VMALLOC_TOTAL=$(cat /proc/meminfo | grep "VmallocTotal" | awk '{ print $2 }')
                    VMALLOC_USED=$(cat /proc/meminfo | grep "VmallocUsed" | awk '{ print $2 }')
                    VMALLOC_FREE=$(( $VMALLOC_TOTAL - $VMALLOC_USED ))

                    if (( "$VMALLOC_FREE" < "$DEBUG_BUFFER" )); then
                        $ECHO "\\nError: Not enough kernel debug buffer free to allocate $DEBUG_BUFFER"
                        $ECHO "Available buffer: $VMALLOC_FREE"
                        $ECHO "Please define a smaller kernel debug buffer"
                        $ECHO "Or follow sk84700 to increase the Vmalloc"
                        $ECHO "Press CTRL-C to exit the script if needed"
                        continue
                    fi

                    echo_shell_log "\\nKernel debug buffer set to $DEBUG_BUFFER\\n"
                    break
                    ;;
                *)
                    $ECHO "\\nError: Kernel debug buffer defined is not valid"
                    $ECHO "Use only numbers and must be between 4000-32768"
                    $ECHO "Press CTRL-C to exit the script if needed"
                    continue
                    ;;
            esac
        done
    else
        DEBUG_BUFFER=32000
        VMALLOC_TOTAL=$(cat /proc/meminfo | grep "VmallocTotal" | awk '{ print $2 }')
        VMALLOC_USED=$(cat /proc/meminfo | grep "VmallocUsed" | awk '{ print $2 }')
        VMALLOC_FREE=$(( $VMALLOC_TOTAL - $VMALLOC_USED ))

        if (( "$VMALLOC_FREE" < "$DEBUG_BUFFER" )); then
            $ECHO "\\nError: Not enough kernel debug buffer free to allocate $DEBUG_BUFFER"
            $ECHO "Available buffer: $VMALLOC_FREE"
            $ECHO "Follow sk84700 to increase the Vmalloc"
            $ECHO "Or run this script again and define a smaller buffer"
            $ECHO "./$SCRIPT_NAME -b\\n"
            clean_up
            exit 1
        fi
    fi
}

kernel_memory_used()
{
    MEMORY_USED=$(fw ctl pstat | grep "Memory used")
    $ECHO "\\nError: Failed to allocate kernel debug buffer of $DEBUG_BUFFER"
    $ECHO "FW Kernel memory usage is high"
    $ECHO "$MEMORY_USED\\n"
    $ECHO "Policy Installation is failing because there is not enough memory"
    $ECHO "Follow sk101875 Scenario 2 or add more RAM to this Gateway\\n"
}

###############################################################################
# ASK USER WHAT TO DEBUG
###############################################################################
debug_mgmt_or_fw()
{
    echo_shell_log "\\nThis is a Standalone Server"
    echo_shell_log "\\n--------DEBUGS AVAILABLE--------\\n"

    echo_shell_log "1. Management (fwm load)"
    echo_shell_log "2. Gateway (fetchlocal + kernel)\\n"

    while true; do
        $ECHO "Which option do you want to debug?"
        $ECHO -n "(1-2): "
        read STAND_DEBUG

        case "$STAND_DEBUG" in
            [1-2])
                $ECHO ""
                echo_log "Selected: $STAND_DEBUG"
                break ;;
            *)
                not_valid
                continue ;;
        esac
    done
}

what_to_debug()
{
    echo_shell_log "\\n--------DEBUGS AVAILABLE--------\\n"

    echo_shell_log "1. Database Installation"
    echo_shell_log "2. Policy Verification"
    echo_shell_log "3. Policy Installation"
    echo_shell_log "4. Slow Policy Install"

    if [[ "$IS_MDS" == "1" ]]; then
        echo_shell_log "5. Assign Global Policy"
    fi

    while true; do
        $ECHO "\\nWhich option do you want to debug?"

        if [[ "$IS_MDS" == "1" ]]; then
            $ECHO -n "(1-5): "
        else
            $ECHO -n "(1-4): "
        fi

        read QUESTION

        if [[ "$IS_MDS" == "1" ]]; then
            case "$QUESTION" in
                [1-5])
                    echo_log "\\nSelected: $QUESTION"
                    break ;;
                *)
                    not_valid
                    continue ;;
            esac
        else
            case "$QUESTION" in
                [1-4])
                    echo_log "\\nSelected: $QUESTION"
                    break ;;
                *)
                    not_valid
                    continue ;;
            esac
        fi
    done
}

which_fw_policy()
{
    echo_shell_log "\\n\\n--------POLICY DEBUGS AVAILABLE--------\\n"
    echo_shell_log "1. Network Security"
    echo_shell_log "2. Threat Prevention"
    echo_shell_log "3. QoS"
    echo_shell_log "4. Desktop Security\\n"

    while true; do
        $ECHO "Which policy do you want to debug?"
        $ECHO -n "(1-4): "
        read WHICH_POLICY

        case "$WHICH_POLICY" in
            [1-4])
                echo_log "Selected: $WHICH_POLICY"
                break ;;
            *)
                not_valid
                continue ;;
        esac
    done
}

not_valid()
{
    $ECHO "\\nError: Selection is not valid"
    $ECHO "Press CTRL-C to exit the script if needed"
}

###############################################################################
# SELECTION OF POLICY/MGMT/GW
###############################################################################
display_objects()
{
    if [[ -z "$OBJECT_ARRAY" ]]; then
        $ECHO "\\nError: There are no $1 detected"
        $ECHO "Verify there are $1 in the SmartConsole\\n"
        clean_up
        exit 1
    fi

    OBJECT_ARRAY_NUMBER=$(printf '%s\n' "${OBJECT_ARRAY[@]}" | wc -l | awk '{ print $1 }')
    OBJECT_ARRAY_NUMBER_OPTION="$OBJECT_ARRAY_NUMBER"

    for (( OBJECT_ARRAY_LIST = 1; "$OBJECT_ARRAY_NUMBER" > 0; OBJECT_ARRAY_LIST++ )); do
        $ECHO "${OBJECT_ARRAY_LIST}. ${OBJECT_ARRAY[$((OBJECT_ARRAY_LIST-1))]}"
        let "OBJECT_ARRAY_NUMBER -= 1"
    done
}

select_object()
{
    while true; do
        $ECHO "\\nWhat is the number of the $1 you want to debug?"
        $ECHO -n "(1-${OBJECT_ARRAY_NUMBER_OPTION}): "
        read OBJECT_NUMBER

        case "$OBJECT_NUMBER" in
            [1-9]|[1-9][0-9]|[1-9][0-9][0-9])
                OBJECT_NAME="${OBJECT_ARRAY[$((OBJECT_NUMBER-1))]}"

                if [[ "$1" == "Policy" ]]; then
                    if [[ "$IS_MDS" == "1" ]]; then
                        OBJECT_NAME_EXIST=$($ECHO "$CMA_IP\n-t policies_collections -a\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' | grep ^"$OBJECT_NAME"$)
                    else
                        OBJECT_NAME_EXIST=$($ECHO "localhost\n-t policies_collections -a\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' | grep ^"$OBJECT_NAME"$)
                    fi

                elif [[ "$1" == "Global Policy" ]]; then
                    OBJECT_NAME_EXIST=$(cpmiquerybin attr "" policies_collections "" -a __name__ | grep -v "No Global Policy" | sed 's/[[:blank:]]*$//' | grep ^"$OBJECT_NAME"$)

                elif [[ "$1" == "Management" ]]; then
                    if [[ "$IS_MDS" == "1" ]]; then
                        OBJECT_NAME_EXIST=$($ECHO "$CMA_IP\n-t network_objects -s management='true' -s log_server='true'\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' | grep ^"$OBJECT_NAME"$)
                    else
                        OBJECT_NAME_EXIST=$($ECHO "localhost\n-t network_objects -s management='true' -s log_server='true'\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' | grep ^"$OBJECT_NAME"$)
                    fi

                elif [[ "$1" == "Gateway/Cluster" ]]; then
                    if [[ "$IS_MDS" == "1" ]]; then
                        OBJECT_NAME_EXIST=$($ECHO "$CMA_IP\n-t network_objects -s firewall='installed'\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' | grep ^"$OBJECT_NAME"$)
                    else
                        OBJECT_NAME_EXIST=$($ECHO "localhost\n-t network_objects -s firewall='installed'\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' | grep ^"$OBJECT_NAME"$)
                    fi
                fi
                ;;
            *)
                not_valid
                continue ;;
        esac

        case "$OBJECT_NAME" in
            "")
                not_valid
                continue ;;

            "$OBJECT_NAME_EXIST")
                $ECHO "Selected: $OBJECT_NAME"
                echo_log "\\nSelected: $OBJECT_NAME"
                break ;;
        esac
    done
}

###############################################################################
# DETECTION OF POLICY/MGMT/GW
###############################################################################
policy_detect()
{
    echo_shell_log "\\n\\n--------POLICIES DETECTED--------\\n"

    if [[ "$IS_MDS" == "1" ]]; then
        OBJECT_ARRAY=($($ECHO "$CMA_IP\n-t policies_collections -a\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' | tee -a "$SESSION_LOG"))
    else
        OBJECT_ARRAY=($($ECHO "localhost\n-t policies_collections -a\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' | tee -a "$SESSION_LOG"))
    fi

    display_objects "Policies"
    select_object "Policy"

    POLICY_NAME="$OBJECT_NAME"
}

global_policy_detect()
{
    echo_shell_log "\\n\\n--------GLOBAL POLICIES DETECTED--------\\n"

    mdsenv
    OBJECT_ARRAY=($(cpmiquerybin attr "" policies_collections "" -a __name__ | grep -v "No Global Policy" | sort | tee -a "$SESSION_LOG"))

    display_objects "Global Policies"
    select_object "Global Policy"

    GLOBAL_POLICY_NAME="$OBJECT_NAME"
}

mgmt_detect()
{
    # $ECHO "\\nWhat is the number of the Management you want to Install Database to?"
    echo_shell_log "\\n\\n--------MANAGEMENTS DETECTED--------\\n"

    if [[ "$IS_MDS" == "1" ]]; then
        OBJECT_ARRAY=($($ECHO "$CMA_IP\n-t network_objects -s management='true' -s log_server='true'\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' | tee -a "$SESSION_LOG"))
    else
        OBJECT_ARRAY=($($ECHO "localhost\n-t network_objects -s management='true' -s log_server='true'\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' | tee -a "$SESSION_LOG"))
    fi

    display_objects "Management servers"
    select_object "Management"

    MGMT_NAME="$OBJECT_NAME"
}

gateway_detect()
{
    echo_shell_log "\\n\\n--------GATEWAYS DETECTED--------\\n"

    # NETWORK SECURITY
    if [[ "$1" == "1" ]]; then
        if [[ "$IS_MDS" == "1" ]]; then
            OBJECT_ARRAY=($($ECHO "$CMA_IP\n-t network_objects -s firewall='installed'\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' | tee -a "$SESSION_LOG"))
        else
            OBJECT_ARRAY=($($ECHO "localhost\n-t network_objects -s firewall='installed'\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' | tee -a "$SESSION_LOG"))
        fi

    # THREAT PREVENTION
    elif [[ "$1" == "2" ]]; then
        THREAT_GATEWAY_FILE="$DBGDIR_FILES"/tp.txt

        if [[ "$IS_MDS" == "1" ]]; then
            THREAT_AMW=($($ECHO "$CMA_IP\n-t network_objects -s firewall='installed' -s anti_malware_blade='installed'\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' >> "$THREAT_GATEWAY_FILE"))
            THREAT_AV=($($ECHO "$CMA_IP\n-t network_objects -s firewall='installed' -s anti_virus_blade='installed'\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' >> "$THREAT_GATEWAY_FILE"))
            THREAT_EX=($($ECHO "$CMA_IP\n-t network_objects -s firewall='installed' -s scrubbing_blade='installed'\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' >> "$THREAT_GATEWAY_FILE"))
            THREAT_EM=($($ECHO "$CMA_IP\n-t network_objects -s firewall='installed' -s threat_emulation_blade='installed'\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' >> "$THREAT_GATEWAY_FILE"))
            OBJECT_ARRAY=($(cat "$THREAT_GATEWAY_FILE" | sort -u | tee -a "$SESSION_LOG"))
        else
            THREAT_AMW=($($ECHO "localhost\n-t network_objects -s firewall='installed' -s anti_malware_blade='installed'\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' >> "$THREAT_GATEWAY_FILE"))
            THREAT_AV=($($ECHO "localhost\n-t network_objects -s firewall='installed' -s anti_virus_blade='installed'\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' >> "$THREAT_GATEWAY_FILE"))
            THREAT_EX=($($ECHO "localhost\n-t network_objects -s firewall='installed' -s scrubbing_blade='installed'\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' >> "$THREAT_GATEWAY_FILE"))
            THREAT_EM=($($ECHO "localhost\n-t network_objects -s firewall='installed' -s threat_emulation_blade='installed'\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' >> "$THREAT_GATEWAY_FILE"))
            OBJECT_ARRAY=($(cat "$THREAT_GATEWAY_FILE" | sort -u | tee -a "$SESSION_LOG"))
        fi

        rm "$THREAT_GATEWAY_FILE"

    # QoS
    elif [[ "$1" == "3" ]]; then
        if [[ "$IS_MDS" == "1" ]]; then
            OBJECT_ARRAY=($($ECHO "$CMA_IP\n-t network_objects -s floodgate='installed'\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' | tee -a "$SESSION_LOG"))
        else
            OBJECT_ARRAY=($($ECHO "localhost\n-t network_objects -s floodgate='installed'\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' | tee -a "$SESSION_LOG"))
        fi

    # DESKTOP SECURITY
    elif [[ "$1" == "4" ]]; then
        if [[ "$IS_MDS" == "1" ]]; then
            OBJECT_ARRAY=($($ECHO "$CMA_IP\n-t network_objects -s policy_server='installed'\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' | tee -a "$SESSION_LOG"))
        else
            OBJECT_ARRAY=($($ECHO "localhost\n-t network_objects -s policy_server='installed'\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' | tee -a "$SESSION_LOG"))
        fi
    fi

    display_objects "Gateways"
    select_object "Gateway/Cluster"

    GATEWAY_NAME="$OBJECT_NAME"
}

###############################################################################
# FUNCTIONS FOR MAIN DEBUG
###############################################################################
starting_mgmt_debug()
{
    echo_shell_log "\\n\\n--------STARTING DEBUG--------\\n"
    DEBUG_DATE=$(/bin/date "+%d %b %Y %H:%M:%S %z")
    echo_log "Debug Started at $DEBUG_DATE"
}

starting_fw_debug()
{
    if [[ "$IS_61K" != "Failed to find the value" ]]; then
        if [[ "$IS_VSX" == *"1"* ]]; then
            echo_shell_log "\\n\\n----STARTING DEBUG ON CHASSIS $IS_61K BLADE $BLADEID VS ${VSID_SCRIPT}----\\n"
        else
            echo_shell_log "\\n\\n----STARTING DEBUG ON CHASSIS $IS_61K BLADE $BLADEID----\\n"
        fi

    elif [[ "$IS_VSX" == *"1"* ]]; then
        echo_shell_log "\\n\\n----STARTING DEBUG ON VS ${VSID_SCRIPT}----\\n"
    else
        echo_shell_log "\\n----STARTING DEBUG----\\n"
    fi

    $ECHO "Turning debug on..."

    DEBUG_DATE=$(/bin/date "+%d %b %Y %H:%M:%S %z")
    echo_log "Debug Started at $DEBUG_DATE"
}

progress_bar()
{
    PB_CHARS=( "-" "\\" "|" "/" )
    PB_COUNT=0
    PB_PID=$!

    while [ -d /proc/"$PB_PID" ]; do
        PB_POS=$(( $PB_COUNT % 4 ))
        $ECHO -n "\b${PB_CHARS[$PB_POS]}"
        PB_COUNT=$(( $PB_COUNT + 1 ))
        sleep 1
    done
}

export_tderror()
{
    echo_log "\\nRunning:"
    echo_log "export TDERROR_ALL_ALL=5"
    export TDERROR_ALL_ALL=5
}

export_internal_policy_r80()
{
    echo_log "\\nRunning:"
    echo_log "export INTERNAL_POLICY_LOADING=1"
    export INTERNAL_POLICY_LOADING=1
}

export_tderror_all_r80()
{
    echo_log "\\nRunning:"
    echo_log "export TDERROR_ALL_ALL=5"
    echo_log "export INTERNAL_POLICY_LOADING=1"
    export TDERROR_ALL_ALL=5
    export INTERNAL_POLICY_LOADING=1
}

export_tderror_debug()
{
    if [[ "$MAJOR_VERSION" == "R80" ]]; then
        if [[ "$MORE_DEBUG_FLAGS" == "1" ]]; then
            export_tderror_all_r80
        else
            export_internal_policy_r80
        fi
    else
        if [[ "$MORE_DEBUG_FLAGS" == "1" ]]; then
            export_tderror
        else
            echo_log "\\nRunning:"
        fi
    fi
}

###############################################################################
# MAIN DEBUG MGMT
###############################################################################
debug_mgmt()
{
    # DATABASE
    if [[ "$QUESTION" == "1" ]]; then
        mgmt_detect
        starting_mgmt_debug

        export_tderror_debug
        echo_log "fwm -d dbload $MGMT_NAME &> install_database_debug.txt"

        $ECHO -n "Installing Database to $MGMT_NAME   "
        fwm -d dbload "$MGMT_NAME" &> "$DBGDIR_FILES"/install_database_debug.txt &
        progress_bar
    fi

    # VERIFY
    if [[ "$QUESTION" == "2" ]]; then
        policy_detect
        starting_mgmt_debug

        export_tderror_debug
        echo_log "fwm -d verify $POLICY_NAME &> policy_verify_debug.txt"

        $ECHO -n "Verifying $POLICY_NAME Policy   "
        fwm -d verify "$POLICY_NAME" &> "$DBGDIR_FILES"/policy_verify_debug.txt &
        progress_bar
    fi

    # INSTALL
    if [[ "$QUESTION" == "3" ]]; then
        which_fw_policy
        policy_detect

        if [[ "$WHICH_POLICY" == "1" ]]; then
            gateway_detect "1"
            starting_mgmt_debug

            export_tderror_debug
            echo_log "fwm -d load $POLICY_NAME $GATEWAY_NAME &> security_policy_install_debug.txt"

            $ECHO -n "Installing Security Policy $POLICY_NAME to $GATEWAY_NAME   "
            fwm -d load "$POLICY_NAME" "$GATEWAY_NAME" &> "$DBGDIR_FILES"/security_policy_install_debug.txt &
            progress_bar

        elif [[ "$WHICH_POLICY" == "2" ]]; then
            gateway_detect "2"
            starting_mgmt_debug

            export_tderror_debug
            echo_log "fwm -d load -p threatprevention $POLICY_NAME $GATEWAY_NAME &> threat_prevention_policy_install_debug.txt"

            $ECHO -n "Installing Threat Prevention Policy $POLICY_NAME to $GATEWAY_NAME   "
            fwm -d load -p threatprevention "$POLICY_NAME" "$GATEWAY_NAME" &> "$DBGDIR_FILES"/threat_prevention_policy_install_debug.txt &
            progress_bar

        elif [[ "$WHICH_POLICY" == "3" ]]; then
            gateway_detect "3"
            starting_mgmt_debug

            export_tderror_debug
            echo_log "fgate -d load ${POLICY_NAME}.F $GATEWAY_NAME &> qos_policy_install_debug.txt"

            $ECHO -n "Installing QoS Policy $POLICY_NAME to $GATEWAY_NAME   "
            fgate -d load "${POLICY_NAME}.F" "$GATEWAY_NAME" &> "$DBGDIR_FILES"/qos_policy_install_debug.txt &
            progress_bar

        elif [[ "$WHICH_POLICY" == "4" ]]; then
            gateway_detect "4"
            starting_mgmt_debug

            export_tderror_debug
            echo_log "fwm -d psload $FWDIR/conf/${POLICY_NAME}.S $GATEWAY_NAME &> desktop_policy_install_debug.txt"

            $ECHO -n "Installing Desktop Security Policy $POLICY_NAME to $GATEWAY_NAME   "
            fwm -d psload "$FWDIR/conf/${POLICY_NAME}.S" "$GATEWAY_NAME" &> "$DBGDIR_FILES"/desktop_policy_install_debug.txt &
            progress_bar
        fi
    fi

    # SLOW INSTALL
    if [[ "$QUESTION" == "4" ]]; then
        policy_detect
        gateway_detect "1"
        starting_mgmt_debug

        if [[ "$MAJOR_VERSION" == "R80" ]]; then
            export_internal_policy_r80
        else
            echo_log "\\nRunning:"
        fi

        export TDERROR_ALL_PLCY_INST_TIMING=5
        echo_log "export TDERROR_ALL_PLCY_INST_TIMING=5"
        echo_log "fwm load $POLICY_NAME $GATEWAY_NAME &> policy_install_timing_debug.txt"

        $ECHO -n "Installing Security Policy $POLICY_NAME to $GATEWAY_NAME   "
        fwm load "$POLICY_NAME" "$GATEWAY_NAME" &> "$DBGDIR_FILES"/policy_install_timing_debug.txt &
        progress_bar
    fi

    # GLOBAL ASSIGN
    if [[ "$QUESTION" == "5" ]]; then
        if [[ "$MAJOR_VERSION" == "R80" ]]; then
            JETTY_PID=$(pgrep -f $MDS_CPDIR/jetty/start.jar)
            API_STATUS=$(tail -n 1 $MDS_FWDIR/api/conf/jetty.state | grep STARTED)

            if [[ -z "$JETTY_PID" || -z "$API_STATUS" ]]; then
                $ECHO "\\nError: The API server is not running"
                $ECHO "R80 Global Policy debug requires API to be running"
                $ECHO "Run 'api start' and then run this script again\\n"
                clean_up
                exit 1
            fi

            $ECHO "\\nUsing the API server to run the debug"

            # UNSET MGMT_CLI ENV VARIABLE
            for UNSET_MGMTCLI in $(env | grep MGMT_CLI_ | cut -f1 -d"="); do
                unset "$UNSET_MGMTCLI"
            done

            GLOBAL_POLICY_NAME_R80=$(mgmt_cli show global-assignment global-domain "Global" dependent-domain "$DOMAIN_NAME" -r true -f json | $MDS_CPDIR/jq/jq '.["global-access-policy"]' -r)
            if [[ "$GLOBAL_POLICY_NAME_R80" == "null" ]]; then
                $ECHO "\\nError: $DOMAIN_NAME is not assigned a Global Policy"
                $ECHO "Verify $DOMAIN_NAME has a Global Policy assigned in the SmartConsole\\n"
                clean_up
                exit 1
            fi

            $ECHO "=debug_start=" > $MDS_FWDIR/log/cpm.elg
            echo_log "\\nRunning:"
            echo_log "$MDS_FWDIR/scripts/cpm_debug.sh -t Assign_Global_Policy -s DEBUG"
            echo_log "mgmt_cli assign-global-assignment global-domains Global dependent-domains $DOMAIN_NAME -r true"

            $ECHO "Assigning Global Policy $GLOBAL_POLICY_NAME_R80 to $DOMAIN_NAME"
            $MDS_FWDIR/scripts/cpm_debug.sh -t Assign_Global_Policy -s DEBUG
            mgmt_cli assign-global-assignment global-domains "Global" dependent-domains "$DOMAIN_NAME" -r true
        else
            global_policy_detect
            starting_mgmt_debug

            mdsenv "$CMA_NAME"
            rm $FWDIR/log/fwm.elg.* 2> /dev/null
            $ECHO "=debug_start=" > $FWDIR/log/fwm.elg
            fw debug fwm on TDERROR_ALL_ALL=5

            mdsenv
            echo_log "\\nRunning:"
            echo_log "export TDERROR_ALL_ALL=5"
            echo_log "fwm -d mds fwmconnect -assign -n 10 -g ##$GLOBAL_POLICY_NAME -l ${CMA_NAME}_._._${DOMAIN_NAME} &> global_policy_assign_debug.txt"

            $ECHO -n "Assigning Global Policy $GLOBAL_POLICY_NAME to $DOMAIN_NAME   "
            export TDERROR_ALL_ALL=5
            fwm -d mds fwmconnect -assign -n 10 -g "##$GLOBAL_POLICY_NAME" -l "${CMA_NAME}_._._${DOMAIN_NAME}" &> "$DBGDIR_FILES"/global_policy_assign_debug.txt &
            progress_bar
        fi
    fi
}

###############################################################################
# MAIN DEBUG FW
###############################################################################
debug_fw()
{
    starting_fw_debug
    fw ctl debug 0 > /dev/null

    if [[ "$IS_VSX" == *"1"* ]]; then
        fw ctl debug -buf "$DEBUG_BUFFER" -v "$VSID_SCRIPT" > /dev/null

        if [[ "$?" != "0" ]]; then
            kernel_memory_used
            clean_up
            exit 1
        fi

        if [[ "$MORE_DEBUG_FLAGS" != "1" ]]; then
            fw ctl debug -v "$VSID_SCRIPT" -m fw + filter ioctl > /dev/null
            fw ctl debug -v "$VSID_SCRIPT" -m kiss + salloc > /dev/null

            echo_log "\\nRunning:"
            echo_log "fw ctl debug 0"
            echo_log "fw ctl debug -buf $DEBUG_BUFFER -v $VSID_SCRIPT"
            echo_log "fw ctl debug -v $VSID_SCRIPT -m fw + filter ioctl"
            echo_log "fw ctl debug -v $VSID_SCRIPT -m kiss + salloc"
        else
            fw ctl debug -v "$VSID_SCRIPT" -m fw + filter ioctl cmi > /dev/null

            if [[ "$MAJOR_VERSION" == "R80" ]]; then
                fw ctl debug -v "$VSID_SCRIPT" -m UP + error warning > /dev/null
            fi

            fw ctl debug -v "$VSID_SCRIPT" -m WS + error warning > /dev/null
            fw ctl debug -v "$VSID_SCRIPT" -m cmi_loader + error warning policy info > /dev/null
            fw ctl debug -v "$VSID_SCRIPT" -m kiss + error warning htab ghtab mtctx salloc pm > /dev/null

            echo_log "\\nRunning:"
            echo_log "fw ctl debug 0"
            echo_log "fw ctl debug -buf $DEBUG_BUFFER -v $VSID_SCRIPT"
            echo_log "fw ctl debug -v $VSID_SCRIPT -m fw + filter ioctl cmi"

            if [[ "$MAJOR_VERSION" == "R80" ]]; then
                echo_log "fw ctl debug -v $VSID_SCRIPT -m UP + error warning"
            fi

            echo_log "fw ctl debug -v $VSID_SCRIPT -m WS + error warning"
            echo_log "fw ctl debug -v $VSID_SCRIPT -m cmi_loader + error warning policy info"
            echo_log "fw ctl debug -v $VSID_SCRIPT -m kiss + error warning htab ghtab mtctx salloc pm"
        fi

        fw ctl kdebug -v "$VSID_SCRIPT" -T -f &> "$DBGDIR_FILES"/kernel_atomic_debug_VS"$VSID_SCRIPT".txt &

        echo_log "fw ctl kdebug -v $VSID_SCRIPT -T -f &> kernel_atomic_debug_VS$VSID_SCRIPT.txt"
        echo_log "\\nexport TDERROR_ALL_ALL=5"
        echo_log "fw -d fetchlocal -d $FWDIR/state/__tmp/FW1 &> fetch_local_debug_VS$VSID_SCRIPT.txt"

        $ECHO -n "Fetching local policy   "

        $ECHO "Vmalloc before install:\\n" >> "$DBGDIR_FILES"/vmalloc.txt
        cat /proc/meminfo | grep Vmalloc >> "$DBGDIR_FILES"/vmalloc.txt

        export TDERROR_ALL_ALL=5
        fw -d fetchlocal -d $FWDIR/state/__tmp/FW1 &> "$DBGDIR_FILES"/fetch_local_debug_VS"$VSID_SCRIPT".txt &
        progress_bar

        $ECHO "\\n\\nVmalloc after install:\\n" >> "$DBGDIR_FILES"/vmalloc.txt
        cat /proc/meminfo | grep Vmalloc >> "$DBGDIR_FILES"/vmalloc.txt
        $ECHO "\\n\\nVmalloc in /boot/grub/grub.conf:\\n" >> "$DBGDIR_FILES"/vmalloc.txt
        grep 'vmalloc' /boot/grub/grub.conf >> "$DBGDIR_FILES"/vmalloc.txt
    fi

    if [[ "$IS_VSX" != *"1"* ]]; then
        fw ctl debug -buf "$DEBUG_BUFFER" > /dev/null

        if [[ "$?" != "0" ]]; then
            kernel_memory_used
            clean_up
            exit 1
        fi

        if [[ "$MORE_DEBUG_FLAGS" != "1" ]]; then
            fw ctl debug -m fw + filter ioctl > /dev/null
            fw ctl debug -m kiss + salloc > /dev/null

            echo_log "\\nRunning:"
            echo_log "fw ctl debug 0"
            echo_log "fw ctl debug -buf $DEBUG_BUFFER"
            echo_log "fw ctl debug -m fw + filter ioctl"
            echo_log "fw ctl debug -m kiss + salloc"
        else
            fw ctl debug -m fw + filter ioctl cmi > /dev/null

            if [[ "$MAJOR_VERSION" == "R80" ]]; then
                fw ctl debug -m UP + error warning > /dev/null
            fi

            fw ctl debug -m WS + error warning > /dev/null
            fw ctl debug -m cmi_loader + error warning policy info > /dev/null
            fw ctl debug -m kiss + error warning htab ghtab mtctx salloc pm > /dev/null

            echo_log "\\nRunning:"
            echo_log "fw ctl debug 0"
            echo_log "fw ctl debug -buf $DEBUG_BUFFER"
            echo_log "fw ctl debug -m fw + filter ioctl cmi"

            if [[ "$MAJOR_VERSION" == "R80" ]]; then
                echo_log "fw ctl debug -m UP + error warning"
            fi

            echo_log "fw ctl debug -m WS + error warning"
            echo_log "fw ctl debug -m cmi_loader + error warning policy info"
            echo_log "fw ctl debug -m kiss + error warning htab ghtab mtctx salloc pm"
        fi

        fw ctl kdebug -T -f &> "$DBGDIR_FILES"/kernel_atomic_debug.txt &

        echo_log "fw ctl kdebug -T -f &> kernel_atomic_debug.txt"
        echo_log "\\nexport TDERROR_ALL_ALL=5"
        echo_log "fw -d fetchlocal -d $FWDIR/state/__tmp/FW1 &> fetch_local_debug.txt"

        $ECHO -n "Fetching local policy   "

        if [[ "$IS_SG80" == "Failed to find the value" ]]; then
            $ECHO "Vmalloc before install:\\n" >> "$DBGDIR_FILES"/vmalloc.txt
            cat /proc/meminfo | grep Vmalloc >> "$DBGDIR_FILES"/vmalloc.txt

            export TDERROR_ALL_ALL=5
            fw -d fetchlocal -d $FWDIR/state/__tmp/FW1 &> "$DBGDIR_FILES"/fetch_local_debug.txt &
            progress_bar

            $ECHO "\\n\\nVmalloc after install:\\n" >> "$DBGDIR_FILES"/vmalloc.txt
            cat /proc/meminfo | grep Vmalloc >> "$DBGDIR_FILES"/vmalloc.txt
            $ECHO "\\n\\nVmalloc in /boot/grub/grub.conf:\\n" >> "$DBGDIR_FILES"/vmalloc.txt
            grep 'vmalloc' /boot/grub/grub.conf >> "$DBGDIR_FILES"/vmalloc.txt
        else
            export TDERROR_ALL_ALL=5
            fw -d fetchlocal -d $FWDIR/state/__tmp/FW1 &> "$DBGDIR_FILES"/fetch_local_debug.txt &
            progress_bar
        fi
    fi
}

###############################################################################
# STOP DEBUG
###############################################################################
stop_debug()
{
    STOP_DATE=$(/bin/date "+%d %b %Y %H:%M:%S %z")
    echo_log "\\nDebug Completed at $STOP_DATE"
    $ECHO "\\nDebug Completed\\n"
    $ECHO "Turning debug off..."

    unset TDERROR_ALL_ALL
    unset TDERROR_ALL_PLCY_INST_TIMING

    if [[ "$IS_FW" == *"1"* ]]; then
        fw ctl debug 0 > /dev/null
    fi

    if [[ "QUESTION" == "5" ]]; then
        if [[ "$MAJOR_VERSION" == "R80" ]]; then
            $MDS_FWDIR/scripts/cpm_debug.sh -t Assign_Global_Policy -s INFO
            $MDS_FWDIR/scripts/cpm_debug.sh -r
        else
            mdsenv "$CMA_NAME"
            fw debug fwm off TDERROR_ALL_ALL=0
        fi
    fi
}

###############################################################################
# COLLECT GENERAL INFO AND FILES
###############################################################################
section_general_log()
{
    SEP="***********************"
    $ECHO "\\n" >> "$GENERAL_LOG"
    $ECHO "$SEP $1 $SEP" >> "$GENERAL_LOG"
}

section_files_log()
{
    SEP="***********************"
    $ECHO "$SEP $1 $SEP\\n" >> "$2"
}

collect_files()
{
    $ECHO "Copying files..."

    # GENERAL LOG

    if [[ "$IS_SG80" == "Failed to find the value" ]]; then
        section_general_log "MACHINE DETAILS (clish -c \"show asset all\")"
        if [[ -f "/bin/clish" ]]; then
            clish -c "lock database override" &> /dev/null
            clish -c "show asset all" >> "$GENERAL_LOG" 2>&1
        else
            $ECHO "/bin/clish does not exist" >> "$GENERAL_LOG"
            $ECHO "This Operating System is not Gaia" >> "$GENERAL_LOG"
        fi

        section_general_log "VERSION (clish -c \"show version all\")"
        if [[ -f "/bin/clish" ]]; then
            clish -c "lock database override" &> /dev/null
            clish -c "show version all" >> "$GENERAL_LOG" 2>&1
        else
            $ECHO "/bin/clish does not exist" >> "$GENERAL_LOG"
            $ECHO "This Operating System is not Gaia" >> "$GENERAL_LOG"
        fi
    else
        section_general_log "VERSION (ver)"
        ver >> "$GENERAL_LOG"
    fi

    section_general_log "SYSTEM INFO (uname -a)"
    uname -a >> "$GENERAL_LOG"

    section_general_log "CPU (cat /proc/cpuinfo | egrep \"^processor|^Processor\" | wc -l)"
    $ECHO -n "Total CPU: " >> "$GENERAL_LOG"
    cat /proc/cpuinfo | egrep "^processor|^Processor" | wc -l >> "$GENERAL_LOG"

    if [[ "$IS_SG80" == "Failed to find the value" ]]; then
        section_general_log "MEMORY (free -m -t)"
        free -m -t >> "$GENERAL_LOG" 2>&1

        section_general_log "DISK SPACE (df -haT)"
        df -haT >> "$GENERAL_LOG" 2>&1

        section_general_log "TOP (top -bn1 -p 0 | head -5)"
        top -bn1 -p 0 2>&1 | head -5 >> "$GENERAL_LOG"
    else
        section_general_log "MEMORY (free)"
        free >> "$GENERAL_LOG" 2>&1

        section_general_log "DISK SPACE (df -h)"
        df -h >> "$GENERAL_LOG" 2>&1

        section_general_log "TOP (top -n1 | head -5)"
        top -n1 2>&1 | head -5 >> "$GENERAL_LOG"
    fi

    section_general_log "TIME (hwclock and ntpstat)"
    hwclock >> "$GENERAL_LOG"
    ntpstat >> "$GENERAL_LOG" 2>&1

    if [[ "$IS_FW" == *"1"* ]]; then
        if [[ "$IS_SG80" == "Failed to find the value" ]]; then
            section_general_log "ENABLED BLADES (enabled_blades)"
            enabled_blades >> "$GENERAL_LOG" 2>&1
        fi

        section_general_log "IPS STATUS (ips stat)"
        ips stat >> "$GENERAL_LOG" 2>&1

        section_general_log "STRING_DICTIONARY_TABLE SIZE (fw tab -t string_dictionary_table -s)"
        fw tab -t string_dictionary_table -s >> "$GENERAL_LOG"

        section_general_log "STRING_DICTIONARY_TABLE LIMIT (fw tab -t string_dictionary_table | grep limit)"
        fw tab -t string_dictionary_table | grep limit >> "$GENERAL_LOG"
    fi

    if [[ "$IS_SG80" == "Failed to find the value" ]]; then
        section_general_log "CORE DUMPS"
        $ECHO "/var/crash" >> "$GENERAL_LOG"
        ls -lhA /var/crash >> "$GENERAL_LOG" 2>&1
        $ECHO "/var/log/crash" >> "$GENERAL_LOG"
        ls -lhA /var/log/crash >> "$GENERAL_LOG" 2>&1
        $ECHO "/var/log/dump/usermode" >> "$GENERAL_LOG"
        ls -lhA /var/log/dump/usermode >> "$GENERAL_LOG" 2>&1
    else
        section_general_log "CORE DUMPS (ls -lhA /logs/core)"
        ls -lhA /logs/core >> "$GENERAL_LOG" 2>&1
    fi

    section_general_log "WATCHDOG (cpwd_admin list)"
    cpwd_admin list >> "$GENERAL_LOG"

    section_general_log "LICENSES (cplic print -x)"
    cplic print -x >> "$GENERAL_LOG" 2>&1

    if [[ "$IS_SG80" == "Failed to find the value" ]]; then
        section_general_log "HOTFIXES (cpinfo -y all)"
        if [[ "$IS_MDS" == "1" ]]; then
            mdsenv
            script -q -c 'cpinfo -y all' /dev/null >> "$GENERAL_LOG" 2>&1
        elif [[ "$IS_VSX" == *"1"* ]]; then
            vsenv > /dev/null
            script -q -c 'cpinfo -y all' /dev/null >> "$GENERAL_LOG" 2>&1
            cp -p $CPDIR/log/cpwd.elg* "$DBGDIR_FILES" 2>&1
            vsenv "$VSID_SCRIPT" > /dev/null
        elif [[ "$IS_FW" == *"1"* ]]; then
            script -q -c 'cpinfo -y all' /dev/null >> "$GENERAL_LOG" 2>&1
            cp -p $CPDIR/log/cpwd.elg* "$DBGDIR_FILES" 2>&1
        else
            script -q -c 'cpinfo -y all' /dev/null >> "$GENERAL_LOG" 2>&1
        fi

        section_general_log "JUMBO HOTFIX TAKE (installed_jumbo_take)"
        if [[ "$IS_MDS" == "1" ]]; then
            if [[ -e $MDS_TEMPLATE/bin/installed_jumbo_take ]]; then
                installed_jumbo_take >> "$GENERAL_LOG"
            else
                $ECHO "Jumbo Hotfix Accumulator is not installed" >> "$GENERAL_LOG"
            fi
        else
            if [[ -e $FWDIR/bin/installed_jumbo_take ]]; then
                installed_jumbo_take >> "$GENERAL_LOG"
            else
                $ECHO "Jumbo Hotfix Accumulator is not installed" >> "$GENERAL_LOG"
            fi
        fi
    fi

    if [[ "$MAJOR_VERSION" == "R80" ]]; then
        section_general_log "dleserver.jar BUILD NUMBER (cpvinfo $MDS_FWDIR/cpm-server/dleserver.jar)"
        cpvinfo $MDS_FWDIR/cpm-server/dleserver.jar >> "$GENERAL_LOG"
    fi

    # FILES LOG

    section_files_log "(cpstat os -f all)" "$DBGDIR_FILES/cpstatos.txt"
    cpstat os -f all >> "$DBGDIR_FILES"/cpstatos.txt

    if [[ "$IS_FW" == *"1"* ]]; then
        section_files_log "(cpstat ha -f all)" "$DBGDIR_FILES/clusterxl.txt"
        cpstat ha -f all >> "$DBGDIR_FILES"/clusterxl.txt 2>&1
    fi

    section_files_log "(ifconfig -a)" "$DBGDIR_FILES/ifconfig.txt"
    ifconfig -a >> "$DBGDIR_FILES"/ifconfig.txt

    section_files_log "(netstat -rn)" "$DBGDIR_FILES/routes.txt"
    netstat -rn >> "$DBGDIR_FILES"/routes.txt

    if [[ "$IS_SG80" == "Failed to find the value" ]]; then
        section_files_log "(netstat -anp)" "$DBGDIR_FILES/sockets.txt"
        netstat -anp >> "$DBGDIR_FILES"/sockets.txt
    else
        section_files_log "(netstat -an)" "$DBGDIR_FILES/sockets.txt"
        netstat -an >> "$DBGDIR_FILES"/sockets.txt 2>&1
    fi

    section_files_log "(ps auxww)" "$DBGDIR_FILES/psauxww.txt"
    ps auxww >> "$DBGDIR_FILES"/psauxww.txt

    if [[ "$IS_FW" == *"1"* ]]; then
        section_files_log "(fw ctl pstat)" "$DBGDIR_FILES/pstat.txt"
        fw ctl pstat >> "$DBGDIR_FILES"/pstat.txt

        if [[ -f "$FWDIR/boot/modules/fwkern.conf" ]]; then
            cp -p $FWDIR/boot/modules/fwkern.conf* "$DBGDIR_FILES"
        fi

        cp -p $CPDIR/registry/HKLM_registry.data* "$DBGDIR_FILES"
    fi

    cp -p /var/log/messages* "$DBGDIR_FILES"

    if [[ "$MAJOR_VERSION" == "R80" ]]; then
        if [[ "$IS_MDS" == "1" ]]; then
            cp -p $MDS_CPDIR/log/cpwd.elg* "$DBGDIR_FILES" 2>&1
            cp -p $MDS_TEMPLATE/log/cpm.elg* "$DBGDIR_FILES"
            cp -p $MDS_TEMPLATE/log/install_policy.elg* "$DBGDIR_FILES"
            mdsenv "$CMA_NAME"
            cp -p $CPDIR/registry/HKLM_registry.data* "$DBGDIR_FILES"
            cp -p $FWDIR/conf/objects_5_0.C* "$DBGDIR_FILES"
            cp -p $FWDIR/tmp/fwm_load.state* "$DBGDIR_FILES" 2>&1
        elif [[ "$IS_MGMT" == *"1"* ]]; then
            cp -p $CPDIR/registry/HKLM_registry.data* "$DBGDIR_FILES"
            cp -p $FWDIR/conf/objects_5_0.C* "$DBGDIR_FILES"
            cp -p $CPDIR/log/cpwd.elg* "$DBGDIR_FILES" 2>&1
            cp -p $FWDIR/log/cpm.elg* "$DBGDIR_FILES"
            cp -p $FWDIR/log/install_policy.elg* "$DBGDIR_FILES"
            cp -p $FWDIR/tmp/fwm_load.state* "$DBGDIR_FILES" 2>&1
        fi
    else
        if [[ "$IS_MDS" == "1" ]]; then
            cp -p $MDSDIR/conf/mdsdb/customers.C* "$DBGDIR_FILES"
            cp -p $MDS_CPDIR/log/cpwd.elg* "$DBGDIR_FILES" 2>&1
            mdsenv "$CMA_NAME"
            cp -p $CPDIR/registry/HKLM_registry.data* "$DBGDIR_FILES"
            cp -p $FWDIR/conf/objects_5_0.C* "$DBGDIR_FILES"
            cp -p $FWDIR/conf/rulebases_5_0.fws* "$DBGDIR_FILES"
        elif [[ "$IS_MGMT" == *"1"* ]]; then
            cp -p $CPDIR/log/cpwd.elg* "$DBGDIR_FILES" 2>&1
            cp -p $CPDIR/registry/HKLM_registry.data* "$DBGDIR_FILES"
            cp -p $FWDIR/conf/objects_5_0.C* "$DBGDIR_FILES"
            cp -p $FWDIR/conf/rulebases_5_0.fws* "$DBGDIR_FILES"
        fi
    fi

    if [[ "$QUESTION" == "5" ]]; then
        if [[ "$MAJOR_VERSION" != "R80" ]]; then
            mdsenv "$CMA_NAME"
            cp -p $FWDIR/log/fwm.elg* "$DBGDIR_FILES"
            cp -p $FWDIR/log/gpolicy.log* "$DBGDIR_FILES"
        fi
    fi
}

###############################################################################
# COMPRESS FILES FOR FINAL ARCHIVE
###############################################################################
compress_files()
{
    HOST_DTS=($(hostname)_at_$(date +%Y-%m-%d_%Hh%Mm%Ss))
    FINAL_ARCHIVE="$DBGDIR"/policy_debug_of_"$HOST_DTS".tgz

    $ECHO "Compressing files..."
    tar czf "$DBGDIR"/policy_debug_of_"$HOST_DTS".tgz -C "$DBGDIR" "$FILES"

    if [[ "$?" == "0" ]]; then
        rm -rf "$DBGDIR_FILES"
        $ECHO "Please send back file: $FINAL_ARCHIVE\\n"
    else
        $ECHO "\\nError: Failed to create archive"
        $ECHO "Consider running this script again with verbose output"
        $ECHO "./$SCRIPT_NAME -d\\n"
        if [[ "$IS_SG80" == "Failed to find the value" ]]; then
            clean_up
        else
            rm -rf "$DBGDIR_FILES"
        fi
        exit 1
    fi
}

###############################################################################
# MAIN
###############################################################################
debug_mgmt_all()
{
    check_fwm
    what_to_debug
    debug_mgmt
}

debug_fw_all()
{
    verify_buffer
    debug_fw
}

main()
{
    # Standalone
    if [[ "$IS_MGMT" == *"1"* && "$IS_FW" == *"1"* ]]; then
        debug_mgmt_or_fw

        if [[ "$STAND_DEBUG" == "1" ]]; then
            debug_mgmt_all
        else
            debug_fw_all
        fi

    # MGMT
    elif [[ "$IS_MGMT" == *"1"* && "$IS_FW" == *"0"* ]]; then

        # MDS
        if [[ "$IS_MDS" == "1" ]]; then
            change_to_cma
        else
            echo_shell_log "\\nThis is a Management Server"
        fi
        debug_mgmt_all

    # FW
    elif [[ "$IS_61K" != "Failed to find the value" ]]; then
        verify_61k
        debug_fw_all

    elif [[ "$IS_VSX" == *"1"* ]]; then
        verify_vsx
        debug_fw_all

    elif [[ "$IS_FW" == *"1"* ]]; then
        echo_shell_log "\\nThis is a Security Gateway"
        debug_fw_all

    else
        $ECHO "\\nCould not detect if this is a Management or Gateway"
        $ECHO "Verify \$CPDIR/registry/HKLM_registry.data is not corrupted\\n"
        clean_up
        exit 1
    fi

    stop_debug
    collect_files
    compress_files
}

main
exit 0
