#!/bin/bash

# Russell Seifert
# Escalation Engineer - Management Products
# Check Point Software Technologies Ltd.

###############################################################################
# HELP SCREEN
###############################################################################
HELP_USAGE="Usage: $0 [OPTIONS]

   -h    display this help
   -d    debug this script. a log file named 'script_debug.txt' will be
           created in the current working directory
   -f    enable more debug flags
   -m    install policy to more than one gateway
   -s    disable minimum disk space check. files will be written
           to /var/log/tmp/policy-debug
   -v    version information
"

HELP_VERSION="
Management Policy Debug Script
Version 3.1 February 12, 2017
Contribute at <https://github.com/seiruss/policy-debug>
"

OPTIND=1
while getopts ':h-:d-:f-:m-:s-:v-:' HELP_OPTION; do
    case "$HELP_OPTION" in
        h) echo "$HELP_USAGE" ; exit ;;
        d) set -vx ; exec &> >(tee script_debug.txt) ;;
        f) MORE_DEBUG_FLAGS=1 ;;
        m) MULTIPLE_INSTALL=1 ;;
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
echo -e "\033[1m**********************************************\\nWelcome to the Management Policy Debug Script\\n**********************************************\\n\033[0m"
echo -e "This script will debug Management Policy problems\\nPlease answer the following questions"
unset TMOUT

###############################################################################
# VERIFY ENVIRONMENT AND IMPORT CHECKPOINT VARIABLES
###############################################################################
if [[ $(uname -s) != "Linux" ]]; then
    echo -e "\\nError: This is not running on Linux\\nThis script is designed to run on a Linux OS\\nPlease find an alternate method to debug Policy Installation\\n"
    exit 1
fi

if [[ -r /etc/profile.d/CP.sh ]]; then
    source /etc/profile.d/CP.sh
elif [[ -r /opt/CPshared/5.0/tmp/.CPprofile.sh ]]; then
    source /opt/CPshared/5.0/tmp/.CPprofile.sh
elif [[ -r $CPDIR/tmp/.CPprofile.sh ]]; then
    source $CPDIR/tmp/.CPprofile.sh
else
    echo -e "\\nError: Unable to find \$CPDIR/tmp/.CPprofile.sh\\nVerify this file exists and you can read it\\n"
    exit 1
fi

if [[ $($CPDIR/bin/cpprod_util FwIsFirewallMgmt) != *"1"* ]]; then
    echo -e "\\nError: This is not a Management\\nThis script is designed to run on a Management\\nPlease upload this script to the Management and run it again\\n"
    exit 1
fi

###############################################################################
# BASIC VARIABLES
###############################################################################
SCRIPTNAME=($(basename $0))
FILES="$SCRIPTNAME"_files.$$
MAJOR_VERSION=$($CPDIR/bin/cpprod_util CPPROD_GetValue CPshared VersionText 1)
ISMDS=$($CPDIR/bin/cpprod_util CPPROD_GetValue PROVIDER-1 ProdActive 1 2> /dev/null)

###############################################################################
# CREATE TEMPORARY DIRECTORIES ON EITHER ROOT OR /VAR/LOG. 2GB MINIMUM
###############################################################################
if [[ "$SPACE_CHECK_OFF" == "1" ]]; then
    DBGDIR=/var/log/tmp/policy-debug
    DBGDIR_FILES=/var/log/tmp/policy-debug/"$FILES"
    if [[ ! -d "$DBGDIR_FILES" ]]; then
        mkdir -p "$DBGDIR_FILES"
    else
        rm -rf "$DBGDIR_FILES"
        mkdir -p "$DBGDIR_FILES"
    fi
else
    if [[ $(df -P | grep /$ | awk '{ print $4 }') -lt "2000000" ]]; then
        if [[ $(df -P | egrep "/var$|/var/log$" | awk '{ print $4 }') -lt "2000000" ]]; then
            echo -e "\\nError: There is not enough disk space available\\nPlease follow sk60080 to clear disk space\\n"
            exit 1
        else
            DBGDIR=/var/log/tmp/policy-debug
            DBGDIR_FILES=/var/log/tmp/policy-debug/"$FILES"
            if [[ ! -d "$DBGDIR_FILES" ]]; then
                mkdir -p "$DBGDIR_FILES"
            else
                rm -rf "$DBGDIR_FILES"
                mkdir -p "$DBGDIR_FILES"
            fi
        fi
    else
        DBGDIR=/tmp/policy-debug
        DBGDIR_FILES=/tmp/policy-debug/"$FILES"
        if [[ ! -d "$DBGDIR_FILES" ]]; then
            mkdir -p "$DBGDIR_FILES"
        else
            rm -rf "$DBGDIR_FILES"
            mkdir -p "$DBGDIR_FILES"
        fi
    fi
fi

###############################################################################
# PROCESS CLEANUP AND TERMINATION SIGNALS
###############################################################################
interrupted()
{
    echo -e "\\nError: Script interrupted, cleaning temporary files..."
    unset TDERROR_ALL_ALL
    if [[ "$MAJOR_VERSION" == "R80" ]]; then
        if [[ $(grep \#TOPIC-DEBUG:assign_global_policy:SEVERITY $MDS_FWDIR/conf/tdlog.cpm) == "#TOPIC-DEBUG:assign_global_policy:SEVERITY"* ]]; then
            $MDS_FWDIR/scripts/cpm_debug.sh -t Assign_Global_Policy -s INFO
            $MDS_FWDIR/scripts/cpm_debug.sh -r
        fi
    fi
    pkill -P $$
    rm -rf "$DBGDIR_FILES"
    echo -e "Completed\\n"
    exit 1
}
trap interrupted SIGHUP SIGINT SIGTERM # 1 2 15

clean_up()
{
    pkill -P $$
    rm -rf "$DBGDIR_FILES"
}
trap clean_up EXIT # 0

###############################################################################
# MONITOR DISK SPACE USAGE
###############################################################################
disk_space_check()
{
    while true; do
        DISKCHECK=$(df -P $DBGDIR | grep / | awk '{print $4}')
        if [[ "$DISKCHECK" -lt "500000" ]]; then
            echo -en "\\n\\nError: Disk space is less than 500MB. Stopping debug..."
            kill -15 $$
        fi
    sleep 20
    done
}
disk_space_check &

###############################################################################
# START SCRIPT SESSION LOG
###############################################################################
GENERAL_LOG="$DBGDIR_FILES"/general.txt
SESSION_LOG="$DBGDIR_FILES"/session.log
START_DATE=$(/bin/date "+%d %b %Y %H:%M:%S %z")
echo -e "$HELP_VERSION\\nScript Started at $START_DATE" >> "$SESSION_LOG"
[[ "$SPACE_CHECK_OFF" == "1" ]] && echo -e "\\nWarning: Minimum disk space check is disabled" | tee -a "$SESSION_LOG"
[[ "$MORE_DEBUG_FLAGS" == "1" ]] && echo -e "\\nInfo: More debug flags is enabled" | tee -a "$SESSION_LOG"
[[ "$MULTIPLE_INSTALL" == "1" ]] && echo -e "\\nInfo: Install to multiple Gateways is enabled" | tee -a "$SESSION_LOG"

###############################################################################
# CHANGE TO CMA CONTEXT IF MDS
###############################################################################
if [[ "$ISMDS" == "1" ]]; then
    echo -e "\\nThis is a Multi-Domain Management Server\\n\\n--------DOMAINS DETECTED--------" | tee -a "$SESSION_LOG"
    CMA_ARRAY=($($MDSVERUTIL AllCMAs | sort | tee -a "$SESSION_LOG"))
    CMA_ARRAY_NUMBER=$(printf '%s\n' "${CMA_ARRAY[@]}" | wc -l | awk '{ print $1 }')
    CMA_ARRAY_NUMBER_OPTION="$CMA_ARRAY_NUMBER"
    CMA_ARRAY_LIST=0
    while [[ "$CMA_ARRAY_NUMBER" > "0" ]]; do
        let "CMA_ARRAY_LIST += 1"
        echo "${CMA_ARRAY_LIST}. ${CMA_ARRAY[$((CMA_ARRAY_LIST-1))]}"
        let "CMA_ARRAY_NUMBER -= 1"
    done
    while true; do
        echo -e "\\nWhat is the number of the Domain you want to debug?"
        echo -n "(1-${CMA_ARRAY_NUMBER_OPTION}): "
        read CMA_NUMBER
        case "$CMA_NUMBER" in
            [1-9]|[1-9][0-9]|[1-9][0-9][0-9])
                CMA_NAME="${CMA_ARRAY[$((CMA_NUMBER-1))]}"
                CMA_NAME_EXIST=$($MDSVERUTIL AllCMAs | grep ^"$CMA_NAME"$)
                ;;
            *)
                echo -e "\\nError: Number selected is not valid\\nSelect a valid number with a Domain\\nPress CTRL-C to exit the script if needed"
                continue ;;
        esac
        case "$CMA_NAME" in
            "")
                echo -e "\\nError: Number selected is not valid\\nSelect a valid number with a Domain\\nPress CTRL-C to exit the script if needed"
                continue ;;
            "$CMA_NAME_EXIST")
                CMA_IP=$($MDSVERUTIL CMAIp -n $CMA_NAME)
                if [[ "$?" != "0" ]]; then
                    echo -e "\\nError: There is no Domain Management Server with Name: $CMA_NAME\\nRun the script again and specify a valid Domain\\n"
                    clean_up
                    exit 1
                fi
                mdsenv "$CMA_NAME"
                DOMAIN_NAME=$($CPDIR/bin/cpprod_util CPPROD_GetValue FW1 CustomerName 1)
                if [[ -z "$DOMAIN_NAME" ]]; then
                    echo -e "\\nError: Failed to retrieve Domain name\\nConsider running this script again with verbose output\\n"
                    clean_up
                    exit 1
                fi
                echo -e "CMA:    $CMA_NAME\\nDomain: $DOMAIN_NAME"
                echo -e "\\nUsing $CMA_NAME" >> "$SESSION_LOG"
                break ;;
        esac
    done
fi

###############################################################################
# ASK USER WHAT TO DEBUG
###############################################################################
echo -e "\\n--------DEBUGS AVAILABLE--------" | tee -a "$SESSION_LOG"
if [[ "$ISMDS" == "1" ]]; then
    echo -e "\\n1. Database Installation\\n2. Policy Verification\\n3. Policy Installation\\n4. Slow Policy Install\\n5. Assign Global Policy\\n" | tee -a "$SESSION_LOG"
    while true; do
        echo "Which option do you want to debug?"
        echo -n "(1-5): "
        read QUESTION
        case "$QUESTION" in
            [1-5])
                echo "Selected number $QUESTION" >> "$SESSION_LOG"
                break ;;
            *)
                echo -e "\\nError: Invalid option\\nPress CTRL-C to exit the script if needed\\n"
                continue ;;
        esac
    done
else
    echo -e "\\n1. Database Installation\\n2. Policy Verification\\n3. Policy Installation\\n4. Slow Policy Install\\n" | tee -a "$SESSION_LOG"
    while true; do
        echo "Which option do you want to debug?"
        echo -n "(1-4): "
        read QUESTION
        case "$QUESTION" in
            [1-4])
                echo "Selected number $QUESTION" >> "$SESSION_LOG"
                break ;;
            *)
                echo -e "\\nError: Invalid option\\nPress CTRL-C to exit the script if needed\\n"
                continue ;;
        esac
    done
fi

###############################################################################
# COLLECT GENERAL INFO ABOUT MACHINE
###############################################################################
section_general_log()
{
    SEP="***********************"
    echo -e "\\n" >> "$GENERAL_LOG"
    echo "$SEP $1 $SEP" >> "$GENERAL_LOG"
}

section_general_log "MACHINE DETAILS (uname -a)"
uname -a >> "$GENERAL_LOG"

section_general_log "DISK SPACE (df -haT)"
df -haT >> "$GENERAL_LOG"

section_general_log "MEMORY (free -m -t)"
free -m -t >> "$GENERAL_LOG"

section_general_log "CPU (top -bn1 -p 0)"
top -bn1 -p 0 2>&1 | head -5 >> "$GENERAL_LOG"

section_general_log "TIME (hwclock and ntpstat)"
hwclock >> "$GENERAL_LOG"
ntpstat >> "$GENERAL_LOG" 2>&1

###############################################################################
# FUNCTIONS FOR DETECTION OF POLICY/MGMT/GW
###############################################################################
policy_detect()
{
    echo -e "\\n--------POLICIES DETECTED--------" | tee -a "$SESSION_LOG"
    if [[ "$ISMDS" == "1" ]]; then
        POLICY_ARRAY=($(echo -e "$CMA_IP\n-t policies_collections -a\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' | tee -a "$SESSION_LOG"))
    else
        POLICY_ARRAY=($(echo -e "localhost\n-t policies_collections -a\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' | tee -a "$SESSION_LOG"))
    fi
    if [[ -z "$POLICY_ARRAY" ]]; then
        echo -e "\\nError: There are no Policies detected\\nVerify there are Policies in the GUI\\n"
        clean_up
        exit 1
    fi
    POLICY_ARRAY_NUMBER=$(printf '%s\n' "${POLICY_ARRAY[@]}" | wc -l | awk '{ print $1 }')
    POLICY_ARRAY_NUMBER_OPTION="$POLICY_ARRAY_NUMBER"
    POLICY_ARRAY_LIST=0
    while [[ "$POLICY_ARRAY_NUMBER" > "0" ]]; do
        let "POLICY_ARRAY_LIST += 1"
        echo "${POLICY_ARRAY_LIST}. ${POLICY_ARRAY[$((POLICY_ARRAY_LIST-1))]}"
        let "POLICY_ARRAY_NUMBER -= 1"
    done
    while true; do
        echo -e "\\nWhat is the number of the Policy you want to debug?"
        echo -n "(1-${POLICY_ARRAY_NUMBER_OPTION}): "
        read POLICY_NUMBER
        case "$POLICY_NUMBER" in
            [1-9]|[1-9][0-9]|[1-9][0-9][0-9])
                POLICY_NAME="${POLICY_ARRAY[$((POLICY_NUMBER-1))]}"
                if [[ "$ISMDS" == "1" ]]; then
                    POLICY_NAME_EXIST=$(echo -e "$CMA_IP\n-t policies_collections -a\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' | grep ^"$POLICY_NAME"$)
                else
                    POLICY_NAME_EXIST=$(echo -e "localhost\n-t policies_collections -a\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' | grep ^"$POLICY_NAME"$)
                fi
                ;;
            *)
                echo -e "\\nError: Number selected is not valid\\nSelect a valid number with a Policy\\nPress CTRL-C to exit the script if needed"
                continue ;;
        esac
        case "$POLICY_NAME" in
            "")
                echo -e "\\nError: Number selected is not valid\\nSelect a valid number with a Policy\\nPress CTRL-C to exit the script if needed"
                continue ;;
            "$POLICY_NAME_EXIST")
                echo "Policy: $POLICY_NAME"
                echo -e "\\nUsing $POLICY_NAME" >> "$SESSION_LOG"
                break ;;
        esac
    done
}

global_policy_detect()
{
    echo -e "\\n--------GLOBAL POLICIES DETECTED--------" | tee -a "$SESSION_LOG"
    mdsenv
    GLOBAL_POLICY_ARRAY=($(cpmiquerybin attr "" policies_collections "" -a __name__ | grep -v "No Global Policy" | tee -a "$SESSION_LOG"))
    if [[ -z "$GLOBAL_POLICY_ARRAY" ]]; then
        echo -e "\\nError: There are no Global Policies detected\\nVerify there are Global Policies in the GUI\\n"
        clean_up
        exit 1
    fi
    GLOBAL_POLICY_ARRAY_NUMBER=$(printf '%s\n' "${GLOBAL_POLICY_ARRAY[@]}" | wc -l | awk '{ print $1 }')
    GLOBAL_POLICY_ARRAY_NUMBER_OPTION="$GLOBAL_POLICY_NUMBER"
    GLOBAL_POLICY_ARRAY_LIST=0
    while [[ "$GLOBAL_POLICY_ARRAY_NUMBER" > "0" ]]; do
        let "GLOBAL_POLICY_ARRAY_LIST += 1"
        echo "${GLOBAL_POLICY_ARRAY_LIST}. ${GLOBAL_POLICY_ARRAY[$((GLOBAL_POLICY_ARRAY_LIST-1))]}"
        let "GLOBAL_POLICY_ARRAY_NUMBER -= 1"
    done
    while true; do
        echo -e "\\nWhat is the name of the Global Policy you want to debug?"
        echo -n "(1-${GLOBAL_POLICY_ARRAY_NUMBER_OPTION}): "
        read GLOBAL_POLICY_NUMBER
        case "$GLOBAL_POLICY_NUMBER" in
            [1-9]|[1-9][0-9]|[1-9][0-9][0-9])
                GLOBAL_POLICY_NAME="${GLOBAL_POLICY_ARRAY[$((GLOBAL_POLICY_NUMBER-1))]}"
                GLOBAL_POLICY_NAME_EXIST=$(cpmiquerybin attr "" policies_collections "" -a __name__ | grep -v "No Global Policy" | sed 's/[[:blank:]]*$//' | grep ^"$GLOBAL_POLICY_NAME"$)
                ;;
            *)
                echo -e "\\nError: Number selected is not valid\\nSelect a valid number with a Global Policy\\nPress CTRL-C to exit the script if needed"
                continue ;;
        esac
        case "$GLOBAL_POLICY_NAME" in
            "")
                echo -e "\\nError: Number selected is not valid\\nSelect a valid number with a Global Policy\\nPress CTRL-C to exit the script if needed"
                continue ;;
            "$GLOBAL_POLICY_NAME_EXIST")
                echo "Global Policy: $GLOBAL_POLICY_NAME"
                echo -e "\\nUsing $GLOBAL_POLICY_NAME" >> "$SESSION_LOG"
                break ;;
        esac
    done
}

mgmt_detect()
{
    echo -e "\\n--------MANAGEMENTS DETECTED--------" | tee -a "$SESSION_LOG"
    if [[ "$ISMDS" == "1" ]]; then
        MGMT_ARRAY=($(echo -e "$CMA_IP\n-t network_objects -s management='true' -s log_server='true'\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' | tee -a "$SESSION_LOG"))
    else
        MGMT_ARRAY=($(echo -e "localhost\n-t network_objects -s management='true' -s log_server='true'\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' | tee -a "$SESSION_LOG"))
    fi
    if [[ -z "$MGMT_ARRAY" ]]; then
        echo -e "\\nError: There are no Management servers detected\\nVerify there are Management servers in the GUI\\n"
        clean_up
        exit 1
    fi
    MGMT_ARRAY_NUMBER=$(printf '%s\n' "${MGMT_ARRAY[@]}" | wc -l | awk '{ print $1 }')
    MGMT_ARRAY_NUMBER_OPTION="$MGMT_ARRAY_NUMBER"
    MGMT_ARRAY_LIST=0
    while [[ "$MGMT_ARRAY_NUMBER" > "0" ]]; do
        let "MGMT_ARRAY_LIST += 1"
        echo "${MGMT_ARRAY_LIST}. ${MGMT_ARRAY[$((MGMT_ARRAY_LIST-1))]}"
        let "MGMT_ARRAY_NUMBER -= 1"
    done
    while true; do
        echo -e "\\nWhat is the name of the Management you want to Install Database to?"
        echo -n "(1-${MGMT_ARRAY_NUMBER_OPTION}): "
        read MGMT_NUMBER
        case "$MGMT_NUMBER" in
            [1-9]|[1-9][0-9]|[1-9][0-9][0-9])
                MGMT_NAME="${MGMT_ARRAY[$((MGMT_NUMBER-1))]}"
                if [[ "$ISMDS" == "1" ]]; then
                    MGMT_NAME_EXIST=$(echo -e "$CMA_IP\n-t network_objects -s management='true' -s log_server='true'\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' | grep ^"$MGMT_NAME"$)
                else
                    MGMT_NAME_EXIST=$(echo -e "localhost\n-t network_objects -s management='true' -s log_server='true'\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' | grep ^"$MGMT_NAME"$)
                fi
                ;;
            *)
                echo -e "\\nError: Number selected is not valid\\nSelect a valid number with a Management\\nPress CTRL-C to exit the script if needed"
                continue ;;
        esac
        case "$MGMT_NAME" in
            "")
                echo -e "\\nError: Number selected is not valid\\nSelect a valid number with a Management\\nPress CTRL-C to exit the script if needed"
                continue ;;
            "$MGMT_NAME_EXIST")
                echo "Management: $MGMT_NAME"
                echo -e "\\nUsing $MGMT_NAME" >> "$SESSION_LOG"
                break ;;
        esac
    done
}

gateway_detect()
{
    echo -e "\\n--------GATEWAYS DETECTED--------" | tee -a "$SESSION_LOG"
    if [[ "$ISMDS" == "1" ]]; then
        GATEWAY_ARRAY=($(echo -e "$CMA_IP\n-t network_objects -s firewall='installed'\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' | tee -a "$SESSION_LOG"))
    else
        GATEWAY_ARRAY=($(echo -e "localhost\n-t network_objects -s firewall='installed'\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' | tee -a "$SESSION_LOG"))
    fi
    if [[ -z "$GATEWAY_ARRAY" ]]; then
        echo -e "\\nError: There are no Gateways detected\\nVerify there are Gateways in the GUI\\n"
        clean_up
        exit 1
    fi
    GATEWAY_ARRAY_NUMBER=$(printf '%s\n' "${GATEWAY_ARRAY[@]}" | wc -l | awk '{ print $1 }')
    GATEWAY_ARRAY_NUMBER_OPTION="$GATEWAY_ARRAY_NUMBER"
    GATEWAY_ARRAY_LIST=0
    if [[ "$MULTIPLE_INSTALL" == "1" ]]; then
        while [[ "$GATEWAY_ARRAY_NUMBER" > "0" ]]; do
            let "GATEWAY_ARRAY_LIST += 1"
            echo "${GATEWAY_ARRAY[$((GATEWAY_ARRAY_LIST-1))]}"
            let "GATEWAY_ARRAY_NUMBER -= 1"
        done
        while true; do
            echo -e "\\nWhat are the names of the Gateways/Clusters you want to install $POLICY_NAME to?"
            echo "Enter the names and separate each with a space"
            read -a MULTIPLE_GATEWAY_NAMES
            GATEWAY_NAME=$(printf '%s ' "${MULTIPLE_GATEWAY_NAMES[@]}")
            echo -e "\\nGoing to install $POLICY_NAME to: $GATEWAY_NAME"
            read -p "Are these the correct Gateways/Clusters? (y/n) [n]? " CORRECT_GWS
            case "$CORRECT_GWS" in
                [yY][eE][sS]|[yY])
                    echo -e "\\nUsing $GATEWAY_NAME" >> "$SESSION_LOG"
                    break ;;
                *)
                    echo -e "\\nPlease enter the right Gateway/Cluster names\\nPress CTRL-C to exit the script if needed"
                    continue ;;
            esac
        done
    else
        while [[ "$GATEWAY_ARRAY_NUMBER" > "0" ]]; do
            let "GATEWAY_ARRAY_LIST += 1"
            echo "${GATEWAY_ARRAY_LIST}. ${GATEWAY_ARRAY[$((GATEWAY_ARRAY_LIST-1))]}"
            let "GATEWAY_ARRAY_NUMBER -= 1"
        done
        while true; do
            echo -e "\\nWhat is the number of the Gateway/Cluster you want to install $POLICY_NAME to?"
            echo -n "(1-${GATEWAY_ARRAY_NUMBER_OPTION}): "
            case "$GATEWAY_NUMBER" in
                [1-9]|[1-9][0-9]|[1-9][0-9][0-9])
                    GATEWAY_NAME="${GATEWAY_ARRAY[$((GATEWAY_NUMBER-1))]}"
                    if [[ "$ISMDS" == "1" ]]; then
                        GATEWAY_NAME_EXIST=$(echo -e "$CMA_IP\n-t network_objects -s firewall='installed'\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' | grep ^"$GATEWAY_NAME"$)
                    else
                        GATEWAY_NAME_EXIST=$(echo -e "localhost\n-t network_objects -s firewall='installed'\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' | grep ^"$GATEWAY_NAME"$)
                    fi
                    ;;
                *)
                    echo -e "\\nError: Number selected is not valid\\nSelect a valid number with a Gateway/Cluster\\nPress CTRL-C to exit the script if needed"
                    continue ;;
            esac
            case "$GATEWAY_NAME" in
                "")
                    echo -e "\\nError: Number selected is not valid\\nSelect a valid number with a Gateway/Cluster\\nPress CTRL-C to exit the script if needed"
                    continue ;;
                "$GATEWAY_NAME_EXIST")
                    echo "Gateway/Cluster: $GATEWAY_NAME"
                    echo -e "\\nUsing $GATEWAY_NAME" >> "$SESSION_LOG"
                    break ;;
            esac
        done
    fi
}

threatprevention_gateway_detect()
{
    THREAT_GATEWAY_FILE="$DBGDIR_FILES"/tp.txt
    echo -e "\\n--------GATEWAYS DETECTED--------" | tee -a "$SESSION_LOG"
    if [[ "$ISMDS" == "1" ]]; then
        THREAT_AMW=($(echo -e "$CMA_IP\n-t network_objects -s firewall='installed' -s anti_malware_blade='installed'\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' >> "$THREAT_GATEWAY_FILE"))
        THREAT_AV=($(echo -e "$CMA_IP\n-t network_objects -s firewall='installed' -s anti_virus_blade='installed'\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' >> "$THREAT_GATEWAY_FILE"))
        THREAT_EX=($(echo -e "$CMA_IP\n-t network_objects -s firewall='installed' -s scrubbing_blade='installed'\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' >> "$THREAT_GATEWAY_FILE"))
        THREAT_EM=($(echo -e "$CMA_IP\n-t network_objects -s firewall='installed' -s threat_emulation_blade='installed'\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' >> "$THREAT_GATEWAY_FILE"))
        THREAT_GATEWAY_ARRAY=($(cat "$THREAT_GATEWAY_FILE" | sort -u | tee -a "$SESSION_LOG"))
    else
        THREAT_AMW=($(echo -e "localhost\n-t network_objects -s firewall='installed' -s anti_malware_blade='installed'\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' >> "$THREAT_GATEWAY_FILE"))
        THREAT_AV=($(echo -e "localhost\n-t network_objects -s firewall='installed' -s anti_virus_blade='installed'\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' >> "$THREAT_GATEWAY_FILE"))
        THREAT_EX=($(echo -e "localhost\n-t network_objects -s firewall='installed' -s scrubbing_blade='installed'\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' >> "$THREAT_GATEWAY_FILE"))
        THREAT_EM=($(echo -e "localhost\n-t network_objects -s firewall='installed' -s threat_emulation_blade='installed'\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' >> "$THREAT_GATEWAY_FILE"))
        THREAT_GATEWAY_ARRAY=($(cat "$THREAT_GATEWAY_FILE" | sort -u | tee -a "$SESSION_LOG"))
    fi
    if [[ -z "$THREAT_GATEWAY_ARRAY" ]]; then
        echo -e "\\nError: There are no Threat Prevention Gateways detected\\nVerify there are Threat Prevention Gateways in the GUI\\n"
        clean_up
        exit 1
    fi
    THREAT_GATEWAY_ARRAY_NUMBER=$(printf '%s\n' "${THREAT_GATEWAY_ARRAY[@]}" | wc -l | awk '{ print $1 }')
    THREAT_GATEWAY_ARRAY_NUMBER_OPTION="$THREAT_GATEWAY_ARRAY_NUMBER"
    THREAT_GATEWAY_ARRAY_LIST=0
    if [[ "$MULTIPLE_INSTALL" == "1" ]]; then
        while [[ "$THREAT_GATEWAY_ARRAY_NUMBER" > "0" ]]; do
            let "THREAT_GATEWAY_ARRAY_LIST += 1"
            echo "${THREAT_GATEWAY_ARRAY[$((THREAT_GATEWAY_ARRAY_LIST-1))]}"
            let "THREAT_GATEWAY_ARRAY_NUMBER -= 1"
        done
        while true; do
            echo -e "\\nWhat are the names of the Gateways/Clusters you want to install $POLICY_NAME to?"
            echo "Enter the names and separate each with a space"
            read -a THREAT_MULTIPLE_GATEWAY_NAMES
            THREAT_GATEWAY_NAME=$(printf '%s ' "${THREAT_MULTIPLE_GATEWAY_NAMES[@]}")
            echo -e "\\nGoing to install $POLICY_NAME to: $THREAT_GATEWAY_NAME"
            read -p "Are these the correct Gateways/Clusters? (y/n) [n]? " CORRECT_THREAT_GWS
            case "$CORRECT_THREAT_GWS" in
                [yY][eE][sS]|[yY])
                    echo -e "\\nUsing $THREAT_GATEWAY_NAME" >> "$SESSION_LOG"
                    break ;;
                *)
                    echo -e "\\nPlease enter the right Gateway/Cluster names\\nPress CTRL-C to exit the script if needed"
                    continue ;;
            esac
        done
    else
        while [[ "$THREAT_GATEWAY_ARRAY_NUMBER" > "0" ]]; do
            let "THREAT_GATEWAY_ARRAY_LIST += 1"
            echo "${THREAT_GATEWAY_ARRAY_LIST}. ${THREAT_GATEWAY_ARRAY[$((THREAT_GATEWAY_ARRAY_LIST-1))]}"
            let "THREAT_GATEWAY_ARRAY_NUMBER -= 1"
        done
        while true; do
            echo -e "\\nWhat is the number of the Gateway/Cluster you want to install $POLICY_NAME to?"
            echo -n "(1-${THREAT_GATEWAY_ARRAY_NUMBER_OPTION}): "
            read THREAT_GATEWAY_NUMBER
            case "$THREAT_GATEWAY_NUMBER" in
                [1-9]|[1-9][0-9]|[1-9][0-9][0-9])
                    THREAT_GATEWAY_NAME="${THREAT_GATEWAY_ARRAY[$((THREAT_GATEWAY_NUMBER-1))]}"
                    if [[ "$ISMDS" == "1" ]]; then
                        THREAT_GATEWAY_NAME_EXIST=$(echo -e "$CMA_IP\n-t network_objects -s firewall='installed'\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' | grep ^"$THREAT_GATEWAY_NAME"$)
                    else
                        THREAT_GATEWAY_NAME_EXIST=$(echo -e "localhost\n-t network_objects -s firewall='installed'\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' | grep ^"$THREAT_GATEWAY_NAME"$)
                    fi
                    ;;
                *)
                    echo -e "\\nError: Number selected is not valid\\nSelect a valid number with a Gateway/Cluster\\nPress CTRL-C to exit the script if needed"
                    continue ;;
            esac
            case "$THREAT_GATEWAY_NAME" in
                "")
                    echo -e "\\nError: Number selected is not valid\\nSelect a valid number with a Gateway/Cluster\\nPress CTRL-C to exit the script if needed"
                    continue ;;
                "$THREAT_GATEWAY_NAME_EXIST")
                    echo "Gateway/Cluster: $THREAT_GATEWAY_NAME"
                    echo -e "\\nUsing $THREAT_GATEWAY_NAME" >> "$SESSION_LOG"
                    break ;;
            esac
        done
        rm "$THREAT_GATEWAY_FILE"
    fi
}

qos_gateway_detect()
{
    echo -e "\\n--------GATEWAYS DETECTED--------" | tee -a "$SESSION_LOG"
    if [[ "$ISMDS" == "1" ]]; then
        QOS_GATEWAY_ARRAY=($(echo -e "$CMA_IP\n-t network_objects -s floodgate='installed'\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' | tee -a "$SESSION_LOG"))
    else
        QOS_GATEWAY_ARRAY=($(echo -e "localhost\n-t network_objects -s floodgate='installed'\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' | tee -a "$SESSION_LOG"))
    fi
    if [[ -z "$QOS_GATEWAY_ARRAY" ]]; then
        echo -e "\\nError: There are no QoS Gateways detected\\nVerify there are QoS Gateways in the GUI\\n"
        clean_up
        exit 1
    fi
    QOS_GATEWAY_ARRAY_NUMBER=$(printf '%s\n' "${QOS_GATEWAY_ARRAY[@]}" | wc -l | awk '{ print $1 }')
    QOS_GATEWAY_ARRAY_NUMBER_OPTION="$QOS_GATEWAY_ARRAY_NUMBER"
    QOS_GATEWAY_ARRAY_LIST=0
    if [[ "$MULTIPLE_INSTALL" == "1" ]]; then
        while [[ "$QOS_GATEWAY_ARRAY_NUMBER" > "0" ]]; do
            let "QOS_GATEWAY_ARRAY_LIST += 1"
            echo "${QOS_GATEWAY_ARRAY[$((QOS_GATEWAY_ARRAY_LIST-1))]}"
            let "QOS_GATEWAY_ARRAY_NUMBER -= 1"
        done
        while true; do
            echo -e "\\nWhat are the names of the Gateways/Clusters you want to install $POLICY_NAME to?"
            echo "Enter the names and separate each with a space"
            read -a QOS_MULTIPLE_GATEWAY_NAMES
            QOS_GATEWAY_NAME=$(printf '%s ' "${QOS_MULTIPLE_GATEWAY_NAMES[@]}")
            echo -e "\\nGoing to install $POLICY_NAME to: $QOS_GATEWAY_NAME"
            read -p "Are these the correct Gateways/Clusters? (y/n) [n]? " CORRECT_QOS_GWS
            case "$CORRECT_QOS_GWS" in
                [yY][eE][sS]|[yY])
                    echo -e "\\nUsing $QOS_GATEWAY_NAME" >> "$SESSION_LOG"
                    break ;;
                *)
                    echo -e "\\nPlease enter the right Gateway/Cluster names\\nPress CTRL-C to exit the script if needed"
                    continue ;;
            esac
        done
    else
        while [[ "$QOS_GATEWAY_ARRAY_NUMBER" > "0" ]]; do
            let "QOS_GATEWAY_ARRAY_LIST += 1"
            echo "${QOS_GATEWAY_ARRAY_LIST}. ${QOS_GATEWAY_ARRAY[$((QOS_GATEWAY_ARRAY_LIST-1))]}"
            let "QOS_GATEWAY_ARRAY_NUMBER -= 1"
        done
        while true; do
            echo -e "\\nWhat is the number of the Gateway/Cluster you want to install $POLICY_NAME to?"
            echo -n "(1-${QOS_GATEWAY_ARRAY_NUMBER_OPTION}): "
            read QOS_GATEWAY_NUMBER
            case "$QOS_GATEWAY_NUMBER" in
                [1-9]|[1-9][0-9]|[1-9][0-9][0-9])
                    QOS_GATEWAY_NAME="${QOS_GATEWAY_ARRAY[$((QOS_GATEWAY_NUMBER-1))]}"
                    if [[ "$ISMDS" == "1" ]]; then
                        QOS_GATEWAY_NAME_EXIST=$(echo -e "$CMA_IP\n-t network_objects -s floodgate='installed'\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' | grep ^"$QOS_GATEWAY_NAME"$)
                    else
                        QOS_GATEWAY_NAME_EXIST=$(echo -e "localhost\n-t network_objects -s floodgate='installed'\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' | grep ^"$QOS_GATEWAY_NAME"$)
                    fi
                    ;;
                *)
                    echo -e "\\nError: Number selected is not valid\\nSelect a valid number with a Gateway/Cluster\\nPress CTRL-C to exit the script if needed"
                    continue ;;
            esac
            case "$QOS_GATEWAY_NAME" in
                "")
                    echo -e "\\nError: Number selected is not valid\\nSelect a valid number with a Gateway/Cluster\\nPress CTRL-C to exit the script if needed"
                    continue ;;
                "$QOS_GATEWAY_NAME_EXIST")
                    echo "Gateway/Cluster: $QOS_GATEWAY_NAME"
                    echo -e "\\nUsing $QOS_GATEWAY_NAME" >> "$SESSION_LOG"
                    break ;;
            esac
        done
    fi
}

desktop_gateway_detect()
{
    echo -e "\\n--------GATEWAYS DETECTED--------" | tee -a "$SESSION_LOG"
    if [[ "$ISMDS" == "1" ]]; then
        DESKTOP_GATEWAY_ARRAY=($(echo -e "$CMA_IP\n-t network_objects -s policy_server='installed'\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' | tee -a "$SESSION_LOG"))
    else
        DESKTOP_GATEWAY_ARRAY=($(echo -e "localhost\n-t network_objects -s policy_server='installed'\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' | tee -a "$SESSION_LOG"))
    fi
    if [[ -z "$DESKTOP_GATEWAY_ARRAY" ]]; then
        echo -e "\\nError: There are no Desktop Security Gateways detected\\nVerify there are Desktop Security Gateways in the GUI\\n"
        clean_up
        exit 1
    fi
    DESKTOP_GATEWAY_ARRAY_NUMBER=$(printf '%s\n' "${DESKTOP_GATEWAY_ARRAY[@]}" | wc -l | awk '{ print $1 }')
    DESKTOP_GATEWAY_ARRAY_NUMBER_OPTION="$DESKTOP_GATEWAY_ARRAY_NUMBER"
    DESKTOP_GATEWAY_ARRAY_LIST=0
    if [[ "$MULTIPLE_INSTALL" == "1" ]]; then
        while [[ "$DESKTOP_GATEWAY_ARRAY_NUMBER" > "0" ]]; do
            let "DESKTOP_GATEWAY_ARRAY_LIST += 1"
            echo "${DESKTOP_GATEWAY_ARRAY[$((DESKTOP_GATEWAY_ARRAY_LIST-1))]}"
            let "DESKTOP_GATEWAY_ARRAY_NUMBER -= 1"
        done
        while true; do
            echo -e "\\nWhat are the names of the Gateways/Clusters you want to install $POLICY_NAME to?"
            echo "Enter the names and separate each with a space"
            read -a DESKTOP_MULTIPLE_GATEWAY_NAMES
            DESKTOP_GATEWAY_NAME=$(printf '%s ' "${DESKTOP_MULTIPLE_GATEWAY_NAMES[@]}")
            echo -e "\\nGoing to install $POLICY_NAME to: $DESKTOP_GATEWAY_NAME"
            read -p "Are these the correct Gateways/Clusters? (y/n) [n]? " CORRECT_DESKTOP_GWS
            case "$CORRECT_DESKTOP_GWS" in
                [yY][eE][sS]|[yY])
                    echo -e "\\nUsing $DESKTOP_GATEWAY_NAME" >> "$SESSION_LOG"
                    break ;;
                *)
                    echo -e "\\nPlease enter the right Gateway/Cluster names\\nPress CTRL-C to exit the script if needed"
                    continue ;;
            esac
        done
    else
        while [[ "$DESKTOP_GATEWAY_ARRAY_NUMBER" > "0" ]]; do
            let "DESKTOP_GATEWAY_ARRAY_LIST += 1"
            echo "${DESKTOP_GATEWAY_ARRAY_LIST}. ${DESKTOP_GATEWAY_ARRAY[$((DESKTOP_GATEWAY_ARRAY_LIST-1))]}"
            let "DESKTOP_GATEWAY_ARRAY_NUMBER -= 1"
        done
        while true; do
            echo -e "\\nWhat is the number of the Gateway/Cluster you want to install $POLICY_NAME to?"
            echo -n "(1-${DESKTOP_GATEWAY_ARRAY_NUMBER_OPTION}): "
            read DESKTOP_GATEWAY_NUMBER
            case "$DESKTOP_GATEWAY_NUMBER" in
                [1-9]|[1-9][0-9]|[1-9][0-9][0-9])
                    DESKTOP_GATEWAY_NAME="${DESKTOP_GATEWAY_ARRAY[$((DESKTOP_GATEWAY_NUMBER-1))]}"
                    if [[ "$ISMDS" == "1" ]]; then
                        DESKTOP_GATEWAY_NAME_EXIST=$(echo -e "$CMA_IP\n-t network_objects -s policy_server='installed'\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' | grep ^"$DESKTOP_GATEWAY_NAME"$)
                    else
                        DESKTOP_GATEWAY_NAME_EXIST=$(echo -e "localhost\n-t network_objects -s policy_server='installed'\n-q\n" | queryDB_util | awk '/Object Name:/ { print $3 }' | grep ^"$DESKTOP_GATEWAY_NAME"$)
                    fi
                    ;;
                *)
                    echo -e "\\nError: Number selected is not valid\\nSelect a valid number with a Gateway/Cluster\\nPress CTRL-C to exit the script if needed"
                    continue ;;
            esac
            case "$DESKTOP_GATEWAY_NAME" in
                "")
                    echo -e "\\nError: Number selected is not valid\\nSelect a valid number with a Gateway/Cluster\\nPress CTRL-C to exit the script if needed"
                    continue ;;
                "$DESKTOP_GATEWAY_NAME_EXIST")
                    echo "Gateway/Cluster: $DESKTOP_GATEWAY_NAME"
                    echo -e "\\nUsing $DESKTOP_GATEWAY_NAME" >> "$SESSION_LOG"
                    break ;;
            esac
        done
    fi
}

###############################################################################
# PROGRESS BAR DURING DEBUG
###############################################################################
progress_bar()
{
    PB_CHARS=( "-" "\\" "|" "/" )
    PB_COUNT=0
    PB_PID=$!
    while [ -d /proc/"$PB_PID" ]; do
        PB_POS=$(( $PB_COUNT % 4 ))
        echo -en "\b${PB_CHARS[$PB_POS]}"
        PB_COUNT=$(( $PB_COUNT + 1 ))
        sleep 1
    done
}

###############################################################################
# MAIN DEBUG
###############################################################################
# DATABASE
if [[ "$QUESTION" == "1" ]]; then
    echo "This option will debug Database Installation problems"
    mgmt_detect
    if [[ "$MORE_DEBUG_FLAGS" == "1" ]]; then
        echo -e "\\nRunning:\\nexport TDERROR_ALL_ALL=5\\nfwm -d dbload $MGMT_NAME &> install_database_debug.txt" >> "$SESSION_LOG"
        export TDERROR_ALL_ALL=5
    else
        echo -e "\\nRunning:\\nfwm -d dbload $MGMT_NAME &> install_database_debug.txt" >> "$SESSION_LOG"
    fi
    echo -en "\\nInstalling Database to $MGMT_NAME   "
    fwm -d dbload "$MGMT_NAME" &> "$DBGDIR_FILES"/install_database_debug.txt &
    progress_bar
fi

# VERIFY
if [[ "$QUESTION" == "2" ]]; then
    echo "This option will debug Policy Verification problems"
    policy_detect
    if [[ "$MORE_DEBUG_FLAGS" == "1" ]]; then
        echo -e "\\nRunning:\\nexport TDERROR_ALL_ALL=5\\nfwm -d verify $POLICY_NAME &> policy_verify_debug.txt" >> "$SESSION_LOG"
        export TDERROR_ALL_ALL=5
    else
        echo -e "\\nRunning:\\nfwm -d verify $POLICY_NAME &> policy_verify_debug.txt" >> "$SESSION_LOG"
    fi
    echo -en "\\nVerifying $POLICY_NAME Policy   "
    fwm -d verify "$POLICY_NAME" &> "$DBGDIR_FILES"/policy_verify_debug.txt &
    progress_bar
fi

# INSTALL
if [[ "$QUESTION" == "3" ]]; then
    echo -e "\\n--------POLICY DEBUGS AVAILABLE--------" | tee -a "$SESSION_LOG"
    echo -e "\\n1. Network Security\\n2. Threat Prevention\\n3. QoS\\n4. Desktop Security\\n" | tee -a "$SESSION_LOG"
    while true; do
        echo "Which policy do you want to debug?"
        echo -n "(1-4): "
        read WHICH_POLICY
        case "$WHICH_POLICY" in
            [1-4])
                echo "Selected number $WHICH_POLICY" >> "$SESSION_LOG"
                break ;;
            *)
                echo -e "\\nError: Invalid option\\nPress CTRL-C to exit the script if needed\\n"
                continue ;;
        esac
    done
    if [[ "$WHICH_POLICY" == "1" ]]; then
        echo "This option will debug Network Security Policy Installation problems"
        policy_detect
        gateway_detect
        if [[ "$MAJOR_VERSION" == "R80" ]]; then
            if [[ "$MORE_DEBUG_FLAGS" == "1" ]]; then
                echo -e "\\nRunning:\\nexport TDERROR_ALL_ALL=5\\nexport INTERNAL_POLICY_LOADING=1\\nfwm -d load $POLICY_NAME $GATEWAY_NAME &> security_policy_install_debug.txt" >> "$SESSION_LOG"
                export INTERNAL_POLICY_LOADING=1
                export TDERROR_ALL_ALL=5
            else
                echo -e "\\nRunning:\\nexport INTERNAL_POLICY_LOADING=1\\nfwm -d load $POLICY_NAME $GATEWAY_NAME &> security_policy_install_debug.txt" >> "$SESSION_LOG"
                export INTERNAL_POLICY_LOADING=1
            fi
        else
            if [[ "$MORE_DEBUG_FLAGS" == "1" ]]; then
                echo -e "\\nRunning:\\nexport TDERROR_ALL_ALL=5\\nfwm -d load $POLICY_NAME $GATEWAY_NAME &> security_policy_install_debug.txt" >> "$SESSION_LOG"
                export TDERROR_ALL_ALL=5
            else
                echo -e "\\nRunning:\\nfwm -d load $POLICY_NAME $GATEWAY_NAME &> security_policy_install_debug.txt" >> "$SESSION_LOG"
            fi
        fi
        echo -en "\\nInstalling Security Policy $POLICY_NAME to $GATEWAY_NAME   "
        if [[ "$MULTIPLE_INSTALL" == "1" ]]; then
            fwm -d load "$POLICY_NAME" $GATEWAY_NAME &> "$DBGDIR_FILES"/security_policy_install_debug.txt &
        else
            fwm -d load "$POLICY_NAME" "$GATEWAY_NAME" &> "$DBGDIR_FILES"/security_policy_install_debug.txt &
        fi
        progress_bar
    elif [[ "$WHICH_POLICY" == "2" ]]; then
        echo "This option will debug Threat Prevention Policy Installation problems"
        policy_detect
        threatprevention_gateway_detect
        if [[ "$MAJOR_VERSION" == "R80" ]]; then
            if [[ "$MORE_DEBUG_FLAGS" == "1" ]]; then
                echo -e "\\nRunning:\\nexport TDERROR_ALL_ALL=5\\nexport INTERNAL_POLICY_LOADING=1\\nfwm -d load -p threatprevention $POLICY_NAME $THREAT_GATEWAY_NAME &> threat_prevention_policy_install_debug.txt" >> "$SESSION_LOG"
                export INTERNAL_POLICY_LOADING=1
                export TDERROR_ALL_ALL=5
            else
                echo -e "\\nRunning:\\nexport INTERNAL_POLICY_LOADING=1\\nfwm -d load -p threatprevention $POLICY_NAME $THREAT_GATEWAY_NAME &> threat_prevention_policy_install_debug.txt" >> "$SESSION_LOG"
                export INTERNAL_POLICY_LOADING=1
            fi
        else
            if [[ "$MORE_DEBUG_FLAGS" == "1" ]]; then
                echo -e "\\nRunning:\\nexport TDERROR_ALL_ALL=5\\nfwm -d load -p threatprevention $POLICY_NAME $THREAT_GATEWAY_NAME &> threat_prevention_policy_install_debug.txt" >> "$SESSION_LOG"
                export TDERROR_ALL_ALL=5
            else
                echo -e "\\nRunning:\\nfwm -d load -p threatprevention $POLICY_NAME $THREAT_GATEWAY_NAME &> threat_prevention_policy_install_debug.txt" >> "$SESSION_LOG"
            fi
        fi
        echo -en "\\nInstalling Threat Prevention Policy $POLICY_NAME to $THREAT_GATEWAY_NAME   "
        if [[ "$MULTIPLE_INSTALL" == "1" ]]; then
            fwm -d load -p threatprevention "$POLICY_NAME" $THREAT_GATEWAY_NAME &> "$DBGDIR_FILES"/threat_prevention_policy_install_debug.txt &
        else
            fwm -d load -p threatprevention "$POLICY_NAME" "$THREAT_GATEWAY_NAME" &> "$DBGDIR_FILES"/threat_prevention_policy_install_debug.txt &
        fi
        progress_bar
    elif [[ "$WHICH_POLICY" == "3" ]]; then
        echo "This option will debug QoS Policy Installation problems"
        policy_detect
        qos_gateway_detect
        if [[ "$MAJOR_VERSION" == "R80" ]]; then
            if [[ "$MORE_DEBUG_FLAGS" == "1" ]]; then
                echo -e "\\nRunning:\\nexport TDERROR_ALL_ALL=5\\nexport INTERNAL_POLICY_LOADING=1\\nfgate -d load ${POLICY_NAME}.F $QOS_GATEWAY_NAME &> qos_policy_install_debug.txt" >> "$SESSION_LOG"
                export INTERNAL_POLICY_LOADING=1
                export TDERROR_ALL_ALL=5
            else
                echo -e "\\nRunning:\\nexport INTERNAL_POLICY_LOADING=1\\nfgate -d load ${POLICY_NAME}.F $QOS_GATEWAY_NAME &> qos_policy_install_debug.txt" >> "$SESSION_LOG"
                export INTERNAL_POLICY_LOADING=1
            fi
        else
            if [[ "$MORE_DEBUG_FLAGS" == "1" ]]; then
                echo -e "\\nRunning:\\nexport TDERROR_ALL_ALL=5\\nfgate -d load ${POLICY_NAME}.F $QOS_GATEWAY_NAME &> qos_policy_install_debug.txt" >> "$SESSION_LOG"
                export TDERROR_ALL_ALL=5
            else
                echo -e "\\nRunning:\\nfgate -d load ${POLICY_NAME}.F $QOS_GATEWAY_NAME &> qos_policy_install_debug.txt" >> "$SESSION_LOG"
            fi
        fi
        echo -en "\\nInstalling QoS Policy $POLICY_NAME to $QOS_GATEWAY_NAME   "
        if [[ "$MULTIPLE_INSTALL" == "1" ]]; then
            fgate -d load "${POLICY_NAME}.F" $QOS_GATEWAY_NAME &> "$DBGDIR_FILES"/qos_policy_install_debug.txt &
        else
            fgate -d load "${POLICY_NAME}.F" "$QOS_GATEWAY_NAME" &> "$DBGDIR_FILES"/qos_policy_install_debug.txt &
        fi
        progress_bar
    elif [[ "$WHICH_POLICY" == "4" ]]; then
        echo "This option will debug Desktop Security Policy Installation problems"
        policy_detect
        desktop_gateway_detect
        if [[ "$MAJOR_VERSION" == "R80" ]]; then
            if [[ "$MORE_DEBUG_FLAGS" == "1" ]]; then
                echo -e "\\nRunning:\\nexport TDERROR_ALL_ALL=5\\nexport INTERNAL_POLICY_LOADING=1\\nfwm -d psload $FWDIR/conf/${POLICY_NAME}.S $DESKTOP_GATEWAY_NAME &> desktop_policy_install_debug.txt" >> "$SESSION_LOG"
                export INTERNAL_POLICY_LOADING=1
                export TDERROR_ALL_ALL=5
            else
                echo -e "\\nRunning:\\nexport INTERNAL_POLICY_LOADING=1\\nfwm -d psload $FWDIR/conf/${POLICY_NAME}.S $DESKTOP_GATEWAY_NAME &> desktop_policy_install_debug.txt" >> "$SESSION_LOG"
                export INTERNAL_POLICY_LOADING=1
            fi
        else
            if [[ "$MORE_DEBUG_FLAGS" == "1" ]]; then
                echo -e "\\nRunning:\\nexport TDERROR_ALL_ALL=5\\nfwm -d psload $FWDIR/conf/${POLICY_NAME}.S $DESKTOP_GATEWAY_NAME &> desktop_policy_install_debug.txt" >> "$SESSION_LOG"
                export TDERROR_ALL_ALL=5
            else
                echo -e "\\nRunning:\\nfwm -d psload $FWDIR/conf/${POLICY_NAME}.S $DESKTOP_GATEWAY_NAME &> desktop_policy_install_debug.txt" >> "$SESSION_LOG"
            fi
        fi
        echo -en "\\nInstalling Desktop Security Policy $POLICY_NAME to $DESKTOP_GATEWAY_NAME   "
        if [[ "$MULTIPLE_INSTALL" == "1" ]]; then
            fwm -d psload "$FWDIR/conf/${POLICY_NAME}.S" $DESKTOP_GATEWAY_NAME &> "$DBGDIR_FILES"/desktop_policy_install_debug.txt &
        else
            fwm -d psload "$FWDIR/conf/${POLICY_NAME}.S" "$DESKTOP_GATEWAY_NAME" &> "$DBGDIR_FILES"/desktop_policy_install_debug.txt &
        fi
        progress_bar
    fi
fi

# SLOW INSTALL
if [[ "$QUESTION" == "4" ]]; then
    echo "This option will debug slow Policy Installation"
    policy_detect
    gateway_detect
    if [[ "$MAJOR_VERSION" == "R80" ]]; then
        echo -e "\\nRunning:\\nexport INTERNAL_POLICY_LOADING=1\\nexport TDERROR_ALL_PLCY_INST_TIMING=5\\nfwm load $POLICY_NAME $GATEWAY_NAME &> policy_install_timing_debug.txt" >> "$SESSION_LOG"
        export INTERNAL_POLICY_LOADING=1
    else
        echo -e "\\nRunning:\\nexport TDERROR_ALL_PLCY_INST_TIMING=5\\nfwm load $POLICY_NAME $GATEWAY_NAME &> policy_install_timing_debug.txt" >> "$SESSION_LOG"
    fi
    echo -en "\\nInstalling Security Policy $POLICY_NAME to $GATEWAY_NAME   "
    export TDERROR_ALL_PLCY_INST_TIMING=5
    if [[ "$MULTIPLE_INSTALL" == "1" ]]; then
        fwm load "$POLICY_NAME" $GATEWAY_NAME &> "$DBGDIR_FILES"/policy_install_timing_debug.txt &
    else
        fwm load "$POLICY_NAME" "$GATEWAY_NAME" &> "$DBGDIR_FILES"/policy_install_timing_debug.txt &
    fi
    progress_bar
    unset TDERROR_ALL_PLCY_INST_TIMING
fi

# GLOBAL ASSIGN
if [[ "$QUESTION" == "5" ]]; then
    echo "This option will debug Global Policy Assignment problems"
    if [[ "$MAJOR_VERSION" == "R80" ]]; then
        JETTY_PID=$(pgrep -f $MDS_CPDIR/jetty/start.jar)
        API_STATUS=$(tail -n 1 $MDS_FWDIR/api/conf/jetty.state | grep STARTED)
        if [[ -z "$JETTY_PID" || -z "$API_STATUS" ]]; then
            echo -e "\\nError: The API server is not running\\nGlobal Policy debug requires API to be running\\nRun 'api start' and then run this script again\\n"
            clean_up
            exit 1
        fi
        echo "Using the API server to run the debug"
        for UNSET_MGMTCLI in $(env | grep MGMT_CLI_ | cut -f1 -d"=") ; do unset "$UNSET_MGMTCLI" ; done
        rm $MDS_FWDIR/log/cpm.elg.* 2> /dev/null
        echo "=debug_start=" > $MDS_FWDIR/log/cpm.elg
        GLOBAL_POLICY_NAME_R80=$(mgmt_cli show global-assignment global-domain "Global" dependent-domain "$DOMAIN_NAME" -r true -f json | $MDS_CPDIR/jq/jq '.["global-access-policy"]' -r)
        echo -e "\\nAssigning Global Policy $GLOBAL_POLICY_NAME_R80 to $DOMAIN_NAME"
        echo -e "\\nRunning:\\n$MDS_FWDIR/scripts/cpm_debug.sh -t Assign_Global_Policy -s DEBUG\\nmgmt_cli assign-global-assignment global-domains Global dependent-domains $DOMAIN_NAME -r true" >> "$SESSION_LOG"
        $MDS_FWDIR/scripts/cpm_debug.sh -t Assign_Global_Policy -s DEBUG
        mgmt_cli assign-global-assignment global-domains "Global" dependent-domains "$DOMAIN_NAME" -r true
        $MDS_FWDIR/scripts/cpm_debug.sh -t Assign_Global_Policy -s INFO
        $MDS_FWDIR/scripts/cpm_debug.sh -r
    else
        global_policy_detect
        # START CMA FWM DEBUG
        mdsenv "$CMA_NAME"
        rm $FWDIR/log/fwm.elg.* 2> /dev/null
        echo "=debug_start=" > $FWDIR/log/fwm.elg
        fw debug fwm on TDERROR_ALL_ALL=5

        # START GLOBAL REASSIGN DEBUG
        mdsenv
        echo -e "\\nRunning:\\nexport TDERROR_ALL_ALL=5\\nfwm -d mds fwmconnect -assign -n 10 -g ##$GLOBAL_POLICY_NAME -l ${CMA_NAME}_._._${DOMAIN_NAME} &> global_policy_assign_debug.txt" >> "$SESSION_LOG"
        echo -en "\\nAssigning Global Policy $GLOBAL_POLICY_NAME to $DOMAIN_NAME   "
        export TDERROR_ALL_ALL=5
        fwm -d mds fwmconnect -assign -n 10 -g "##$GLOBAL_POLICY_NAME" -l "${CMA_NAME}_._._${DOMAIN_NAME}" &> "$DBGDIR_FILES"/global_policy_assign_debug.txt &
        progress_bar

        # STOP GLOBAL REASSIGN DEBUG
        unset TDERROR_ALL_ALL
        cp -p $MDSDIR/conf/mdsdb/customers.C* "$DBGDIR_FILES"

        # STOP CMA DEBUG
        mdsenv "$CMA_NAME"
        fw debug fwm off TDERROR_ALL_ALL=0
        cp -p $FWDIR/log/fwm.elg* "$DBGDIR_FILES"
        cp -p $FWDIR/log/gpolicy.log* "$DBGDIR_FILES"
    fi
fi

###############################################################################
# STOP DEBUG
###############################################################################
STOP_DATE=$(/bin/date "+%d %b %Y %H:%M:%S %z")
echo -e "\\nDebug Completed at $STOP_DATE" >> "$SESSION_LOG"
echo -e "\\nDebug Completed\\n\\nTurning debug off..."
unset TDERROR_ALL_ALL

###############################################################################
# COLLECT FILES, OUTPUT, AND MORE GENERAL INFO
###############################################################################
echo "Copying files..."
cpstat os -f all > "$DBGDIR_FILES"/cpstatos.txt
ifconfig -a > "$DBGDIR_FILES"/ifconfig.txt
netstat -rn > "$DBGDIR_FILES"/routes.txt
netstat -anp > "$DBGDIR_FILES"/sockets.txt
ps auxww > "$DBGDIR_FILES"/psauxww.txt

section_general_log "CORE DUMPS"
echo "/var/crash" >> "$GENERAL_LOG"
ls -lhA /var/crash >> "$GENERAL_LOG" 2>&1
echo "/var/log/crash" >> "$GENERAL_LOG"
ls -lhA /var/log/crash >> "$GENERAL_LOG" 2>&1
echo "/var/log/dump/usermode" >> "$GENERAL_LOG"
ls -lhA /var/log/dump/usermode >> "$GENERAL_LOG" 2>&1

section_general_log "WATCHDOG (cpwd_admin list)"
cpwd_admin list >> "$GENERAL_LOG"

section_general_log "LICENSES (cplic print -x)"
cplic print -x >> "$GENERAL_LOG"

section_general_log "HOTFIXES (cpinfo -y all)"
if [[ "$ISMDS" == "1" ]]; then
    mdsenv
    script -q -c 'cpinfo -y all' /dev/null >> "$GENERAL_LOG" 2>&1
else
    script -q -c 'cpinfo -y all' /dev/null >> "$GENERAL_LOG" 2>&1
fi

section_general_log "JUMBO HOTFIX TAKE (installed_jumbo_take)"
if [[ "$ISMDS" == "1" ]]; then
    if [[ -e $MDS_TEMPLATE/bin/installed_jumbo_take ]]; then
        installed_jumbo_take >> "$GENERAL_LOG"
    else
        echo "Jumbo Hotfix Accumulator is not installed" >> "$GENERAL_LOG"
    fi
else
    if [[ -e $FWDIR/bin/installed_jumbo_take ]]; then
        installed_jumbo_take >> "$GENERAL_LOG"
    else
        echo "Jumbo Hotfix Accumulator is not installed" >> "$GENERAL_LOG"
    fi
fi

cp -p /var/log/messages* "$DBGDIR_FILES"

if [[ "$MAJOR_VERSION" == "R80" ]]; then
    if [[ "$ISMDS" == "1" ]]; then
        cp -p $MDS_CPDIR/log/cpwd.elg* "$DBGDIR_FILES" 2>&1
        cp -p $MDS_TEMPLATE/log/cpm.elg* "$DBGDIR_FILES"
        cp -p $MDS_TEMPLATE/log/install_policy.elg* "$DBGDIR_FILES"
        mdsenv "$CMA_NAME"
        cp -p $CPDIR/registry/HKLM_registry.data* "$DBGDIR_FILES"
        cp -p $FWDIR/conf/objects_5_0.C* "$DBGDIR_FILES"
        cp -p $FWDIR/tmp/fwm_load.state* "$DBGDIR_FILES"
    else
        cp -p $CPDIR/registry/HKLM_registry.data* "$DBGDIR_FILES"
        cp -p $FWDIR/conf/objects_5_0.C* "$DBGDIR_FILES"
        cp -p $CPDIR/log/cpwd.elg* "$DBGDIR_FILES" 2>&1
        cp -p $FWDIR/log/cpm.elg* "$DBGDIR_FILES"
        cp -p $FWDIR/log/install_policy.elg* "$DBGDIR_FILES"
        cp -p $FWDIR/tmp/fwm_load.state* "$DBGDIR_FILES"
    fi
else
    if [[ "$ISMDS" == "1" ]]; then
        cp -p $MDS_CPDIR/log/cpwd.elg* "$DBGDIR_FILES" 2>&1
        mdsenv "$CMA_NAME"
        cp -p $CPDIR/registry/HKLM_registry.data* "$DBGDIR_FILES"
        cp -p $FWDIR/conf/objects_5_0.C* "$DBGDIR_FILES"
        cp -p $FWDIR/conf/rulebases_5_0.fws* "$DBGDIR_FILES"
    else
        cp -p $CPDIR/log/cpwd.elg* "$DBGDIR_FILES" 2>&1
        cp -p $CPDIR/registry/HKLM_registry.data* "$DBGDIR_FILES"
        cp -p $FWDIR/conf/objects_5_0.C* "$DBGDIR_FILES"
        cp -p $FWDIR/conf/rulebases_5_0.fws* "$DBGDIR_FILES"
    fi
fi

if [[ "$MAJOR_VERSION" == "R80" ]]; then
    section_general_log "dleserver.jar BUILD NUMBER (cpvinfo $MDS_FWDIR/cpm-server/dleserver.jar)"
    cpvinfo $MDS_FWDIR/cpm-server/dleserver.jar >> "$GENERAL_LOG"
fi

###############################################################################
# COMPRESS FILES FOR FINAL ARCHIVE
###############################################################################
HOST_DTS=($(hostname)_at_$(date +%Y-%m-%d_%Hh%Mm%Ss))
FINAL_ARCHIVE="$DBGDIR"/debug_of_"$HOST_DTS".tgz
echo "Compressing files..."
tar czf "$DBGDIR"/debug_of_"$HOST_DTS".tgz --remove-files -C "$DBGDIR" "$FILES"
if [[ "$?" == "0" ]]; then
    echo -e "Please send back file: $FINAL_ARCHIVE\\n"
    exit 0
else
    echo -e "\\nError: Failed to create archive\\nConsider running this script again with verbose output\\n./$SCRIPTNAME -d\\n"
    clean_up
    exit 1
fi