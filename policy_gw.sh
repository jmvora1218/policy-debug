#!/bin/bash

# Russell Seifert, Untitled on Purpose
# Escalation Engineer - Management Products
# Check Point Software Technologies Ltd.

###############################################################################
# HELP SCREEN
###############################################################################
HELP_USAGE="Usage: $0 [OPTIONS]

   -h    display this help
   -b    define the kernel debug buffer
   -d    debug this script. a log file named 'script_debug.txt' will be
           created in the current working directory
   -f    enable more kernel debug flags
   -s    disable minimum disk space check. files will be written
           to /var/log/tmp/policy-debug
   -v    version information
"

HELP_VERSION="
Gateway Policy Debug Script
Version 3.2.2 March 27, 2017
Contribute at <https://github.com/seiruss/policy-debug>
"

OPTIND=1
while getopts ':h-:b-:d-:f-:s-:v-:' HELP_OPTION; do
    case "$HELP_OPTION" in
        h) echo "$HELP_USAGE" ; exit ;;
        b) DEBUG_BUFFER_ON=1 ;;
        d) set -vx ; exec &> >(tee script_debug.txt) ;;
        f) MORE_DEBUG_FLAGS=1 ;;
        m) SPACE_CHECK_OFF=1 ;;
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
echo -e "\033[1m*******************************************"
echo -e "Welcome to the Gateway Policy Debug Script"
echo -e "*******************************************\\n\033[0m"
echo -e "This script will debug Gateway Policy problems"
echo -e "Stop the script by pressing CTRL-C only if there is a problem\\n"
unset TMOUT

###############################################################################
# VERIFY ENVIRONMENT AND IMPORT CHECKPOINT VARIABLES
###############################################################################
if [[ $(uname -s) != "Linux" ]]; then
    echo -e "\\nError: This is not running on Linux"
    echo -e "This script is designed to run on a Linux OS"
    echo -e "Please follow sk84700 to debug Policy Installation\\n"
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

if [[ $($CPDIR/bin/cpprod_util FwIsFirewallModule) != *"1"* ]]; then
    echo -e "\\nError: This is not a Gateway"
    echo -e "This script is designed to run on a Gateway"
    echo -e "Please upload this script to the Gateway and run it again\\n"
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

if [[ $($CPDIR/bin/cpprod_util CPPROD_GetValue Products SG80 1) == *"1"* ]]; then
    echo -e "\\nError: This is an SG80 Gateway"
    echo -e "This script is not supported on SG80"
    echo -e "Please find an alternate method to debug Policy Installation\\n"
    exit 1
fi

###############################################################################
# BASIC VARIABLES
###############################################################################
ECHO="/bin/echo -e"
SCRIPTNAME=($(basename $0))
FILES="$SCRIPTNAME"_files.$$
MAJOR_VERSION=$($CPDIR/bin/cpprod_util CPPROD_GetValue CPshared VersionText 1)
ISVSX=$($CPDIR/bin/cpprod_util FwIsVSX 2> /dev/null)
IS61K=$($CPDIR/bin/cpprod_util CPPROD_GetValue ASG_CHASSIS ChassisID 1 2> /dev/null)

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
            $ECHO "\\nError: There is not enough disk space available"
            $ECHO "Please follow sk60080 to clear disk space\\n"
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
    $ECHO "\\n\\nError: Script interrupted, cleaning temporary files..."
    unset TDERROR_ALL_ALL
    fw ctl debug 0 1> /dev/null
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

###############################################################################
# MONITOR DISK SPACE USAGE
###############################################################################
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
    echo_shell_log "\\nWarning: Minimum disk space check is disabled"
fi
if [[ "$MORE_DEBUG_FLAGS" == "1" ]]; then
    echo_shell_log "\\nInfo: More kernel debug flags is enabled"
fi

###############################################################################
# VERIFY 61K/41K CHASSIS AND BLADE
###############################################################################
if [[ "$IS61K" != "Failed to find the value" ]]; then
    BLADEID=$($CPDIR/bin/cpprod_util CPPROD_GetValue ASG_CHASSIS BladeID 1)
    echo_shell_log "\\nThis is a 61k/41k Gateway on Chassis $IS61K Blade $BLADEID"
    read -p "Do you want to run the debug on Chassis $IS61K Blade $BLADEID? (y/n) [n]? " CORRECT_61K
        case "$CORRECT_61K" in
            [yY][eE][sS]|[yY])
                echo_log "Using Chassis $IS61K Blade $BLADEID"
                ;;
            *)
                $ECHO "Please change to the correct Chassis and Blade\\n"
                clean_up
                exit 1
                ;;
        esac
fi

###############################################################################
# VERIFY VSX CONTEXT
###############################################################################
if [[ "$ISVSX" == *"1"* ]]; then
    VSID_SCRIPT=$(cat /proc/self/vrf)
    echo_shell_log "\\nThis is a VSX Gateway"
    read -p "Do you want to run the debug on VS $VSID_SCRIPT? (y/n) [n]? " CORRECT_VS
        case "$CORRECT_VS" in
            [yY][eE][sS]|[yY])
                echo_log "Using VS $VSID_SCRIPT"
                ;;
            *)
                $ECHO "Please change to the correct Virtual System\\n"
                clean_up
                exit 1
                ;;
        esac
    vsenv "$VSID_SCRIPT" > /dev/null
fi

###############################################################################
# VERIFY KERNEL DEBUG BUFFER
###############################################################################
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
                    $ECHO "Or follow sk84700 to increase the Vmalloc or sk101875 Scenario 2"
                    $ECHO "Press CTRL-C to exit the script if needed"
                    continue
                fi
                echo_shell_log "\\nKernel debug buffer set to $DEBUG_BUFFER"
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
        $ECHO "Follow sk84700 to increase the Vmalloc or sk101875 Scenario 2"
        $ECHO "Or run this script again and define a smaller buffer"
        $ECHO "./$SCRIPTNAME -b\\n"
        clean_up
        exit 1
    fi
fi

###############################################################################
# FUNCTIONS FOR MAIN DEBUG
###############################################################################
starting_debug()
{
    if [[ "$IS61K" != "Failed to find the value" ]]; then
        if [[ "$ISVSX" == *"1"* ]]; then
            echo_shell_log "\\n\\n----STARTING DEBUG ON CHASSIS $IS61K BLADE $BLADEID VS ${VSID_SCRIPT}----\\n"
        else
            echo_shell_log "\\n\\n----STARTING DEBUG ON CHASSIS $IS61K BLADE $BLADEID----\\n"
        fi
    elif [[ "$ISVSX" == *"1"* ]]; then
        echo_shell_log "\\n\\n----STARTING DEBUG ON VS ${VSID_SCRIPT}----\\n"
    else
        echo_shell_log "\\n----STARTING DEBUG----\\n"
    fi

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

###############################################################################
# MAIN DEBUG VSX
###############################################################################
if [[ "$ISVSX" == *"1"* ]]; then
    starting_debug
    fw ctl debug 0 > /dev/null
    fw ctl debug -buf "$DEBUG_BUFFER" -v "$VSID_SCRIPT" > /dev/null
    if [[ "$?" != "0" ]]; then
        $ECHO "\\nError: Failed to allocate kernel debug buffer of $DEBUG_BUFFER"
        $ECHO "Available buffer: $VMALLOC_FREE"
        $ECHO "Follow sk84700 to increase the Vmalloc or sk101875 Scenario 2"
        $ECHO "Or run this script again and define a smaller buffer"
        $ECHO "./$SCRIPTNAME -b\\n"
        clean_up
        exit 1
    fi
    if [[ "$MORE_DEBUG_FLAGS" != "1" ]]; then
        fw ctl debug -v "$VSID_SCRIPT" -m fw + filter ioctl > /dev/null
        fw ctl kdebug -v "$VSID_SCRIPT" -T -f &> "$DBGDIR_FILES"/kernel_atomic_debug_VS"$VSID_SCRIPT".txt &
        echo_log "\\nRunning:"
        echo_log "fw ctl debug 0"
        echo_log "fw ctl debug -buf $DEBUG_BUFFER -v $VSID_SCRIPT"
        echo_log "fw ctl debug -v $VSID_SCRIPT -m fw + filter ioctl"
    else
        fw ctl debug -v "$VSID_SCRIPT" -m fw + filter ioctl cmi > /dev/null
        fw ctl debug -v "$VSID_SCRIPT" -m WS + error warning > /dev/null
        fw ctl debug -v "$VSID_SCRIPT" -m cmi_loader + error warning policy info > /dev/null
        fw ctl debug -v "$VSID_SCRIPT" -m kiss + error warning htab ghtab mtctx salloc pm thinnfa > /dev/null
        fw ctl kdebug -v "$VSID_SCRIPT" -T -f &> "$DBGDIR_FILES"/kernel_atomic_debug_VS"$VSID_SCRIPT".txt &
        echo_log "\\nRunning:"
        echo_log "fw ctl debug 0"
        echo_log "fw ctl debug -buf $DEBUG_BUFFER -v $VSID_SCRIPT"
        echo_log "fw ctl debug -v $VSID_SCRIPT -m fw + filter ioctl cmi"
        echo_log "fw ctl debug -v $VSID_SCRIPT -m WS + error warning"
        echo_log "fw ctl debug -v $VSID_SCRIPT -m cmi_loader + error warning policy info"
        echo_log "fw ctl debug -v $VSID_SCRIPT -m kiss + error warning htab ghtab mtctx salloc pm thinnfa"
    fi
    echo_log "fw ctl kdebug -v $VSID_SCRIPT -T -f &> kernel_atomic_debug_VS$VSID_SCRIPT.txt"
    echo_log "\\nexport TDERROR_ALL_ALL=5"
    echo_log "fw -d fetchlocal -d $FWDIR/state/__tmp/FW1 &> fetch_local_debug_VS$VSID_SCRIPT.txt"

    $ECHO -n "Fetching local policy   "
    $ECHO "Vmalloc before install:\\n" >> "$DBGDIR_FILES"/vmalloc.txt
    cat /proc/meminfo | grep Vmalloc >> "$DBGDIR_FILES"/vmalloc.txt
    export TDERROR_ALL_ALL=5
    fw -d fetchlocal -d $FWDIR/state/__tmp/FW1 &> "$DBGDIR_FILES"/fetch_local_debug_VS"$VSID_SCRIPT".txt &
    progress_bar
    unset TDERROR_ALL_ALL
    $ECHO "\\n\\nVmalloc after install:\\n" >> "$DBGDIR_FILES"/vmalloc.txt
    cat /proc/meminfo | grep Vmalloc >> "$DBGDIR_FILES"/vmalloc.txt
    $ECHO "\\n\\nVmalloc in /boot/grub/grub.conf:\\n" >> "$DBGDIR_FILES"/vmalloc.txt
    grep 'vmalloc' /boot/grub/grub.conf >> "$DBGDIR_FILES"/vmalloc.txt
fi

###############################################################################
# MAIN DEBUG GW
###############################################################################
if [[ "$ISVSX" != *"1"* ]]; then
    starting_debug
    fw ctl debug 0 > /dev/null
    fw ctl debug -buf "$DEBUG_BUFFER" > /dev/null
    if [[ "$?" != "0" ]]; then
        $ECHO "\\nError: Failed to allocate kernel debug buffer of $DEBUG_BUFFER"
        $ECHO "Available buffer: $VMALLOC_FREE"
        $ECHO "Follow sk84700 to increase the Vmalloc or sk101875 Scenario 2"
        $ECHO "Or run this script again and define a smaller buffer"
        $ECHO "./$SCRIPTNAME -b\\n"
        clean_up
        exit 1
    fi
    if [[ "$MORE_DEBUG_FLAGS" != "1" ]]; then
        fw ctl debug -m fw + filter ioctl > /dev/null
        fw ctl kdebug -T -f &> "$DBGDIR_FILES"/kernel_atomic_debug.txt &
        echo_log "\\nRunning:"
        echo_log "fw ctl debug 0"
        echo_log "fw ctl debug -buf $DEBUG_BUFFER"
        echo_log "fw ctl debug -m fw + filter ioctl"
    else
        fw ctl debug -m fw + filter ioctl cmi > /dev/null
        fw ctl debug -m WS + error warning > /dev/null
        fw ctl debug -m cmi_loader + error warning policy info > /dev/null
        fw ctl debug -m kiss + error warning htab ghtab mtctx salloc pm thinnfa > /dev/null
        fw ctl kdebug -T -f &> "$DBGDIR_FILES"/kernel_atomic_debug.txt &
        echo_log "\\nRunning:"
        echo_log "fw ctl debug 0"
        echo_log "fw ctl debug -buf $DEBUG_BUFFER"
        echo_log "fw ctl debug -m fw + filter ioctl cmi"
        echo_log "fw ctl debug -m WS + error warning"
        echo_log "fw ctl debug -m cmi_loader + error warning policy info"
        echo_log "fw ctl debug -m kiss + error warning htab ghtab mtctx salloc pm thinnfa"
    fi
    echo_log "fw ctl kdebug -T -f &> kernel_atomic_debug.txt"
    echo_log "\\nexport TDERROR_ALL_ALL=5"
    echo_log "fw -d fetchlocal -d $FWDIR/state/__tmp/FW1 &> fetch_local_debug.txt"
    
    $ECHO -n "Fetching local policy   "
    $ECHO "Vmalloc before install:\\n" >> "$DBGDIR_FILES"/vmalloc.txt
    cat /proc/meminfo | grep Vmalloc >> "$DBGDIR_FILES"/vmalloc.txt
    export TDERROR_ALL_ALL=5
    fw -d fetchlocal -d $FWDIR/state/__tmp/FW1 &> "$DBGDIR_FILES"/fetch_local_debug.txt &
    progress_bar
    unset TDERROR_ALL_ALL
    $ECHO "\\n\\nVmalloc after install:\\n" >> "$DBGDIR_FILES"/vmalloc.txt
    cat /proc/meminfo | grep Vmalloc >> "$DBGDIR_FILES"/vmalloc.txt
    $ECHO "\\n\\nVmalloc in /boot/grub/grub.conf:\\n" >> "$DBGDIR_FILES"/vmalloc.txt
    grep 'vmalloc' /boot/grub/grub.conf >> "$DBGDIR_FILES"/vmalloc.txt
fi

###############################################################################
# STOP DEBUG
###############################################################################
STOP_DATE=$(/bin/date "+%d %b %Y %H:%M:%S %z")
echo_log "\\nDebug Completed at $STOP_DATE"
$ECHO "\\nDebug Completed\\n"
$ECHO "Turning debug off..."
fw ctl debug 0 > /dev/null

###############################################################################
# COLLECT GENERAL INFO AND FILES
###############################################################################
$ECHO "Copying files..."

section_general_log()
{
    SEP="***********************"
    $ECHO "\\n" >> "$GENERAL_LOG"
    $ECHO "$SEP $1 $SEP" >> "$GENERAL_LOG"
}

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

section_general_log "SYSTEM INFO (uname -a)"
uname -a >> "$GENERAL_LOG"

section_general_log "CPU (cat /proc/cpuinfo | grep processor | wc -l)"
$ECHO -n "Total CPU: " >> "$GENERAL_LOG"
cat /proc/cpuinfo | grep processor | wc -l >> "$GENERAL_LOG"

section_general_log "MEMORY (free -m -t)"
free -m -t >> "$GENERAL_LOG"

section_general_log "DISK SPACE (df -haT)"
df -haT >> "$GENERAL_LOG"

section_general_log "TOP (top -bn1 -p 0)"
top -bn1 -p 0 2>&1 | head -5 >> "$GENERAL_LOG"

section_general_log "TIME (hwclock and ntpstat)"
hwclock >> "$GENERAL_LOG"
ntpstat >> "$GENERAL_LOG" 2>&1

section_general_log "ENABLED BLADES (enabled_blades)"
enabled_blades >> "$GENERAL_LOG" 2>&1

section_general_log "IPS STATUS (ips stat)"
ips stat >> "$GENERAL_LOG" 2>&1

section_general_log "STRING_DICTIONARY_TABLE SIZE (fw tab -t string_dictionary_table -s)"
fw tab -t string_dictionary_table -s >> "$GENERAL_LOG"

section_general_log "STRING_DICTIONARY_TABLE LIMIT (fw tab -t string_dictionary_table | grep limit)"
fw tab -t string_dictionary_table | grep limit >> "$GENERAL_LOG"

section_general_log "CORE DUMPS"
$ECHO "/var/crash" >> "$GENERAL_LOG"
ls -lhA /var/crash >> "$GENERAL_LOG" 2>&1
$ECHO "/var/log/crash" >> "$GENERAL_LOG"
ls -lhA /var/log/crash >> "$GENERAL_LOG" 2>&1
$ECHO "/var/log/dump/usermode" >> "$GENERAL_LOG"
ls -lhA /var/log/dump/usermode >> "$GENERAL_LOG" 2>&1

section_general_log "WATCHDOG (cpwd_admin list)"
cpwd_admin list >> "$GENERAL_LOG"

section_general_log "LICENSES (cplic print -x)"
cplic print -x >> "$GENERAL_LOG"

section_general_log "HOTFIXES (cpinfo -y all)"
if [[ "$ISVSX" == *"1"* ]]; then
    vsenv > /dev/null
    script -q -c 'cpinfo -y all' /dev/null >> "$GENERAL_LOG" 2>&1
    cp -p $CPDIR/log/cpwd.elg* "$DBGDIR_FILES" 2>&1
    vsenv "$VSID_SCRIPT" > /dev/null
else
    script -q -c 'cpinfo -y all' /dev/null >> "$GENERAL_LOG" 2>&1
    cp -p $CPDIR/log/cpwd.elg* "$DBGDIR_FILES" 2>&1
fi

section_general_log "JUMBO HOTFIX TAKE (installed_jumbo_take)"
if [[ -e $FWDIR/bin/installed_jumbo_take ]]; then
    installed_jumbo_take >> "$GENERAL_LOG"
else
    $ECHO "Jumbo Hotfix Accumulator is not installed" >> "$GENERAL_LOG"
fi

if [[ "$MAJOR_VERSION" == "R80" ]]; then
    section_general_log "dleserver.jar BUILD NUMBER (cpvinfo $MDS_FWDIR/cpm-server/dleserver.jar)"
    cpvinfo $MDS_FWDIR/cpm-server/dleserver.jar >> "$GENERAL_LOG"
    cp -p $FWDIR/state/__tmp/FW1/install_policy_report.txt "$DBGDIR_FILES" 2>&1
fi

section_files_log()
{
    SEP="***********************"
    $ECHO "$SEP $1 $SEP\\n" >> "$2"
}

section_files_log "(cpstat os -f all)" "$DBGDIR_FILES/cpstatos.txt"
cpstat os -f all >> "$DBGDIR_FILES"/cpstatos.txt

section_files_log "(cpstat ha -f all)" "$DBGDIR_FILES/clusterxl.txt"
cpstat ha -f all >> "$DBGDIR_FILES"/clusterxl.txt 2>&1

section_files_log "(ifconfig -a)" "$DBGDIR_FILES/ifconfig.txt"
ifconfig -a >> "$DBGDIR_FILES"/ifconfig.txt

section_files_log "(netstat -rn)" "$DBGDIR_FILES/routes.txt"
netstat -rn >> "$DBGDIR_FILES"/routes.txt

section_files_log "(netstat -anp)" "$DBGDIR_FILES/sockets.txt"
netstat -anp >> "$DBGDIR_FILES"/sockets.txt

section_files_log "(ps auxww)" "$DBGDIR_FILES/psauxww.txt"
ps auxww >> "$DBGDIR_FILES"/psauxww.txt

section_files_log "(fw ctl pstat)" "$DBGDIR_FILES/pstat.txt"
fw ctl pstat >> "$DBGDIR_FILES"/pstat.txt

if [[ -f "$FWDIR/boot/modules/fwkern.conf" ]]; then
    cp -p $FWDIR/boot/modules/fwkern.conf* "$DBGDIR_FILES"
fi
cp -p $CPDIR/registry/HKLM_registry.data* "$DBGDIR_FILES"
cp -p /var/log/messages* "$DBGDIR_FILES"

###############################################################################
# COMPRESS FILES FOR FINAL ARCHIVE
###############################################################################
HOST_DTS=($(hostname)_at_$(date +%Y-%m-%d_%Hh%Mm%Ss))
FINAL_ARCHIVE="$DBGDIR"/debug_of_"$HOST_DTS".tgz
$ECHO "Compressing files..."
tar czf "$DBGDIR"/debug_of_"$HOST_DTS".tgz --remove-files -C "$DBGDIR" "$FILES"
if [[ "$?" == "0" ]]; then
    $ECHO "Please send back file: $FINAL_ARCHIVE\\n"
    exit 0
else
    $ECHO "\\nError: Failed to create archive"
    $ECHO "Consider running this script again with verbose output"
    $ECHO "./$SCRIPTNAME -d\\n"
    clean_up
    exit 1
fi