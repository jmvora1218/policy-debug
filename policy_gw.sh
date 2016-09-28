#!/bin/bash

###############################################################################
# HELP SCREEN
###############################################################################
HELP_USAGE="Usage: $0 [OPTIONS]

   -h    display this help
   -b    define the kernel debug buffer
   -d    debug this script. a log file named 'script_debug.txt' will be
           created in the current working directory
   -f    enable more kernel debug flags
   -m    disable minimum disk space check. files will be written
           to /var/log/tmp/debug
   -l    license terms
   -v    version information
"

HELP_VERSION="
Gateway Policy Debug Script
Version 2.8.2 September 28, 2016
Contribute at <https://github.com/seiruss/policy-debug>
"

HELP_LICENSE="
MIT License

Copyright (c) 2016 Russell Seifert

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the \"Software\"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"

OPTIND=1
while getopts ':h-:b-:d-:f-:m-:l-:v-:' HELP_OPTION; do
    case "$HELP_OPTION" in
        h) echo "$HELP_USAGE" ; exit ;;
        b) DEBUG_BUFFER_ON=1 ;;
        d) set -vx ; exec &> >(tee script_debug.txt) ;;
        f) MORE_DEBUG_FLAGS=1 ;;
        m) SPACE_CHECK_OFF=1 ;;
        l) echo "$HELP_LICENSE" ; exit ;;
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
echo -e "\033[1m*******************************************\\nWelcome to the Gateway Policy Debug Script\\n*******************************************\\n\033[0m"
echo -e "This script will debug Gateway Policy problems\\nStop the script by pressing CTRL-C only if there is a problem\\n"
echo "Debug is initializing, please wait..."
sleep 2
unset TMOUT

###############################################################################
# VERIFY ENVIRONMENT AND IMPORT CHECKPOINT VARIABLES
###############################################################################
if [[ $(uname -s) != "Linux" ]]; then
    echo -e "\\nError: This is not running on Linux\\nThis script is designed to run on a Linux OS\\nPlease follow sk84700 to debug Policy Installation\\n"
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

if [[ $($CPDIR/bin/cpprod_util FwIsFirewallModule) != *"1"* ]]; then
    echo -e "\\nError: This is not a Gateway\\nThis script is designed to run on a Gateway\\nPlease upload this script to the Gateway and run it again\\n"
    exit 1
fi

if [[ $($CPDIR/bin/cpprod_util FwIsVSX 2> /dev/null) == *"1"* ]]; then
    if [[ -r /etc/profile.d/vsenv.sh ]]; then
        source /etc/profile.d/vsenv.sh
    elif [[ -r $FWDIR/scripts/vsenv.sh ]]; then
        source $FWDIR/scripts/vsenv.sh
    else
        if [[ $($CPDIR/bin/cpprod_util CPPROD_GetValue CPshared VersionText 1) == *"R6"* ]]; then
            echo -e "\\nError: This is a VSX Gateway on a version lower than R75.40VS\\nThis script is not supported on this version\\nPlease follow sk84700 to debug Policy Installation\\n"
            exit 1
        else
            echo -e "\\nError: Unable to find /etc/profile.d/vsenv.sh or \$FWDIR/scripts/vsenv.sh\\nVerify this file exists in either directory and you can read it\\n"
            exit 1
        fi
    fi
fi

if [[ $($CPDIR/bin/cpprod_util CPPROD_GetValue Products SG80 1) == *"1"* ]]; then
    echo -e "\\nError: This is an SG80 Gateway\\nThis script is not supported on SG80\\nPlease find an alternate method to debug Policy Installation\\n"
    exit 1
fi

###############################################################################
# BASIC VARIABLES
###############################################################################
SCRIPTNAME=($(basename $0))
FILES="$SCRIPTNAME"_files.$$
ISVSX=$($CPDIR/bin/cpprod_util FwIsVSX 2> /dev/null)
IS61K=$($CPDIR/bin/cpprod_util CPPROD_GetValue ASG_CHASSIS ChassisID 1 2> /dev/null)

###############################################################################
# CREATE TEMPORARY DIRECTORIES ON EITHER ROOT OR /VAR/LOG. 2GB MINIMUM
###############################################################################
if [[ "$SPACE_CHECK_OFF" == "1" ]]; then
    DBGDIR=/var/log/tmp/debug
    DBGDIR_FILES=/var/log/tmp/debug/"$FILES"
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
            DBGDIR=/var/log/tmp/debug
            DBGDIR_FILES=/var/log/tmp/debug/"$FILES"
            if [[ ! -d "$DBGDIR_FILES" ]]; then
                mkdir -p "$DBGDIR_FILES"
            else
                rm -rf "$DBGDIR_FILES"
                mkdir -p "$DBGDIR_FILES"
            fi
        fi
    else
        DBGDIR=/tmp/debug
        DBGDIR_FILES=/tmp/debug/"$FILES"
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
    fw ctl debug 0 1> /dev/null
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
[[ "$MORE_DEBUG_FLAGS" == "1" ]] && echo -e "\\nInfo: More kernel debug flags is enabled" | tee -a "$SESSION_LOG"

###############################################################################
# VERIFY 61K/41K CHASSIS AND BLADE
###############################################################################
if [[ "$IS61K" != "Failed to find the value" ]]; then
    BLADEID=$($CPDIR/bin/cpprod_util CPPROD_GetValue ASG_CHASSIS BladeID 1)
    echo -e "\\nThis is a 61k/41k Gateway on Chassis $IS61K Blade $BLADEID" | tee -a "$SESSION_LOG"
    read -p "Do you want to run this debug on Chassis $IS61K Blade $BLADEID? (y/n) [n]? " CORRECT_61K
        case "$CORRECT_61K" in
            [yY][eE][sS]|[yY])
                echo "Chassis: $IS61K Blade: $BLADEID"
                echo "Using Chassis $IS61K Blade $BLADEID" >> "$SESSION_LOG"
                ;;
            *)
                echo -e "Please change to the correct Chassis and Blade and run the script again\\n"
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
    echo -e "\\nThis is a VSX Gateway" | tee -a "$SESSION_LOG"
    read -p "Do you want to run this debug on VS $VSID_SCRIPT? (y/n) [n]? " CORRECT_VS
        case "$CORRECT_VS" in
            [yY][eE][sS]|[yY])
                echo "Virtual System: VS ${VSID_SCRIPT}"
                echo "Using VS $VSID_SCRIPT" >> "$SESSION_LOG"
                ;;
            *)
                echo -e "Please change to the correct Virtual System and run the script again\\n"
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
        echo -e "\\nWhat size in kilobytes do you want the kernel debug buffer? [4000-32768]"
        read DEBUG_BUFFER
        case "$DEBUG_BUFFER" in
            [4-9][0-9][0-9][0-9]|[1-9][0-9][0-9][0-9][0-9])
                if (( "$DEBUG_BUFFER" < 16384 )); then
                    echo -e "\\nInfo: The kernel debug buffer is defined less than 16384\\nThe debug may not show the error with a buffer of $DEBUG_BUFFER"
                    read -p "Do you want to continue running the debug? (y/n) [n]? " LOW_BUFFER
                    case "$LOW_BUFFER" in
                        [yY][eE][sS]|[yY])
                            ;;
                        *)
                            echo -e "\\nPlease define a larger buffer\\nPress CTRL-C to exit the script if needed"
                            continue
                            ;;
                    esac
                fi
                if (( "$DEBUG_BUFFER" > 32768 )); then
                    echo -e "\\nError: Kernel debug buffer can only be up to 32768\\nPlease define a valid buffer between 4000-32768\\nPress CTRL-C to exit the script if needed"
                    continue
                fi
                VMALLOC_TOTAL=$(cat /proc/meminfo | grep "VmallocTotal" | awk '{ print $2 }')
                VMALLOC_USED=$(cat /proc/meminfo | grep "VmallocUsed" | awk '{ print $2 }')
                VMALLOC_FREE=$(( $VMALLOC_TOTAL - $VMALLOC_USED ))
                if (( "$VMALLOC_FREE" < "$DEBUG_BUFFER" )); then
                    echo -e "\\nError: Not enough kernel debug buffer free to allocate $DEBUG_BUFFER\\nAvailable buffer: $VMALLOC_FREE\\nPlease define a smaller buffer or follow sk84700 to increase the Vmalloc\\nPress CTRL-C to exit the script if needed"
                    continue
                fi
                echo -e "\\nKernel debug buffer set to $DEBUG_BUFFER" | tee -a "$SESSION_LOG"
                break
                ;;
            *)
                echo -e "\\nError: Kernel debug buffer defined is not valid\\nUse only numbers and must be between 4000-32768\\nPress CTRL-C to exit the script if needed"
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
        echo -e "\\nError: Not enough kernel debug buffer free to allocate $DEBUG_BUFFER\\nAvailable buffer: $VMALLOC_FREE\\nPlease follow sk84700 to increase the Vmalloc\\nOr run this script again and define a smaller buffer\\n./$SCRIPTNAME -b\\n"
        clean_up
        exit 1
    fi
fi

###############################################################################
# START DEBUG
###############################################################################
if [[ "$IS61K" != "Failed to find the value" ]]; then
    if [[ "$ISVSX" == *"1"* ]]; then
        echo -e "\\nStarting debug on Chassis $IS61K Blade $BLADEID VS ${VSID_SCRIPT}..." | tee -a "$SESSION_LOG"
    else
        echo -e "\\nStarting debug on Chassis $IS61K Blade $BLADEID..." | tee -a "$SESSION_LOG"
    fi
elif [[ "$ISVSX" == *"1"* ]]; then
    echo -e "\\nStarting debug on VS ${VSID_SCRIPT}..." | tee -a "$SESSION_LOG"
else
    echo -e "\\nStarting debug..." | tee -a "$SESSION_LOG"
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
# MAIN DEBUG VSX
###############################################################################
if [[ "$ISVSX" == *"1"* ]]; then
    fw ctl debug 0 > /dev/null
    fw ctl debug -buf "$DEBUG_BUFFER" -v "$VSID_SCRIPT" > /dev/null
    if [[ "$?" != "0" ]]; then
        echo -e "\\nError: Failed to allocate kernel debug buffer\\nPlease run this script again and define a smaller buffer\\n./$SCRIPTNAME -b\\n"
        clean_up
        exit 1
    fi
    if [[ "$MORE_DEBUG_FLAGS" != "1" ]]; then
        fw ctl debug -v "$VSID_SCRIPT" -m fw + filter ioctl > /dev/null
        fw ctl kdebug -v "$VSID_SCRIPT" -T -f &> "$DBGDIR_FILES"/kernel_atomic_debug_VS"$VSID_SCRIPT".txt &
        echo -e "\\nRunning:\\nfw ctl debug 0\\nfw ctl debug -buf $DEBUG_BUFFER -v $VSID_SCRIPT\\nfw ctl debug -v $VSID_SCRIPT -m fw + filter ioctl\\nfw ctl kdebug -v $VSID_SCRIPT -T -f &> kernel_atomic_debug_VS$VSID_SCRIPT.txt\\n\\nexport TDERROR_ALL_ALL=5\\nfw -d fetchlocal -d $FWDIR/state/__tmp/FW1 &> fetch_local_debug_VS$VSID_SCRIPT.txt" >> "$SESSION_LOG"
    else
        fw ctl debug -v "$VSID_SCRIPT" -m fw + filter ioctl cmi > /dev/null
        fw ctl debug -v "$VSID_SCRIPT" -m WS + error warning > /dev/null
        fw ctl debug -v "$VSID_SCRIPT" -m cmi_loader + error warning policy info > /dev/null
        fw ctl debug -v "$VSID_SCRIPT" -m kiss + error warning htab ghtab mtctx salloc pm > /dev/null
        fw ctl kdebug -v "$VSID_SCRIPT" -T -f &> "$DBGDIR_FILES"/kernel_atomic_debug_VS"$VSID_SCRIPT".txt &
        echo -e "\\nRunning:\\nfw ctl debug 0\\nfw ctl debug -buf $DEBUG_BUFFER -v $VSID_SCRIPT\\nfw ctl debug -v $VSID_SCRIPT -m fw + filter ioctl cmi\\nfw ctl debug -v $VSID_SCRIPT -m WS + error warning\\nfw ctl debug -v $VSID_SCRIPT -m cmi_loader + error warning policy info\\nfw ctl debug -v $VSID_SCRIPT -m kiss + error warning htab ghtab mtctx salloc pm\\nfw ctl kdebug -v $VSID_SCRIPT -T -f &> kernel_atomic_debug_VS$VSID_SCRIPT.txt\\n\\nexport TDERROR_ALL_ALL=5\\nfw -d fetchlocal -d $FWDIR/state/__tmp/FW1 &> fetch_local_debug_VS$VSID_SCRIPT.txt" >> "$SESSION_LOG"
    fi
    echo -n "Fetching local policy   "
    echo -e "Vmalloc before install:\\n" >> "$DBGDIR_FILES"/vmalloc.txt
    cat /proc/meminfo | grep Vmalloc >> "$DBGDIR_FILES"/vmalloc.txt
    export TDERROR_ALL_ALL=5
    fw -d fetchlocal -d $FWDIR/state/__tmp/FW1 &> "$DBGDIR_FILES"/fetch_local_debug_VS"$VSID_SCRIPT".txt &
    progress_bar
    unset TDERROR_ALL_ALL
    echo -e "\\n\\nVmalloc after install:\\n" >> "$DBGDIR_FILES"/vmalloc.txt
    cat /proc/meminfo | grep Vmalloc >> "$DBGDIR_FILES"/vmalloc.txt
    echo -e "\\n\\nVmalloc in /boot/grub/grub.conf:\\n" >> "$DBGDIR_FILES"/vmalloc.txt
    grep 'vmalloc' /boot/grub/grub.conf >> "$DBGDIR_FILES"/vmalloc.txt
fi

###############################################################################
# MAIN DEBUG GW
###############################################################################
if [[ "$ISVSX" != *"1"* ]]; then
    fw ctl debug 0 > /dev/null
    fw ctl debug -buf "$DEBUG_BUFFER" > /dev/null
    if [[ "$?" != "0" ]]; then
        echo -e "\\nError: Failed to allocate kernel debug buffer\\nPlease run this script again and define a smaller buffer\\n./$SCRIPTNAME -b\\n"
        clean_up
        exit 1
    fi
    if [[ "$MORE_DEBUG_FLAGS" != "1" ]]; then
        fw ctl debug -m fw + filter ioctl > /dev/null
        fw ctl kdebug -T -f &> "$DBGDIR_FILES"/kernel_atomic_debug.txt &
        echo -e "\\nRunning:\\nfw ctl debug 0\\nfw ctl debug -buf $DEBUG_BUFFER\\nfw ctl debug -m fw + filter ioctl\\nfw ctl kdebug -T -f &> kernel_atomic_debug.txt\\n\\nexport TDERROR_ALL_ALL=5\\nfw -d fetchlocal -d $FWDIR/state/__tmp/FW1 &> fetch_local_debug.txt" >> "$SESSION_LOG"
    else
        fw ctl debug -m fw + filter ioctl cmi > /dev/null
        fw ctl debug -m WS + error warning > /dev/null
        fw ctl debug -m cmi_loader + error warning policy info > /dev/null
        fw ctl debug -m kiss + error warning htab ghtab mtctx salloc pm > /dev/null
        fw ctl kdebug -T -f &> "$DBGDIR_FILES"/kernel_atomic_debug.txt &
        echo -e "\\nRunning:\\nfw ctl debug 0\\nfw ctl debug -buf $DEBUG_BUFFER\\nfw ctl debug -m fw + filter ioctl cmi\\nfw ctl debug -m WS + error warning\\nfw ctl debug -m cmi_loader + error warning policy info\\nfw ctl debug -m kiss + error warning htab ghtab mtctx salloc pm\\nfw ctl kdebug -T -f &> kernel_atomic_debug.txt\\n\\nexport TDERROR_ALL_ALL=5\\nfw -d fetchlocal -d $FWDIR/state/__tmp/FW1 &> fetch_local_debug.txt" >> "$SESSION_LOG"
    fi
    echo -n "Fetching local policy   "
    echo -e "Vmalloc before install:\\n" >> "$DBGDIR_FILES"/vmalloc.txt
    cat /proc/meminfo | grep Vmalloc >> "$DBGDIR_FILES"/vmalloc.txt
    export TDERROR_ALL_ALL=5
    fw -d fetchlocal -d $FWDIR/state/__tmp/FW1 &> "$DBGDIR_FILES"/fetch_local_debug.txt &
    progress_bar
    unset TDERROR_ALL_ALL
    echo -e "\\n\\nVmalloc after install:\\n" >> "$DBGDIR_FILES"/vmalloc.txt
    cat /proc/meminfo | grep Vmalloc >> "$DBGDIR_FILES"/vmalloc.txt
    echo -e "\\n\\nVmalloc in /boot/grub/grub.conf:\\n" >> "$DBGDIR_FILES"/vmalloc.txt
    grep 'vmalloc' /boot/grub/grub.conf >> "$DBGDIR_FILES"/vmalloc.txt
fi

###############################################################################
# STOP DEBUG
###############################################################################
STOP_DATE=$(/bin/date "+%d %b %Y %H:%M:%S %z")
echo -e "\\nDebug Completed at $STOP_DATE" >> "$SESSION_LOG"
echo -e "\\nDebug Completed\\n\\nTurning debug off..."
fw ctl debug 0 > /dev/null

###############################################################################
# COLLECT FILES, OUTPUT, AND MORE GENERAL INFO
###############################################################################
echo "Copying files..."
cpstat os -f all > "$DBGDIR_FILES"/cpstatos.txt
ifconfig -a > "$DBGDIR_FILES"/ifconfig.txt
netstat -rn > "$DBGDIR_FILES"/routes.txt
netstat -anp > "$DBGDIR_FILES"/sockets.txt
ps auxww > "$DBGDIR_FILES"/psauxww.txt
fw ctl pstat > "$DBGDIR_FILES"/pstat.txt

section_general_log "ENABLED BLADES (enabled_blades)"
enabled_blades >> "$GENERAL_LOG" 2>&1

section_general_log "IPS STATUS (ips stat)"
ips stat >> "$GENERAL_LOG" 2>&1

section_general_log "CLUSTERXL STATUS (cphaprob stat)"
cphaprob stat >> "$GENERAL_LOG" 2>&1

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
    echo "Jumbo Hotfix Accumulator is not installed" >> "$GENERAL_LOG"
fi

cp -p $CPDIR/registry/HKLM_registry.data* "$DBGDIR_FILES"
cp -p /var/log/messages* "$DBGDIR_FILES"

###############################################################################
# COMPRESS FILES FOR FINAL ARCHIVE
###############################################################################
HOST_DTS=`hostname`_at_`date +%Y-%m-%d_%Hh%Mm%Ss`
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