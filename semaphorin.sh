#!/bin/bash
verbose=1
#{
os=$(uname)
maj_ver=$(echo "$os_ver" | awk -F. '{print $1}')
dir="$(pwd)"
bin="$(pwd)/$(uname)"
sshtars="$(pwd)/sshtars"
printf '%s\n' '#'
printf '%s\n' '# semaphorin: v2.0.1 '
printf '%s\n' '#'
printf '%s\n' '# ========  Made by  ======='
printf '%s\n' '# Made by: y08wilm, Mineek, Ploosh, edwin170'
printf '%s\n' '# ======== Thanks to ======='
printf '%s\n' '# Thanks to: md.0269, TheRealClarity, nikias (libimobiledevice),'
printf '%s\n' '# exploit3dguy, dora2-ios, LukeZGD, PsychoTea, Nathan, LunarN0v4,'
printf '%s\n' '# checkra1n team (Siguza, axi0mx, littlelaillo et al.)'
printf '%s\n' '# =========================='
printf '%s\n' ''
RED='\033[0;31m'
YELLOW='\033[0;33m'
DARK_GRAY='\033[90m'
LIGHT_CYAN='\033[0;96m'
DARK_CYAN='\033[0;36m'
NO_COLOR='\033[0m'
BOLD='\033[1m'
error() {
    printf '%b\n' " - [${DARK_GRAY}$(date +'%m/%d/%y %H:%M:%S')${NO_COLOR}] ${RED}${BOLD}<Error>${NO_COLOR}: ${RED}$1${NO_COLOR}"
}
info() {
    printf '%b\n' " - [${DARK_GRAY}$(date +'%m/%d/%y %H:%M:%S')${NO_COLOR}] ${DARK_CYAN}${BOLD}<Info>${NO_COLOR}: ${DARK_CYAN}$1${NO_COLOR}"
}
warning() {
    printf '%b\n' " - [${DARK_GRAY}$(date +'%m/%d/%y %H:%M:%S')${NO_COLOR}] ${YELLOW}${BOLD}<Warning>${NO_COLOR}: ${YELLOW}$1${NO_COLOR}"
}
max_args=1
arg_count=0
if [ "$os" = 'Linux' ]; then
    linux_cmds='lsusb'
fi
for cmd in curl unzip python3 git ssh scp killall sudo grep pgrep ${linux_cmds}; do
    if ! command -v "${cmd}" > /dev/null; then
        if [ "$cmd" = "python3" ]; then
            error "Command '${cmd}' not installed, please install it!";
            if [ "$os" = 'Darwin' ]; then
                if [ ! -e python-3.11.9-macos11.pkg ]; then
                    curl -k https://www.python.org/ftp/python/3.11.9/python-3.11.9-macos11.pkg -o python-3.11.9-macos11.pkg
                fi
                open -W python-3.11.9-macos11.pkg
            fi
            if ! command -v "${cmd}" > /dev/null; then
                cmd_not_found=1
            fi
        else
            if ! command -v "${cmd}" > /dev/null; then
                error "Command '${cmd}' not installed, please install it!";
                cmd_not_found=1
            fi
        fi
    fi
done
if [ "$cmd_not_found" = "1" ]; then
    exit 1
fi
if ! python3 -c 'import pkgutil; exit(not pkgutil.find_loader("pyimg4"))'; then
    python3 -m pip install pyimg4
fi
clean_usbmuxd() {
    sudo killall usbmuxd 2>/dev/null
    if [[ $(which systemctl 2>/dev/null) ]]; then
        sleep 1
        sudo systemctl restart usbmuxd
    fi
}
if [[ $os =~ Darwin ]]; then
    info "Running on Darwin . . ."
    #sudo xattr -cr .
    os_ver=$(sw_vers -productVersion)
    sudo killall -STOP AMPDevicesAgent AMPDeviceDiscoveryAgent MobileDeviceUpdater
    if [[ $os_ver =~ ^10\.1[3]\.* ]]; then
        error "macOS/OS X $os_ver is not supported by this script. Please install macOS 10.14 (Mojave) or later to continue if possible."
        sleep 1
        read -p "[*] You can press the enter key on your keyboard to skip this warning  " r1
    else
        info "You are running macOS $os_ver. Continuing . . ."
    fi
elif [[ $os =~ Linux ]]; then
    info "Running on Linux . . ."
    curl -LO https://opensource.apple.com/tarballs/cctools/cctools-927.0.2.tar.gz
    mkdir cctools-tmp
    tar -xzf cctools-927.0.2.tar.gz -C cctools-tmp/
    sed -i "s_#include_//_g" cctools-tmp/*cctools-927.0.2/include/mach-o/loader.h
    sed -i -e "s=<stdint.h>=\n#include <stdint.h>\ntypedef int integer_t;\ntypedef integer_t cpu_type_t;\ntypedef integer_t cpu_subtype_t;\ntypedef integer_t cpu_threadtype_t;\ntypedef int vm_prot_t;=g" cctools-tmp/*cctools-927.0.2/include/mach-o/loader.h
    cp -r cctools-tmp/*cctools-927.0.2/include/* /usr/local/include/
    rm -rf cctools-tmp/
    apt install clang lld build-essential libpng-dev libpng16-16 libxml2-dev pkg-config libplist-utils
    if [[ ! -e libssl1.1_1.1.1f-1ubuntu2.22_amd64.deb ]]; then
        curl -SLO http://security.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.1f-1ubuntu2.22_amd64.deb
        dpkg -i libssl1.1_1.1.1f-1ubuntu2.22_amd64.deb
    fi
    if [[ ! -e libssl-dev_1.1.1f-1ubuntu2.22_amd64.deb ]]; then
        curl -SLO http://security.ubuntu.com/ubuntu/pool/main/o/openssl/libssl-dev_1.1.1f-1ubuntu2.22_amd64.deb
        dpkg -i libssl-dev_1.1.1f-1ubuntu2.22_amd64.deb
    fi
    if [[ $(which systemctl 2>/dev/null) ]]; then
        sudo systemctl stop usbmuxd
    fi
    #sudo killall usbmuxd 2>/dev/null
    #sleep 1
    sudo -b $bin/usbmuxd -pf
    trap "clean_usbmuxd" EXIT
else
    error "What operating system are you even using . . ."
    exit 1
fi
print_help() {
    cat << EOF
Usage:`if [ $EUID = 0 ]; then echo " sudo"; fi` $0 [VERSION...] [OPTION...]
iOS/iPadOS 7.0.6-9.3 Downgrade & Jailbreak tool for older checkm8 devices using seprmvr64
Examples:
   `if [ $EUID = 0 ]; then echo " sudo"; fi` $0 7.0.6 --restore
   `if [ $EUID = 0 ]; then echo " sudo"; fi` $0 7.0.6 --boot

Main operation mode:
    --help                     Print this help
    --ramdisk                  Download& enter ramdisk
    --dump-blobs               Self explanatory
    --serial                   Enable serial debugging
    --ssh                      Tries to connect to ssh over usb interface to the connected device
    --restore                  Wipe device and downgrade ios
    --dump-activation          Backs up your activation records and other important files from your iOS/iPadOS device
    --restore-activation       Copies the backed up activation records to /dev/disk0s1s2 on the iOS/iPadOS device
    --dump-nand                Backs up the entire contents of your iOS/iPadOS device to disk0.gz
    --appleinternal            Enables internalization during restore
    --NoMoreSIGABRT            Adds the "protect" flag to /dev/disk0s1s2
    --disable-NoMoreSIGABRT    Removes the "protect" flag from /dev/disk0s1s2
    --restore-factorydata      Copies the factory data from your backed up records folder to your iOS/iPadOS device
    --restore-nand             Copies the contents of disk0.gz to /dev/disk0 of the iOS/iPadOS device
    --boot                     Don't enter ramdisk or wipe device, just boot
    --boot-clean               Don't enter ramdisk or wipe device, just boot without seprmvr64
    --clean                    Delete all the created boot files for your device
    --force-activation         Forces FactoryActivation on your device during restore
    --fix-auto-boot            Fixes booting into the main OS on A11 devices such as the iPhone X

The iOS/iPadOS version argument should be the iOS/iPadOS version you are downgrading to.
EOF
}
remote_cmd() {
    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "$@"
}
parse_opt() {
    case "$1" in
        --)
            no_more_opts=1
            ;;
        --ramdisk)
            ramdisk=1
            ;;
        --dump-blobs)
            dump_blobs=1
            ;;
        --serial)
            serial=1
            ;;
        --dump-nand)
            dump_nand=1
            ;;
        --NoMoreSIGABRT)
            NoMoreSIGABRT=1
            ;;
        --disable-NoMoreSIGABRT)
            disable_NoMoreSIGABRT=1
            ;;
        --dump-activation)
            dump_activation=1
            ;;
        --restore-activation)
            restore_activation=1
            ;;
        --restore-factorydata)
            restore_factorydata=1
            ;;
        --restore-nand)
            restore_nand=1
            ;;
        --force-activation)
            force_activation=1
            ;;
        --appleinternal)
            appleinternal=1
            ;;
        --ssh)
            _kill_if_running iproxy
            "$bin"/iproxy 2222 22 &
            ssh -o StrictHostKeyChecking=no -p2222 root@localhost
            exit 0
            ;;
        --restore)
            restore=1
            ;;
        --boot)
            boot=1
            ;;
        --boot-clean)
            boot_clean=1
            ;;
        --clean)
            clean=1
            ;;
        --help)
            print_help
            exit 0
            ;;
        *)
            error "Unknown option $1. Use`if [ $EUID = 0 ]; then echo " sudo"; fi` $0 --help for help."
            exit 1;
    esac
}
parse_arg() {
    arg_count=$((arg_count + 1))
    case "$1" in
        clean)
            clean=1
            hit=1
            ;;
        ssh)
            _kill_if_running iproxy
            "$bin"/iproxy 2222 22 &
            ssh -o StrictHostKeyChecking=no -p2222 root@localhost
            exit 0
            ;;
        *)
            if [ -z "$version" ]; then
                version="$1"
            fi
            if [[ "$version" == "12.1."* ]]; then
                version="12.1"
            fi
            ;;
    esac
}
parse_cmdline() {
    if [ -z "$1" ]; then
        print_help
        exit 0
    fi
    hit=0
    for arg in $@; do
        if [[ "$arg" == --* ]] && [ -z "$no_more_opts" ]; then
            parse_opt "$arg";
            hit=1
        elif [ "$arg_count" -lt "$max_args" ]; then
            parse_arg "$arg";
        else
            error "Too many arguments. Use`if [ $EUID = 0 ]; then echo " sudo"; fi` $0 --help for help.";
            exit 1;
        fi
    done
    if [[ "$hit" == 0 ]]; then
        print_help
        exit 0
    fi
    if [ -z "$version" ]; then
        print_help
        exit 0
    fi
}
get_device_mode() {
    if [ "$os" = "Darwin" ]; then
        apples="$(system_profiler SPUSBDataType 2> /dev/null | grep -B1 'Vendor ID: 0x05ac' | grep 'Product ID:' | cut -dx -f2 | cut -d' ' -f1 | tail -r)"
    elif [ "$os" = "Linux" ]; then
        apples="$(lsusb | cut -d' ' -f6 | grep '05ac:' | cut -d: -f2)"
    fi
    local device_count=0
    local usbserials=""
    for apple in $apples; do
        case "$apple" in
            12a8|12aa|12ab)
            device_mode=normal
            device_count=$((device_count+1))
            ;;
            1281)
            device_mode=recovery
            device_count=$((device_count+1))
            ;;
            1227)
            device_mode=dfu
            device_count=$((device_count+1))
            ;;
            1222)
            device_mode=diag
            device_count=$((device_count+1))
            ;;
            1338)
            device_mode=checkra1n_stage2
            device_count=$((device_count+1))
            ;;
            4141)
            device_mode=pongo
            device_count=$((device_count+1))
            ;;
        esac
    done
    if [ "$device_count" = "0" ]; then
        device_mode=none
    elif [ "$device_count" -ge "2" ]; then
        error "Please attach only one device" > /dev/tty
        kill -30 0
        exit 1;
    fi
    if [ "$os" = "Linux" ]; then
        usbserials=$(cat /sys/bus/usb/devices/*/serial)
    elif [ "$os" = "Darwin" ]; then
        usbserials=$(system_profiler SPUSBDataType 2> /dev/null | grep 'Serial Number' | cut -d: -f2- | sed 's/ //')
    fi
    if grep -qE '(ramdisk tool|SSHRD_Script) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [0-9]{1,2} [0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2}' <<< "$usbserials"; then
        device_mode=ramdisk
    fi
    echo "$device_mode"
}
_wait_for_dfu() {
    if [ "$os" = "Darwin" ]; then
        if ! (system_profiler SPUSBDataType 2> /dev/null | grep ' Apple Mobile Device (DFU Mode)' >> /dev/null); then
            info "Waiting for device in DFU mode"
        fi

        while ! (system_profiler SPUSBDataType 2> /dev/null | grep ' Apple Mobile Device (DFU Mode)' >> /dev/null); do
            sleep 1
        done
    else
        if ! (lsusb | cut -d' ' -f6 | grep '05ac:' | cut -d: -f2 | grep 1227 >> /dev/null); then
            info "Waiting for device in DFU mode"
        fi

        while ! (lsusb | cut -d' ' -f6 | grep '05ac:' | cut -d: -f2 | grep 1227 >> /dev/null); do
            sleep 1
        done
    fi
}
_dfuhelper() {
    if [[ ! "$deviceid" == "iPhone6"* && ! "$deviceid" == "iPad4"* && ! "$cpid" == "0x8015" ]]; then
        "$bin"/dfuhelper3.sh
    elif [ "$os" = "Darwin" ]; then
        if ! (system_profiler SPUSBDataType 2> /dev/null | grep ' Apple Mobile Device (DFU Mode)' >> /dev/null); then
            "$bin"/dfuhelper3.sh
        fi
    else
        if ! (lsusb | cut -d' ' -f6 | grep '05ac:' | cut -d: -f2 | grep 1227 >> /dev/null); then
            "$bin"/dfuhelper3.sh
        fi
    fi
    _wait_for_dfu
}
_download_ramdisk_boot_files() {
    ipswurl=$(curl -k -sL "https://api.ipsw.me/v4/device/$deviceid?type=ipsw" | "$bin"/jq '.firmwares | .[] | select(.version=="'$3'")' | "$bin"/jq -s '.[0] | .url' --raw-output)
    rm -rf BuildManifest.plist
    mkdir -p "$dir"/$1/$cpid/ramdisk/$3
    rm -rf "$dir"/work
    mkdir "$dir"/work
    cd "$dir"/work
    "$bin"/img4tool -e -s "$dir"/other/shsh/"${check}".shsh -m IM4M
    if [ ! -e "$dir"/$1/$cpid/ramdisk/$3/ramdisk.img4 ]; then
        if [[ "$3" == "10."* ]]; then
            if [[ "$deviceid" == "iPhone8,1" || "$deviceid" == "iPhone8,2" ]]; then
                ipswurl=$(curl -k -sL "https://api.ipsw.me/v4/device/$deviceid?type=ipsw" | "$bin"/jq '.firmwares | .[] | select(.version=="'11.1'")' | "$bin"/jq -s '.[0] | .url' --raw-output)
            else
                ipswurl=$(curl -k -sL "https://api.ipsw.me/v4/device/$deviceid?type=ipsw" | "$bin"/jq '.firmwares | .[] | select(.version=="'10.3.3'")' | "$bin"/jq -s '.[0] | .url' --raw-output)
            fi
        fi
        "$bin"/pzb -g BuildManifest.plist "$ipswurl"
        if [ ! -e "$dir"/$1/$cpid/ramdisk/$3/iBSS.dec ]; then
            "$bin"/pzb -g $(awk "/""$replace""/{x=1}x&&/iBSS[.]/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1) "$ipswurl"
            fn="$(awk "/""$replace""/{x=1}x&&/iBSS[.]/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | sed 's/Firmware[/]dfu[/]//')"
            if [[ "$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -e $3 $1)" == "true" ]]; then
                if [[ "$3" == "10."* ]]; then
                    if [[ "$deviceid" == "iPhone8,1" || "$deviceid" == "iPhone8,2" ]]; then
                        ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn 11.1 $1)"
                    else
                        ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn 10.3.3 $1)"
                    fi
                else
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $3 $1)"
                fi
                if [ -z $ivkey ]; then
                    kbag=$("$bin"/img4 -i $fn -b | head -n 1)
                    iv=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ',' -f 1 | cut -d ' ' -f 2)
                    key=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ' ' -f 4)
                    ivkey="$iv$key"
                    "$bin"/img4 -i $fn -o "$dir"/$1/$cpid/ramdisk/$3/iBSS.dec -k $ivkey
                else
                    "$bin"/img4 -i $fn -o "$dir"/$1/$cpid/ramdisk/$3/iBSS.dec -k $ivkey
                fi
            else
                kbag=$("$bin"/img4 -i $fn -b | head -n 1)
                iv=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ',' -f 1 | cut -d ' ' -f 2)
                key=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ' ' -f 4)
                ivkey="$iv$key"
                "$bin"/img4 -i $fn -o "$dir"/$1/$cpid/ramdisk/$3/iBSS.dec -k $ivkey
            fi
        fi
        if [ ! -e "$dir"/$1/$cpid/ramdisk/$3/iBEC.dec ]; then
            "$bin"/pzb -g $(awk "/""$replace""/{x=1}x&&/iBEC[.]/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1) "$ipswurl"
            fn="$(awk "/""$replace""/{x=1}x&&/iBEC[.]/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | sed 's/Firmware[/]dfu[/]//')"
            if [[ "$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -e $3 $1)" == "true" ]]; then
                if [[ "$3" == "10."* ]]; then
                    if [[ "$deviceid" == "iPhone8,1" || "$deviceid" == "iPhone8,2" ]]; then
                        ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn 11.1 $1)"
                    else
                        ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn 10.3.3 $1)"
                    fi
                else
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $3 $1)"
                fi
                if [ -z $ivkey ]; then
                    kbag=$("$bin"/img4 -i $fn -b | head -n 1)
                    iv=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ',' -f 1 | cut -d ' ' -f 2)
                    key=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ' ' -f 4)
                    ivkey="$iv$key"
                    "$bin"/img4 -i $fn -o "$dir"/$1/$cpid/ramdisk/$3/iBEC.dec -k $ivkey
                else
                    "$bin"/img4 -i $fn -o "$dir"/$1/$cpid/ramdisk/$3/iBEC.dec -k $ivkey
                fi
            else
                kbag=$("$bin"/img4 -i $fn -b | head -n 1)
                iv=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ',' -f 1 | cut -d ' ' -f 2)
                key=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ' ' -f 4)
                ivkey="$iv$key"
                "$bin"/img4 -i $fn -o "$dir"/$1/$cpid/ramdisk/$3/iBEC.dec -k $ivkey
            fi
        fi
        if [[ "$3" == "10."* ]]; then
            rm -rf BuildManifest.plist
            ipswurl=$(curl -k -sL "https://api.ipsw.me/v4/device/$deviceid?type=ipsw" | "$bin"/jq '.firmwares | .[] | select(.version=="'$3'")' | "$bin"/jq -s '.[0] | .url' --raw-output)
            "$bin"/pzb -g BuildManifest.plist "$ipswurl"
        fi
        if [ ! -e "$dir"/$1/$cpid/ramdisk/$3/kernelcache.dec ]; then
            "$bin"/pzb -g $(awk "/""$replace""/{x=1}x&&/kernelcache.release/{print;exit}" BuildManifest.plist | grep '<string>' | cut -d\> -f2 | cut -d\< -f1) "$ipswurl"
            if [[ "$3" == "7."* || "$3" == "8."* || "$3" == "9."* ]]; then
                fn="$(awk "/""$replace""/{x=1}x&&/kernelcache.release/{print;exit}" BuildManifest.plist | grep '<string>' | cut -d\> -f2 | cut -d\< -f1)"
                if [[ "$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -e $3 $1)" == "true" ]]; then
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $3 $1)"
                    if [ -z $ivkey ]; then
                        kbag=$("$bin"/img4 -i $fn -b | head -n 1)
                        iv=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ',' -f 1 | cut -d ' ' -f 2)
                        key=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ' ' -f 4)
                        ivkey="$iv$key"
                        "$bin"/img4 -i $fn -o "$dir"/$1/$cpid/ramdisk/$3/kcache.raw -k $ivkey
                        "$bin"/img4 -i $fn -o "$dir"/$1/$cpid/ramdisk/$3/kernelcache.dec -k $ivkey -D
                    else
                        "$bin"/img4 -i $fn -o "$dir"/$1/$cpid/ramdisk/$3/kcache.raw -k $ivkey
                        "$bin"/img4 -i $fn -o "$dir"/$1/$cpid/ramdisk/$3/kernelcache.dec -k $ivkey -D
                    fi
                else
                    kbag=$("$bin"/img4 -i $fn -b | head -n 1)
                    iv=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ',' -f 1 | cut -d ' ' -f 2)
                    key=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ' ' -f 4)
                    ivkey="$iv$key"
                    "$bin"/img4 -i $fn -o "$dir"/$1/$cpid/ramdisk/$3/kcache.raw -k $ivkey
                    "$bin"/img4 -i $fn -o "$dir"/$1/$cpid/ramdisk/$3/kernelcache.dec -k $ivkey -D
                fi
            else
                "$bin"/img4 -i $(awk "/""$replace""/{x=1}x&&/kernelcache.release/{print;exit}" BuildManifest.plist | grep '<string>' | cut -d\> -f2 | cut -d\< -f1) -o "$dir"/$1/$cpid/ramdisk/$3/kcache.raw
                "$bin"/img4 -i $(awk "/""$replace""/{x=1}x&&/kernelcache.release/{print;exit}" BuildManifest.plist | grep '<string>' | cut -d\> -f2 | cut -d\< -f1) -o "$dir"/$1/$cpid/ramdisk/$3/kernelcache.dec -D
            fi
        fi
        if [ ! -e "$dir"/$1/$cpid/ramdisk/$3/DeviceTree.dec ]; then
            "$bin"/pzb -g $(awk "/""$replace""/{x=1}x&&/DeviceTree[.]/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1) "$ipswurl"
            if [[ "$3" == "7."* || "$3" == "8."* || "$3" == "9."* ]]; then
                fn="$(awk "/""$replace""/{x=1}x&&/DeviceTree[.]/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | sed 's/Firmware[/]all_flash[/]all_flash.*production[/]//' | sed 's/Firmware[/]all_flash[/]//')"
                if [[ "$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -e $3 $1)" == "true" ]]; then
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $3 $1)"
                    if [ -z $ivkey ]; then
                        kbag=$("$bin"/img4 -i $fn -b | head -n 1)
                        iv=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ',' -f 1 | cut -d ' ' -f 2)
                        key=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ' ' -f 4)
                        ivkey="$iv$key"
                        "$bin"/img4 -i $fn -o "$dir"/$1/$cpid/ramdisk/$3/DeviceTree.dec -k $ivkey
                    else
                        "$bin"/img4 -i $fn -o "$dir"/$1/$cpid/ramdisk/$3/DeviceTree.dec -k $ivkey
                    fi
                else
                    kbag=$("$bin"/img4 -i $fn -b | head -n 1)
                    iv=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ',' -f 1 | cut -d ' ' -f 2)
                    key=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ' ' -f 4)
                    ivkey="$iv$key"
                    "$bin"/img4 -i $fn -o "$dir"/$1/$cpid/ramdisk/$3/DeviceTree.dec -k $ivkey
                fi
            else
                mv $(awk "/""$replace""/{x=1}x&&/DeviceTree[.]/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | sed 's/Firmware[/]all_flash[/]all_flash.*production[/]//' | sed 's/Firmware[/]all_flash[/]//') "$dir"/$1/$cpid/ramdisk/$3/DeviceTree.dec
            fi
        fi
        if [ "$os" = "Darwin" ]; then
            fn="$(/usr/bin/plutil -extract "BuildIdentities".0."Manifest"."RestoreRamDisk"."Info"."Path" xml1 -o - BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | head -1)"
        else
            fn="$("$bin"/PlistBuddy -c "Print BuildIdentities:0:Manifest:RestoreRamDisk:Info:Path" BuildManifest.plist | tr -d '"')"
        fi
        if [ ! -e "$dir"/$1/$cpid/ramdisk/$3/RestoreRamDisk.dmg ]; then
            "$bin"/pzb -g "$fn" "$ipswurl"
            if [[ "$3" == "7."* || "$3" == "8."* || "$3" == "9."* ]]; then
                if [[ "$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -e $3 $1)" == "true" ]]; then
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $3 $1)"
                    if [ -z $ivkey ]; then
                        kbag=$("$bin"/img4 -i $fn -b | head -n 1)
                        iv=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ',' -f 1 | cut -d ' ' -f 2)
                        key=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ' ' -f 4)
                        ivkey="$iv$key"
                        "$bin"/img4 -i $fn -o "$dir"/$1/$cpid/ramdisk/$3/RestoreRamDisk.dmg -k $ivkey
                    else
                        "$bin"/img4 -i $fn -o "$dir"/$1/$cpid/ramdisk/$3/RestoreRamDisk.dmg -k $ivkey
                    fi
                else
                    kbag=$("$bin"/img4 -i $fn -b | head -n 1)
                    iv=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ',' -f 1 | cut -d ' ' -f 2)
                    key=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ' ' -f 4)
                    ivkey="$iv$key"
                    "$bin"/img4 -i $fn -o "$dir"/$1/$cpid/ramdisk/$3/RestoreRamDisk.dmg -k $ivkey
                fi
            else
                "$bin"/img4 -i "$fn" -o "$dir"/$1/$cpid/ramdisk/$3/RestoreRamDisk.dmg
            fi
        fi
        if [[ ! "$3" == "7."* && ! "$3" == "8."* && ! "$3" == "9."* && ! "$3" == "10."* && ! "$3" == "11."* ]]; then
            if [ ! -e "$dir"/$1/$cpid/ramdisk/$3/trustcache.img4 ]; then
                "$bin"/pzb -g Firmware/"$fn".trustcache "$ipswurl"
                 mv "$fn".trustcache "$dir"/$1/$cpid/ramdisk/$3/trustcache.im4p
            fi
        fi
        rm -rf BuildManifest.plist
        if [ "$os" = "Darwin" ]; then
            if [[ "$3" == "7."* || "$3" == "8."* || "$3" == "9."* ]]; then
                if [[ "$3" == "9."* ]]; then
                    hdiutil resize -size 80M "$dir"/$1/$cpid/ramdisk/$3/RestoreRamDisk.dmg
                else
                    hdiutil resize -size 60M "$dir"/$1/$cpid/ramdisk/$3/RestoreRamDisk.dmg
                fi
                hdiutil attach -mountpoint /tmp/ramdisk "$dir"/$1/$cpid/ramdisk/$3/RestoreRamDisk.dmg
                sudo diskutil enableOwnership /tmp/ramdisk
                gzip -d "$sshtars"/ssh.tar.gz
                sudo "$bin"/gnutar -xvf "$sshtars"/ssh.tar -C /tmp/ramdisk
                #gzip -d "$sshtars"/ploosh.tar.gz
                #sudo "$bin"/gnutar -xvf "$sshtars"/ploosh.tar -C /tmp/ramdisk
                if [[ "$3" == "7."* || "$3" == "8."* || "$3" == "9."* || "$3" == "10."* || "$3" == "11."* ]]; then
                    # fix scp
                    sudo "$bin"/gnutar -xvf "$bin"/libcharset.1.dylib_libiconv.2.dylib.tar -C /tmp/ramdisk/usr/lib
                fi
                if [[ "$3" == "7."* || "$3" == "8."* || "$3" == "9."* || "$3" == "10."* || "$3" == "11."* || "$3" == "12."* || "$3" == "13.0"* || "$3" == "13.1"* || "$3" == "13.2"* || "$3" == "13.3"* ]]; then
                    # fix scp
                    sudo "$bin"/gnutar -xvf "$bin"/libresolv.9.dylib.tar -C /tmp/ramdisk/usr/lib
                fi
                # gptfdisk automation shenanigans
                sudo "$bin"/gnutar -xvf "$dir"/jb/gpt.txt.tar -C /tmp/ramdisk
                # fixup update partition script, i.e. changes all Update partitions to UpdateX partitions
                sudo "$bin"/gnutar -xvf "$dir"/jb/fixup_update_partition.tar -C /tmp/ramdisk
                hdiutil detach /tmp/ramdisk
                "$bin"/img4tool -c "$dir"/$1/$cpid/ramdisk/$3/ramdisk.im4p -t rdsk "$dir"/$1/$cpid/ramdisk/$3/RestoreRamDisk.dmg
                "$bin"/img4tool -c "$dir"/$1/$cpid/ramdisk/$3/ramdisk.img4 -p "$dir"/$1/$cpid/ramdisk/$3/ramdisk.im4p -m IM4M
                if [[ ! "$deviceid" == "iPhone6"* && ! "$deviceid" == "iPhone7"* && ! "$deviceid" == "iPad4"* && ! "$deviceid" == "iPad5"* && ! "$deviceid" == "iPod7"* && "$3" == "9."* ]]; then
                    "$bin"/kairos "$dir"/$1/$cpid/ramdisk/$3/iBSS.dec "$dir"/$1/$cpid/ramdisk/$3/iBSS.patched
                    "$bin"/kairos "$dir"/$1/$cpid/ramdisk/$3/iBEC.dec "$dir"/$1/$cpid/ramdisk/$3/iBEC2.patched -b "rd=md0 debug=0x2014e amfi=0xff cs_enforcement_disable=1 $boot_args wdt=-1 `if [ "$check" = '0x8960' ] || [ "$check" = '0x7000' ] || [ "$check" = '0x7001' ]; then echo "-restore"; fi`"
                    if [[ ! "$?" == "0" ]]; then
                        "$bin"/iBoot64Patcher "$dir"/$1/$cpid/ramdisk/$3/iBEC.dec "$dir"/$1/$cpid/ramdisk/$3/iBEC2.patched -b "rd=md0 debug=0x2014e amfi=0xff cs_enforcement_disable=1 $boot_args wdt=-1 `if [ "$check" = '0x8960' ] || [ "$check" = '0x7000' ] || [ "$check" = '0x7001' ]; then echo "-restore"; fi`"
                    fi
                    "$bin"/iBoot64Patcher2 "$dir"/$1/$cpid/ramdisk/$3/iBEC2.patched "$dir"/$1/$cpid/ramdisk/$3/iBEC.patched -n
                    if [[ ! "$?" == "0" ]]; then
                        cp "$dir"/$1/$cpid/ramdisk/$3/iBEC2.patched "$dir"/$1/$cpid/ramdisk/$3/iBEC.patched
                    fi
                elif [[ "$3" == "9."* ]]; then
                    "$bin"/kairos "$dir"/$1/$cpid/ramdisk/$3/iBSS.dec "$dir"/$1/$cpid/ramdisk/$3/iBSS.patched
                    "$bin"/kairos "$dir"/$1/$cpid/ramdisk/$3/iBEC.dec "$dir"/$1/$cpid/ramdisk/$3/iBEC2.patched -b "amfi=0xff cs_enforcement_disable=1 $boot_args rd=md0 nand-enable-reformat=1 -progress"
                    if [[ ! "$?" == "0" ]]; then
                        "$bin"/iBoot64Patcher "$dir"/$1/$cpid/ramdisk/$3/iBEC.dec "$dir"/$1/$cpid/ramdisk/$3/iBEC2.patched -b "amfi=0xff cs_enforcement_disable=1 $boot_args rd=md0 nand-enable-reformat=1 -progress"
                    fi
                    "$bin"/iBoot64Patcher2 "$dir"/$1/$cpid/ramdisk/$3/iBEC2.patched "$dir"/$1/$cpid/ramdisk/$3/iBEC.patched -n
                    if [[ ! "$?" == "0" ]]; then
                        cp "$dir"/$1/$cpid/ramdisk/$3/iBEC2.patched "$dir"/$1/$cpid/ramdisk/$3/iBEC.patched
                    fi
                else
                    "$bin"/ipatcher "$dir"/$1/$cpid/ramdisk/$3/iBSS.dec "$dir"/$1/$cpid/ramdisk/$3/iBSS.patched
                    "$bin"/ipatcher "$dir"/$1/$cpid/ramdisk/$3/iBEC.dec "$dir"/$1/$cpid/ramdisk/$3/iBEC.patched -b "amfi=0xff cs_enforcement_disable=1 $boot_args rd=md0 nand-enable-reformat=1 -progress" -n
                fi
                "$bin"/img4 -i "$dir"/$1/$cpid/ramdisk/$3/iBSS.patched -o "$dir"/$1/$cpid/ramdisk/$3/iBSS.img4 -M IM4M -A -T ibss
                "$bin"/img4 -i "$dir"/$1/$cpid/ramdisk/$3/iBEC.patched -o "$dir"/$1/$cpid/ramdisk/$3/iBEC.img4 -M IM4M -A -T ibec
                "$bin"/img4 -i "$dir"/$1/$cpid/ramdisk/$3/kernelcache.dec -o "$dir"/$1/$cpid/ramdisk/$3/kernelcache.img4 -M IM4M -T rkrn
                "$bin"/img4 -i "$dir"/$1/$cpid/ramdisk/$3/devicetree.dec -o "$dir"/$1/$cpid/ramdisk/$3/devicetree.img4 -A -M IM4M -T rdtr
            else
                if [[ "$3" == *"16"* || "$3" == *"17"* ]]; then
                    hdiutil attach -mountpoint /tmp/ramdisk "$dir"/$1/$cpid/ramdisk/$3/RestoreRamDisk.dmg
                    hdiutil create -size 210m -imagekey diskimage-class=CRawDiskImage -format UDZO -fs HFS+ -layout NONE -srcfolder /tmp/ramdisk -copyuid root "$dir"/$1/$cpid/ramdisk/$3/RestoreRamDisk1.dmg
                    hdiutil detach -force /tmp/ramdisk
                    hdiutil attach -mountpoint /tmp/ramdisk "$dir"/$1/$cpid/ramdisk/$3/RestoreRamDisk1.dmg
                else
                    hdiutil resize -size 120M "$dir"/$1/$cpid/ramdisk/$3/RestoreRamDisk.dmg
                    hdiutil attach -mountpoint /tmp/ramdisk "$dir"/$1/$cpid/ramdisk/$3/RestoreRamDisk.dmg
                fi
                sudo diskutil enableOwnership /tmp/ramdisk
                gzip -d "$sshtars"/ssh.tar.gz
                sudo "$bin"/gnutar -xvf "$sshtars"/ssh.tar -C /tmp/ramdisk
                #gzip -d "$sshtars"/ploosh.tar.gz
                #sudo "$bin"/gnutar -xvf "$sshtars"/ploosh.tar -C /tmp/ramdisk
                if [[ "$3" == "10."* ]]; then
                    gzip -d "$sshtars"/apfs.fs.tar.gz
                    sudo "$bin"/gnutar -xvf "$sshtars"/apfs.fs.tar -C /tmp/ramdisk
                fi
                if [[ "$3" == "7."* || "$3" == "8."* || "$3" == "9."* || "$3" == "10."* || "$3" == "11."* ]]; then
                    # fix scp
                    sudo "$bin"/gnutar -xvf "$bin"/libcharset.1.dylib_libiconv.2.dylib.tar -C /tmp/ramdisk/usr/lib
                fi
                if [[ "$3" == "7."* || "$3" == "8."* || "$3" == "9."* || "$3" == "10."* || "$3" == "11."* || "$3" == "12."* || "$3" == "13.0"* || "$3" == "13.1"* || "$3" == "13.2"* || "$3" == "13.3"* ]]; then
                    # fix scp
                    sudo "$bin"/gnutar -xvf "$bin"/libresolv.9.dylib.tar -C /tmp/ramdisk/usr/lib
                fi
                # gptfdisk automation shenanigans
                sudo "$bin"/gnutar -xvf "$dir"/jb/gpt.txt.tar -C /tmp/ramdisk
                # fixup update partition script, i.e. changes all Update partitions to UpdateX partitions
                sudo "$bin"/gnutar -xvf "$dir"/jb/fixup_update_partition.tar -C /tmp/ramdisk
                hdiutil detach -force /tmp/ramdisk
                if [[ "$3" == *"16"* || "$3" == *"17"* ]]; then
                    hdiutil resize -sectors min "$dir"/$1/$cpid/ramdisk/$3/RestoreRamDisk1.dmg
                    "$bin"/img4 -i "$dir"/$1/$cpid/ramdisk/$3/RestoreRamDisk1.dmg -o "$dir"/$1/$cpid/ramdisk/$3/ramdisk.img4 -M IM4M -A -T rdsk
                else
                    hdiutil resize -sectors min "$dir"/$1/$cpid/ramdisk/$3/RestoreRamDisk.dmg
                    "$bin"/img4 -i "$dir"/$1/$cpid/ramdisk/$3/RestoreRamDisk.dmg -o "$dir"/$1/$cpid/ramdisk/$3/ramdisk.img4 -M IM4M -A -T rdsk
                fi
                "$bin"/iBoot64Patcher "$dir"/$1/$cpid/ramdisk/$3/iBSS.dec "$dir"/$1/$cpid/ramdisk/$3/iBSS.patched
                if [[ ! "$deviceid" == "iPhone6"* && ! "$deviceid" == "iPhone7"* && ! "$deviceid" == "iPad4"* && ! "$deviceid" == "iPad5"* && ! "$deviceid" == "iPod7"* ]]; then
                    "$bin"/iBoot64Patcher "$dir"/$1/$cpid/ramdisk/$3/iBEC.dec "$dir"/$1/$cpid/ramdisk/$3/iBEC.patched -b "rd=md0 debug=0x2014e $boot_args wdt=-1 `if [ "$check" = '0x8960' ] || [ "$check" = '0x7000' ] || [ "$check" = '0x7001' ]; then echo "-restore"; fi`" -n
                else
                    "$bin"/iBoot64Patcher "$dir"/$1/$cpid/ramdisk/$3/iBEC.dec "$dir"/$1/$cpid/ramdisk/$3/iBEC.patched -b "amfi=0xff cs_enforcement_disable=1 $boot_args rd=md0 nand-enable-reformat=1 amfi_get_out_of_my_way=1 -restore -progress" -n
                fi
                "$bin"/img4 -i "$dir"/$1/$cpid/ramdisk/$3/iBSS.patched -o "$dir"/$1/$cpid/ramdisk/$3/iBSS.img4 -M IM4M -A -T ibss
                "$bin"/img4 -i "$dir"/$1/$cpid/ramdisk/$3/iBEC.patched -o "$dir"/$1/$cpid/ramdisk/$3/iBEC.img4 -M IM4M -A -T ibec
                if [[ "$3" == "10.3"* ]]; then
                    "$bin"/KPlooshFinder "$dir"/$1/$cpid/ramdisk/$3/kcache.raw "$dir"/$1/$cpid/ramdisk/$3/kcache2.patched
                else
                    "$bin"/Kernel64Patcher2 "$dir"/$1/$cpid/ramdisk/$3/kcache.raw "$dir"/$1/$cpid/ramdisk/$3/kcache2.patched -a
                fi
                if [[ "$3" == "10."* ]]; then
                    "$bin"/Kernel64Patcher "$dir"/$1/$cpid/ramdisk/$3/kcache2.patched "$dir"/$1/$cpid/ramdisk/$3/kcache3.patched -mo
                    #cp "$dir"/$1/$cpid/ramdisk/$3/kcache2.patched "$dir"/$1/$cpid/ramdisk/$3/kcache3.patched
                else
                    cp "$dir"/$1/$cpid/ramdisk/$3/kcache2.patched "$dir"/$1/$cpid/ramdisk/$3/kcache3.patched
                fi
                "$bin"/kerneldiff "$dir"/$1/$cpid/ramdisk/$3/kcache.raw "$dir"/$1/$cpid/ramdisk/$3/kcache3.patched "$dir"/$1/$cpid/ramdisk/$3/kc.bpatch
                if [[ "$?" == "0" ]]; then
                    "$bin"/img4 -i "$dir"/$1/$cpid/ramdisk/$3/kernelcache.dec -o "$dir"/$1/$cpid/ramdisk/$3/kernelcache.img4 -M IM4M -T rkrn -P "$dir"/$1/$cpid/ramdisk/$3/kc.bpatch
                    "$bin"/img4 -i "$dir"/$1/$cpid/ramdisk/$3/kernelcache.dec -o "$dir"/$1/$cpid/ramdisk/$3/kernelcache -M IM4M -T krnl -P "$dir"/$1/$cpid/ramdisk/$3/kc.bpatch
                else
                    if [[ "$deviceid" == *'iPhone8'* ]] || [[ "$deviceid" == *'iPad6'* ]] || [[ "$deviceid" == *'iPad5'* ]]; then
                        python3 -m pyimg4 im4p create -i "$dir"/$1/$cpid/ramdisk/$3/kcache2.patched -o "$dir"/$1/$cpid/ramdisk/$3/kernelcache.im4p.img4 --extra "$dir"/$1/$cpid/ramdisk/$3/kpp.bin -f rkrn --lzss
                        python3 -m pyimg4 im4p create -i "$dir"/$1/$cpid/ramdisk/$3/kcache2.patched -o "$dir"/$1/$cpid/ramdisk/$3/kernelcache.im4p --extra "$dir"/$1/$cpid/ramdisk/$3/kpp.bin -f krnl --lzss
                    else
                        python3 -m pyimg4 im4p create -i "$dir"/$1/$cpid/ramdisk/$3/kcache2.patched -o "$dir"/$1/$cpid/ramdisk/$3/kernelcache.im4p.img4 -f rkrn --lzss
                        python3 -m pyimg4 im4p create -i "$dir"/$1/$cpid/ramdisk/$3/kcache2.patched -o "$dir"/$1/$cpid/ramdisk/$3/kernelcache.im4p -f krnl --lzss
                    fi
                    python3 -m pyimg4 img4 create -p "$dir"/$1/$cpid/ramdisk/$3/kernelcache.im4p.img4 -o "$dir"/$1/$cpid/ramdisk/$3/kernelcache.img4 -m IM4M
                    python3 -m pyimg4 img4 create -p "$dir"/$1/$cpid/ramdisk/$3/kernelcache.im4p -o "$dir"/$1/$cpid/ramdisk/$3/kernelcache -m IM4M
                fi
                if [[ ! "$3" == "7."* && ! "$3" == "8."* && ! "$3" == "9."* && ! "$3" == "10."* && ! "$3" == "11."* ]]; then
                    "$bin"/img4 -i "$dir"/$1/$cpid/ramdisk/$3/trustcache.im4p -o "$dir"/$1/$cpid/ramdisk/$3/trustcache.img4 -M IM4M -T rtsc
                fi
                "$bin"/img4 -i "$dir"/$1/$cpid/ramdisk/$3/devicetree.dec -o "$dir"/$1/$cpid/ramdisk/$3/devicetree.img4 -M IM4M -T rdtr
            fi
        else
            if [[ "$3" == "7."* || "$3" == "8."* || "$3" == "9."* ]]; then
                if [[ "$3" == "9."* ]]; then
                    "$bin"/hfsplus "$dir"/$1/$cpid/ramdisk/$3/RestoreRamDisk.dmg grow 80000000
                else
                    "$bin"/hfsplus "$dir"/$1/$cpid/ramdisk/$3/RestoreRamDisk.dmg grow 60000000
                fi
                gzip -d "$sshtars"/ssh.tar.gz
                "$bin"/hfsplus "$dir"/$1/$cpid/ramdisk/$3/RestoreRamDisk.dmg untar "$sshtars"/ssh.tar
                #gzip -d "$sshtars"/ploosh.tar.gz
                #"$bin"/hfsplus "$dir"/$1/$cpid/ramdisk/$3/RestoreRamDisk.dmg untar "$sshtars"/ploosh.tar
                if [[ "$3" == "7."* || "$3" == "8."* || "$3" == "9."* || "$3" == "10."* || "$3" == "11."* ]]; then
                    # fix scp
                    "$bin"/hfsplus "$dir"/$1/$cpid/ramdisk/$3/RestoreRamDisk.dmg untar "$bin"/libcharset.1.dylib_libiconv.2.dylib.tar
                fi
                if [[ "$3" == "7."* || "$3" == "8."* || "$3" == "9."* || "$3" == "10."* || "$3" == "11."* || "$3" == "12."* || "$3" == "13.0"* || "$3" == "13.1"* || "$3" == "13.2"* || "$3" == "13.3"* ]]; then
                    # fix scp
                    "$bin"/hfsplus "$dir"/$1/$cpid/ramdisk/$3/RestoreRamDisk.dmg untar "$bin"/libresolv.9.dylib.tar
                fi
                # gptfdisk automation shenanigans
                "$bin"/hfsplus "$dir"/$1/$cpid/ramdisk/$3/RestoreRamDisk.dmg untar "$dir"/jb/gpt.txt.tar
                # fixup update partition script, i.e. changes all Update partitions to UpdateX partitions
                "$bin"/hfsplus "$dir"/$1/$cpid/ramdisk/$3/RestoreRamDisk.dmg untar "$dir"/jb/fixup_update_partition.tar
                "$bin"/img4tool -c "$dir"/$1/$cpid/ramdisk/$3/ramdisk.im4p -t rdsk "$dir"/$1/$cpid/ramdisk/$3/RestoreRamDisk.dmg
                "$bin"/img4tool -c "$dir"/$1/$cpid/ramdisk/$3/ramdisk.img4 -p "$dir"/$1/$cpid/ramdisk/$3/ramdisk.im4p -m IM4M
                if [[ ! "$deviceid" == "iPhone6"* && ! "$deviceid" == "iPhone7"* && ! "$deviceid" == "iPad4"* && ! "$deviceid" == "iPad5"* && ! "$deviceid" == "iPod7"* && "$3" == "9."* ]]; then
                    "$bin"/kairos "$dir"/$1/$cpid/ramdisk/$3/iBSS.dec "$dir"/$1/$cpid/ramdisk/$3/iBSS.patched
                    "$bin"/kairos "$dir"/$1/$cpid/ramdisk/$3/iBEC.dec "$dir"/$1/$cpid/ramdisk/$3/iBEC2.patched -b "rd=md0 debug=0x2014e amfi=0xff cs_enforcement_disable=1 $boot_args wdt=-1 `if [ "$check" = '0x8960' ] || [ "$check" = '0x7000' ] || [ "$check" = '0x7001' ]; then echo "-restore"; fi`"
                    if [[ ! "$?" == "0" ]]; then
                        "$bin"/iBoot64Patcher "$dir"/$1/$cpid/ramdisk/$3/iBEC.dec "$dir"/$1/$cpid/ramdisk/$3/iBEC2.patched -b "rd=md0 debug=0x2014e amfi=0xff cs_enforcement_disable=1 $boot_args wdt=-1 `if [ "$check" = '0x8960' ] || [ "$check" = '0x7000' ] || [ "$check" = '0x7001' ]; then echo "-restore"; fi`"
                    fi
                    "$bin"/iBoot64Patcher2 "$dir"/$1/$cpid/ramdisk/$3/iBEC2.patched "$dir"/$1/$cpid/ramdisk/$3/iBEC.patched -n
                    if [[ ! "$?" == "0" ]]; then
                        cp "$dir"/$1/$cpid/ramdisk/$3/iBEC2.patched "$dir"/$1/$cpid/ramdisk/$3/iBEC.patched
                    fi
                elif [[ "$3" == "9."* ]]; then
                    "$bin"/kairos "$dir"/$1/$cpid/ramdisk/$3/iBSS.dec "$dir"/$1/$cpid/ramdisk/$3/iBSS.patched
                    "$bin"/kairos "$dir"/$1/$cpid/ramdisk/$3/iBEC.dec "$dir"/$1/$cpid/ramdisk/$3/iBEC2.patched -b "amfi=0xff cs_enforcement_disable=1 $boot_args rd=md0 nand-enable-reformat=1 -progress"
                    if [[ ! "$?" == "0" ]]; then
                        "$bin"/iBoot64Patcher "$dir"/$1/$cpid/ramdisk/$3/iBEC.dec "$dir"/$1/$cpid/ramdisk/$3/iBEC2.patched -b "amfi=0xff cs_enforcement_disable=1 $boot_args rd=md0 nand-enable-reformat=1 -progress"
                    fi
                    "$bin"/iBoot64Patcher2 "$dir"/$1/$cpid/ramdisk/$3/iBEC2.patched "$dir"/$1/$cpid/ramdisk/$3/iBEC.patched -n
                    if [[ ! "$?" == "0" ]]; then
                        cp "$dir"/$1/$cpid/ramdisk/$3/iBEC2.patched "$dir"/$1/$cpid/ramdisk/$3/iBEC.patched
                    fi
                else
                    "$bin"/ipatcher "$dir"/$1/$cpid/ramdisk/$3/iBSS.dec "$dir"/$1/$cpid/ramdisk/$3/iBSS.patched
                    "$bin"/ipatcher "$dir"/$1/$cpid/ramdisk/$3/iBEC.dec "$dir"/$1/$cpid/ramdisk/$3/iBEC.patched -b "amfi=0xff cs_enforcement_disable=1 $boot_args rd=md0 nand-enable-reformat=1 -progress" -n
                fi
                "$bin"/img4 -i "$dir"/$1/$cpid/ramdisk/$3/iBSS.patched -o "$dir"/$1/$cpid/ramdisk/$3/iBSS.img4 -M IM4M -A -T ibss
                "$bin"/img4 -i "$dir"/$1/$cpid/ramdisk/$3/iBEC.patched -o "$dir"/$1/$cpid/ramdisk/$3/iBEC.img4 -M IM4M -A -T ibec
                "$bin"/img4 -i "$dir"/$1/$cpid/ramdisk/$3/kernelcache.dec -o "$dir"/$1/$cpid/ramdisk/$3/kernelcache.img4 -M IM4M -T rkrn
                "$bin"/img4 -i "$dir"/$1/$cpid/ramdisk/$3/DeviceTree.dec -o "$dir"/$1/$cpid/ramdisk/$3/devicetree.img4 -A -M IM4M -T rdtr
            else
                if [[ "$3" == *"16"* || "$3" == *"17"* ]]; then
                    "$bin"/hfsplus "$dir"/$1/$cpid/ramdisk/$3/RestoreRamDisk.dmg grow 210000000
                else
                    "$bin"/hfsplus "$dir"/$1/$cpid/ramdisk/$3/RestoreRamDisk.dmg grow 120000000
                fi
                gzip -d "$sshtars"/ssh.tar.gz
                "$bin"/hfsplus "$dir"/$1/$cpid/ramdisk/$3/RestoreRamDisk.dmg untar "$sshtars"/ssh.tar
                #gzip -d "$sshtars"/ploosh.tar.gz
                #"$bin"/hfsplus "$dir"/$1/$cpid/ramdisk/$3/RestoreRamDisk.dmg untar "$sshtars"/ploosh.tar
                if [[ "$3" == "10."* ]]; then
                    gzip -d "$sshtars"/apfs.fs.tar.gz
                    "$bin"/hfsplus "$dir"/$1/$cpid/ramdisk/$3/RestoreRamDisk.dmg untar "$sshtars"/apfs.fs.tar
                fi
                if [[ "$3" == "7."* || "$3" == "8."* || "$3" == "9."* || "$3" == "10."* || "$3" == "11."* ]]; then
                    # fix scp
                    "$bin"/hfsplus "$dir"/$1/$cpid/ramdisk/$3/RestoreRamDisk.dmg untar "$bin"/libcharset.1.dylib_libiconv.2.dylib.tar
                fi
                if [[ "$3" == "7."* || "$3" == "8."* || "$3" == "9."* || "$3" == "10."* || "$3" == "11."* || "$3" == "12."* || "$3" == "13.0"* || "$3" == "13.1"* || "$3" == "13.2"* || "$3" == "13.3"* ]]; then
                    # fix scp
                    "$bin"/hfsplus "$dir"/$1/$cpid/ramdisk/$3/RestoreRamDisk.dmg untar "$bin"/libresolv.9.dylib.tar
                fi
                # gptfdisk automation shenanigans
                "$bin"/hfsplus "$dir"/$1/$cpid/ramdisk/$3/RestoreRamDisk.dmg untar "$dir"/jb/gpt.txt.tar
                # fixup update partition script, i.e. changes all Update partitions to UpdateX partitions
                "$bin"/hfsplus "$dir"/$1/$cpid/ramdisk/$3/RestoreRamDisk.dmg untar "$dir"/jb/fixup_update_partition.tar
                "$bin"/img4 -i "$dir"/$1/$cpid/ramdisk/$3/RestoreRamDisk.dmg -o "$dir"/$1/$cpid/ramdisk/$3/ramdisk.img4 -M IM4M -A -T rdsk
                "$bin"/iBoot64Patcher "$dir"/$1/$cpid/ramdisk/$3/iBSS.dec "$dir"/$1/$cpid/ramdisk/$3/iBSS.patched
                if [[ ! "$deviceid" == "iPhone6"* && ! "$deviceid" == "iPhone7"* && ! "$deviceid" == "iPad4"* && ! "$deviceid" == "iPad5"* && ! "$deviceid" == "iPod7"* ]]; then
                    "$bin"/iBoot64Patcher "$dir"/$1/$cpid/ramdisk/$3/iBEC.dec "$dir"/$1/$cpid/ramdisk/$3/iBEC.patched -b "rd=md0 debug=0x2014e $boot_args wdt=-1 `if [ "$check" = '0x8960' ] || [ "$check" = '0x7000' ] || [ "$check" = '0x7001' ]; then echo "-restore"; fi`" -n
                else
                    "$bin"/iBoot64Patcher "$dir"/$1/$cpid/ramdisk/$3/iBEC.dec "$dir"/$1/$cpid/ramdisk/$3/iBEC.patched -b "amfi=0xff cs_enforcement_disable=1 $boot_args rd=md0 nand-enable-reformat=1 amfi_get_out_of_my_way=1 -restore -progress" -n
                fi
                "$bin"/img4 -i "$dir"/$1/$cpid/ramdisk/$3/iBSS.patched -o "$dir"/$1/$cpid/ramdisk/$3/iBSS.img4 -M IM4M -A -T ibss
                "$bin"/img4 -i "$dir"/$1/$cpid/ramdisk/$3/iBEC.patched -o "$dir"/$1/$cpid/ramdisk/$3/iBEC.img4 -M IM4M -A -T ibec
                if [[ "$3" == "10.3"* ]]; then
                    "$bin"/KPlooshFinder "$dir"/$1/$cpid/ramdisk/$3/kcache.raw "$dir"/$1/$cpid/ramdisk/$3/kcache2.patched
                else
                    "$bin"/Kernel64Patcher2 "$dir"/$1/$cpid/ramdisk/$3/kcache.raw "$dir"/$1/$cpid/ramdisk/$3/kcache2.patched -a
                fi
                if [[ "$3" == "10."* ]]; then
                    "$bin"/Kernel64Patcher "$dir"/$1/$cpid/ramdisk/$3/kcache2.patched "$dir"/$1/$cpid/ramdisk/$3/kcache3.patched -mo
                    #cp "$dir"/$1/$cpid/ramdisk/$3/kcache2.patched "$dir"/$1/$cpid/ramdisk/$3/kcache3.patched
                else
                    cp "$dir"/$1/$cpid/ramdisk/$3/kcache2.patched "$dir"/$1/$cpid/ramdisk/$3/kcache3.patched
                fi
                "$bin"/kerneldiff "$dir"/$1/$cpid/ramdisk/$3/kcache.raw "$dir"/$1/$cpid/ramdisk/$3/kcache3.patched "$dir"/$1/$cpid/ramdisk/$3/kc.bpatch
                if [[ "$?" == "0" ]]; then
                    "$bin"/img4 -i "$dir"/$1/$cpid/ramdisk/$3/kernelcache.dec -o "$dir"/$1/$cpid/ramdisk/$3/kernelcache.img4 -M IM4M -T rkrn -P "$dir"/$1/$cpid/ramdisk/$3/kc.bpatch
                    "$bin"/img4 -i "$dir"/$1/$cpid/ramdisk/$3/kernelcache.dec -o "$dir"/$1/$cpid/ramdisk/$3/kernelcache -M IM4M -T krnl -P "$dir"/$1/$cpid/ramdisk/$3/kc.bpatch
                else
                    if [[ "$deviceid" == *'iPhone8'* ]] || [[ "$deviceid" == *'iPad6'* ]] || [[ "$deviceid" == *'iPad5'* ]]; then
                        python3 -m pyimg4 im4p create -i "$dir"/$1/$cpid/ramdisk/$3/kcache2.patched -o "$dir"/$1/$cpid/ramdisk/$3/kernelcache.im4p.img4 --extra "$dir"/$1/$cpid/ramdisk/$3/kpp.bin -f rkrn --lzss
                        python3 -m pyimg4 im4p create -i "$dir"/$1/$cpid/ramdisk/$3/kcache2.patched -o "$dir"/$1/$cpid/ramdisk/$3/kernelcache.im4p --extra "$dir"/$1/$cpid/ramdisk/$3/kpp.bin -f krnl --lzss
                    else
                        python3 -m pyimg4 im4p create -i "$dir"/$1/$cpid/ramdisk/$3/kcache2.patched -o "$dir"/$1/$cpid/ramdisk/$3/kernelcache.im4p.img4 -f rkrn --lzss
                        python3 -m pyimg4 im4p create -i "$dir"/$1/$cpid/ramdisk/$3/kcache2.patched -o "$dir"/$1/$cpid/ramdisk/$3/kernelcache.im4p -f krnl --lzss
                    fi
                    python3 -m pyimg4 img4 create -p "$dir"/$1/$cpid/ramdisk/$3/kernelcache.im4p.img4 -o "$dir"/$1/$cpid/ramdisk/$3/kernelcache.img4 -m IM4M
                    python3 -m pyimg4 img4 create -p "$dir"/$1/$cpid/ramdisk/$3/kernelcache.im4p -o "$dir"/$1/$cpid/ramdisk/$3/kernelcache -m IM4M
                fi
                if [[ ! "$3" == "7."* && ! "$3" == "8."* && ! "$3" == "9."* && ! "$3" == "10."* && ! "$3" == "11."* ]]; then
                    "$bin"/img4 -i "$dir"/$1/$cpid/ramdisk/$3/trustcache.im4p -o "$dir"/$1/$cpid/ramdisk/$3/trustcache.img4 -M IM4M -T rtsc
                fi
                "$bin"/img4 -i "$dir"/$1/$cpid/ramdisk/$3/DeviceTree.dec -o "$dir"/$1/$cpid/ramdisk/$3/devicetree.img4 -M IM4M -T rdtr
            fi
        fi
    fi
    cd ..
    rm -rf work
}
_download_boot_files() {
    ipswurl=$(curl -k -sL "https://api.ipsw.me/v4/device/$deviceid?type=ipsw" | "$bin"/jq '.firmwares | .[] | select(.version=="'$3'")' | "$bin"/jq -s '.[0] | .url' --raw-output)
    rm -rf BuildManifest.plist
    mkdir -p "$dir"/$1/$cpid/$3
    rm -rf "$dir"/work
    mkdir "$dir"/work
    cd "$dir"/work
    rm -rf IM4M
    "$bin"/img4tool -e -s "$dir"/$1/0.0/shsh.shsh2 -m IM4M
    if [ ! -e "$dir"/$1/$cpid/$3/kernelcache ]; then
        if [[ "$3" == "10."* ]]; then
            if [[ "$deviceid" == "iPhone8,1" || "$deviceid" == "iPhone8,2" ]]; then
                ipswurl=$(curl -k -sL "https://api.ipsw.me/v4/device/$deviceid?type=ipsw" | "$bin"/jq '.firmwares | .[] | select(.version=="'11.1'")' | "$bin"/jq -s '.[0] | .url' --raw-output)
            else
                ipswurl=$(curl -k -sL "https://api.ipsw.me/v4/device/$deviceid?type=ipsw" | "$bin"/jq '.firmwares | .[] | select(.version=="'10.3.3'")' | "$bin"/jq -s '.[0] | .url' --raw-output)
            fi
        fi
        "$bin"/pzb -g BuildManifest.plist "$ipswurl"
        if [ ! -e "$dir"/$1/$cpid/$3/iBSS.dec ]; then
            "$bin"/pzb -g $(awk "/""$replace""/{x=1}x&&/iBSS[.]/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1) "$ipswurl"
            fn="$(awk "/""$replace""/{x=1}x&&/iBSS[.]/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | sed 's/Firmware[/]dfu[/]//')"
            if [[ "$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -e $3 $1)" == "true" ]]; then
                if [[ "$3" == "10."* ]]; then
                    if [[ "$deviceid" == "iPhone8,1" || "$deviceid" == "iPhone8,2" ]]; then
                        ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn 11.1 $1)"
                    else
                        ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn 10.3.3 $1)"
                    fi
                else
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $3 $1)"
                fi
                if [ -z $ivkey ]; then
                    kbag=$("$bin"/img4 -i $fn -b | head -n 1)
                    iv=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ',' -f 1 | cut -d ' ' -f 2)
                    key=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ' ' -f 4)
                    ivkey="$iv$key"
                    "$bin"/img4 -i $fn -o "$dir"/$1/$cpid/$3/iBSS.dec -k $ivkey
                else
                    "$bin"/img4 -i $fn -o "$dir"/$1/$cpid/$3/iBSS.dec -k $ivkey
                fi
            else
                kbag=$("$bin"/img4 -i $fn -b | head -n 1)
                iv=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ',' -f 1 | cut -d ' ' -f 2)
                key=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ' ' -f 4)
                ivkey="$iv$key"
                "$bin"/img4 -i $fn -o "$dir"/$1/$cpid/$3/iBSS.dec -k $ivkey
            fi
        fi
        if [ ! -e "$dir"/$1/$cpid/$3/iBEC.dec ]; then
            "$bin"/pzb -g $(awk "/""$replace""/{x=1}x&&/iBEC[.]/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1) "$ipswurl"
            fn="$(awk "/""$replace""/{x=1}x&&/iBEC[.]/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | sed 's/Firmware[/]dfu[/]//')"
            if [[ "$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -e $3 $1)" == "true" ]]; then
                if [[ "$3" == "10."* ]]; then
                    if [[ "$deviceid" == "iPhone8,1" || "$deviceid" == "iPhone8,2" ]]; then
                        ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn 11.1 $1)"
                    else
                        ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn 10.3.3 $1)"
                    fi
                else
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $3 $1)"
                fi
                if [ -z $ivkey ]; then
                    kbag=$("$bin"/img4 -i $fn -b | head -n 1)
                    iv=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ',' -f 1 | cut -d ' ' -f 2)
                    key=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ' ' -f 4)
                    ivkey="$iv$key"
                    "$bin"/img4 -i $fn -o "$dir"/$1/$cpid/$3/iBEC.dec -k $ivkey
                else
                    "$bin"/img4 -i $fn -o "$dir"/$1/$cpid/$3/iBEC.dec -k $ivkey
                fi
            else
                kbag=$("$bin"/img4 -i $fn -b | head -n 1)
                iv=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ',' -f 1 | cut -d ' ' -f 2)
                key=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ' ' -f 4)
                ivkey="$iv$key"
                "$bin"/img4 -i $fn -o "$dir"/$1/$cpid/$3/iBEC.dec -k $ivkey
            fi
        fi
        if [ ! -e "$dir"/$1/$cpid/$3/iBoot.dec ]; then
            "$bin"/pzb -g $(awk "/""$replace""/{x=1}x&&/iBoot[.]/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1) "$ipswurl"
            fn="$(awk "/""$replace""/{x=1}x&&/iBoot[.]/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | sed 's/Firmware[/]all_flash[/]all_flash.*production[/]//' | sed 's/Firmware[/]all_flash[/]//')"
            if [[ "$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -e $3 $1)" == "true" ]]; then
                if [[ "$3" == "10."* ]]; then
                    if [[ "$deviceid" == "iPhone8,1" || "$deviceid" == "iPhone8,2" ]]; then
                        ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn 11.1 $1)"
                    else
                        ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn 10.3.3 $1)"
                    fi
                else
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $3 $1)"
                fi
                if [ -z $ivkey ]; then
                    kbag=$("$bin"/img4 -i $fn -b | head -n 1)
                    iv=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ',' -f 1 | cut -d ' ' -f 2)
                    key=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ' ' -f 4)
                    ivkey="$iv$key"
                    "$bin"/img4 -i $fn -o "$dir"/$1/$cpid/$3/iBoot.dec -k $ivkey
                else
                    "$bin"/img4 -i $fn -o "$dir"/$1/$cpid/$3/iBoot.dec -k $ivkey
                fi
            else
                kbag=$("$bin"/img4 -i $fn -b | head -n 1)
                iv=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ',' -f 1 | cut -d ' ' -f 2)
                key=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ' ' -f 4)
                ivkey="$iv$key"
                "$bin"/img4 -i $fn -o "$dir"/$1/$cpid/$3/iBoot.dec -k $ivkey
            fi
        fi
        if [ ! -e "$dir"/$1/$cpid/$3/LLB.dec ]; then
            "$bin"/pzb -g $(awk "/""$replace""/{x=1}x&&/LLB[.]/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1) "$ipswurl"
            fn="$(awk "/""$replace""/{x=1}x&&/LLB[.]/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | sed 's/Firmware[/]all_flash[/]all_flash.*production[/]//' | sed 's/Firmware[/]all_flash[/]//')"
            if [[ "$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -e $3 $1)" == "true" ]]; then
                if [[ "$3" == "10."* ]]; then
                    if [[ "$deviceid" == "iPhone8,1" || "$deviceid" == "iPhone8,2" ]]; then
                        ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn 11.1 $1)"
                    else
                        ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn 10.3.3 $1)"
                    fi
                else
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $3 $1)"
                fi
                if [ -z $ivkey ]; then
                    kbag=$("$bin"/img4 -i $fn -b | head -n 1)
                    iv=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ',' -f 1 | cut -d ' ' -f 2)
                    key=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ' ' -f 4)
                    ivkey="$iv$key"
                    "$bin"/img4 -i $fn -o "$dir"/$1/$cpid/$3/LLB.dec -k $ivkey
                else
                    "$bin"/img4 -i $fn -o "$dir"/$1/$cpid/$3/LLB.dec -k $ivkey
                fi
            else
                kbag=$("$bin"/img4 -i $fn -b | head -n 1)
                iv=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ',' -f 1 | cut -d ' ' -f 2)
                key=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ' ' -f 4)
                ivkey="$iv$key"
                "$bin"/img4 -i $fn -o "$dir"/$1/$cpid/$3/LLB.dec -k $ivkey
            fi
        fi
        if [[ "$3" == "10."* ]]; then
            rm -rf BuildManifest.plist
            ipswurl=$(curl -k -sL "https://api.ipsw.me/v4/device/$deviceid?type=ipsw" | "$bin"/jq '.firmwares | .[] | select(.version=="'$3'")' | "$bin"/jq -s '.[0] | .url' --raw-output)
            "$bin"/pzb -g BuildManifest.plist "$ipswurl"
        fi
        if [ ! -e "$dir"/$1/$cpid/$3/sepi.dec ]; then
            "$bin"/pzb -g $(awk "/""$replace""/{x=1}x&&/sep-firmware[.]/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1) "$ipswurl"
            fn="$(awk "/""$replace""/{x=1}x&&/sep-firmware[.]/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | sed 's/Firmware[/]all_flash[/]all_flash.*production[/]//' | sed 's/Firmware[/]all_flash[/]//')"
            "$bin"/img4 -i "$fn" -o "$dir"/$1/$cpid/$3/sepi.dec
        fi
        if [ ! -e "$dir"/$1/$cpid/$3/kernelcache.dec ]; then
            "$bin"/pzb -g $(awk "/""$replace""/{x=1}x&&/kernelcache.release/{print;exit}" BuildManifest.plist | grep '<string>' | cut -d\> -f2 | cut -d\< -f1) "$ipswurl"
            if [[ "$3" == "7."* || "$3" == "8."* || "$3" == "9."* ]]; then
                fn="$(awk "/""$replace""/{x=1}x&&/kernelcache.release/{print;exit}" BuildManifest.plist | grep '<string>' | cut -d\> -f2 | cut -d\< -f1)"
                if [[ "$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -e $3 $1)" == "true" ]]; then
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $3 $1)"
                    if [ -z $ivkey ]; then
                        kbag=$("$bin"/img4 -i $fn -b | head -n 1)
                        iv=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ',' -f 1 | cut -d ' ' -f 2)
                        key=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ' ' -f 4)
                        ivkey="$iv$key"
                        "$bin"/img4 -i $fn -o "$dir"/$1/$cpid/$3/kcache.raw -k $ivkey
                        "$bin"/img4 -i $fn -o "$dir"/$1/$cpid/$3/kernelcache.dec -k $ivkey -D
                        python3 -m pyimg4 im4p extract -i $fn -o "$dir"/$1/$cpid/$3/kcache.raw.pyimg4 --iv $iv --key $key --extra "$dir"/$1/$cpid/$3/kpp.bin
                    else
                        "$bin"/img4 -i $fn -o "$dir"/$1/$cpid/$3/kcache.raw -k $ivkey
                        "$bin"/img4 -i $fn -o "$dir"/$1/$cpid/$3/kernelcache.dec -k $ivkey -D
                        iv="${ivkey:0:32}"
                        key="${ivkey:32}"
                        python3 -m pyimg4 im4p extract -i $fn -o "$dir"/$1/$cpid/$3/kcache.raw.pyimg4 --iv $iv --key $key --extra "$dir"/$1/$cpid/$3/kpp.bin
                    fi
                else
                    kbag=$("$bin"/img4 -i $fn -b | head -n 1)
                    iv=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ',' -f 1 | cut -d ' ' -f 2)
                    key=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ' ' -f 4)
                    ivkey="$iv$key"
                    "$bin"/img4 -i $fn -o "$dir"/$1/$cpid/$3/kcache.raw -k $ivkey
                    "$bin"/img4 -i $fn -o "$dir"/$1/$cpid/$3/kernelcache.dec -k $ivkey -D
                    python3 -m pyimg4 im4p extract -i $fn -o "$dir"/$1/$cpid/$3/kcache.raw.pyimg4 --iv $iv --key $key --extra "$dir"/$1/$cpid/$3/kpp.bin
                fi
            else
                "$bin"/img4 -i $(awk "/""$replace""/{x=1}x&&/kernelcache.release/{print;exit}" BuildManifest.plist | grep '<string>' | cut -d\> -f2 | cut -d\< -f1) -o "$dir"/$1/$cpid/$3/kcache.raw
                "$bin"/img4 -i $(awk "/""$replace""/{x=1}x&&/kernelcache.release/{print;exit}" BuildManifest.plist | grep '<string>' | cut -d\> -f2 | cut -d\< -f1) -o "$dir"/$1/$cpid/$3/kernelcache.dec -D
                python3 -m pyimg4 im4p extract -i $(awk "/""$replace""/{x=1}x&&/kernelcache.release/{print;exit}" BuildManifest.plist | grep '<string>' | cut -d\> -f2 | cut -d\< -f1) -o "$dir"/$1/$cpid/$3/kcache.raw.pyimg4 --iv $iv --key $key --extra "$dir"/$1/$cpid/$3/kpp.bin
            fi
        fi
        if [ ! -e "$dir"/$1/$cpid/$3/DeviceTree.dec ]; then
            "$bin"/pzb -g $(awk "/""$replace""/{x=1}x&&/DeviceTree[.]/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1) "$ipswurl"
            if [[ "$3" == "7."* || "$3" == "8."* || "$3" == "9."* ]]; then
                fn="$(awk "/""$replace""/{x=1}x&&/DeviceTree[.]/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | sed 's/Firmware[/]all_flash[/]all_flash.*production[/]//' | sed 's/Firmware[/]all_flash[/]//')"
                if [[ "$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -e $3 $1)" == "true" ]]; then
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $3 $1)"
                    if [ -z $ivkey ]; then
                        kbag=$("$bin"/img4 -i $fn -b | head -n 1)
                        iv=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ',' -f 1 | cut -d ' ' -f 2)
                        key=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ' ' -f 4)
                        ivkey="$iv$key"
                        "$bin"/img4 -i $fn -o "$dir"/$1/$cpid/$3/DeviceTree.dec -k $ivkey
                    else
                        "$bin"/img4 -i $fn -o "$dir"/$1/$cpid/$3/DeviceTree.dec -k $ivkey
                    fi
                else
                    kbag=$("$bin"/img4 -i $fn -b | head -n 1)
                    iv=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ',' -f 1 | cut -d ' ' -f 2)
                    key=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ' ' -f 4)
                    ivkey="$iv$key"
                    "$bin"/img4 -i $fn -o "$dir"/$1/$cpid/$3/DeviceTree.dec -k $ivkey
                fi
            else
                mv $(awk "/""$replace""/{x=1}x&&/DeviceTree[.]/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | sed 's/Firmware[/]all_flash[/]all_flash.*production[/]//' | sed 's/Firmware[/]all_flash[/]//') "$dir"/$1/$cpid/$3/DeviceTree.dec
            fi
        fi
        if [[ ! "$3" == "7."* && ! "$3" == "8."* && ! "$3" == "9."* ]]; then
            if [ ! -e "$dir"/$1/$cpid/$3/aopfw.dec ]; then
                "$bin"/pzb -g $(awk "/""$replace""/{x=1}x&&/aopfw/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1)  "$ipswurl"
                if [[ "$3" == "7."* || "$3" == "8."* || "$3" == "9."* ]]; then
                    fn="$(awk "/""$replace""/{x=1}x&&/aopfw/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | sed 's/Firmware[/]AOP[/]//' | sed 's/Firmware[/]//')"
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $3 $1)"
                    "$bin"/img4 -i $fn -o "$dir"/$1/$cpid/$3/aopfw.dec -k $ivkey
                else
                    mv $(awk "/""$replace""/{x=1}x&&/aopfw/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | sed 's/Firmware[/]AOP[/]//' | sed 's/Firmware[/]//') "$dir"/$1/$cpid/$3/aopfw.dec
                fi
            fi
        fi
        if [[ ! "$3" == "7."* && ! "$3" == "8."* && ! "$3" == "9."* ]]; then
            if [ ! -e "$dir"/$1/$cpid/$3/homerfw.dec ]; then
                "$bin"/pzb -g $(awk "/""$replace""/{x=1}x&&/homer/{print;exit}" BuildManifest.plist | grep '<string>' | cut -d\> -f2 | cut -d\< -f1)  "$ipswurl"
                if [[ "$3" == "7."* || "$3" == "8."* || "$3" == "9."* ]]; then
                    fn="$(awk "/""$replace""/{x=1}x&&/homer/{print;exit}" BuildManifest.plist | grep '<string>' | cut -d\> -f2 | cut -d\< -f1 | sed 's/Firmware[/]//')"
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $3 $1)"
                    "$bin"/img4 -i $fn -o "$dir"/$1/$cpid/$3/homerfw.dec -k $ivkey
                else
                    mv $(awk "/""$replace""/{x=1}x&&/homer/{print;exit}" BuildManifest.plist | grep '<string>' | cut -d\> -f2 | cut -d\< -f1 | sed 's/Firmware[/]//') "$dir"/$1/$cpid/$3/homerfw.dec
                fi
            fi
        fi
        if [[ ! "$3" == "7."* && ! "$3" == "8."* && ! "$3" == "9."* ]]; then
            if [ ! -e "$dir"/$1/$cpid/$3/avefw.dec ]; then
                "$bin"/pzb -g $(awk "/""$replace""/{x=1}x&&/ave/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1)  "$ipswurl"
                if [[ "$3" == "7."* || "$3" == "8."* || "$3" == "9."* ]]; then
                    fn="$(awk "/""$replace""/{x=1}x&&/ave/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | sed 's/Firmware[/]ave[/]//' | sed 's/Firmware[/]//')"
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $3 $1)"
                    "$bin"/img4 -i $fn -o "$dir"/$1/$cpid/$3/avefw.dec -k $ivkey
                else
                    mv $(awk "/""$replace""/{x=1}x&&/ave/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | sed 's/Firmware[/]ave[/]//' | sed 's/Firmware[/]//') "$dir"/$1/$cpid/$3/avefw.dec
                fi
            fi
        fi
        if [[ ! "$3" == "7."* && ! "$3" == "8."* && ! "$3" == "9."* ]]; then
            if [ ! -e "$dir"/$1/$cpid/$3/multitouch.dec ]; then
                "$bin"/pzb -g $(awk "/""$replace""/{x=1}x&&/[_]Multitouch/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1)  "$ipswurl"
                if [[ "$3" == "7."* || "$3" == "8."* || "$3" == "9."* ]]; then
                    fn="$(awk "/""$replace""/{x=1}x&&/[_]Multitouch/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | sed 's/Firmware[/]Multitouch[/]//' | sed 's/Firmware[/]//')"
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $3 $1)"
                    "$bin"/img4 -i $fn -o "$dir"/$1/$cpid/$3/multitouch.dec -k $ivkey
                else
                    mv $(awk "/""$replace""/{x=1}x&&/[_]Multitouch/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | sed 's/Firmware[/]Multitouch[/]//' | sed 's/Firmware[/]//') "$dir"/$1/$cpid/$3/multitouch.dec
                fi
            fi
        fi
        if [[ ! "$3" == "7."* && ! "$3" == "8."* && ! "$3" == "9."* ]]; then
            if [ ! -e "$dir"/$1/$cpid/$3/audiocodecfirmware.dec ]; then
                "$bin"/pzb -g $(awk "/""$replace""/{x=1}x&&/[A]udioDSP/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1)  "$ipswurl"
                if [[ "$3" == "7."* || "$3" == "8."* || "$3" == "9."* ]]; then
                    fn="$(awk "/""$replace""/{x=1}x&&/[A]udioDSP/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | sed 's/Firmware[/]Callan[/]//' | sed 's/Firmware[/]//')"
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $3 $1)"
                    "$bin"/img4 -i $fn -o "$dir"/$1/$cpid/$3/audiocodecfirmware.dec -k $ivkey
                else
                    mv $(awk "/""$replace""/{x=1}x&&/[A]udioDSP/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | sed 's/Firmware[/]Callan[/]//' | sed 's/Firmware[/]//') "$dir"/$1/$cpid/$3/audiocodecfirmware.dec
                fi
            fi
        fi
        if [[ ! "$3" == "7."* && ! "$3" == "8."* && ! "$3" == "9."* ]]; then
            if [ ! -e "$dir"/$1/$cpid/$3/audiocodecfirmware.dec ]; then
                "$bin"/pzb -g $(awk "/""$replace""/{x=1}x&&/[_]Callan/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1)  "$ipswurl"
                if [[ "$3" == "7."* || "$3" == "8."* || "$3" == "9."* ]]; then
                    fn="$(awk "/""$replace""/{x=1}x&&/[_]Callan/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | sed 's/Firmware[/]Callan[/]//' | sed 's/Firmware[/]//')"
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $3 $1)"
                    "$bin"/img4 -i $fn -o "$dir"/$1/$cpid/$3/audiocodecfirmware.dec -k $ivkey
                else
                    mv $(awk "/""$replace""/{x=1}x&&/[_]Callan/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | sed 's/Firmware[/]Callan[/]//' | sed 's/Firmware[/]//') "$dir"/$1/$cpid/$3/audiocodecfirmware.dec
                fi
            fi
        fi
        if [[ ! "$3" == "7."* && ! "$3" == "8."* && ! "$3" == "9."* ]]; then
            if [ ! -e "$dir"/$1/$cpid/$3/ispfw.dec ]; then
                "$bin"/pzb -g $(awk "/""$replace""/{x=1}x&&/isp_bni/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1)  "$ipswurl"
                if [[ "$3" == "7."* || "$3" == "8."* || "$3" == "9."* ]]; then
                    fn="$(awk "/""$replace""/{x=1}x&&/isp_bni/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | sed 's/Firmware[/]isp_bni[/]//' | sed 's/Firmware[/]//')"
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $3 $1)"
                    "$bin"/img4 -i $fn -o "$dir"/$1/$cpid/$3/ispfw.dec -k $ivkey
                else
                    mv $(awk "/""$replace""/{x=1}x&&/isp_bni/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | sed 's/Firmware[/]isp_bni[/]//' | sed 's/Firmware[/]//') "$dir"/$1/$cpid/$3/ispfw.dec
                fi
            fi
        fi
        if [ "$os" = "Darwin" ]; then
            fn="$(/usr/bin/plutil -extract "BuildIdentities".0."Manifest"."RestoreRamDisk"."Info"."Path" xml1 -o - BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | head -1)"
        else
            fn="$("$bin"/PlistBuddy -c "Print BuildIdentities:0:Manifest:RestoreRamDisk:Info:Path" BuildManifest.plist | tr -d '"')"
        fi
        if [ ! -e "$dir"/$1/$cpid/$3/RestoreRamDisk.dmg ]; then
            "$bin"/pzb -g "$fn" "$ipswurl"
            if [[ "$3" == "7."* || "$3" == "8."* || "$3" == "9."* ]]; then
                if [[ "$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -e $3 $1)" == "true" ]]; then
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $3 $1)"
                    if [ -z $ivkey ]; then
                        kbag=$("$bin"/img4 -i $fn -b | head -n 1)
                        iv=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ',' -f 1 | cut -d ' ' -f 2)
                        key=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ' ' -f 4)
                        ivkey="$iv$key"
                        "$bin"/img4 -i $fn -o "$dir"/$1/$cpid/$3/RestoreRamDisk.dmg -k $ivkey
                    else
                        "$bin"/img4 -i $fn -o "$dir"/$1/$cpid/$3/RestoreRamDisk.dmg -k $ivkey
                    fi
                else
                    kbag=$("$bin"/img4 -i $fn -b | head -n 1)
                    iv=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ',' -f 1 | cut -d ' ' -f 2)
                    key=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ' ' -f 4)
                    ivkey="$iv$key"
                    "$bin"/img4 -i $fn -o "$dir"/$1/$cpid/$3/RestoreRamDisk.dmg -k $ivkey
                fi
            else
                "$bin"/img4 -i "$fn" -o "$dir"/$1/$cpid/$3/RestoreRamDisk.dmg
            fi
        fi
        if [[ ! "$3" == "7."* && ! "$3" == "8."* && ! "$3" == "9."* && ! "$3" == "10."* && ! "$3" == "11."* ]]; then
            if [ ! -e "$dir"/$1/$cpid/$3/trustcache.img4 ]; then
                local fn
                if [ "$os" = "Darwin" ]; then
                    fn="$(/usr/bin/plutil -extract "BuildIdentities".0."Manifest"."OS"."Info"."Path" xml1 -o - BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | head -1)"
                else
                    fn="$("$bin"/PlistBuddy -c "Print BuildIdentities:0:Manifest:OS:Info:Path" BuildManifest.plist | tr -d '"')"
                fi
                "$bin"/pzb -g Firmware/"$fn".trustcache "$ipswurl"
                mv "$fn".trustcache "$dir"/$1/$cpid/$3/trustcache.im4p
            fi
        fi
        rm -rf BuildManifest.plist
        if [[ "$3" == "7."* ]]; then
            "$bin"/ipatcher "$dir"/$1/$cpid/$3/iBSS.dec "$dir"/$1/$cpid/$3/iBSS.patched
            "$bin"/ipatcher "$dir"/$1/$cpid/$3/iBEC.dec "$dir"/$1/$cpid/$3/iBEC.patched -b "$boot_args rd=disk0s1s1 amfi=0xff cs_enforcement_disable=1 keepsyms=1 debug=0x2014e wdt=-1 PE_i_can_has_debugger=1 amfi_get_out_of_my_way=0x1 amfi_unrestrict_task_for_pid=0x0"
        elif [[ "$3" == "8."* ]]; then
            "$bin"/ipatcher "$dir"/$1/$cpid/$3/iBSS.dec "$dir"/$1/$cpid/$3/iBSS.patched
            "$bin"/ipatcher "$dir"/$1/$cpid/$3/iBEC.dec "$dir"/$1/$cpid/$3/iBEC.patched -b "$boot_args rd=disk0s1s1 amfi=0xff cs_enforcement_disable=1 keepsyms=1 debug=0x2014e PE_i_can_has_debugger=1"
        elif [[ "$3" == "9."* ]]; then
            "$bin"/kairos "$dir"/$1/$cpid/$3/iBSS.dec "$dir"/$1/$cpid/$3/iBSS.patched
            "$bin"/kairos "$dir"/$1/$cpid/$3/iBEC.dec "$dir"/$1/$cpid/$3/iBEC.patched -b "$boot_args rd=disk0s1s1 amfi=0xff cs_enforcement_disable=1 keepsyms=1 debug=0x2014e PE_i_can_has_debugger=1 amfi_get_out_of_my_way=1 amfi_allow_any_signature=1" -n
        else
            "$bin"/iBoot64Patcher "$dir"/$1/$cpid/$3/iBSS.dec "$dir"/$1/$cpid/$3/iBSS.patched
            "$bin"/iBoot64Patcher "$dir"/$1/$cpid/$3/iBEC.dec "$dir"/$1/$cpid/$3/iBEC.patched -b "$boot_args rd=disk0s1s1 amfi=0xff cs_enforcement_disable=1 keepsyms=1 debug=0x2014e PE_i_can_has_debugger=1 amfi_get_out_of_my_way=1 amfi_allow_any_signature=1" -n
        fi
        if [[ "$3" == "8."* ]]; then
            "$bin"/img4 -i "$dir"/$1/$cpid/$3/iBSS.patched -o "$dir"/$1/$cpid/$3/iBSS.img4 -M IM4M -A -T ibss
            "$bin"/img4 -i "$dir"/$1/$cpid/$3/iBEC.patched -o "$dir"/$1/$cpid/$3/iBEC.img4 -M IM4M -A -T ibec
            "$bin"/Kernel64Patcher "$dir"/$1/$cpid/$3/kcache.raw "$dir"/$1/$cpid/$3/kcache.patched -u 8 -t -p -e 8 -f 8 -a -m 8 -g -s -d
            "$bin"/kerneldiff "$dir"/$1/$cpid/$3/kcache.raw "$dir"/$1/$cpid/$3/kcache.patched "$dir"/$1/$cpid/$3/kc.bpatch
            "$bin"/img4 -i "$dir"/$1/$cpid/$3/kernelcache.dec -o "$dir"/$1/$cpid/$3/kernelcache.img4 -M IM4M -T rkrn -P "$dir"/$1/$cpid/$3/kc.bpatch
            "$bin"/img4 -i "$dir"/$1/$cpid/$3/kernelcache.dec -o "$dir"/$1/$cpid/$3/kernelcache -M IM4M -T krnl -P "$dir"/$1/$cpid/$3/kc.bpatch
            "$bin"/dtree_patcher "$dir"/$1/$cpid/$3/DeviceTree.dec "$dir"/$1/$cpid/$3/DeviceTree.patched -n
            "$bin"/img4 -i "$dir"/$1/$cpid/$3/DeviceTree.patched -o "$dir"/$1/$cpid/$3/devicetree.img4 -A -M IM4M -T rdtr
        elif [[ "$3" == "9."* ]]; then
            "$bin"/img4 -i "$dir"/$1/$cpid/$3/iBSS.patched -o "$dir"/$1/$cpid/$3/iBSS.img4 -M IM4M -A -T ibss
            "$bin"/img4 -i "$dir"/$1/$cpid/$3/iBEC.patched -o "$dir"/$1/$cpid/$3/iBEC.img4 -M IM4M -A -T ibec
            "$bin"/Kernel64Patcher "$dir"/$1/$cpid/$3/kcache.raw "$dir"/$1/$cpid/$3/kcache.patched -u 9 -f 9 -k
            "$bin"/kerneldiff "$dir"/$1/$cpid/$3/kcache.raw "$dir"/$1/$cpid/$3/kcache.patched "$dir"/$1/$cpid/$3/kc.bpatch
            "$bin"/img4 -i "$dir"/$1/$cpid/$3/kernelcache.dec -o "$dir"/$1/$cpid/$3/kernelcache.img4 -M IM4M -T rkrn -P "$dir"/$1/$cpid/$3/kc.bpatch
            "$bin"/img4 -i "$dir"/$1/$cpid/$3/kernelcache.dec -o "$dir"/$1/$cpid/$3/kernelcache -M IM4M -T krnl -P "$dir"/$1/$cpid/$3/kc.bpatch
            "$bin"/dtree_patcher "$dir"/$1/$cpid/$3/DeviceTree.dec "$dir"/$1/$cpid/$3/DeviceTree.patched -n
            "$bin"/img4 -i "$dir"/$1/$cpid/$3/DeviceTree.patched -o "$dir"/$1/$cpid/$3/devicetree.img4 -A -M IM4M -T rdtr
        elif [[ "$3" == "7."* ]]; then
            "$bin"/img4 -i "$dir"/$1/$cpid/$3/iBSS.patched -o "$dir"/$1/$cpid/$3/iBSS.img4 -M IM4M -A -T ibss
            "$bin"/img4 -i "$dir"/$1/$cpid/$3/iBEC.patched -o "$dir"/$1/$cpid/$3/iBEC.img4 -M IM4M -A -T ibec
            "$bin"/Kernel64Patcher "$dir"/$1/$cpid/$3/kcache.raw "$dir"/$1/$cpid/$3/kcache.patched -u 7 -m 7 -e 7 -f 7 -k
            "$bin"/kerneldiff "$dir"/$1/$cpid/$3/kcache.raw "$dir"/$1/$cpid/$3/kcache.patched "$dir"/$1/$cpid/$3/kc.bpatch
            "$bin"/img4 -i "$dir"/$1/$cpid/$3/kernelcache.dec -o "$dir"/$1/$cpid/$3/kernelcache.img4 -M IM4M -T rkrn -P "$dir"/$1/$cpid/$3/kc.bpatch
            "$bin"/img4 -i "$dir"/$1/$cpid/$3/kernelcache.dec -o "$dir"/$1/$cpid/$3/kernelcache -M IM4M -T krnl -P "$dir"/$1/$cpid/$3/kc.bpatch
            "$bin"/dtree_patcher "$dir"/$1/$cpid/$3/DeviceTree.dec "$dir"/$1/$cpid/$3/DeviceTree.patched -n
            "$bin"/img4 -i "$dir"/$1/$cpid/$3/DeviceTree.patched -o "$dir"/$1/$cpid/$3/devicetree.img4 -A -M IM4M -T rdtr
        elif [[ "$3" == "10."* ]]; then
            "$bin"/img4 -i "$dir"/$1/$cpid/$3/iBSS.patched -o "$dir"/$1/$cpid/$3/iBSS.img4 -M IM4M -A -T ibss
            "$bin"/img4 -i "$dir"/$1/$cpid/$3/iBEC.patched -o "$dir"/$1/$cpid/$3/iBEC.img4 -M IM4M -A -T ibec
            "$bin"/img4 -i "$dir"/$1/$cpid/$3/aopfw.dec -o "$dir"/$1/$cpid/$3/aopfw.img4 -M IM4M -T aopf
            if [ -e "$dir"/$1/$cpid/$3/homerfw.dec ]; then
                "$bin"/img4 -i "$dir"/$1/$cpid/$3/homerfw.dec -o "$dir"/$1/$cpid/$3/homerfw.img4 -M IM4M -T homr
            fi
            if [ -e "$dir"/$1/$cpid/$3/avefw.dec ]; then
                "$bin"/img4 -i "$dir"/$1/$cpid/$3/avefw.dec -o "$dir"/$1/$cpid/$3/avefw.img4 -M IM4M -T avef
            fi
            if [ -e "$dir"/$1/$cpid/$3/multitouch.dec ]; then
                "$bin"/img4 -i "$dir"/$1/$cpid/$3/multitouch.dec -o "$dir"/$1/$cpid/$3/multitouch.img4 -M IM4M -T mtfw
            fi
            if [ -e "$dir"/$1/$cpid/$3/audiocodecfirmware.dec ]; then
                "$bin"/img4 -i "$dir"/$1/$cpid/$3/audiocodecfirmware.dec -o "$dir"/$1/$cpid/$3/audiocodecfirmware.img4 -M IM4M -T acfw
            fi
            "$bin"/KPlooshFinder "$dir"/$1/$cpid/$3/kcache.raw "$dir"/$1/$cpid/$3/kcache.patched
            "$bin"/Kernel64Patcher "$dir"/$1/$cpid/$3/kcache.patched "$dir"/$1/$cpid/$3/kcache2.patched -u 10 -a -f 10 -q
            "$bin"/kerneldiff "$dir"/$1/$cpid/$3/kcache.raw "$dir"/$1/$cpid/$3/kcache2.patched "$dir"/$1/$cpid/$3/kc.bpatch
            "$bin"/img4 -i "$dir"/$1/$cpid/$3/kernelcache.dec -o "$dir"/$1/$cpid/$3/kernelcache.img4 -M IM4M -T rkrn -P "$dir"/$1/$cpid/$3/kc.bpatch
            "$bin"/img4 -i "$dir"/$1/$cpid/$3/kernelcache.dec -o "$dir"/$1/$cpid/$3/kernelcache -M IM4M -T krnl -P "$dir"/$1/$cpid/$3/kc.bpatch
            if [ -e "$dir"/$1/$cpid/$3/trustcache.im4p ]; then
                "$bin"/img4 -i "$dir"/$1/$cpid/$3/trustcache.im4p -o "$dir"/$1/$cpid/$3/trustcache.img4 -M IM4M -T rtsc
            fi
            "$bin"/img4tool -e -o "$dir"/$1/$cpid/$3/devicetree.out "$dir"/$1/$cpid/$3/DeviceTree.dec
            "$bin"/dtree_patcher "$dir"/$1/$cpid/$3/devicetree.out "$dir"/$1/$cpid/$3/DeviceTree.patched -n
            "$bin"/img4 -i "$dir"/$1/$cpid/$3/DeviceTree.patched -o "$dir"/$1/$cpid/$3/devicetree.img4 -A -M IM4M -T rdtr
        elif [[ "$3" == "11."* ]]; then
            "$bin"/img4 -i "$dir"/$1/$cpid/$3/iBSS.patched -o "$dir"/$1/$cpid/$3/iBSS.img4 -M IM4M -A -T ibss
            "$bin"/img4 -i "$dir"/$1/$cpid/$3/iBEC.patched -o "$dir"/$1/$cpid/$3/iBEC.img4 -M IM4M -A -T ibec
            "$bin"/img4 -i "$dir"/$1/$cpid/$3/aopfw.dec -o "$dir"/$1/$cpid/$3/aopfw.img4 -M IM4M -T aopf
            if [ -e "$dir"/$1/$cpid/$3/homerfw.dec ]; then
                "$bin"/img4 -i "$dir"/$1/$cpid/$3/homerfw.dec -o "$dir"/$1/$cpid/$3/homerfw.img4 -M IM4M -T homr
            fi
            if [ -e "$dir"/$1/$cpid/$3/avefw.dec ]; then
                "$bin"/img4 -i "$dir"/$1/$cpid/$3/avefw.dec -o "$dir"/$1/$cpid/$3/avefw.img4 -M IM4M -T avef
            fi
            if [ -e "$dir"/$1/$cpid/$3/multitouch.dec ]; then
                "$bin"/img4 -i "$dir"/$1/$cpid/$3/multitouch.dec -o "$dir"/$1/$cpid/$3/multitouch.img4 -M IM4M -T mtfw
            fi
            if [ -e "$dir"/$1/$cpid/$3/audiocodecfirmware.dec ]; then
                "$bin"/img4 -i "$dir"/$1/$cpid/$3/audiocodecfirmware.dec -o "$dir"/$1/$cpid/$3/audiocodecfirmware.img4 -M IM4M -T acfw
            fi
            "$bin"/KPlooshFinder "$dir"/$1/$cpid/$3/kcache.raw "$dir"/$1/$cpid/$3/kcache.patched
            if [[ "$3" == "11.3"* || "$3" == "11.4"* ]]; then
                if [[ "$deviceid" == "iPhone10"* || "$cpid" == "0x8015"* ]]; then
                    "$bin"/Kernel64Patcher "$dir"/$1/$cpid/$3/kcache.patched "$dir"/$1/$cpid/$3/kcache2.patched -u 11 -f 11 -r -c
                else
                    "$bin"/Kernel64Patcher "$dir"/$1/$cpid/$3/kcache.patched "$dir"/$1/$cpid/$3/kcache2.patched -u 11 -f 11 -r
                fi
            else
                if [[ "$deviceid" == "iPhone10"* || "$cpid" == "0x8015"* ]]; then
                    "$bin"/Kernel64Patcher "$dir"/$1/$cpid/$3/kcache.patched "$dir"/$1/$cpid/$3/kcache2.patched -u 11 -f 11 -b -c
                else
                    "$bin"/Kernel64Patcher "$dir"/$1/$cpid/$3/kcache.patched "$dir"/$1/$cpid/$3/kcache2.patched -u 11 -f 11 -b
                fi
            fi
            "$bin"/kerneldiff "$dir"/$1/$cpid/$3/kcache.raw "$dir"/$1/$cpid/$3/kcache2.patched "$dir"/$1/$cpid/$3/kc.bpatch
            "$bin"/img4 -i "$dir"/$1/$cpid/$3/kernelcache.dec -o "$dir"/$1/$cpid/$3/kernelcache.img4 -M IM4M -T rkrn -P "$dir"/$1/$cpid/$3/kc.bpatch
            "$bin"/img4 -i "$dir"/$1/$cpid/$3/kernelcache.dec -o "$dir"/$1/$cpid/$3/kernelcache -M IM4M -T krnl -P "$dir"/$1/$cpid/$3/kc.bpatch
            if [ -e "$dir"/$1/$cpid/$3/trustcache.im4p ]; then
                "$bin"/img4 -i "$dir"/$1/$cpid/$3/trustcache.im4p -o "$dir"/$1/$cpid/$3/trustcache.img4 -M IM4M -T rtsc
            fi
            "$bin"/img4tool -e -o "$dir"/$1/$cpid/$3/devicetree.out "$dir"/$1/$cpid/$3/DeviceTree.dec
            "$bin"/dtree_patcher "$dir"/$1/$cpid/$3/devicetree.out "$dir"/$1/$cpid/$3/DeviceTree.patched -n
            "$bin"/img4 -i "$dir"/$1/$cpid/$3/DeviceTree.patched -o "$dir"/$1/$cpid/$3/devicetree.img4 -A -M IM4M -T rdtr
        elif [[ "$3" == "12."* ]]; then
            "$bin"/img4 -i "$dir"/$1/$cpid/$3/iBSS.patched -o "$dir"/$1/$cpid/$3/iBSS.img4 -M IM4M -A -T ibss
            "$bin"/img4 -i "$dir"/$1/$cpid/$3/iBEC.patched -o "$dir"/$1/$cpid/$3/iBEC.img4 -M IM4M -A -T ibec
            "$bin"/img4 -i "$dir"/$1/$cpid/$3/aopfw.dec -o "$dir"/$1/$cpid/$3/aopfw.img4 -M IM4M -T aopf
            if [ -e "$dir"/$1/$cpid/$3/homerfw.dec ]; then
                "$bin"/img4 -i "$dir"/$1/$cpid/$3/homerfw.dec -o "$dir"/$1/$cpid/$3/homerfw.img4 -M IM4M -T homr
            fi
            if [ -e "$dir"/$1/$cpid/$3/avefw.dec ]; then
                "$bin"/img4 -i "$dir"/$1/$cpid/$3/avefw.dec -o "$dir"/$1/$cpid/$3/avefw.img4 -M IM4M -T avef
            fi
            if [ -e "$dir"/$1/$cpid/$3/multitouch.dec ]; then
                "$bin"/img4 -i "$dir"/$1/$cpid/$3/multitouch.dec -o "$dir"/$1/$cpid/$3/multitouch.img4 -M IM4M -T mtfw
            fi
            if [ -e "$dir"/$1/$cpid/$3/audiocodecfirmware.dec ]; then
                "$bin"/img4 -i "$dir"/$1/$cpid/$3/audiocodecfirmware.dec -o "$dir"/$1/$cpid/$3/audiocodecfirmware.img4 -M IM4M -T acfw
            fi
            "$bin"/KPlooshFinder "$dir"/$1/$cpid/$3/kcache.raw "$dir"/$1/$cpid/$3/kcache.patched
            if [[ "$deviceid" == "iPhone10"* || "$cpid" == "0x8015"* ]]; then
                "$bin"/Kernel64Patcher "$dir"/$1/$cpid/$3/kcache.patched "$dir"/$1/$cpid/$3/kcache2.patched -u 12 -r -f 12 -c
            else
                "$bin"/Kernel64Patcher "$dir"/$1/$cpid/$3/kcache.patched "$dir"/$1/$cpid/$3/kcache2.patched -u 12 -r -f 12
            fi
            "$bin"/kerneldiff "$dir"/$1/$cpid/$3/kcache.raw "$dir"/$1/$cpid/$3/kcache2.patched "$dir"/$1/$cpid/$3/kc.bpatch
            "$bin"/img4 -i "$dir"/$1/$cpid/$3/kernelcache.dec -o "$dir"/$1/$cpid/$3/kernelcache.img4 -M IM4M -T rkrn -P "$dir"/$1/$cpid/$3/kc.bpatch
            "$bin"/img4 -i "$dir"/$1/$cpid/$3/kernelcache.dec -o "$dir"/$1/$cpid/$3/kernelcache -M IM4M -T krnl -P "$dir"/$1/$cpid/$3/kc.bpatch
            if [ -e "$dir"/$1/$cpid/$3/trustcache.im4p ]; then
                "$bin"/img4 -i "$dir"/$1/$cpid/$3/trustcache.im4p -o "$dir"/$1/$cpid/$3/trustcache.img4 -M IM4M -T rtsc
                "$bin"/img4 -i "$dir"/$1/$cpid/$3/trustcache.im4p -o "$dir"/$1/$cpid/$3/trustcache -M IM4M -T trst
            fi
            "$bin"/img4tool -e -o "$dir"/$1/$cpid/$3/devicetree.out "$dir"/$1/$cpid/$3/DeviceTree.dec
            "$bin"/dtree_patcher "$dir"/$1/$cpid/$3/devicetree.out "$dir"/$1/$cpid/$3/DeviceTree.patched -n
            "$bin"/img4 -i "$dir"/$1/$cpid/$3/DeviceTree.patched -o "$dir"/$1/$cpid/$3/devicetree.img4 -A -M IM4M -T rdtr
        elif [[ "$3" == "13."* ]]; then
            "$bin"/img4 -i "$dir"/$1/$cpid/$3/iBSS.patched -o "$dir"/$1/$cpid/$3/iBSS.img4 -M IM4M -A -T ibss
            "$bin"/img4 -i "$dir"/$1/$cpid/$3/iBEC.patched -o "$dir"/$1/$cpid/$3/iBEC.img4 -M IM4M -A -T ibec
            "$bin"/img4 -i "$dir"/$1/$cpid/$3/aopfw.dec -o "$dir"/$1/$cpid/$3/aopfw.img4 -M IM4M -T aopf
            if [ -e "$dir"/$1/$cpid/$3/homerfw.dec ]; then
                "$bin"/img4 -i "$dir"/$1/$cpid/$3/homerfw.dec -o "$dir"/$1/$cpid/$3/homerfw.img4 -M IM4M -T homr
            fi
            if [ -e "$dir"/$1/$cpid/$3/avefw.dec ]; then
                "$bin"/img4 -i "$dir"/$1/$cpid/$3/avefw.dec -o "$dir"/$1/$cpid/$3/avefw.img4 -M IM4M -T avef
            fi
            if [ -e "$dir"/$1/$cpid/$3/multitouch.dec ]; then
                "$bin"/img4 -i "$dir"/$1/$cpid/$3/multitouch.dec -o "$dir"/$1/$cpid/$3/multitouch.img4 -M IM4M -T mtfw
            fi
            if [ -e "$dir"/$1/$cpid/$3/audiocodecfirmware.dec ]; then
                "$bin"/img4 -i "$dir"/$1/$cpid/$3/audiocodecfirmware.dec -o "$dir"/$1/$cpid/$3/audiocodecfirmware.img4 -M IM4M -T acfw
            fi
            if [ -e "$dir"/$1/$cpid/$3/ispfw.dec ]; then
                "$bin"/img4 -i "$dir"/$1/$cpid/$3/ispfw.dec -o "$dir"/$1/$cpid/$3/ispfw.img4 -M IM4M -T ispf
            fi
            "$bin"/KPlooshFinder "$dir"/$1/$cpid/$3/kcache.raw "$dir"/$1/$cpid/$3/kcache.patched
            #"$bin"/Kernel64Patcher "$dir"/$1/$cpid/$3/kcache.patched "$dir"/$1/$cpid/$3/kcache2.patched -u 13 -r -f 13
            "$bin"/Kernel64Patcher "$dir"/$1/$cpid/$3/kcache.patched "$dir"/$1/$cpid/$3/kcache2.patched -z -r -f 13
            "$bin"/kerneldiff "$dir"/$1/$cpid/$3/kcache.raw "$dir"/$1/$cpid/$3/kcache2.patched "$dir"/$1/$cpid/$3/kc.bpatch
            if [[ "$?" == "0" ]]; then
                "$bin"/img4 -i "$dir"/$1/$cpid/$3/kernelcache.dec -o "$dir"/$1/$cpid/$3/kernelcache.img4 -M IM4M -T rkrn -P "$dir"/$1/$cpid/$3/kc.bpatch
                "$bin"/img4 -i "$dir"/$1/$cpid/$3/kernelcache.dec -o "$dir"/$1/$cpid/$3/kernelcache -M IM4M -T krnl -P "$dir"/$1/$cpid/$3/kc.bpatch
            else
                if [[ "$deviceid" == *'iPhone8'* ]] || [[ "$deviceid" == *'iPad6'* ]] || [[ "$deviceid" == *'iPad5'* ]]; then
                    python3 -m pyimg4 im4p create -i "$dir"/$1/$cpid/$3/kcache2.patched -o "$dir"/$1/$cpid/$3/kernelcache.im4p.img4 --extra "$dir"/$1/$cpid/$3/kpp.bin -f rkrn --lzss
                    python3 -m pyimg4 im4p create -i "$dir"/$1/$cpid/$3/kcache2.patched -o "$dir"/$1/$cpid/$3/kernelcache.im4p --extra "$dir"/$1/$cpid/$3/kpp.bin -f krnl --lzss
                else
                    python3 -m pyimg4 im4p create -i "$dir"/$1/$cpid/$3/kcache2.patched -o "$dir"/$1/$cpid/$3/kernelcache.im4p.img4 -f rkrn --lzss
                    python3 -m pyimg4 im4p create -i "$dir"/$1/$cpid/$3/kcache2.patched -o "$dir"/$1/$cpid/$3/kernelcache.im4p -f krnl --lzss
                fi
                python3 -m pyimg4 img4 create -p "$dir"/$1/$cpid/$3/kernelcache.im4p.img4 -o "$dir"/$1/$cpid/$3/kernelcache.img4 -m IM4M
                python3 -m pyimg4 img4 create -p "$dir"/$1/$cpid/$3/kernelcache.im4p -o "$dir"/$1/$cpid/$3/kernelcache -m IM4M
            fi
            if [ -e "$dir"/$1/$cpid/$3/trustcache.im4p ]; then
                "$bin"/img4 -i "$dir"/$1/$cpid/$3/trustcache.im4p -o "$dir"/$1/$cpid/$3/trustcache.img4 -M IM4M -T rtsc
                "$bin"/img4 -i "$dir"/$1/$cpid/$3/trustcache.im4p -o "$dir"/$1/$cpid/$3/trustcache -M IM4M -T trst
            fi
            "$bin"/img4tool -e -o "$dir"/$1/$cpid/$3/devicetree.out "$dir"/$1/$cpid/$3/DeviceTree.dec
            "$bin"/dtree_patcher "$dir"/$1/$cpid/$3/devicetree.out "$dir"/$1/$cpid/$3/DeviceTree.patched -n -d 0
            "$bin"/img4 -i "$dir"/$1/$cpid/$3/DeviceTree.patched -o "$dir"/$1/$cpid/$3/devicetree.img4 -A -M IM4M -T rdtr
        elif [[ "$3" == "14."* ]]; then
            "$bin"/img4 -i "$dir"/$1/$cpid/$3/iBSS.patched -o "$dir"/$1/$cpid/$3/iBSS.img4 -M IM4M -A -T ibss
            "$bin"/img4 -i "$dir"/$1/$cpid/$3/iBEC.patched -o "$dir"/$1/$cpid/$3/iBEC.img4 -M IM4M -A -T ibec
            "$bin"/img4 -i "$dir"/$1/$cpid/$3/aopfw.dec -o "$dir"/$1/$cpid/$3/aopfw.img4 -M IM4M -T aopf
            if [ -e "$dir"/$1/$cpid/$3/homerfw.dec ]; then
                "$bin"/img4 -i "$dir"/$1/$cpid/$3/homerfw.dec -o "$dir"/$1/$cpid/$3/homerfw.img4 -M IM4M -T homr
            fi
            if [ -e "$dir"/$1/$cpid/$3/avefw.dec ]; then
                "$bin"/img4 -i "$dir"/$1/$cpid/$3/avefw.dec -o "$dir"/$1/$cpid/$3/avefw.img4 -M IM4M -T avef
            fi
            if [ -e "$dir"/$1/$cpid/$3/multitouch.dec ]; then
                "$bin"/img4 -i "$dir"/$1/$cpid/$3/multitouch.dec -o "$dir"/$1/$cpid/$3/multitouch.img4 -M IM4M -T mtfw
            fi
            if [ -e "$dir"/$1/$cpid/$3/audiocodecfirmware.dec ]; then
                "$bin"/img4 -i "$dir"/$1/$cpid/$3/audiocodecfirmware.dec -o "$dir"/$1/$cpid/$3/audiocodecfirmware.img4 -M IM4M -T acfw
            fi
            if [ -e "$dir"/$1/$cpid/$3/ispfw.dec ]; then
                "$bin"/img4 -i "$dir"/$1/$cpid/$3/ispfw.dec -o "$dir"/$1/$cpid/$3/ispfw.img4 -M IM4M -T ispf
            fi
            "$bin"/KPlooshFinder "$dir"/$1/$cpid/$3/kcache.raw "$dir"/$1/$cpid/$3/kcache.patched
            #"$bin"/Kernel64Patcher "$dir"/$1/$cpid/$3/kcache.patched "$dir"/$1/$cpid/$3/kcache2.patched -u 14 -f 14
            "$bin"/Kernel64Patcher "$dir"/$1/$cpid/$3/kcache.patched "$dir"/$1/$cpid/$3/kcache2.patched -w -f 14
            if [[ "$deviceid" == *'iPhone8'* ]] || [[ "$deviceid" == *'iPad6'* ]] || [[ "$deviceid" == *'iPad5'* ]]; then
                python3 -m pyimg4 im4p create -i "$dir"/$1/$cpid/$3/kcache2.patched -o "$dir"/$1/$cpid/$3/kernelcache.im4p.img4 --extra "$dir"/$1/$cpid/$3/kpp.bin -f rkrn --lzss
                python3 -m pyimg4 im4p create -i "$dir"/$1/$cpid/$3/kcache2.patched -o "$dir"/$1/$cpid/$3/kernelcache.im4p --extra "$dir"/$1/$cpid/$3/kpp.bin -f krnl --lzss
            else
                python3 -m pyimg4 im4p create -i "$dir"/$1/$cpid/$3/kcache2.patched -o "$dir"/$1/$cpid/$3/kernelcache.im4p.img4 -f rkrn --lzss
                python3 -m pyimg4 im4p create -i "$dir"/$1/$cpid/$3/kcache2.patched -o "$dir"/$1/$cpid/$3/kernelcache.im4p -f krnl --lzss
            fi
            python3 -m pyimg4 img4 create -p "$dir"/$1/$cpid/$3/kernelcache.im4p.img4 -o "$dir"/$1/$cpid/$3/kernelcache.img4 -m IM4M
            python3 -m pyimg4 img4 create -p "$dir"/$1/$cpid/$3/kernelcache.im4p -o "$dir"/$1/$cpid/$3/kernelcache -m IM4M
            if [ -e "$dir"/$1/$cpid/$3/trustcache.im4p ]; then
                "$bin"/img4 -i "$dir"/$1/$cpid/$3/trustcache.im4p -o "$dir"/$1/$cpid/$3/trustcache.img4 -M IM4M -T rtsc
                "$bin"/img4 -i "$dir"/$1/$cpid/$3/trustcache.im4p -o "$dir"/$1/$cpid/$3/trustcache -M IM4M -T trst
            fi
            "$bin"/img4tool -e -o "$dir"/$1/$cpid/$3/devicetree.out "$dir"/$1/$cpid/$3/DeviceTree.dec
            "$bin"/dtree_patcher "$dir"/$1/$cpid/$3/devicetree.out "$dir"/$1/$cpid/$3/DeviceTree.patched -n -d 0 -p D
            "$bin"/img4 -i "$dir"/$1/$cpid/$3/DeviceTree.patched -o "$dir"/$1/$cpid/$3/devicetree.img4 -A -M IM4M -T rdtr
        fi
    fi
    cd ..
    rm -rf work
}
_download_clean_boot_files() {
    ipswurl=$(curl -k -sL "https://api.ipsw.me/v4/device/$deviceid?type=ipsw" | "$bin"/jq '.firmwares | .[] | select(.version=="'$3'")' | "$bin"/jq -s '.[0] | .url' --raw-output)
    rm -rf BuildManifest.plist
    mkdir -p "$dir"/$1/clean/$cpid/$3
    rm -rf "$dir"/work
    mkdir "$dir"/work
    cd "$dir"/work
    rm -rf IM4M
    "$bin"/img4tool -e -s "$dir"/$1/0.0/shsh.shsh2 -m IM4M
    if [ ! -e "$dir"/$1/clean/$cpid/$3/kernelcache ]; then
        if [[ "$3" == "10."* ]]; then
            if [[ "$deviceid" == "iPhone8,1" || "$deviceid" == "iPhone8,2" ]]; then
                ipswurl=$(curl -k -sL "https://api.ipsw.me/v4/device/$deviceid?type=ipsw" | "$bin"/jq '.firmwares | .[] | select(.version=="'11.1'")' | "$bin"/jq -s '.[0] | .url' --raw-output)
            else
                ipswurl=$(curl -k -sL "https://api.ipsw.me/v4/device/$deviceid?type=ipsw" | "$bin"/jq '.firmwares | .[] | select(.version=="'10.3.3'")' | "$bin"/jq -s '.[0] | .url' --raw-output)
            fi
        fi
        "$bin"/pzb -g BuildManifest.plist "$ipswurl"
        if [ ! -e "$dir"/$1/clean/$cpid/$3/iBSS.dec ]; then
            "$bin"/pzb -g $(awk "/""$replace""/{x=1}x&&/iBSS[.]/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1) "$ipswurl"
            fn="$(awk "/""$replace""/{x=1}x&&/iBSS[.]/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | sed 's/Firmware[/]dfu[/]//')"
            if [[ "$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -e $3 $1)" == "true" ]]; then
                if [[ "$3" == "10."* ]]; then
                    if [[ "$deviceid" == "iPhone8,1" || "$deviceid" == "iPhone8,2" ]]; then
                        ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn 11.1 $1)"
                    else
                        ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn 10.3.3 $1)"
                    fi
                else
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $3 $1)"
                fi
                "$bin"/img4 -i $fn -o "$dir"/$1/clean/$cpid/$3/iBSS.dec -k $ivkey
            else
                kbag=$("$bin"/img4 -i $fn -b | head -n 1)
                iv=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ',' -f 1 | cut -d ' ' -f 2)
                key=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ' ' -f 4)
                ivkey="$iv$key"
                "$bin"/img4 -i $fn -o "$dir"/$1/clean/$cpid/$3/iBSS.dec -k $ivkey
            fi
        fi
        if [ ! -e "$dir"/$1/clean/$cpid/$3/iBEC.dec ]; then
            "$bin"/pzb -g $(awk "/""$replace""/{x=1}x&&/iBEC[.]/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1) "$ipswurl"
            fn="$(awk "/""$replace""/{x=1}x&&/iBEC[.]/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | sed 's/Firmware[/]dfu[/]//')"
            if [[ "$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -e $3 $1)" == "true" ]]; then
                if [[ "$3" == "10."* ]]; then
                    if [[ "$deviceid" == "iPhone8,1" || "$deviceid" == "iPhone8,2" ]]; then
                        ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn 11.1 $1)"
                    else
                        ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn 10.3.3 $1)"
                    fi
                else
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $3 $1)"
                fi
                "$bin"/img4 -i $fn -o "$dir"/$1/clean/$cpid/$3/iBEC.dec -k $ivkey
            else
                kbag=$("$bin"/img4 -i $fn -b | head -n 1)
                iv=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ',' -f 1 | cut -d ' ' -f 2)
                key=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ' ' -f 4)
                ivkey="$iv$key"
                "$bin"/img4 -i $fn -o "$dir"/$1/clean/$cpid/$3/iBEC.dec -k $ivkey
            fi
        fi
        if [[ "$3" == "10."* ]]; then
            rm -rf BuildManifest.plist
            ipswurl=$(curl -k -sL "https://api.ipsw.me/v4/device/$deviceid?type=ipsw" | "$bin"/jq '.firmwares | .[] | select(.version=="'$3'")' | "$bin"/jq -s '.[0] | .url' --raw-output)
            "$bin"/pzb -g BuildManifest.plist "$ipswurl"
        fi
        if [ ! -e "$dir"/$1/clean/$cpid/$3/kernelcache.dec ]; then
            "$bin"/pzb -g $(awk "/""$replace""/{x=1}x&&/kernelcache.release/{print;exit}" BuildManifest.plist | grep '<string>' | cut -d\> -f2 | cut -d\< -f1) "$ipswurl"
            if [[ "$3" == "7."* || "$3" == "8."* || "$3" == "9."* ]]; then
                fn="$(awk "/""$replace""/{x=1}x&&/kernelcache.release/{print;exit}" BuildManifest.plist | grep '<string>' | cut -d\> -f2 | cut -d\< -f1)"
                if [[ "$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -e $3 $1)" == "true" ]]; then
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $3 $1)"
                    "$bin"/img4 -i $fn -o "$dir"/$1/clean/$cpid/$3/kcache.raw -k $ivkey
                    "$bin"/img4 -i $fn -o "$dir"/$1/clean/$cpid/$3/kernelcache.dec -k $ivkey -D
                else
                    kbag=$("$bin"/img4 -i $fn -b | head -n 1)
                    iv=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ',' -f 1 | cut -d ' ' -f 2)
                    key=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ' ' -f 4)
                    ivkey="$iv$key"
                    "$bin"/img4 -i $fn -o "$dir"/$1/clean/$cpid/$3/kcache.raw -k $ivkey
                    "$bin"/img4 -i $fn -o "$dir"/$1/clean/$cpid/$3/kernelcache.dec -k $ivkey -D
                fi
            else
                "$bin"/img4 -i $(awk "/""$replace""/{x=1}x&&/kernelcache.release/{print;exit}" BuildManifest.plist | grep '<string>' | cut -d\> -f2 | cut -d\< -f1) -o "$dir"/$1/clean/$cpid/$3/kcache.raw
                "$bin"/img4 -i $(awk "/""$replace""/{x=1}x&&/kernelcache.release/{print;exit}" BuildManifest.plist | grep '<string>' | cut -d\> -f2 | cut -d\< -f1) -o "$dir"/$1/clean/$cpid/$3/kernelcache.dec -D
            fi
        fi
        if [ ! -e "$dir"/$1/clean/$cpid/$3/DeviceTree.dec ]; then
            "$bin"/pzb -g $(awk "/""$replace""/{x=1}x&&/DeviceTree[.]/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1) "$ipswurl"
            if [[ "$3" == "7."* || "$3" == "8."* || "$3" == "9."* ]]; then
                fn="$(awk "/""$replace""/{x=1}x&&/DeviceTree[.]/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | sed 's/Firmware[/]all_flash[/]all_flash.*production[/]//' | sed 's/Firmware[/]all_flash[/]//')"
                if [[ "$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -e $3 $1)" == "true" ]]; then
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $3 $1)"
                    "$bin"/img4 -i $fn -o "$dir"/$1/clean/$cpid/$3/DeviceTree.dec -k $ivkey
                else
                    kbag=$("$bin"/img4 -i $fn -b | head -n 1)
                    iv=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ',' -f 1 | cut -d ' ' -f 2)
                    key=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ' ' -f 4)
                    ivkey="$iv$key"
                    "$bin"/img4 -i $fn -o "$dir"/$1/clean/$cpid/$3/DeviceTree.dec -k $ivkey
                fi
            else
                mv $(awk "/""$replace""/{x=1}x&&/DeviceTree[.]/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | sed 's/Firmware[/]all_flash[/]all_flash.*production[/]//' | sed 's/Firmware[/]all_flash[/]//') "$dir"/$1/clean/$cpid/$3/DeviceTree.dec
            fi
        fi
        if [[ ! "$3" == "7."* && ! "$3" == "8."* && ! "$3" == "9."* ]]; then
            if [ ! -e "$dir"/$1/clean/$cpid/$3/aopfw.dec ]; then
                "$bin"/pzb -g $(awk "/""$replace""/{x=1}x&&/aopfw/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1)  "$ipswurl"
                if [[ "$3" == "7."* || "$3" == "8."* || "$3" == "9."* ]]; then
                    fn="$(awk "/""$replace""/{x=1}x&&/aopfw/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | sed 's/Firmware[/]AOP[/]//' | sed 's/Firmware[/]//')"
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $3 $1)"
                    "$bin"/img4 -i $fn -o "$dir"/$1/clean/$cpid/$3/aopfw.dec -k $ivkey
                else
                    mv $(awk "/""$replace""/{x=1}x&&/aopfw/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | sed 's/Firmware[/]AOP[/]//' | sed 's/Firmware[/]//') "$dir"/$1/clean/$cpid/$3/aopfw.dec
                fi
            fi
        fi
        if [[ ! "$3" == "7."* && ! "$3" == "8."* && ! "$3" == "9."* ]]; then
            if [ ! -e "$dir"/$1/clean/$cpid/$3/homerfw.dec ]; then
                "$bin"/pzb -g $(awk "/""$replace""/{x=1}x&&/homer/{print;exit}" BuildManifest.plist | grep '<string>' | cut -d\> -f2 | cut -d\< -f1)  "$ipswurl"
                if [[ "$3" == "7."* || "$3" == "8."* || "$3" == "9."* ]]; then
                    fn="$(awk "/""$replace""/{x=1}x&&/homer/{print;exit}" BuildManifest.plist | grep '<string>' | cut -d\> -f2 | cut -d\< -f1 | sed 's/Firmware[/]//')"
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $3 $1)"
                    "$bin"/img4 -i $fn -o "$dir"/$1/clean/$cpid/$3/homerfw.dec -k $ivkey
                else
                    mv $(awk "/""$replace""/{x=1}x&&/homer/{print;exit}" BuildManifest.plist | grep '<string>' | cut -d\> -f2 | cut -d\< -f1 | sed 's/Firmware[/]//') "$dir"/$1/clean/$cpid/$3/homerfw.dec
                fi
            fi
        fi
        if [[ ! "$3" == "7."* && ! "$3" == "8."* && ! "$3" == "9."* ]]; then
            if [ ! -e "$dir"/$1/clean/$cpid/$3/avefw.dec ]; then
                "$bin"/pzb -g $(awk "/""$replace""/{x=1}x&&/ave/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1)  "$ipswurl"
                if [[ "$3" == "7."* || "$3" == "8."* || "$3" == "9."* ]]; then
                    fn="$(awk "/""$replace""/{x=1}x&&/ave/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | sed 's/Firmware[/]ave[/]//' | sed 's/Firmware[/]//')"
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $3 $1)"
                    "$bin"/img4 -i $fn -o "$dir"/$1/clean/$cpid/$3/avefw.dec -k $ivkey
                else
                    mv $(awk "/""$replace""/{x=1}x&&/ave/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | sed 's/Firmware[/]ave[/]//' | sed 's/Firmware[/]//') "$dir"/$1/clean/$cpid/$3/avefw.dec
                fi
            fi
        fi
        if [[ ! "$3" == "7."* && ! "$3" == "8."* && ! "$3" == "9."* ]]; then
            if [ ! -e "$dir"/$1/clean/$cpid/$3/multitouch.dec ]; then
                "$bin"/pzb -g $(awk "/""$replace""/{x=1}x&&/[_]Multitouch/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1)  "$ipswurl"
                if [[ "$3" == "7."* || "$3" == "8."* || "$3" == "9."* ]]; then
                    fn="$(awk "/""$replace""/{x=1}x&&/[_]Multitouch/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | sed 's/Firmware[/]Multitouch[/]//' | sed 's/Firmware[/]//')"
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $3 $1)"
                    "$bin"/img4 -i $fn -o "$dir"/$1/clean/$cpid/$3/multitouch.dec -k $ivkey
                else
                    mv $(awk "/""$replace""/{x=1}x&&/[_]Multitouch/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | sed 's/Firmware[/]Multitouch[/]//' | sed 's/Firmware[/]//') "$dir"/$1/clean/$cpid/$3/multitouch.dec
                fi
            fi
        fi
        if [[ ! "$3" == "7."* && ! "$3" == "8."* && ! "$3" == "9."* ]]; then
            if [ ! -e "$dir"/$1/clean/$cpid/$3/audiocodecfirmware.dec ]; then
                "$bin"/pzb -g $(awk "/""$replace""/{x=1}x&&/[A]udioDSP/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1)  "$ipswurl"
                if [[ "$3" == "7."* || "$3" == "8."* || "$3" == "9."* ]]; then
                    fn="$(awk "/""$replace""/{x=1}x&&/[A]udioDSP/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | sed 's/Firmware[/]Callan[/]//' | sed 's/Firmware[/]//')"
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $3 $1)"
                    "$bin"/img4 -i $fn -o "$dir"/$1/clean/$cpid/$3/audiocodecfirmware.dec -k $ivkey
                else
                    mv $(awk "/""$replace""/{x=1}x&&/[A]udioDSP/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | sed 's/Firmware[/]Callan[/]//' | sed 's/Firmware[/]//') "$dir"/$1/clean/$cpid/$3/audiocodecfirmware.dec
                fi
            fi
        fi
        if [ "$os" = "Darwin" ]; then
            fn="$(/usr/bin/plutil -extract "BuildIdentities".0."Manifest"."RestoreRamDisk"."Info"."Path" xml1 -o - BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | head -1)"
        else
            fn="$("$bin"/PlistBuddy -c "Print BuildIdentities:0:Manifest:RestoreRamDisk:Info:Path" BuildManifest.plist | tr -d '"')"
        fi
        if [ ! -e "$dir"/$1/clean/$cpid/$3/RestoreRamDisk.dmg ]; then
            "$bin"/pzb -g "$fn" "$ipswurl"
            if [[ "$3" == "7."* || "$3" == "8."* || "$3" == "9."* ]]; then
                if [[ "$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -e $3 $1)" == "true" ]]; then
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $3 $1)"
                    "$bin"/img4 -i $fn -o "$dir"/$1/clean/$cpid/$3/RestoreRamDisk.dmg -k $ivkey
                else
                    kbag=$("$bin"/img4 -i $fn -b | head -n 1)
                    iv=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ',' -f 1 | cut -d ' ' -f 2)
                    key=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ' ' -f 4)
                    ivkey="$iv$key"
                    "$bin"/img4 -i $fn -o "$dir"/$1/clean/$cpid/$3/RestoreRamDisk.dmg -k $ivkey
                fi
            else
                "$bin"/img4 -i "$fn" -o "$dir"/$1/clean/$cpid/$3/RestoreRamDisk.dmg
            fi
        fi
        if [[ ! "$3" == "7."* && ! "$3" == "8."* && ! "$3" == "9."* && ! "$3" == "10."* && ! "$3" == "11."* ]]; then
            if [ ! -e "$dir"/$1/clean/$cpid/$3/trustcache.img4 ]; then
                local fn
                if [ "$os" = "Darwin" ]; then
                    fn="$(/usr/bin/plutil -extract "BuildIdentities".0."Manifest"."OS"."Info"."Path" xml1 -o - BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | head -1)"
                else
                    fn="$("$bin"/PlistBuddy -c "Print BuildIdentities:0:Manifest:OS:Info:Path" BuildManifest.plist | tr -d '"')"
                fi
                "$bin"/pzb -g Firmware/"$fn".trustcache "$ipswurl"
                mv "$fn".trustcache "$dir"/$1/clean/$cpid/$3/trustcache.im4p
            fi
        fi
        rm -rf BuildManifest.plist
        if [[ "$3" == "9."* ]]; then
            "$bin"/kairos "$dir"/$1/clean/$cpid/$3/iBSS.dec "$dir"/$1/clean/$cpid/$3/iBSS.patched
            "$bin"/kairos "$dir"/$1/clean/$cpid/$3/iBEC.dec "$dir"/$1/clean/$cpid/$3/iBEC.patched -b "$boot_args rd=disk0s1s1 amfi=0xff cs_enforcement_disable=1 keepsyms=1 debug=0x2014e PE_i_can_has_debugger=1 amfi_get_out_of_my_way=1 amfi_allow_any_signature=1" -n
        else
            "$bin"/iBoot64Patcher "$dir"/$1/clean/$cpid/$3/iBSS.dec "$dir"/$1/clean/$cpid/$3/iBSS.patched
            "$bin"/iBoot64Patcher "$dir"/$1/clean/$cpid/$3/iBEC.dec "$dir"/$1/clean/$cpid/$3/iBEC.patched -b "$boot_args rd=disk0s1s1 amfi=0xff cs_enforcement_disable=1 keepsyms=1 debug=0x2014e PE_i_can_has_debugger=1 amfi_get_out_of_my_way=1 amfi_allow_any_signature=1" -n
        fi
        "$bin"/img4 -i "$dir"/$1/clean/$cpid/$3/iBSS.patched -o "$dir"/$1/clean/$cpid/$3/iBSS.img4 -M IM4M -A -T ibss
        "$bin"/img4 -i "$dir"/$1/clean/$cpid/$3/iBEC.patched -o "$dir"/$1/clean/$cpid/$3/iBEC.img4 -M IM4M -A -T ibec
        "$bin"/img4 -i "$dir"/$1/clean/$cpid/$3/aopfw.dec -o "$dir"/$1/clean/$cpid/$3/aopfw.img4 -M IM4M -T aopf
        if [ -e "$dir"/$1/clean/$cpid/$3/homerfw.dec ]; then
            "$bin"/img4 -i "$dir"/$1/clean/$cpid/$3/homerfw.dec -o "$dir"/$1/clean/$cpid/$3/homerfw.img4 -M IM4M -T homr
        fi
        if [ -e "$dir"/$1/clean/$cpid/$3/avefw.dec ]; then
            "$bin"/img4 -i "$dir"/$1/clean/$cpid/$3/avefw.dec -o "$dir"/$1/clean/$cpid/$3/avefw.img4 -M IM4M -T avef
        fi
        if [ -e "$dir"/$1/clean/$cpid/$3/multitouch.dec ]; then
            "$bin"/img4 -i "$dir"/$1/clean/$cpid/$3/multitouch.dec -o "$dir"/$1/clean/$cpid/$3/multitouch.img4 -M IM4M -T mtfw
        fi
        if [ -e "$dir"/$1/clean/$cpid/$3/audiocodecfirmware.dec ]; then
            "$bin"/img4 -i "$dir"/$1/clean/$cpid/$3/audiocodecfirmware.dec -o "$dir"/$1/clean/$cpid/$3/audiocodecfirmware.img4 -M IM4M -T acfw
        fi
        if [[ "$3" == "15."* || "$3" == "16."* ]]; then
            cp "$dir"/$1/clean/$cpid/$3/kcache.raw "$dir"/$1/clean/$cpid/$3/kcache.patched
            "$bin"/KPlooshFinder2 "$dir"/$1/clean/$cpid/$3/kcache.patched "$dir"/$1/clean/$cpid/$3/kcache2.patched
        else
            "$bin"/KPlooshFinder "$dir"/$1/clean/$cpid/$3/kcache.raw "$dir"/$1/clean/$cpid/$3/kcache.patched
            "$bin"/Kernel64Patcher "$dir"/$1/clean/$cpid/$3/kcache.patched "$dir"/$1/clean/$cpid/$3/kcache2.patched -f $(echo "$3" | cut -d '.' -f 1)
        fi
        "$bin"/kerneldiff "$dir"/$1/clean/$cpid/$3/kcache.raw "$dir"/$1/clean/$cpid/$3/kcache2.patched "$dir"/$1/clean/$cpid/$3/kc.bpatch
        if [[ "$?" == "0" ]]; then
            "$bin"/img4 -i "$dir"/$1/clean/$cpid/$3/kernelcache.dec -o "$dir"/$1/clean/$cpid/$3/kernelcache.img4 -M IM4M -T rkrn -P "$dir"/$1/clean/$cpid/$3/kc.bpatch
            "$bin"/img4 -i "$dir"/$1/clean/$cpid/$3/kernelcache.dec -o "$dir"/$1/clean/$cpid/$3/kernelcache -M IM4M -T krnl -P "$dir"/$1/clean/$cpid/$3/kc.bpatch
        else
            if [[ "$deviceid" == *'iPhone8'* ]] || [[ "$deviceid" == *'iPad6'* ]] || [[ "$deviceid" == *'iPad5'* ]]; then
                python3 -m pyimg4 im4p create -i "$dir"/$1/clean/$cpid/$3/kcache2.patched -o "$dir"/$1/clean/$cpid/$3/kernelcache.im4p.img4 --extra "$dir"/$1/clean/$cpid/$3/kpp.bin -f rkrn --lzss
                python3 -m pyimg4 im4p create -i "$dir"/$1/clean/$cpid/$3/kcache2.patched -o "$dir"/$1/clean/$cpid/$3/kernelcache.im4p --extra "$dir"/$1/clean/$cpid/$3/kpp.bin -f krnl --lzss
            else
                python3 -m pyimg4 im4p create -i "$dir"/$1/clean/$cpid/$3/kcache2.patched -o "$dir"/$1/clean/$cpid/$3/kernelcache.im4p.img4 -f rkrn --lzss
                python3 -m pyimg4 im4p create -i "$dir"/$1/clean/$cpid/$3/kcache2.patched -o "$dir"/$1/clean/$cpid/$3/kernelcache.im4p -f krnl --lzss
            fi
            python3 -m pyimg4 img4 create -p "$dir"/$1/clean/$cpid/$3/kernelcache.im4p.img4 -o "$dir"/$1/clean/$cpid/$3/kernelcache.img4 -m IM4M
            python3 -m pyimg4 img4 create -p "$dir"/$1/clean/$cpid/$3/kernelcache.im4p -o "$dir"/$1/clean/$cpid/$3/kernelcache -m IM4M
        fi
        if [ -e "$dir"/$1/clean/$cpid/$3/trustcache.im4p ]; then
            "$bin"/img4 -i "$dir"/$1/clean/$cpid/$3/trustcache.im4p -o "$dir"/$1/clean/$cpid/$3/trustcache.img4 -M IM4M -T rtsc
            "$bin"/img4 -i "$dir"/$1/clean/$cpid/$3/trustcache.im4p -o "$dir"/$1/clean/$cpid/$3/trustcache -M IM4M -T trst
        fi
        if [[ "$3" == "7."* || "$3" == "8."* || "$3" == "9."* ]]; then
            "$bin"/img4 -i "$dir"/$1/clean/$cpid/$3/DeviceTree.dec -o "$dir"/$1/clean/$cpid/$3/devicetree.img4 -A -M IM4M -T rdtr
        else
            "$bin"/img4 -i "$dir"/$1/clean/$cpid/$3/DeviceTree.dec -o "$dir"/$1/clean/$cpid/$3/devicetree.img4 -M IM4M -T rdtr
        fi
    fi
    cd ..
    rm -rf work
}
_download_root_fs() {
    ipswurl=$(curl -k -sL "https://api.ipsw.me/v4/device/$deviceid?type=ipsw" | "$bin"/jq '.firmwares | .[] | select(.version=="'$3'")' | "$bin"/jq -s '.[0] | .url' --raw-output)
    rm -rf BuildManifest.plist
    mkdir -p "$dir"/$1/$cpid/$3
    rm -rf "$dir"/work
    mkdir "$dir"/work
    cd "$dir"/work
    rm -rf IM4M
    "$bin"/img4tool -e -s "$dir"/$1/0.0/shsh.shsh2 -m IM4M
    if [ ! -e "$dir"/$1/$cpid/$3/ipswcfw.ipsw ]; then
        rm -rf "$dir"/$1/$cpid/$3/ipswcfw
        mkdir -p "$dir"/$1/$cpid/$3/ipswcfw
        local fn
        "$bin"/pzb -g BuildManifest.plist "$ipswurl"
        if [ "$os" = "Darwin" ]; then
            fn="$(/usr/bin/plutil -extract "BuildIdentities".0."Manifest"."OS"."Info"."Path" xml1 -o - BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | head -1)"
        else
            fn="$("$bin"/PlistBuddy -c "Print BuildIdentities:0:Manifest:OS:Info:Path" BuildManifest.plist | tr -d '"')"
        fi
        ipswfn=$(echo ${ipswurl##*/})
        cd "$dir"/$1/$cpid/$3/
        if [ ! -e $ipswfn ]; then
            "$bin"/aria2c --file-allocation=none $ipswurl
        fi
        cp $(find . -name '*.ipsw*') "$dir"/$1/$cpid/$3/ipswcfw
        cd "$dir"/$1/$cpid/$3/ipswcfw
        "$bin"/7z x $(find . -name '*.ipsw*')
        mkdir work
        "$bin"/img4tool -e -s "$dir"/$1/0.0/shsh.shsh2 -m IM4M
        if [[ "$3" == "7."* || "$3" == "8."* || "$3" == "9."* ]]; then
            if [ ! -e "$dir"/$1/$cpid/$3/OS.dmg ]; then
                cd "$dir"/work
                if [[ "$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -e $3 $1)" == "true" ]]; then
                    cd "$dir"/$1/$cpid/$3/ipswcfw
                    local fn
                    "$bin"/pzb -g BuildManifest.plist "$ipswurl"
                    if [ "$os" = "Darwin" ]; then
                        fn="$(/usr/bin/plutil -extract "BuildIdentities".0."Manifest"."OS"."Info"."Path" xml1 -o - BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | head -1)"
                    else
                        fn="$("$bin"/PlistBuddy -c "Print BuildIdentities:0:Manifest:OS:Info:Path" BuildManifest.plist | tr -d '"')"
                    fi
                    cd "$dir"/work
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $3 $1)"
                    cd "$dir"/$1/$cpid/$3/ipswcfw
                    "$bin"/dmg extract $fn "$dir"/$1/$cpid/$3/OS.dmg -k $ivkey
                else
                    cd "$dir"/$1/$cpid/$3/ipswcfw
                    local fno
                    local fnr
                    "$bin"/pzb -g BuildManifest.plist "$ipswurl"
                    if [ "$os" = "Darwin" ]; then
                        fno="$(/usr/bin/plutil -extract "BuildIdentities".0."Manifest"."OS"."Info"."Path" xml1 -o - BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | head -1)"
                        fnr="$(/usr/bin/plutil -extract "BuildIdentities".0."Manifest"."RestoreRamDisk"."Info"."Path" xml1 -o - BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | head -1)"
                    else
                        fno="$("$bin"/PlistBuddy -c "Print BuildIdentities:0:Manifest:OS:Info:Path" BuildManifest.plist | tr -d '"')"
                        fnr="$("$bin"/PlistBuddy -c "Print BuildIdentities:0:Manifest:RestoreRamDisk:Info:Path" BuildManifest.plist | tr -d '"')"
                    fi
                    if [ ! -e "$dir"/$1/$cpid/$3/RestoreRamDisk.dmg ]; then
                        "$bin"/pzb -g "$fnr" "$ipswurl"
                        if [[ "$3" == "7."* || "$3" == "8."* || "$3" == "9."* ]]; then
                            fn="$fnr"
                            cd "$dir"/work
                            if [[ "$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -e $3 $1)" == "true" ]]; then
                                ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $3 $1)"
                                cd "$dir"/$1/$cpid/$3/ipswcfw
                                "$bin"/img4 -i $fn -o "$dir"/$1/$cpid/$3/RestoreRamDisk.dmg -k $ivkey
                            else
                                cd "$dir"/$1/$cpid/$3/ipswcfw
                                kbag=$("$bin"/img4 -i $fn -b | head -n 1)
                                iv=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ',' -f 1 | cut -d ' ' -f 2)
                                key=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ' ' -f 4)
                                ivkey="$iv$key"
                                "$bin"/img4 -i $fn -o "$dir"/$1/$cpid/$3/RestoreRamDisk.dmg -k $ivkey
                            fi
                        else
                            "$bin"/img4 -i "$fnr" -o "$dir"/$1/$cpid/$3/RestoreRamDisk.dmg
                        fi
                    fi
                    fn="$fno"
                    ivkey=$("$bin"/pass2key $scid "$dir"/$1/$cpid/$3/RestoreRamDisk.dmg $fn | tail -n 1 | cut -d ' ' -f 3)
                    "$bin"/dmg extract $fn "$dir"/$1/$cpid/$3/OS.dmg -k $ivkey
                fi
            fi
            if [ ! -e "$dir"/$1/$cpid/$3/rw.dmg ]; then
                "$bin"/dmg build "$dir"/$1/$cpid/$3/OS.dmg "$dir"/$1/$cpid/$3/rw.dmg
            fi
            rm -rf $fn
            cp "$dir"/$1/$cpid/$3/rw.dmg $fn
        fi
        # rdsk
        rdskpath=$(plutil -extract "BuildIdentities".0."Manifest"."RestoreRamDisk"."Info"."Path" xml1 -o - BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | head -1)
        cp "$dir"/$1/$cpid/$3/RestoreRamDisk.dmg work/rdsk.dmg
        mkdir rdmount
        current_size=$(stat -f %z work/rdsk.dmg)
        hdiutil resize -size "$((current_size + 10000000))" work/rdsk.dmg # 10MB more
        hdiutil attach -mountpoint rdmount work/rdsk.dmg
        if [[ "$3" == "7"* ]]; then
            "$bin"/dsc64patcher2 ./rdmount/System/Library/PrivateFrameworks/MobileKeyBag.framework/MobileKeyBag ./work/MobileKeyBag.patched -7
        elif [[ "$3" == "8"* ]]; then
            "$bin"/dsc64patcher2 ./rdmount/System/Library/PrivateFrameworks/MobileKeyBag.framework/MobileKeyBag ./work/MobileKeyBag.patched -8
        elif [[ "$3" == "9"* ]]; then
            "$bin"/dsc64patcher2 ./rdmount/System/Library/PrivateFrameworks/MobileKeyBag.framework/MobileKeyBag ./work/MobileKeyBag.patched -9
        elif [[ "$3" == "10.0"* || "$3" == "10.1"* || "$3" == "10.2"* ]]; then
            "$bin"/dsc64patcher2 ./rdmount/System/Library/PrivateFrameworks/MobileKeyBag.framework/MobileKeyBag ./work/MobileKeyBag.patched -10
        elif [[ "$3" == "10."* ]]; then
            "$bin"/dsc64patcher2 ./rdmount/System/Library/PrivateFrameworks/MobileKeyBag.framework/MobileKeyBag ./work/MobileKeyBag.patched -103
        elif [[ "$3" == "11.0"* || "$3" == "11.1"* || "$3" == "11.2"* ]]; then
            "$bin"/dsc64patcher2 ./rdmount/System/Library/PrivateFrameworks/MobileKeyBag.framework/MobileKeyBag ./work/MobileKeyBag.patched -11
        elif [[ "$3" == "11."* ]]; then
            "$bin"/dsc64patcher2 ./rdmount/System/Library/PrivateFrameworks/MobileKeyBag.framework/MobileKeyBag ./work/MobileKeyBag.patched -113
        elif [[ "$3" == "12.0"* || "$3" == "12.1"* ]]; then
            "$bin"/dsc64patcher2 ./rdmount/System/Library/PrivateFrameworks/MobileKeyBag.framework/MobileKeyBag ./work/MobileKeyBag.patched -12
        elif [[ "$3" == "12."* ]]; then
            "$bin"/dsc64patcher2 ./rdmount/System/Library/PrivateFrameworks/MobileKeyBag.framework/MobileKeyBag ./work/MobileKeyBag.patched -122
        elif [[ "$3" == "13.0"* || "$3" == "13.1"* || "$3" == "13.2"* || "$3" == "13.3"* ]]; then
            "$bin"/dsc64patcher2 ./rdmount/System/Library/PrivateFrameworks/MobileKeyBag.framework/MobileKeyBag ./work/MobileKeyBag.patched -13
        elif [[ "$3" == "13."* ]]; then
            "$bin"/dsc64patcher2 ./rdmount/System/Library/PrivateFrameworks/MobileKeyBag.framework/MobileKeyBag ./work/MobileKeyBag.patched -134
        elif [[ "$3" == "14."* ]]; then
            "$bin"/dsc64patcher2 ./rdmount/System/Library/PrivateFrameworks/MobileKeyBag.framework/MobileKeyBag ./work/MobileKeyBag.patched -14
        else
            cp ./rdmount/System/Library/PrivateFrameworks/MobileKeyBag.framework/MobileKeyBag ./work/MobileKeyBag.patched
        fi
        "$bin"/ldid -e ./rdmount/System/Library/PrivateFrameworks/MobileKeyBag.framework/MobileKeyBag > ./work/MobileKeyBag.xml
        "$bin"/ldid -S./work/MobileKeyBag.xml ./work/MobileKeyBag.patched 2> /dev/null
        cp -av ./work/MobileKeyBag.patched ./rdmount/System/Library/PrivateFrameworks/MobileKeyBag.framework/MobileKeyBag
        #"$bin"/restored_external64patcher ./rdmount/usr/local/bin/restored_external ./work/restored_external.patched -s -b
        #"$bin"/Kernel64Patcher ./work/restored_external2.patched ./work/restored_external.patched -i
        "$bin"/restored_external64patcher ./rdmount/usr/local/bin/restored_external ./work/restored_external.patched -s -b -f
        "$bin"/Kernel64Patcher ./work/restored_external2.patched ./work/restored_external.patched -i
        "$bin"/ldid -e ./rdmount/usr/local/bin/restored_external > ./work/restored_external.xml
        "$bin"/ldid -S./work/restored_external.xml ./work/restored_external.patched 2> /dev/null
        cp -av ./work/restored_external.patched ./rdmount/usr/local/bin/restored_external
        chmod +x ./rdmount/usr/local/bin/restored_external
        chmod 755 ./rdmount/usr/local/bin/restored_external
        "$bin"/asr64_patcher ./rdmount/usr/sbin/asr ./work/asr.patched
        "$bin"/ldid -e ./rdmount/usr/sbin/asr > ./work/asr.xml
        "$bin"/ldid -S./work/asr.xml ./work/asr.patched 2> /dev/null
        cp -av ./work/asr.patched ./rdmount/usr/sbin/asr
        chmod +x ./rdmount/usr/sbin/asr
        chmod 755 ./rdmount/usr/sbin/asr
        hdiutil detach rdmount
        if [[ "$3" == "15"* ]]; then
            "$bin"/img4tool -c work/rdsk.im4p -t rdsk work/rdsk.dmg
        else
            "$bin"/img4 -i work/rdsk.dmg -o work/rdsk.im4p -A -T rdsk
        fi
        # get build id from version
        cd "$dir"/work
        buildid="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -b $3 $1)"
        cd "$dir"/$1/$cpid/$3/ipswcfw
        # illb
        illbpath="$(awk "/""${replace}""/{x=1}x&&/LLB[.]/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1)"
        cp "$dir"/$1/$cpid/$3/LLB.dec work/illb.dec
        if [[ "$3" == "7."* || "$3" == "8."* || "$3" == "9."* ]]; then
            if [[ ! "$deviceid" == "iPhone6"* && ! "$deviceid" == "iPhone7"* && ! "$deviceid" == "iPad4"* && ! "$deviceid" == "iPad5"* && ! "$deviceid" == "iPod7"* && "$3" == "9."* ]]; then
                "$bin"/kairos work/illb.dec work/illb.patched
                if [[ ! "$?" == "0" ]]; then
                    "$bin"/iBoot64Patcher work/illb.dec work/illb.patched
                fi
            elif [[ "$3" == "9."* ]]; then
                "$bin"/kairos work/illb.dec work/illb.patched
                if [[ ! "$?" == "0" ]]; then
                    "$bin"/iBoot64Patcher work/illb.dec work/illb.patched
                fi
            else
                "$bin"/ipatcher work/illb.dec work/illb.patched
            fi
        else
            "$bin"/iBoot64Patcher work/illb.dec work/illb.patched
        fi
        "$bin"/img4 -i work/illb.patched -o work/illb.im4p -A -T illb
        # ibot
        ibotpath="$(awk "/""${replace}""/{x=1}x&&/iBoot[.]/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1)"
        cp "$dir"/$1/$cpid/$3/iBoot.dec work/ibot.dec
        if [[ "$3" == "7."* || "$3" == "8."* || "$3" == "9."* ]]; then
            if [[ ! "$deviceid" == "iPhone6"* && ! "$deviceid" == "iPhone7"* && ! "$deviceid" == "iPad4"* && ! "$deviceid" == "iPad5"* && ! "$deviceid" == "iPod7"* && "$3" == "9."* ]]; then
                "$bin"/kairos work/ibot.dec work/ibot2.patched -b "rd=md0 debug=0x2014e amfi=0xff cs_enforcement_disable=1 $boot_args wdt=-1 `if [ "$check" = '0x8960' ] || [ "$check" = '0x7000' ] || [ "$check" = '0x7001' ]; then echo "-restore"; fi`"
                if [[ ! "$?" == "0" ]]; then
                    "$bin"/iBoot64Patcher work/ibot.dec work/ibot2.patched -b "rd=md0 debug=0x2014e amfi=0xff cs_enforcement_disable=1 $boot_args wdt=-1 `if [ "$check" = '0x8960' ] || [ "$check" = '0x7000' ] || [ "$check" = '0x7001' ]; then echo "-restore"; fi`"
                fi
                "$bin"/iBoot64Patcher2 work/ibot2.patched work/ibot.patched -n
                if [[ ! "$?" == "0" ]]; then
                    cp work/ibot2.patched work/ibot.patched
                fi
            elif [[ "$3" == "9."* ]]; then
                "$bin"/kairos work/ibot.dec work/ibot2.patched -b "amfi=0xff cs_enforcement_disable=1 $boot_args rd=md0 nand-enable-reformat=1 -progress"
                if [[ ! "$?" == "0" ]]; then
                    "$bin"/iBoot64Patcher work/ibot.dec work/ibot2.patched -b "amfi=0xff cs_enforcement_disable=1 $boot_args rd=md0 nand-enable-reformat=1 -progress"
                fi
                "$bin"/iBoot64Patcher2 work/ibot2.patched work/ibot.patched -n
                if [[ ! "$?" == "0" ]]; then
                    cp work/ibot2.patched work/ibot.patched
                fi
            else
                "$bin"/ipatcher work/ibot.dec work/ibot.patched -b "amfi=0xff cs_enforcement_disable=1 $boot_args rd=md0 nand-enable-reformat=1 -progress"
            fi
        else
            if [[ ! "$deviceid" == "iPhone6"* && ! "$deviceid" == "iPhone7"* && ! "$deviceid" == "iPad4"* && ! "$deviceid" == "iPad5"* && ! "$deviceid" == "iPod7"* ]]; then
                "$bin"/iBoot64Patcher work/ibot.dec work/ibot.patched -b "rd=md0 debug=0x2014e $boot_args wdt=-1 `if [ "$check" = '0x8960' ] || [ "$check" = '0x7000' ] || [ "$check" = '0x7001' ]; then echo "-restore"; fi`" -n
            else
                "$bin"/iBoot64Patcher work/ibot.dec work/ibot.patched -b "amfi=0xff cs_enforcement_disable=1 $boot_args rd=md0 nand-enable-reformat=1 amfi_get_out_of_my_way=1 -restore -progress" -n
            fi
        fi
        "$bin"/img4 -i work/ibot.patched -o work/ibot.im4p -A -T ibot
        rm -rf /tmp/futurerestore
        mkdir -p /tmp/futurerestore
        # ibss
        ibsspath="$(awk "/""${replace}""/{x=1}x&&/iBSS[.]/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1)"
        cp "$dir"/$1/$cpid/$3/iBSS.dec work/ibss.dec
        if [[ "$3" == "7."* || "$3" == "8."* || "$3" == "9."* ]]; then
            if [[ ! "$deviceid" == "iPhone6"* && ! "$deviceid" == "iPhone7"* && ! "$deviceid" == "iPad4"* && ! "$deviceid" == "iPad5"* && ! "$deviceid" == "iPod7"* && "$3" == "9."* ]]; then
                "$bin"/kairos work/ibss.dec work/ibss.patched
                if [[ ! "$?" == "0" ]]; then
                    "$bin"/iBoot64Patcher work/ibss.dec work/ibss.patched
                fi
            elif [[ "$3" == "9."* ]]; then
                "$bin"/kairos work/ibss.dec work/ibss.patched
                if [[ ! "$?" == "0" ]]; then
                    "$bin"/iBoot64Patcher work/ibss.dec work/ibss.patched
                fi
            else
                "$bin"/ipatcher work/ibss.dec work/ibss.patched
            fi
        else
            "$bin"/iBoot64Patcher work/ibss.dec work/ibss.patched
        fi
        "$bin"/img4 -i work/ibss.patched -o work/ibss.im4p -A -T ibss
        "$bin"/img4 -i work/ibss.patched -o work/ibss.img4 -M IM4M -A -T ibss
        cp work/ibss.img4 /tmp/futurerestore/ibss.$replace.$buildid.patched.img4
        # ibec
        ibecpath="$(awk "/""${replace}""/{x=1}x&&/iBEC[.]/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1)"
        cp "$dir"/$1/$cpid/$3/iBEC.dec work/ibec.dec
        if [[ "$3" == "7."* || "$3" == "8."* || "$3" == "9."* ]]; then
            if [[ ! "$deviceid" == "iPhone6"* && ! "$deviceid" == "iPhone7"* && ! "$deviceid" == "iPad4"* && ! "$deviceid" == "iPad5"* && ! "$deviceid" == "iPod7"* && "$3" == "9."* ]]; then
                "$bin"/kairos work/ibec.dec work/ibec2.patched -b "rd=md0 debug=0x2014e amfi=0xff cs_enforcement_disable=1 $boot_args wdt=-1 `if [ "$check" = '0x8960' ] || [ "$check" = '0x7000' ] || [ "$check" = '0x7001' ]; then echo "-restore"; fi`"
                if [[ ! "$?" == "0" ]]; then
                    "$bin"/iBoot64Patcher work/ibec.dec work/ibec2.patched -b "rd=md0 debug=0x2014e amfi=0xff cs_enforcement_disable=1 $boot_args wdt=-1 `if [ "$check" = '0x8960' ] || [ "$check" = '0x7000' ] || [ "$check" = '0x7001' ]; then echo "-restore"; fi`"
                fi
                "$bin"/iBoot64Patcher2 work/ibec2.patched work/ibec.patched -n
                if [[ ! "$?" == "0" ]]; then
                    cp work/ibec2.patched work/ibec.patched
                fi
            elif [[ "$3" == "9."* ]]; then
                "$bin"/kairos work/ibec.dec work/ibec2.patched -b "amfi=0xff cs_enforcement_disable=1 $boot_args rd=md0 nand-enable-reformat=1 -progress"
                if [[ ! "$?" == "0" ]]; then
                    "$bin"/iBoot64Patcher work/ibec.dec work/ibec2.patched -b "amfi=0xff cs_enforcement_disable=1 $boot_args rd=md0 nand-enable-reformat=1 -progress"
                fi
                "$bin"/iBoot64Patcher2 work/ibec2.patched work/ibec.patched -n
                if [[ ! "$?" == "0" ]]; then
                    cp work/ibec2.patched work/ibec.patched
                fi
            else
                "$bin"/ipatcher work/ibec.dec work/ibec.patched -b "amfi=0xff cs_enforcement_disable=1 $boot_args rd=md0 nand-enable-reformat=1 -progress"
            fi
        else
            if [[ ! "$deviceid" == "iPhone6"* && ! "$deviceid" == "iPhone7"* && ! "$deviceid" == "iPad4"* && ! "$deviceid" == "iPad5"* && ! "$deviceid" == "iPod7"* && ! "$3" == "10."* ]]; then
                "$bin"/iBoot64Patcher work/ibec.dec work/ibec.patched -b "rd=md0 debug=0x2014e $boot_args wdt=-1 nand-enable-reformat=1 `if [ "$check" = '0x8960' ] || [ "$check" = '0x7000' ] || [ "$check" = '0x7001' ]; then echo "-restore"; fi`" -n
            elif [[ ! "$deviceid" == "iPhone6"* && ! "$deviceid" == "iPhone7"* && ! "$deviceid" == "iPad4"* && ! "$deviceid" == "iPad5"* && ! "$deviceid" == "iPod7"* ]]; then
                "$bin"/iBoot64Patcher work/ibec.dec work/ibec.patched -b "rd=md0 debug=0x2014e $boot_args wdt=-1 `if [ "$check" = '0x8960' ] || [ "$check" = '0x7000' ] || [ "$check" = '0x7001' ]; then echo "-restore"; fi`" -n
            else
                "$bin"/iBoot64Patcher work/ibec.dec work/ibec.patched -b "amfi=0xff cs_enforcement_disable=1 $boot_args rd=md0 nand-enable-reformat=1 amfi_get_out_of_my_way=1 -restore -progress" -n
            fi
        fi
        "$bin"/img4 -i work/ibec.patched -o work/ibec.im4p -A -T ibec
        "$bin"/img4 -i work/ibec.patched -o work/ibec.img4 -M IM4M -A -T ibec
        cp work/ibec.img4 "/tmp/futurerestore/ibec.$replace.$buildid.patched.img4"
        # dtre
        dtrepath="$(awk "/""${replace}""/{x=1}x&&/DeviceTree[.]/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1)"
        if [[ "$3" == "10."* || "$3" == "11."* || "$3" == "12."* || "$3" == "13."* || "$3" == "14."* ]]; then
            "$bin"/img4 -i "$dir"/$1/$cpid/$3/DeviceTree.dec -o work/dtree.raw 
        else
            cp "$dir"/$1/$cpid/$3/DeviceTree.dec work/dtree.raw
        fi
        LC_ALL=C sed -i '' 's/content-protect/mineeek-protect/g' work/dtree.raw
        "$bin"/img4 -i work/dtree.raw -o work/dtre.im4p -A -T dtre
        # rkrn
        rkrnpath="$(awk "/""${replace}""/{x=1}x&&/kernelcache.release/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1)"
        krnlpath="$(awk "/""${replace}""/{x=1}x&&/kernelcache.release/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1)"
        cp "$dir"/$1/$cpid/$3/kcache.raw work/kcache.raw
        if [[ "$3" == "7."* ]]; then
            cp work/kcache.raw work/kcache1.raw
            "$bin"/Kernel64Patcher work/kcache1.raw work/kcache2.raw -u 7 -f 7 -k
        elif [[ "$3" == "8"* ]]; then
            cp work/kcache.raw work/kcache1.raw
            "$bin"/Kernel64Patcher work/kcache1.raw work/kcache2.raw -u 8 -f 8 -k
        elif [[ "$3" == "9"* ]]; then
            cp work/kcache.raw work/kcache1.raw
            "$bin"/Kernel64Patcher work/kcache1.raw work/kcache2.raw -u 9 -f 9 -k
        elif [[ "$3" == "10."* ]]; then
            "$bin"/KPlooshFinder work/kcache.raw work/kcache1.raw
            "$bin"/Kernel64Patcher work/kcache1.raw work/kcache2.raw -u 10 -f 10 -q -a
        elif [[ "$3" == "11"* ]]; then
            "$bin"/KPlooshFinder work/kcache.raw work/kcache1.raw
            if [[ "$3" == "11.3"* || "$3" == "11.4"* ]]; then
                if [[ "$deviceid" == "iPhone10"* || "$cpid" == "0x8015"* ]]; then
                    "$bin"/Kernel64Patcher work/kcache1.raw work/kcache2.raw -u 11 -f 11 -r -c
                else
                    "$bin"/Kernel64Patcher work/kcache1.raw work/kcache2.raw -u 11 -f 11 -r
                fi
            else
                if [[ "$deviceid" == "iPhone10"* || "$cpid" == "0x8015"* ]]; then
                    "$bin"/Kernel64Patcher work/kcache1.raw work/kcache2.raw -u 11 -f 11 -b -c
                else
                    "$bin"/Kernel64Patcher work/kcache1.raw work/kcache2.raw -u 11 -f 11 -b
                fi
            fi
        elif [[ "$3" == "12"* ]]; then
            "$bin"/KPlooshFinder work/kcache.raw work/kcache1.raw
            if [[ "$deviceid" == "iPhone10"* || "$cpid" == "0x8015"* ]]; then
                "$bin"/Kernel64Patcher work/kcache1.raw work/kcache2.raw -u 12 -r -f 12 -c
            else
                "$bin"/Kernel64Patcher work/kcache1.raw work/kcache2.raw -u 12 -r -f 12
            fi
        elif [[ "$3" == "13"* ]]; then
            "$bin"/KPlooshFinder work/kcache.raw work/kcache1.raw
            "$bin"/Kernel64Patcher work/kcache1.raw work/kcache2.raw -z -r -f 13
        elif [[ "$3" == "14"* ]]; then
            "$bin"/KPlooshFinder work/kcache.raw work/kcache1.raw
            "$bin"/Kernel64Patcher work/kcache1.raw work/kcache2.raw -w -f 14
        elif [[ "$3" == "15."* || "$3" == "16."* ]]; then
            #cp work/kcache.raw work/kcache1.raw
            #"$bin"/KPlooshFinder2 work/kcache1.raw work/kcache2.raw
            "$bin"/KPlooshFinder work/kcache.raw work/kcache2.raw
        fi
        "$bin"/kerneldiff work/kcache.raw work/kcache2.raw work/kc.bpatch
        if [[ "$?" == "0" ]]; then
            "$bin"/img4 -i "$dir"/$1/$cpid/$3/kernelcache.dec -o work/rkrn.im4p -T rkrn -P work/kc.bpatch
            "$bin"/img4 -i "$dir"/$1/$cpid/$3/kernelcache.dec -o work/krnl.im4p -T krnl -P work/kc.bpatch
            "$bin"/img4 -i "$dir"/$1/$cpid/$3/kernelcache.dec -o work/rkrn.img4 -M IM4M -T rkrn -P work/kc.bpatch
            "$bin"/img4 -i "$dir"/$1/$cpid/$3/kernelcache.dec -o work/krnl.img4 -M IM4M -T krnl -P work/kc.bpatch
        else
            if [[ "$deviceid" == *'iPhone8'* ]] || [[ "$deviceid" == *'iPad6'* ]] || [[ "$deviceid" == *'iPad5'* ]]; then
                python3 -m pyimg4 im4p create -i work/kcache2.raw -o work/rkrn.im4p --extra "$dir"/$1/$cpid/$3/kpp.bin -f rkrn --lzss
                python3 -m pyimg4 im4p create -i work/kcache2.raw -o work/krnl.im4p --extra "$dir"/$1/$cpid/$3/kpp.bin -f krnl --lzss
            else
                python3 -m pyimg4 im4p create -i work/kcache2.raw -o work/rkrn.im4p -f rkrn --lzss
                python3 -m pyimg4 im4p create -i work/kcache2.raw -o work/krnl.im4p -f krnl --lzss
            fi
            python3 -m pyimg4 img4 create -p work/rkrn.im4p -o work/rkrn.img4 -m IM4M
            python3 -m pyimg4 img4 create -p work/krnl.im4p -o work/krnl.img4 -m IM4M
        fi
        rm -vf "$illbpath"
        rm -vf "$ibotpath"
        rm -vf "$krnlpath"
        cp -av work/illb.im4p "$illbpath"
        cp -av work/ibot.im4p "$ibotpath"
        cp -av work/krnl.im4p "$krnlpath"
        rm -vf "$dtrepath"
        cp -av work/dtre.im4p "$dtrepath"
        rm -rf "$dir"/$1/$cpid/$3/rdsk.im4p
        rm -rf "$dir"/$1/$cpid/$3/dtre.im4p
        rm -rf "$dir"/$1/$cpid/$3/rkrn.im4p
        cp -av work/rdsk.im4p "$dir"/$1/$cpid/$3/rdsk.im4p
        cp -av work/dtre.im4p "$dir"/$1/$cpid/$3/dtre.im4p
        cp -av work/rkrn.im4p "$dir"/$1/$cpid/$3/rkrn.im4p
        rm -rf rdmount
        rm -rf work
        rm -rf IM4M
        rm -rf *.ipsw
        zip -0 -r "$dir"/$1/$cpid/$3/ipswcfw.ipsw *
        info "CFW created"
        cd "$dir"/work
        rm -rf "$dir"/$1/$cpid/$3/ipswcfw/
        mkdir -p "$dir"/$1/$cpid/$3/ipswcfw/
        cp /tmp/futurerestore/ibss.$replace.$buildid.patched.img4 "$dir"/$1/$cpid/$3/ipswcfw/ibss.$replace.$buildid.patched.img4
        cp /tmp/futurerestore/ibec.$replace.$buildid.patched.img4 "$dir"/$1/$cpid/$3/ipswcfw/ibec.$replace.$buildid.patched.img4
    else
        rm -rf /tmp/futurerestore
        mkdir -p /tmp/futurerestore
        cp -av "$dir"/$1/$cpid/$3/ipswcfw/* /tmp/futurerestore
    fi
    cd ..
    rm -rf work
}
_get_ios_ver_prior_to_downgrade() {
    if [[ -e "$dir"/$deviceid/0.0/SystemVersion.plist ]]; then
        cd "$dir"/$deviceid/0.0/
        if [ "$os" = "Darwin" ]; then
            r="$(/usr/bin/plutil -extract "ProductVersion" xml1 -o - SystemVersion.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | head -1)"
        else
            r="$("$bin"/PlistBuddy -c "Print ProductVersion" SystemVersion.plist | tr -d '"')"
        fi
        info "$r"
        cd "$dir"/
    fi
    if [ -z "$r" ]; then
        warning "What iOS version is or was installed on this device prior to downgrade?"
        read r
        if [[ "$(./java/bin/java -jar ./Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -e $r $deviceid)" == "false" ]]; then
            if [[ ! "$device_os" == "iPadOS" || "$(./java/bin/java -jar ./Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -e 12.1 $deviceid)" == "true" ]]; then
                r=""
                error "That version does not exist"
                exit 1
            fi
        fi
        info "$r"
        if [[ ! -e "$dir"/$deviceid/0.0/apticket.der || ! -e "$dir"/$deviceid/0.0/sep-firmware.img4 || ! -e "$dir"/$deviceid/0.0/keybags || ! -e "$dir"/$deviceid/0.0/shsh.shsh2 ]]; then
            version="$r"
        fi
    fi
}
_kill_if_running() {
    if (pgrep -u root -xf "$1" &> /dev/null > /dev/null); then
        sudo killall $1
    else
        if (pgrep -x "$1" &> /dev/null > /dev/null); then
            killall $1
        fi
    fi
}
_boot() {
    if [[ "$cpid" == "0x8003" || "$cpid" == "0x8000" || "$cpid" == "0x8010" || "$cpid" == "0x8011" || "$cpid" == "0x8015" ]]; then
        cd "$dir/"
        pwd
        "$bin"/boot.sh
        echo "fuse lock" | "$bin"/pongoterm
        echo "sep auto" | "$bin"/pongoterm
        if [[ "$3" == "7."* ]]; then
            echo "xargs $boot_args rd=disk0s1s1 amfi=0xff cs_enforcement_disable=1 keepsyms=1 debug=0x2014e wdt=-1 PE_i_can_has_debugger=1 amfi_get_out_of_my_way=0x1 amfi_unrestrict_task_for_pid=0x0" | "$bin"/pongoterm
        elif [[ "$3" == "8."* ]]; then
            echo "xargs $boot_args rd=disk0s1s1 amfi=0xff cs_enforcement_disable=1 keepsyms=1 debug=0x2014e PE_i_can_has_debugger=1" | "$bin"/pongoterm
        elif [[ "$3" == "9."* ]]; then
            echo "xargs rd=disk0s1s1 amfi=0xff cs_enforcement_disable=1 keepsyms=1 debug=0x2014e PE_i_can_has_debugger=1 amfi_get_out_of_my_way=1 amfi_allow_any_signature=1" | "$bin"/pongoterm
        else
            echo "xargs rd=disk0s1s1 amfi=0xff cs_enforcement_disable=1 keepsyms=1 debug=0x2014e PE_i_can_has_debugger=1 amfi_get_out_of_my_way=1 amfi_allow_any_signature=1" | "$bin"/pongoterm
        fi
        echo "xfb" | "$bin"/pongoterm
        bash -c "nohup sh -c 'echo "bootux" | "$bin"/pongoterm &' > /dev/null &"
    else
        _boot_legacy $1 $cpid $3
    fi
}
_boot_legacy() {
    if [[ "$cpid" == "0x8001" || "$cpid" == "0x8000" || "$cpid" == "0x8003" ]]; then
        kbag="24A0F3547373C6FED863FC0F321D7FEA216D0258B48413903939DF968CC2C0E571949EFB72DED8B55B8670932CA7A039"
        iv=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ',' -f 1 | cut -d ' ' -f 2)
        key=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ' ' -f 4)
        ivkey="$iv$key"
        pwd
        echo "$ivkey"
    fi
    if [[ "$deviceid" == "iPhone6"* || "$deviceid" == "iPad4"* ]]; then
        "$bin"/ipwnder -p
        sleep 1
        "$bin"/gaster reset
    else
        "$bin"/gaster pwn
        "$bin"/gaster reset
    fi
    "$bin"/irecovery -f iBSS.img4
    sleep 1
    "$bin"/irecovery -f iBEC.img4
    sleep 2
    if [ "$check" = '0x8010' ] || [ "$check" = '0x8015' ] || [ "$check" = '0x8011' ] || [ "$check" = '0x8012' ]; then
        sleep 1
        "$bin"/irecovery -c go
        sleep 2
    else
        sleep 1
    fi
    "$bin"/irecovery -f devicetree.img4
    "$bin"/irecovery -c devicetree
    if [ -e ./trustcache.img4 ]; then
        "$bin"/irecovery -f trustcache.img4
        "$bin"/irecovery -c firmware
    fi
    "$bin"/irecovery -f kernelcache.img4
    "$bin"/irecovery -c bootx &
}
_boot_ramdisk2() {
    if [[ "$cpid" == "0x8001" || "$cpid" == "0x8000" || "$cpid" == "0x8003" ]]; then
        kbag="24A0F3547373C6FED863FC0F321D7FEA216D0258B48413903939DF968CC2C0E571949EFB72DED8B55B8670932CA7A039"
        iv=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ',' -f 1 | cut -d ' ' -f 2)
        key=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ' ' -f 4)
        ivkey="$iv$key"
    fi
    pwd
    if [[ "$deviceid" == "iPhone6"* || "$deviceid" == "iPad4"* ]]; then
        "$bin"/ipwnder -p
        sleep 1
        "$bin"/gaster reset
    else
        "$bin"/gaster pwn
        "$bin"/gaster reset
    fi
    "$bin"/irecovery -f iBSS.img4
    sleep 1
    "$bin"/irecovery -f iBEC.img4
    sleep 2
    if [ "$check" = '0x8010' ] || [ "$check" = '0x8015' ] || [ "$check" = '0x8011' ] || [ "$check" = '0x8012' ]; then
        sleep 1
        "$bin"/irecovery -c go
        sleep 2
    else
        sleep 1
    fi
    "$bin"/irecovery -f ramdisk.img4
    "$bin"/irecovery -c ramdisk
    "$bin"/irecovery -f devicetree.img4
    "$bin"/irecovery -c devicetree
    if [ -e ./trustcache.img4 ]; then
        "$bin"/irecovery -f trustcache.img4
        "$bin"/irecovery -c firmware
    fi
    "$bin"/irecovery -f kernelcache.img4
    "$bin"/irecovery -c bootx &
}
_boot_ramdisk() {
    if [[ "$deviceid" == "iPhone10"* || "$deviceid" == "iPad6"* || "$deviceid" == "iPad7"* ]]; then
        if [[ -e "$dir"/$deviceid/0.0/apticket.der && -e "$dir"/$deviceid/0.0/sep-firmware.img4 && -e "$dir"/$deviceid/0.0/keybags ]]; then
            pongo=0
        else
            pongo=1
        fi
    else
        pongo=0
    fi
    if [[ "$cpid" == "0x8015" ]]; then
        pongo=1
    fi
    if [[ "$pongo" == 1 ]]; then
        if [[ "$3" == "16."* || "$3" == "17."* ]]; then
            if [[ "$cpid" == "0x8003" || "$cpid" == "0x8000" || "$cpid" == "0x8010" || "$cpid" == "0x8011" || "$cpid" == "0x8015" ]]; then
                _download_ramdisk_boot_files $deviceid $replace $3
                cd "$dir"/$deviceid/$cpid/ramdisk/$3
                cd "$dir"/
                pwd
                "$bin"/boot.sh
                echo "fuse lock" | "$bin"/pongoterm
                echo "sep auto" | "$bin"/pongoterm
                cd "$bin"/
                echo "/send $(pwd)/checkra1n-kpf-pongo" | "$bin"/pongoterm
                echo "modload" | "$bin"/pongoterm
                rm -rf "$dir"/work
                mkdir -p "$dir"/work
                cd "$dir"/work
                if [ -e "$dir"/$deviceid/$cpid/ramdisk/$3/RestoreRamDisk1.dmg ]; then
                    cp "$dir"/$deviceid/$cpid/ramdisk/$3/RestoreRamDisk1.dmg ./ramdisk.dmg
                else
                    cp "$dir"/$deviceid/$cpid/ramdisk/$3/RestoreRamDisk.dmg ./ramdisk.dmg
                fi
                sz=$(wc -c < ramdisk.dmg | tr -d ' ')
                if [[ ! -e "$dir"/$deviceid/$cpid/ramdisk/$3/ramdisk.dmg.lzma ]]; then
                    xz --format=lzma -vf6ekT 0 ramdisk.dmg
                    cp ramdisk.dmg.lzma "$dir"/$deviceid/$cpid/ramdisk/$3/ramdisk.dmg.lzma
                else
                    cp "$dir"/$deviceid/$cpid/ramdisk/$3/ramdisk.dmg.lzma ramdisk.dmg.lzma
                fi
                echo "/send $(pwd)/ramdisk.dmg.lzma" | "$bin"/pongoterm
                echo "ramdisk $sz" | "$bin"/pongoterm
                cd "$dir"/sshtars
                #echo "/send $(pwd)/binpack.dmg" | "$bin"/pongoterm
                #echo "overlay" | "$bin"/pongoterm
                cd "$dir"/$deviceid/$cpid/ramdisk/$3
                rm -rf "$dir"/work
                if [[ "$3" == "7."* || "$3" == "8."* || "$3" == "9."* ]]; then
                    if [[ ! "$deviceid" == "iPhone6"* && ! "$deviceid" == "iPhone7"* && ! "$deviceid" == "iPad4"* && ! "$deviceid" == "iPad5"* && ! "$deviceid" == "iPod7"* && "$3" == "9."* ]]; then
                        echo "xargs rd=md0 debug=0x2014e amfi=0xff cs_enforcement_disable=1 $boot_args wdt=-1 `if [ "$check" = '0x8960' ] || [ "$check" = '0x7000' ] || [ "$check" = '0x7001' ]; then echo "-restore"; fi`" | "$bin"/pongoterm
                    elif [[ "$3" == "9."* ]]; then
                        echo "xargs amfi=0xff cs_enforcement_disable=1 $boot_args rd=md0 nand-enable-reformat=1 -progress" | "$bin"/pongoterm
                    else
                        echo "xargs amfi=0xff cs_enforcement_disable=1 $boot_args rd=md0 nand-enable-reformat=1 -progress" | "$bin"/pongoterm
                    fi
                else
                    if [[ ! "$deviceid" == "iPhone6"* && ! "$deviceid" == "iPhone7"* && ! "$deviceid" == "iPad4"* && ! "$deviceid" == "iPad5"* && ! "$deviceid" == "iPod7"* ]]; then
                        echo "xargs rd=md0 debug=0x2014e $boot_args wdt=-1 `if [ "$check" = '0x8960' ] || [ "$check" = '0x7000' ] || [ "$check" = '0x7001' ]; then echo "-restore"; fi`" | "$bin"/pongoterm
                    else
                        echo "xargs amfi=0xff cs_enforcement_disable=1 $boot_args rd=md0 nand-enable-reformat=1 amfi_get_out_of_my_way=1 -restore -progress" | "$bin"/pongoterm
                    fi
                fi
                echo "xfb" | "$bin"/pongoterm
                bash -c "nohup sh -c 'echo "bootx" | "$bin"/pongoterm &' > /dev/null &"
                #"$bin"/pongoterm
            else
                _boot_ramdisk_legacy $1 $cpid $3
            fi
        else
            _boot_ramdisk2
        fi
    else
        _boot_ramdisk2
    fi
}
_boot_ramdisk_legacy() {
    if [[ "$pongo" == 1 ]]; then
        if [[ "$3" == "16."* || "$3" == "17."* ]]; then
            _download_ramdisk_boot_files $deviceid $replace $3
            cd "$dir"/$deviceid/$cpid/ramdisk/$3
            cp "$bin"/checkra1n-kpf-pongo .
            if [ -e ./RestoreRamDisk1.dmg ]; then
                if [[ "$cpid" == "0x8001" || "$cpid" == "0x8000" || "$cpid" == "0x8003" ]]; then
                    "$bin"/palera1n -r RestoreRamDisk1.dmg -K checkra1n-kpf-pongo &
                    echo "Waiting 10 seconds.."
                    sleep 10
                    "$bin"/palera1n -r RestoreRamDisk1.dmg -K checkra1n-kpf-pongo
                else
                    "$bin"/palera1n -r RestoreRamDisk1.dmg -K checkra1n-kpf-pongo
                fi
            else
                if [[ "$cpid" == "0x8001" || "$cpid" == "0x8000" || "$cpid" == "0x8003" ]]; then
                    "$bin"/palera1n -r RestoreRamDisk.dmg -K checkra1n-kpf-pongo &
                    echo "Waiting 10 seconds.."
                    sleep 10
                    "$bin"/palera1n -r RestoreRamDisk.dmg -K checkra1n-kpf-pongo
                else
                    "$bin"/palera1n -r RestoreRamDisk.dmg -K checkra1n-kpf-pongo
                fi
            fi
        else
            _boot_ramdisk2
        fi
    else
        _boot_ramdisk2
    fi
}
if [ ! -e java/bin/java ]; then
    mkdir java
    cd java
    if [ "$os" = "Darwin" ]; then
        curl -k -SLO https://builds.openlogic.com/downloadJDK/openlogic-openjdk-jre/8u262-b10/openlogic-openjdk-jre-8u262-b10-mac-x64.zip
        "$bin"/7z x openlogic-openjdk-jre-8u262-b10-mac-x64.zip
        sudo cp -rf openlogic-openjdk-jre-8u262-b10-mac-x64/jdk1.8.0_262.jre/Contents/Home/* .
        sudo rm -rf openlogic-openjdk-jre-8u262-b10-mac-x64/
    else
        curl -k -SLO https://builds.openlogic.com/downloadJDK/openlogic-openjdk-jre/8u262-b10/openlogic-openjdk-jre-8u262-b10-linux-x64.tar.gz
        "$bin"/gnutar -xzf openlogic-openjdk-jre-8u262-b10-linux-x64.tar.gz
        cp -rf openlogic-openjdk-jre-8u262-b10-linux-64/* .
        rm -rf openlogic-openjdk-jre-8u262-b10-linux*
    fi
    cd ..
fi
sudo killall -STOP -c usbd
if [[ "$(get_device_mode)" == "normal" ]]; then
    "$bin"/reboot_into_recovery.sh
fi 
if [[ "$(get_device_mode)" == "none" ]]; then
    error "Please connect a device in recovery mode or dfu mode to continue"
    exit 0
fi
if [[ ! "$(get_device_mode)" == "dfu" && ! "$(get_device_mode)" == "recovery" ]]; then
    error "You can not run`if [ $EUID = 0 ]; then echo " sudo"; fi` $0 from $(get_device_mode), please put your device into recovery mode"
    exit 0
fi
if [[ "$deviceid" == "iPhone10"* || "$cpid" == "0x8015"* ]]; then
    "$bin"/irecovery -c "setenv auto-boot true"
    "$bin"/irecovery -c "saveenv"
fi
if [[ "$*" == *"--fix-auto-boot"* ]]; then
    "$bin"/irecovery -c "setenv auto-boot true"
    "$bin"/irecovery -c "saveenv"
    "$bin"/irecovery -c "reset"
    exit 0
fi 
if [ "$os" = "Darwin" ]; then
    if ! (system_profiler SPUSBDataType 2> /dev/null | grep ' Apple Mobile Device (DFU Mode)' >> /dev/null); then
        "$bin"/dfuhelper.sh
    fi
else
    if ! (lsusb | cut -d' ' -f6 | grep '05ac:' | cut -d: -f2 | grep 1227 >> /dev/null); then
        "$bin"/dfuhelper.sh
    fi
fi
_wait_for_dfu
sudo killall -STOP -c usbd
rm -rf work
check=$("$bin"/irecovery -q | grep CPID | sed 's/CPID: //')
cpid=$("$bin"/irecovery -q | grep CPID | sed 's/CPID: //')
replace=$("$bin"/irecovery -q | grep MODEL | sed 's/MODEL: //')
deviceid=$("$bin"/irecovery -q | grep PRODUCT | sed 's/PRODUCT: //')
if [[ "$deviceid" == *"iPad"* ]]; then
    device_os=iPadOS
elif [[ "$deviceid" == *"iPod"* ]]; then
    device_os=iOS
else
    device_os=iOS
fi
info $cpid
info $replace
boardcfg="$replace"
info $deviceid
info $device_os
scid="$cpid"
if [[ "$cpid" == "0x8000" || "$cpid" == "0x8001" || "$cpid" == 8003 ]]; then
    scid=$(echo $cpid | sed 's/0x/s/g')
    info $scid
fi
parse_cmdline "$@"
boot_args=""
if [ "$serial" = "1" ]; then
    boot_args="serial=3"
else
    boot_args="-v"
fi
if [[ ! -e "$dir"/$deviceid/0.0/shsh.shsh2 && ! -e "$dir"/$deviceid/0.0/sep-firmware.img4 ]]; then
    if [[ "$restore" == 1 || "$force_activation" == 1 || "$boot" == 1 || "$boot_clean" == 1 ]]; then
        error "You need to dump your activation records first, please run`if [ $EUID = 0 ]; then echo " sudo"; fi` $0 $version --dump-blobs --dump-activation"
        exit 0
    fi
fi
if [[ ! -e "$dir"/$deviceid/0.0/shsh.shsh2 ]]; then
    if [[ "$restore" == 1 || "$force_activation" == 1 || "$boot" == 1 || "$boot_clean" == 1 ]]; then
        error "You need to dump your blobs first, please run`if [ $EUID = 0 ]; then echo " sudo"; fi` $0 $version --dump-blobs"
        exit 0
    fi
fi
if [[ ! -e "$dir"/$deviceid/0.0/apticket.der || ! -e "$dir"/$deviceid/0.0/sep-firmware.img4 || ! -e "$dir"/$deviceid/0.0/keybags ]]; then
    if [[ "$restore" == 1 || "$force_activation" == 1 || "$boot" == 1 || "$boot_clean" == 1 ]]; then
        error "You need to dump your activation records first, please run`if [ $EUID = 0 ]; then echo " sudo"; fi` $0 $version --dump-activation"
        exit 0
    fi
fi
_wait_for_dfu
if [[ "$clean" == 1 ]]; then
    rm -rf "$dir"/$deviceid/$cpid/$version/iBSS*
    rm -rf "$dir"/$deviceid/$cpid/$version/iBEC*
    rm -rf "$dir"/$deviceid/$cpid/$version/kcache2.patched
    rm -rf "$dir"/$deviceid/$cpid/$version/kcache3.patched
    rm -rf "$dir"/$deviceid/$cpid/$version/kcache4.patched
    rm -rf "$dir"/$deviceid/$cpid/$version/kcache5.patched
    rm -rf "$dir"/$deviceid/$cpid/$version/kcache.patched
    rm -rf "$dir"/$deviceid/$cpid/$version/kcache.raw
    rm -rf "$dir"/$deviceid/$cpid/$version/kernelcache.dec
    rm -rf "$dir"/$deviceid/$cpid/$version/kc.bpatch
    rm -rf "$dir"/$deviceid/$cpid/$version/kernelcache.img4
    rm -rf "$dir"/$deviceid/$cpid/$version/kernelcache
    rm -rf "$dir"/$deviceid/$cpid/$version/kernelcache.im4p.img4
    rm -rf "$dir"/$deviceid/$cpid/$version/kernelcache.im4p
    rm -rf "$dir"/$deviceid/$cpid/$version/kpp.bin
    rm -rf "$dir"/$deviceid/$cpid/$version/DeviceTree*
    rm -rf "$dir"/$deviceid/$cpid/$version/devicetree*
    rm -rf "$dir"/$deviceid/$cpid/ramdisk/
    rm -rf "$dir"/work/
    info "Removed the created boot files"
    exit 0
fi
_get_ios_ver_prior_to_downgrade
if [[ "$version" == "9.3"* || "$version" == "10."* ]]; then
    if [[ ! "$ramdisk" == 1 && ! "$dump_blobs" == 1 && ! "$restore_nand" == 1 ]]; then
        force_activation=1
    fi
fi
if [[ "$boot_clean" == 1 ]]; then
    _download_clean_boot_files $deviceid $replace $version
    _kill_if_running iproxy
    sudo killall -STOP -c usbd
    if [ -e "$dir"/$deviceid/clean/$cpid/$version/iBSS.img4 ]; then
        cd "$dir"/$deviceid/clean/$cpid/$version
        _boot $deviceid $replace $version
        cd "$dir"/
        exit 0
    fi
    exit 0
fi
if [[ "$boot" == 1 ]]; then
    _download_boot_files $deviceid $replace $version
    _kill_if_running iproxy
    sudo killall -STOP -c usbd
    if [ -e "$dir"/$deviceid/$cpid/$version/iBSS.img4 ]; then
        cd "$dir"/$deviceid/$cpid/$version
        _boot $deviceid $replace $version
        cd "$dir"/
        exit 0
    fi
    exit 0
fi
if [[ "$ramdisk" == 1 || "$restore" == 1 || "$dump_blobs" == 1 || "$force_activation" == 1 || "$dump_activation" == 1 || "$restore_activation" == 1 || "$dump_nand" == 1 || "$restore_nand" == 1 || "$disable_NoMoreSIGABRT" == 1 || "$NoMoreSIGABRT" == 1 ]]; then
    _kill_if_running iproxy
    if [[ "$restore" == 1 ]]; then
        _download_boot_files $deviceid $replace $version
        if [[ "$restore" == 1 ]]; then
            _download_root_fs $deviceid $replace $version
        fi
        sleep 1
        sudo killall -STOP -c usbd
    fi
    if [[ "$restore" == 1 ]]; then
        mkdir -p "$dir"/$deviceid/0.0/
        hit=0
        if [ ! -e "$dir"/$deviceid/0.0/apticket.der ]; then
            error "Missing ./apticket.der, which is required in order to proceed. exiting . . ."
            exit 0
        fi
        if [ ! -e "$dir"/$deviceid/0.0/sep-firmware.img4 ]; then
            error "Missing ./sep-firmware.img4, which is required in order to proceed. exiting . . ."
            exit 0
        fi
        if [ ! -e "$dir"/$deviceid/0.0/keybags ]; then
            error "Missing ./keybags, which is required in order to proceed. exiting . . ."
            exit 0
        fi
        if [ ! -e "$dir"/$deviceid/0.0/shsh.shsh2 ]; then
            error "Missing ./shsh.shsh2, which is required in order to proceed. exiting . . ."
            exit 0
        fi
        if [ ! -e "$dir"/$deviceid/$cpid/$version/ipswcfw.ipsw ]; then
            error "Missing ./ipswcfw.ipsw, which is required in order to proceed. exiting . . ."
            exit 0
        fi
        if [ ! -e "$dir"/$deviceid/0.0/activation_records/activation_record.plist ]; then
            warning "Missing ./activation_records/activation_record.plist, press any key to continue.. "
            read -n 1
            force_activation=1
        fi
        _wait_for_dfu
        sudo killall -STOP -c usbd
        if [[ ! "$cpid" == "0x8015" ]]; then
            if [[ "$version" == "10."* ]]; then
                rdversion="10.3.3"
            elif [[ "$version" == "7."* || "$version" == "8."* ]]; then
                #rdversion="8.4.1"
                rdversion="9.3"
            elif [[ "$os" = "Darwin" && ! "$deviceid" == "iPhone6"* && ! "$deviceid" == "iPhone7"* && ! "$deviceid" == "iPad4"* && ! "$deviceid" == "iPad5"* && ! "$deviceid" == "iPod7"* && "$version" == "9."* ]]; then
                rdversion="9.3"
            else
                rdversion="$version"
            fi
            _download_ramdisk_boot_files $deviceid $replace $rdversion
            cd "$dir"/$deviceid/$cpid/ramdisk/$rdversion
            if [[ "$cpid" == "0x8001" || "$cpid" == "0x8000" || "$cpid" == "0x8003" ]]; then
                kbag="24A0F3547373C6FED863FC0F321D7FEA216D0258B48413903939DF968CC2C0E571949EFB72DED8B55B8670932CA7A039"
                iv=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ',' -f 1 | cut -d ' ' -f 2)
                key=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ' ' -f 4)
                ivkey="$iv$key"
            fi
            pwd
            if [[ "$deviceid" == "iPhone6"* || "$deviceid" == "iPad4"* ]]; then
                "$bin"/ipwnder -p
                sleep 1
                "$bin"/gaster reset
            else
                "$bin"/gaster pwn
                "$bin"/gaster reset
            fi
            "$bin"/irecovery -f iBSS.img4
            sleep 1
            "$bin"/irecovery -f iBEC.img4
            sleep 2
            if [ "$check" = '0x8010' ] || [ "$check" = '0x8015' ] || [ "$check" = '0x8011' ] || [ "$check" = '0x8012' ]; then
                sleep 1
                "$bin"/irecovery -c go
                sleep 2
            else
                sleep 1
            fi
            cd "$dir"/
            generator=$(cat "$dir"/$deviceid/0.0/shsh.shsh2 | grep "0x" | tail -n 1 | cut -d '>' -f 2 | cut -d '<' -f 1)
            "$bin"/irecovery -c "setenv com.apple.System.boot-nonce $generator"
            sleep 1
            "$bin"/irecovery -c "saveenv"
            sleep 1
            "$bin"/irecovery -c "setenv auto-boot false"
            sleep 1
            "$bin"/irecovery -c "saveenv"
            sleep 1
            "$bin"/irecovery -c "reset"
            sleep 7
        fi
        _dfuhelper
        sudo killall -STOP -c usbd
        if [[ "$cpid" == "0x8001" || "$cpid" == "0x8000" || "$cpid" == "0x8003" ]]; then
            kbag="24A0F3547373C6FED863FC0F321D7FEA216D0258B48413903939DF968CC2C0E571949EFB72DED8B55B8670932CA7A039"
            iv=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ',' -f 1 | cut -d ' ' -f 2)
            key=$("$bin"/gaster decrypt_kbag $kbag | tail -n 1 | cut -d ' ' -f 4)
            ivkey="$iv$key"
        fi
        pwd
        if [[ "$deviceid" == "iPhone6"* || "$deviceid" == "iPad4"* ]]; then
            "$bin"/ipwnder -p
            sleep 1
            "$bin"/gaster reset
        else
            "$bin"/gaster pwn
            "$bin"/gaster reset
        fi
        "$bin"/futurerestore -t "$dir"/$deviceid/0.0/shsh.shsh2 --use-pwndfu --skip-blob --serial --rdsk "$dir"/$deviceid/$cpid/$version/rdsk.im4p --rkrn "$dir"/$deviceid/$cpid/$version/rkrn.im4p --latest-sep --latest-baseband "$dir"/$deviceid/$cpid/$version/ipswcfw.ipsw
        _wait_for_dfu
        _dfuhelper
        sudo killall -STOP -c usbd
        if [[ "$cpid" == "0x8011" && ! "$3" == "10."* ]]; then
            _download_ramdisk_boot_files $deviceid $replace 10.3.3
            cd "$dir"/$deviceid/$cpid/ramdisk/10.3.3
            _boot_ramdisk $deviceid $replace 10.3.3
            cd "$dir"/
            _kill_if_running iproxy
            sudo killall -STOP -c usbd
            "$bin"/iproxy 2222 22 &
            while ! [[ $("$bin"/sshpass -p "alpine" ssh -o StrictHostKeyChecking=no -p2222 root@localhost "echo hello" 2> /dev/null) == "hello" ]]; do
                sleep 1
            done
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount_apfs /dev/disk0s1s1 /mnt1"
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount_apfs /dev/disk0s1s2 /mnt2"
            $("$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/reboot &" 2> /dev/null &)
            _wait_for_dfu
            _dfuhelper
            sudo killall -STOP -c usbd
        fi
        if [[ "$cpid" == "0x8015" ]]; then
            _download_ramdisk_boot_files $deviceid $replace $version
            cd "$dir"/$deviceid/$cpid/ramdisk/$version
            _boot_ramdisk $deviceid $replace $version
        elif [[ "$version" == "7."* || "$version" == "8."* ]]; then
            _download_ramdisk_boot_files $deviceid $replace 8.4.1
            cd "$dir"/$deviceid/$cpid/ramdisk/8.4.1
            _boot_ramdisk $deviceid $replace 8.4.1
        elif [[ "$version" == "10.3"* ]]; then
            _download_ramdisk_boot_files $deviceid $replace 10.3.3
            cd "$dir"/$deviceid/$cpid/ramdisk/10.3.3
            _boot_ramdisk $deviceid $replace 10.3.3
        elif [[ "$version" == "11."* ||  "$version" == "12."* || "$version" == "13."* || "$version" == "14."* ]]; then
            if [[ "$(./java/bin/java -jar ./Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -e 15.6 $deviceid)" == "true" ]]; then
                _download_ramdisk_boot_files $deviceid $replace 15.6
                cd "$dir"/$deviceid/$cpid/ramdisk/15.6
                _boot_ramdisk $deviceid $replace 15.6
            elif [[ "$deviceid" == "iPad"* && ! "$deviceid" == "iPad4"* ]]; then
                _download_ramdisk_boot_files $deviceid $replace 15.6
                cd "$dir"/$deviceid/$cpid/ramdisk/15.6
                _boot_ramdisk $deviceid $replace 15.6
            else
                _download_ramdisk_boot_files $deviceid $replace 12.5.4
                cd "$dir"/$deviceid/$cpid/ramdisk/12.5.4
                _boot_ramdisk $deviceid $replace 12.5.4
            fi
        elif [[ "$os" = "Darwin" && ! "$deviceid" == "iPhone6"* && ! "$deviceid" == "iPhone7"* && ! "$deviceid" == "iPad4"* && ! "$deviceid" == "iPad5"* && ! "$deviceid" == "iPod7"* && "$version" == "9."* ]]; then
            _download_ramdisk_boot_files $deviceid $replace 9.3
            cd "$dir"/$deviceid/$cpid/ramdisk/9.3
            _boot_ramdisk $deviceid $replace 9.3
        else
            _download_ramdisk_boot_files $deviceid $replace 11.4
            cd "$dir"/$deviceid/$cpid/ramdisk/11.4
            _boot_ramdisk $deviceid $replace 11.4
        fi
        cd "$dir"/
        _kill_if_running iproxy
        sudo killall -STOP -c usbd
        "$bin"/iproxy 2222 22 &
        while ! [[ $("$bin"/sshpass -p "alpine" ssh -o StrictHostKeyChecking=no -p2222 root@localhost "echo hello" 2> /dev/null) == "hello" ]]; do
            sleep 1
        done
        if [[ "$version" == "7."* || "$version" == "8."* || "$version" == "9."* || "$version" == "10.0"* || "$version" == "10.1"* || "$version" == "10.2"*  ]]; then
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount_hfs /dev/disk0s1s1 /mnt1" 2> /dev/null
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount -w -t hfs -o suid,dev /dev/disk0s1s2 /mnt2" 2> /dev/null
            if [[ "$version" == "7."* || "$version" == "8."* ]]; then
                "$bin"/sshpass -p 'alpine' scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/cydia_ios7.tar.gz root@localhost:/mnt2 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "tar -xzvf /mnt2/cydia_ios7.tar.gz -C /mnt1"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf /mnt2/cydia_ios7.tar.gz" 2> /dev/null
            fi
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt1/usr/local/standalone/firmware/Baseband" 2> /dev/null
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt2/wireless/baseband_data" 2> /dev/null
            if [ -e "$dir"/$deviceid/0.0/Baseband ]; then
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -r -P 2222 "$dir"/$deviceid/0.0/Baseband root@localhost:/mnt1/usr/local/standalone/firmware 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags -R schg /mnt1/usr/local/standalone/firmware/Baseband"
            fi
            "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/0.0/apticket.der root@localhost:/mnt1/System/Library/Caches/ 2> /dev/null
            "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/0.0/sep-firmware.img4 root@localhost:/mnt1/usr/standalone/firmware/ 2> /dev/null
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags schg /mnt1/usr/standalone/firmware/sep-firmware.img4"
            if [ -e "$dir"/$deviceid/0.0/IC-Info.sisv ]; then
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt2/mobile/Library/FairPlay/iTunes_Control/iTunes/"
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/0.0/IC-Info.sisv root@localhost:/mnt2/mobile/Library/FairPlay/iTunes_Control/iTunes/IC-Info.sisv 2> /dev/null
            fi
            if [ -e "$dir"/$deviceid/0.0/com.apple.commcenter.device_specific_nobackup.plist ]; then
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt2/wireless/Library/Preferences/"
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/0.0/com.apple.commcenter.device_specific_nobackup.plist root@localhost:/mnt2/wireless/Library/Preferences/com.apple.commcenter.device_specific_nobackup.plist 2> /dev/null
            fi
            if [[ -e "$dir"/$deviceid/0.0/activation_records && ! "$force_activation" == 1 ]]; then
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt2/root/Library/Lockdown/activation_records"
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -r -P 2222 "$dir"/$deviceid/0.0/activation_records/* root@localhost:/mnt2/root/Library/Lockdown/activation_records 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags -R schg /mnt2/root/Library/Lockdown/activation_records"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt2/mobile/Library/mad/activation_records"
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -r -P 2222 "$dir"/$deviceid/0.0/activation_records/* root@localhost:/mnt2/mobile/Library/mad/activation_records 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags -R schg /mnt2/mobile/Library/mad/activation_records"
            fi
            if [[ "$version" == "10."* ]]; then
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/data_ark.plist_ios10.tar root@localhost:/mnt2/
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "tar -xvf /mnt2/data_ark.plist_ios10.tar -C /mnt2"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf /mnt2/data_ark.plist_ios10.tar"
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt1/usr/libexec/mobileactivationd "$dir"/$deviceid/$cpid/$version/mobactivationd.raw
                if [[ ! -e "$dir"/$deviceid/0.0/activation_records/activation_record.plist || "$force_activation" == 1 ]]; then
                    "$bin"/mobactivationd64patcher "$dir"/$deviceid/$cpid/$version/mobactivationd.raw "$dir"/$deviceid/$cpid/$version/mobactivationd.patched -b -c -d
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/mobactivationd.patched root@localhost:/mnt1/usr/libexec/mobileactivationd
                fi
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/kernelcache root@localhost:/mnt1/System/Library/Caches/com.apple.kernelcaches
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "touch /mnt1/.cydia_no_stash"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/sbin/chown root:wheel /mnt1/.cydia_no_stash"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "chmod 777 /mnt1/.cydia_no_stash"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf /mnt1/usr/lib/libmis.dylib"
                if [[ "$appleinternal" == 1 ]]; then
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/AppleInternal.tar root@localhost:/mnt1/
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/PrototypeTools.framework_ios10.tar root@localhost:/mnt1/
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt1/System/Library/CoreServices/SystemVersion.plist "$dir"/$deviceid/$cpid/$version/SystemVersion.plist
                    LC_ALL=C sed -i -e 's/<\/dict>/<key>ReleaseType<\/key><string>Internal<\/string><key>ProductType<\/key><string>Internal<\/string><\/dict>/g' "$dir"/$deviceid/$cpid/$version/SystemVersion.plist
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/SystemVersion.plist root@localhost:/mnt1/System/Library/CoreServices/SystemVersion.plist
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/SpringBoard-Internal.strings root@localhost:/mnt1/System/Library/CoreServices/SpringBoard.app/en.lproj/
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/SpringBoard-Internal.strings root@localhost:/mnt1/System/Library/CoreServices/SpringBoard.app/en_GB.lproj/
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/com.apple.springboard_ios10.plist root@localhost:/mnt2/mobile/Library/Preferences/com.apple.springboard.plist
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'tar -xvf /mnt1/PrototypeTools.framework_ios10.tar -C /mnt1/System/Library/PrivateFrameworks/'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost '/usr/sbin/chown -R root:wheel /mnt1/System/Library/PrivateFrameworks/PrototypeTools.framework'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/PrototypeTools.framework_ios10.tar'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'tar -xvf /mnt1/AppleInternal.tar -C /mnt1/'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost '/usr/sbin/chown -R root:wheel /mnt1/AppleInternal/'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/AppleInternal.tar'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt2/mobile/Library/Caches/com.apple.MobileGestalt.plist'
                fi
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/Meridian.app.tar.gz root@localhost:/mnt1/
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'tar --preserve-permissions -xzvf /mnt1/Meridian.app.tar.gz -C /mnt1/Applications' 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/Meridian.app.tar.gz' 2> /dev/null
                if [[ ! "$deviceid" == "iPad"* ]]; then
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/UnlimFileManager.app.tar.gz root@localhost:/mnt1/
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'tar --preserve-permissions -xzvf /mnt1/UnlimFileManager.app.tar.gz -C /mnt1/Applications' 2> /dev/null
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost '/usr/sbin/chown -R root:wheel /mnt1/Applications/UnlimFileManager.app'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/UnlimFileManager.app.tar.gz' 2> /dev/null
                fi
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/System/Library/DataClassMigrators/RestorePostProcess.migrator/' 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/System/Library/DataClassMigrators/MobileNotes.migrator/' 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/System/Library/DataClassMigrators/MobileSlideShow.migrator/' 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/System/Library/DataClassMigrators/HealthMigrator.migrator/' 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/System/Library/DataClassMigrators/rolldMigrator.migrator//' 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/System/Library/DataClassMigrators/BuddyMigrator.migrator/' 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/System/Library/DataClassMigrators/Calendar.migrator/' 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/System/Library/DataClassMigrators/MobileSafari.migrator/' 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/System/Library/DataClassMigrators/WebBookmarks.migrator/' 2> /dev/null
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt1/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64 "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.raw 2> /dev/null
                "$bin"/dsc64patcher "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.raw "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.patched -10
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.patched root@localhost:/mnt1/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64 2> /dev/null
            else
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/data_ark.plist_ios7.tar root@localhost:/mnt2/ 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "tar -xvf /mnt2/data_ark.plist_ios7.tar -C /mnt2" 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf /mnt2/data_ark.plist_ios7.tar" 2> /dev/null
            fi
            if [[ "$version" == "7."* || "$version" == "8."* ]]; then
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/fstab_rw root@localhost:/mnt1/etc/fstab 2> /dev/null
            else
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/fstab root@localhost:/mnt1/etc/ 2> /dev/null
            fi
            if [[ "$version" == "8."* || "$version" == "9.0"* || "$version" == "9.1"* || "$version" == "9.2"* ]]; then
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/data_ark.plist_ios8.tar root@localhost:/mnt2/ 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "tar -xvf /mnt2/data_ark.plist_ios8.tar -C /mnt2" 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf /mnt2/data_ark.plist_ios8.tar" 2> /dev/null
                if [[ ! -e "$dir"/$deviceid/0.0/activation_records/activation_record.plist || "$force_activation" == 1 ]]; then
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt1/System/Library/PrivateFrameworks/MobileActivation.framework/Support/mobactivationd "$dir"/$deviceid/$cpid/$version/mobactivationd.raw 2> /dev/null
                    "$bin"/mobactivationd64patcher "$dir"/$deviceid/$cpid/$version/mobactivationd.raw "$dir"/$deviceid/$cpid/$version/mobactivationd.patched -b -c -d 2> /dev/null
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/mobactivationd.patched root@localhost:/mnt1/System/Library/PrivateFrameworks/MobileActivation.framework/Support/mobactivationd 2> /dev/null
                fi
            elif [[ "$version" == "9.3"* ]]; then
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/data_ark.plist_ios8.tar root@localhost:/mnt2/ 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "tar -xvf /mnt2/data_ark.plist_ios8.tar -C /mnt2" 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf /mnt2/data_ark.plist_ios8.tar" 2> /dev/null
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt1/usr/libexec/mobileactivationd "$dir"/$deviceid/$cpid/$version/mobactivationd.raw 2> /dev/null
                if [[ ! -e "$dir"/$deviceid/0.0/activation_records/activation_record.plist || "$force_activation" == 1 ]]; then
                    "$bin"/mobactivationd64patcher "$dir"/$deviceid/$cpid/$version/mobactivationd.raw "$dir"/$deviceid/$cpid/$version/mobactivationd.patched -b -c -d 2> /dev/null
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/mobactivationd.patched root@localhost:/mnt1/usr/libexec/mobileactivationd 2> /dev/null
                fi
            fi
            if [[ ! "$version" == "10."* && ! "$version" == "9."* ]]; then
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/com.saurik.Cydia.Startup.plist root@localhost:/mnt1/System/Library/LaunchDaemons 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/sbin/chown root:wheel /mnt1/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist" 2> /dev/null
            fi
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf /mnt2/log/asl/SweepStore" 2> /dev/null
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf /mnt2/mobile/Library/PreinstalledAssets/*" 2> /dev/null
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf /mnt2/mobile/Library/Preferences/.GlobalPreferences.plist" 2> /dev/null
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf /mnt2/mobile/.forward" 2> /dev/null
            # fix stuck on apple logo after long progress bar
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf /mnt1/System/Library/DataClassMigrators/CoreLocationMigrator.migrator/"
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf /mnt1/System/Library/DataClassMigrators/PassbookDataMigrator.migrator/"
            if [[ "$version" == "7."*  ]]; then
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/untether_ios7.tar root@localhost:/mnt1/ 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'tar --preserve-permissions -xvf /mnt1/untether_ios7.tar -C /mnt1/' 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "touch /mnt1/evasi0n7-installed" 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "chmod 777 /mnt1/evasi0n7-installed" 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt2/mobile/Media/" 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "touch /mnt2/mobile/Media/.evasi0n7_installed" 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "chmod 777 /mnt2/mobile/Media/.evasi0n7_installed" 2> /dev/null
            elif [[ "$version" == "8."*  ]]; then
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/untether_ios8.tar root@localhost:/mnt1/ 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'tar --preserve-permissions -xvf /mnt1/untether_ios8.tar -C /mnt1/' 2> /dev/null
            fi
            "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/kernelcache root@localhost:/mnt1/System/Library/Caches/com.apple.kernelcaches 2> /dev/null
            if [[ ! "$version" == "10."* && ! "$version" == "9."* ]]; then
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "touch /mnt1/.cydia_no_stash" 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/sbin/chown root:wheel /mnt1/.cydia_no_stash" 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "chmod 777 /mnt1/.cydia_no_stash" 2> /dev/null
            fi
            if [[ "$version" == "8."* ]]; then
                if [[ "$appleinternal" == 1 ]]; then
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/AppleInternal.tar root@localhost:/mnt1/ 2> /dev/null
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/PrototypeTools.framework_ios8.tar root@localhost:/mnt1/ 2> /dev/null
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt1/System/Library/CoreServices/SystemVersion.plist "$dir"/$deviceid/$cpid/$version/SystemVersion.plist 2> /dev/null
                    LC_ALL=C sed -i -e 's/<\/dict>/<key>ReleaseType<\/key><string>Internal<\/string><key>ProductType<\/key><string>Internal<\/string><\/dict>/g' "$dir"/$deviceid/$cpid/$version/SystemVersion.plist 2> /dev/null
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/SystemVersion.plist root@localhost:/mnt1/System/Library/CoreServices/SystemVersion.plist 2> /dev/null
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/SpringBoard-Internal.strings root@localhost:/mnt1/System/Library/CoreServices/SpringBoard.app/en.lproj/ 2> /dev/null
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/SpringBoard-Internal.strings root@localhost:/mnt1/System/Library/CoreServices/SpringBoard.app/en_GB.lproj/ 2> /dev/null
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/com.apple.springboard_ios8.plist root@localhost:/mnt2/mobile/Library/Preferences/com.apple.springboard.plist 2> /dev/null
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'tar -xvf /mnt1/PrototypeTools.framework_ios8.tar -C /mnt1/System/Library/PrivateFrameworks/'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost '/usr/sbin/chown -R root:wheel /mnt1/System/Library/PrivateFrameworks/PrototypeTools.framework' 2> /dev/null
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/PrototypeTools.framework_ios8.tar' 2> /dev/null
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'tar -xvf /mnt1/AppleInternal.tar -C /mnt1/'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost '/usr/sbin/chown -R root:wheel /mnt1/AppleInternal/' 2> /dev/null
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/AppleInternal.tar' 2> /dev/null
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt2/mobile/Library/Caches/com.apple.MobileGestalt.plist' 2> /dev/null
                fi
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/System/Library/DataClassMigrators/MobileNotes.migrator/' 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/System/Library/DataClassMigrators/MobileSlideShow.migrator/' 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/System/Library/DataClassMigrators/HealthMigrator.migrator/' 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/System/Library/DataClassMigrators/rolldMigrator.migrator//' 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/System/Library/DataClassMigrators/BuddyMigrator.migrator/' 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/System/Library/DataClassMigrators/RestorePostProcess.migrator/' 2> /dev/null
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt1/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64 "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.raw 2> /dev/null
                "$bin"/dsc64patcher "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.raw "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.patched -8
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.patched root@localhost:/mnt1/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags schg /mnt2/root/Library/Lockdown/data_ark.plist"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags schg /mnt2/mobile/Library/mad/data_ark.plist"
                #"$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'cp /mnt1/usr/libexec/keybagd /mnt1/usr/libexec/keybagd.bak' 2> /dev/null
                #"$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/fixkeybag root@localhost:/mnt1/usr/libexec/keybagd 2> /dev/null
            elif [[ "$version" == "7."* ]]; then
                if [[ "$appleinternal" == 1 ]]; then
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/AppleInternal.tar root@localhost:/mnt1/ 2> /dev/null
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/PrototypeTools.framework.tar root@localhost:/mnt1/ 2> /dev/null
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt1/System/Library/CoreServices/SystemVersion.plist "$dir"/$deviceid/$cpid/$version/SystemVersion.plist 2> /dev/null
                    LC_ALL=C sed -i -e 's/<\/dict>/<key>ReleaseType<\/key><string>Internal<\/string><key>ProductType<\/key><string>Internal<\/string><\/dict>/g' "$dir"/$deviceid/$cpid/$version/SystemVersion.plist 2> /dev/null
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/SystemVersion.plist root@localhost:/mnt1/System/Library/CoreServices/SystemVersion.plist 2> /dev/null
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/SpringBoard-Internal.strings root@localhost:/mnt1/System/Library/CoreServices/SpringBoard.app/en.lproj/ 2> /dev/null
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/SpringBoard-Internal.strings root@localhost:/mnt1/System/Library/CoreServices/SpringBoard.app/en_GB.lproj/ 2> /dev/null
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/com.apple.springboard.plist root@localhost:/mnt2/mobile/Library/Preferences/com.apple.springboard.plist 2> /dev/null
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'tar -xvf /mnt1/PrototypeTools.framework.tar -C /mnt1/System/Library/PrivateFrameworks/'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost '/usr/sbin/chown -R root:wheel /mnt1/System/Library/PrivateFrameworks/PrototypeTools.framework' 2> /dev/null
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/PrototypeTools.framework.tar' 2> /dev/null
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'tar -xvf /mnt1/AppleInternal.tar -C /mnt1/'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost '/usr/sbin/chown -R root:wheel /mnt1/AppleInternal/' 2> /dev/null
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/AppleInternal.tar' 2> /dev/null
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt2/mobile/Library/Caches/com.apple.MobileGestalt.plist' 2> /dev/null
                fi
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt1/usr/libexec/lockdownd "$dir"/$deviceid/$cpid/$version/lockdownd.raw 2> /dev/null
                if [[ -e "$dir"/$deviceid/0.0/activation_records/activation_record.plist && ! "$force_activation" == 1 ]]; then
                    "$bin"/lockdownd64patcher "$dir"/$deviceid/$cpid/$version/lockdownd.raw "$dir"/$deviceid/$cpid/$version/lockdownd.patched -u -l 2> /dev/null
                else
                    "$bin"/lockdownd64patcher "$dir"/$deviceid/$cpid/$version/lockdownd.raw "$dir"/$deviceid/$cpid/$version/lockdownd.patched -u -l -b 2> /dev/null
                fi
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/lockdownd.patched root@localhost:/mnt1/usr/libexec/lockdownd 2> /dev/null
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt1/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64 "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.raw 2> /dev/null
                "$bin"/dsc64patcher "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.raw "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.patched -7
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.patched root@localhost:/mnt1/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64 2> /dev/null
            elif [[ "$version" == "9."* ]]; then
                if [[ "$appleinternal" == 1 ]]; then
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/AppleInternal.tar root@localhost:/mnt1/ 2> /dev/null
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/PrototypeTools.framework_ios9.tar root@localhost:/mnt1/ 2> /dev/null
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt1/System/Library/CoreServices/SystemVersion.plist "$dir"/$deviceid/$cpid/$version/SystemVersion.plist 2> /dev/null
                    LC_ALL=C sed -i -e 's/<\/dict>/<key>ReleaseType<\/key><string>Internal<\/string><key>ProductType<\/key><string>Internal<\/string><\/dict>/g' "$dir"/$deviceid/$cpid/$version/SystemVersion.plist 2> /dev/null
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/SystemVersion.plist root@localhost:/mnt1/System/Library/CoreServices/SystemVersion.plist 2> /dev/null
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/SpringBoard-Internal.strings root@localhost:/mnt1/System/Library/CoreServices/SpringBoard.app/en.lproj/ 2> /dev/null
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/SpringBoard-Internal.strings root@localhost:/mnt1/System/Library/CoreServices/SpringBoard.app/en_GB.lproj/ 2> /dev/null
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/com.apple.springboard_ios9.plist root@localhost:/mnt2/mobile/Library/Preferences/com.apple.springboard.plist 2> /dev/null
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'tar -xvf /mnt1/PrototypeTools.framework_ios9.tar -C /mnt1/System/Library/PrivateFrameworks/'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost '/usr/sbin/chown -R root:wheel /mnt1/System/Library/PrivateFrameworks/PrototypeTools.framework' 2> /dev/null
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/PrototypeTools.framework_ios9.tar' 2> /dev/null
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'tar -xvf /mnt1/AppleInternal.tar -C /mnt1/'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost '/usr/sbin/chown -R root:wheel /mnt1/AppleInternal/' 2> /dev/null
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/AppleInternal.tar' 2> /dev/null
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt2/mobile/Library/Caches/com.apple.MobileGestalt.plist' 2> /dev/null
                fi
                if [[ "$version" == "9.0"* || "$version" == "9.1"* || "$version" == "9.2"* ]]; then
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/System/Library/DataClassMigrators/MobileNotes.migrator/' 2> /dev/null
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/System/Library/DataClassMigrators/MobileSlideShow.migrator/' 2> /dev/null
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/System/Library/DataClassMigrators/HealthMigrator.migrator/' 2> /dev/null
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/System/Library/DataClassMigrators/rolldMigrator.migrator//' 2> /dev/null
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/System/Library/DataClassMigrators/BuddyMigrator.migrator/' 2> /dev/null
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/System/Library/DataClassMigrators/Calendar.migrator/' 2> /dev/null
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/System/Library/DataClassMigrators/RestorePostProcess.migrator/' 2> /dev/null
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags schg /mnt2/root/Library/Lockdown/data_ark.plist"
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags schg /mnt2/mobile/Library/mad/data_ark.plist"
                fi
                if [[ "$version" == "9.3"* ]]; then
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/NvwaStone.app.tar.gz root@localhost:/mnt1/
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "tar -xzvf /mnt1/NvwaStone.app.tar.gz -C /mnt1/Applications/"
                fi
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt1/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64 "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.raw 2> /dev/null
                "$bin"/dsc64patcher "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.raw "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.patched -9
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.patched root@localhost:/mnt1/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64 2> /dev/null
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt1/usr/libexec/lockdownd "$dir"/$deviceid/$cpid/$version/lockdownd.raw 2> /dev/null
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt1/System/Library/PrivateFrameworks/MobileActivation.framework/Support/mobactivationd "$dir"/$deviceid/$cpid/$version/mobactivationd.raw 2> /dev/null
            fi
            "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/com.apple.Accessibility.Collection.plist root@localhost:/mnt2/mobile/Library/Preferences/com.apple.Accessibility.Collection.plist
            "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/com.apple.Accessibility.plist root@localhost:/mnt2/mobile/Library/Preferences/com.apple.Accessibility.plist
            if [[ -e "$dir"/$deviceid/0.0/activation_records/activation_record.plist && ! "$force_activation" == 1 ]]; then
                if [ -e "$dir"/$deviceid/0.0/data_ark.plist ]; then
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/0.0/data_ark.plist root@localhost:/mnt2/root/Library/Lockdown/data_ark.plist 2> /dev/null
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags schg /mnt2/root/Library/Lockdown/data_ark.plist"
                fi
            fi
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf /mnt1/usr/lib/libmis.dylib" 2> /dev/null
            if [[ "$version" == "9."* ]]; then
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/sbin/nvram -c" 2> /dev/null
            fi
        else
            if [[ "$version" == "10.3"* || "$version" == "11."* || "$version" == "12."* || "$version" == "13."* || "$version" == "14."* ]]; then
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount_apfs /dev/disk0s1s1 /mnt1"
                if [[ "$version" == "11."* || "$version" == "12."* || "$version" == "13."* || "$version" == "14."* ]]; then
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/snaputil -n $(/usr/bin/snaputil -l /mnt1) orig-fs /mnt1"
                fi
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount_apfs /dev/disk0s1s2 /mnt2"
            else
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount_hfs /dev/disk0s1s1 /mnt1" 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount -w -t hfs -o suid,dev /dev/disk0s1s2 /mnt2" 2> /dev/null
            fi
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt1/usr/local/standalone/firmware/Baseband"
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt2/wireless/baseband_data"
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt1/private/xarts"
            if [[ "$version" == "13."* || "$version" == "14."* ]]; then
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt1/private/preboot"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt1" 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt2" 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "bash -c mount_filesystems" 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt1" 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt2" 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount_apfs /dev/disk0s1s1 /mnt1"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount_apfs /dev/disk0s1s2 /mnt2"
            fi
            if [[ "$version" == "14."* ]]; then
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount_apfs /dev/disk0s1s6 /mnt1/private/preboot"
            fi
            if [[ "$version" == "13."* ]]; then
                has_active=$(remote_cmd "ls /mnt6/active" 2> /dev/null)
                if [ ! "$has_active" = "/mnt6/active" ]; then
                    error "Active file does not exist! Please use SSH to create it"
                    error "    /mnt6/active should contain the name of the UUID in /mnt6"
                    error "    When done, type reboot in the SSH session, then rerun the script"
                    error "    ssh root@localhost -p 2222"
                    $("$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/reboot &" 2> /dev/null &)
                    _kill_if_running iproxy
                    exit 0
                fi
                active=$(remote_cmd "cat /mnt6/active" 2> /dev/null)
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "cp -na /mnt6/* /mnt1/private/preboot"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags -R noschg /mnt1/private/preboot/*"
            fi
            if [ -e "$dir"/$deviceid/0.0/Baseband ]; then
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -r -P 2222 "$dir"/$deviceid/0.0/Baseband root@localhost:/mnt1/usr/local/standalone/firmware
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags -R schg /mnt1/usr/local/standalone/firmware/Baseband"
            fi
            "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/0.0/apticket.der root@localhost:/mnt1/System/Library/Caches/
            "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/0.0/sep-firmware.img4 root@localhost:/mnt1/usr/standalone/firmware/
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags schg /mnt1/usr/standalone/firmware/sep-firmware.img4"
            if [ -e "$dir"/$deviceid/0.0/IC-Info.sisv ]; then
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt2/mobile/Library/FairPlay/iTunes_Control/iTunes/"
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/0.0/IC-Info.sisv root@localhost:/mnt2/mobile/Library/FairPlay/iTunes_Control/iTunes/IC-Info.sisv 2> /dev/null
            fi
            if [ -e "$dir"/$deviceid/0.0/com.apple.commcenter.device_specific_nobackup.plist ]; then
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt2/wireless/Library/Preferences/"
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/0.0/com.apple.commcenter.device_specific_nobackup.plist root@localhost:/mnt2/wireless/Library/Preferences/com.apple.commcenter.device_specific_nobackup.plist 2> /dev/null
            fi
            "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/data_ark.plist_ios10.tar root@localhost:/mnt2/
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "tar -xvf /mnt2/data_ark.plist_ios10.tar -C /mnt2"
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf /mnt2/data_ark.plist_ios10.tar"
            "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt1/usr/libexec/mobileactivationd "$dir"/$deviceid/$cpid/$version/mobactivationd.raw
            if [[ ! -e "$dir"/$deviceid/0.0/activation_records/activation_record.plist || "$force_activation" == 1 ]]; then
                "$bin"/mobactivationd64patcher "$dir"/$deviceid/$cpid/$version/mobactivationd.raw "$dir"/$deviceid/$cpid/$version/mobactivationd.patched -b -c -d
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/mobactivationd.patched root@localhost:/mnt1/usr/libexec/mobileactivationd
            fi
            "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/kernelcache root@localhost:/mnt1/System/Library/Caches/com.apple.kernelcaches
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf /mnt1/usr/lib/libmis.dylib"
            # fix stuck on apple logo after long progress bar
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf /mnt1/System/Library/DataClassMigrators/CoreLocationMigrator.migrator/"
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf /mnt1/System/Library/DataClassMigrators/PassbookDataMigrator.migrator/"
            if [[ -e "$dir"/$deviceid/0.0/activation_records && ! "$force_activation" == 1 ]]; then
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt2/root/Library/Lockdown/activation_records"
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -r -P 2222 "$dir"/$deviceid/0.0/activation_records/* root@localhost:/mnt2/root/Library/Lockdown/activation_records 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags -R schg /mnt2/root/Library/Lockdown/activation_records"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt2/mobile/Library/mad/activation_records"
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -r -P 2222 "$dir"/$deviceid/0.0/activation_records/* root@localhost:/mnt2/mobile/Library/mad/activation_records 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags -R schg /mnt2/mobile/Library/mad/activation_records"
            fi
            if [[ -e "$dir"/$deviceid/0.0/activation_records/activation_record.plist && ! "$force_activation" == 1 ]]; then
                if [ -e "$dir"/$deviceid/0.0/data_ark.plist ]; then
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/0.0/data_ark.plist root@localhost:/mnt2/root/Library/Lockdown/data_ark.plist 2> /dev/null
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags schg /mnt2/root/Library/Lockdown/data_ark.plist"
                fi
            fi
            if [[ "$version" == "10."* ]]; then
                if [[ "$appleinternal" == 1 ]]; then
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/AppleInternal.tar root@localhost:/mnt1/
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/PrototypeTools.framework_ios10.tar root@localhost:/mnt1/
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt1/System/Library/CoreServices/SystemVersion.plist "$dir"/$deviceid/$cpid/$version/SystemVersion.plist
                    LC_ALL=C sed -i -e 's/<\/dict>/<key>ReleaseType<\/key><string>Internal<\/string><key>ProductType<\/key><string>Internal<\/string><\/dict>/g' "$dir"/$deviceid/$cpid/$version/SystemVersion.plist
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/SystemVersion.plist root@localhost:/mnt1/System/Library/CoreServices/SystemVersion.plist
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/SpringBoard-Internal.strings root@localhost:/mnt1/System/Library/CoreServices/SpringBoard.app/en.lproj/
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/SpringBoard-Internal.strings root@localhost:/mnt1/System/Library/CoreServices/SpringBoard.app/en_GB.lproj/
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/com.apple.springboard_ios10.plist root@localhost:/mnt2/mobile/Library/Preferences/com.apple.springboard.plist
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'tar -xvf /mnt1/PrototypeTools.framework_ios10.tar -C /mnt1/System/Library/PrivateFrameworks/'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost '/usr/sbin/chown -R root:wheel /mnt1/System/Library/PrivateFrameworks/PrototypeTools.framework'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/PrototypeTools.framework_ios10.tar'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'tar -xvf /mnt1/AppleInternal.tar -C /mnt1/'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost '/usr/sbin/chown -R root:wheel /mnt1/AppleInternal/'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/AppleInternal.tar'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt2/mobile/Library/Caches/com.apple.MobileGestalt.plist'
                fi
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/Meridian.app.tar.gz root@localhost:/mnt1/
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'tar --preserve-permissions -xzvf /mnt1/Meridian.app.tar.gz -C /mnt1/Applications' 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/Meridian.app.tar.gz' 2> /dev/null
                if [[ ! "$deviceid" == "iPad"* ]]; then
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/UnlimFileManager.app.tar.gz root@localhost:/mnt1/
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'tar --preserve-permissions -xzvf /mnt1/UnlimFileManager.app.tar.gz -C /mnt1/Applications' 2> /dev/null
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost '/usr/sbin/chown -R root:wheel /mnt1/Applications/UnlimFileManager.app'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/UnlimFileManager.app.tar.gz' 2> /dev/null
                fi
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'mkdir -p /mnt2/mobile/Library/Preferences' 2> /dev/null
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/com.apple.Accessibility.Collection.plist root@localhost:/mnt2/mobile/Library/Preferences/com.apple.Accessibility.Collection.plist
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/com.apple.Accessibility.plist root@localhost:/mnt2/mobile/Library/Preferences/com.apple.Accessibility.plist
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt1/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64 "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.raw 2> /dev/null
                "$bin"/dsc64patcher "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.raw "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.patched -103
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.patched root@localhost:/mnt1/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64 2> /dev/null
                #"$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'cp /mnt1/usr/libexec/keybagd /mnt1/usr/libexec/keybagd.bak' 2> /dev/null
                #"$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/fixkeybag root@localhost:/mnt1/usr/libexec/keybagd 2> /dev/null
            elif [[ "$version" == "11."* ]]; then
                if [[ "$appleinternal" == 1 ]]; then
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/AppleInternal.tar root@localhost:/mnt1/
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/PrototypeTools.framework_ios11.tar root@localhost:/mnt1/
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt1/System/Library/CoreServices/SystemVersion.plist "$dir"/$deviceid/$cpid/$version/SystemVersion.plist
                    LC_ALL=C sed -i -e 's/<\/dict>/<key>ReleaseType<\/key><string>Internal<\/string><key>ProductType<\/key><string>Internal<\/string><\/dict>/g' "$dir"/$deviceid/$cpid/$version/SystemVersion.plist
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/SystemVersion.plist root@localhost:/mnt1/System/Library/CoreServices/SystemVersion.plist
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/SpringBoard-Internal.strings root@localhost:/mnt1/System/Library/CoreServices/SpringBoard.app/en.lproj/
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/SpringBoard-Internal.strings root@localhost:/mnt1/System/Library/CoreServices/SpringBoard.app/en_GB.lproj/
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/com.apple.springboard_ios10.plist root@localhost:/mnt2/mobile/Library/Preferences/com.apple.springboard.plist
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'tar -xvf /mnt1/PrototypeTools.framework_ios11.tar -C /mnt1/System/Library/PrivateFrameworks/'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost '/usr/sbin/chown -R root:wheel /mnt1/System/Library/PrivateFrameworks/PrototypeTools.framework'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/PrototypeTools.framework_ios11.tar'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'tar -xvf /mnt1/AppleInternal.tar -C /mnt1/'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost '/usr/sbin/chown -R root:wheel /mnt1/AppleInternal/'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/AppleInternal.tar'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt2/mobile/Library/Caches/com.apple.MobileGestalt.plist'
                fi
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/Undecimus.app_disk0s1s1.tar.gz root@localhost:/mnt1/
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "tar -xzvf /mnt1/Undecimus.app_disk0s1s1.tar.gz -C /mnt1/Applications/"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost '/usr/sbin/chown -R root:wheel /mnt1/Applications/Undecimus.app'
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf /mnt1/System/Library/DataClassMigrators/SystemAppMigrator.migrator/"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mv -v /mnt2/staged_system_apps/* /mnt1/Applications"
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/com.apple.Accessibility.Collection.plist root@localhost:/mnt2/mobile/Library/Preferences/com.apple.Accessibility.Collection.plist
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/com.apple.Accessibility.plist root@localhost:/mnt2/mobile/Library/Preferences/com.apple.Accessibility.plist
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/Certificates.bundle.tar.gz root@localhost:/mnt1/
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'tar --preserve-permissions -xzvf /mnt1/Certificates.bundle.tar.gz -C /mnt1/' 2> /dev/null
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt1/System/Library/Security/Certificates.bundle/Info.plist "$dir"/$deviceid/$cpid/$version/Info.plist 2> /dev/null
                cd "$dir"/$deviceid/$cpid/$version/
                if [ "$os" = "Darwin" ]; then
                    plutil -convert xml1 Info.plist
                    cfbundleshortversionstring="$(/usr/bin/plutil -extract "CFBundleShortVersionString" xml1 -o - Info.plist | grep '<string>' | cut -d\> -f2 |cut -d\< -f1 | head -1)"
                else
                    plistutil -i Info.plist -f xml -o Info.plist
                    cfbundleshortversionstring="$("$bin"/PlistBuddy -c "Print CFBundleShortVersionString" Info.plist | tr -d '"')"
                fi
                LC_ALL=C sed -i -e "s/$cfbundleshortversionstring/2022070700/g" Info.plist
                if [ "$os" = "Darwin" ]; then
                    plutil -convert binary1 Info.plist
                else
                    plistutil -i Info.plist -f bin -o Info.plist
                fi
                cd "$dir"/
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/Info.plist root@localhost:/mnt1/System/Library/Security/Certificates.bundle/Info.plist 2> /dev/null
                if [[ "$version" == "11.3"* || "$version" == "11.4"* ]]; then
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt1/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64 "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.raw 2> /dev/null
                    "$bin"/dsc64patcher "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.raw "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.patched -113
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.patched root@localhost:/mnt1/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64 2> /dev/null
                else
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt1/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64 "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.raw 2> /dev/null
                    "$bin"/dsc64patcher "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.raw "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.patched -11
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.patched root@localhost:/mnt1/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64 2> /dev/null
                    "$bin"/setuphelper.sh $version
                fi
            elif [[ "$version" == "12."* ]]; then
                if [[ "$appleinternal" == 1 ]]; then
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/AppleInternal.tar root@localhost:/mnt1/
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/PrototypeTools.framework_ios12.tar root@localhost:/mnt1/
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt1/System/Library/CoreServices/SystemVersion.plist "$dir"/$deviceid/$cpid/$version/SystemVersion.plist
                    LC_ALL=C sed -i -e 's/<\/dict>/<key>ReleaseType<\/key><string>Internal<\/string><key>ProductType<\/key><string>Internal<\/string><\/dict>/g' "$dir"/$deviceid/$cpid/$version/SystemVersion.plist
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/SystemVersion.plist root@localhost:/mnt1/System/Library/CoreServices/SystemVersion.plist
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/SpringBoard-Internal.strings root@localhost:/mnt1/System/Library/CoreServices/SpringBoard.app/en.lproj/
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/SpringBoard-Internal.strings root@localhost:/mnt1/System/Library/CoreServices/SpringBoard.app/en_GB.lproj/
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/com.apple.springboard_ios10.plist root@localhost:/mnt2/mobile/Library/Preferences/com.apple.springboard.plist
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'tar -xvf /mnt1/PrototypeTools.framework_ios12.tar -C /mnt1/System/Library/PrivateFrameworks/'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost '/usr/sbin/chown -R root:wheel /mnt1/System/Library/PrivateFrameworks/PrototypeTools.framework'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/PrototypeTools.framework_ios12.tar'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'tar -xvf /mnt1/AppleInternal.tar -C /mnt1/'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost '/usr/sbin/chown -R root:wheel /mnt1/AppleInternal/'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/AppleInternal.tar'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt2/mobile/Library/Caches/com.apple.MobileGestalt.plist'
                fi
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/Undecimus.app_disk0s1s1.tar.gz root@localhost:/mnt1/
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "tar -xzvf /mnt1/Undecimus.app_disk0s1s1.tar.gz -C /mnt1/Applications/"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf /mnt1/System/Library/DataClassMigrators/SystemAppMigrator.migrator/"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mv -v /mnt2/staged_system_apps/* /mnt1/Applications"
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/com.apple.Accessibility.Collection.plist root@localhost:/mnt2/mobile/Library/Preferences/com.apple.Accessibility.Collection.plist
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/com.apple.Accessibility.plist root@localhost:/mnt2/mobile/Library/Preferences/com.apple.Accessibility.plist
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/Certificates.bundle.tar.gz root@localhost:/mnt1/
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'tar --preserve-permissions -xzvf /mnt1/Certificates.bundle.tar.gz -C /mnt1/' 2> /dev/null
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt1/System/Library/Security/Certificates.bundle/Info.plist "$dir"/$deviceid/$cpid/$version/Info.plist 2> /dev/null
                cd "$dir"/$deviceid/$cpid/$version/
                if [ "$os" = "Darwin" ]; then
                    plutil -convert xml1 Info.plist
                    cfbundleshortversionstring="$(/usr/bin/plutil -extract "CFBundleShortVersionString" xml1 -o - Info.plist | grep '<string>' | cut -d\> -f2 |cut -d\< -f1 | head -1)"
                else
                    plistutil -i Info.plist -f xml -o Info.plist
                    cfbundleshortversionstring="$("$bin"/PlistBuddy -c "Print CFBundleShortVersionString" Info.plist | tr -d '"')"
                fi
                LC_ALL=C sed -i -e "s/$cfbundleshortversionstring/2022070700/g" Info.plist
                if [ "$os" = "Darwin" ]; then
                    plutil -convert binary1 Info.plist
                else
                    plistutil -i Info.plist -f bin -o Info.plist
                fi
                cd "$dir"/
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt1/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64 "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.raw 2> /dev/null
                "$bin"/dsc64patcher "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.raw "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.patched -12
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.patched root@localhost:/mnt1/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64 2> /dev/null
                "$bin"/setuphelper.sh $version
            elif [[ "$version" == "13."* ]]; then
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf /mnt1/System/Library/DataClassMigrators/SystemAppMigrator.migrator/"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mv -v /mnt2/staged_system_apps/* /mnt1/Applications"
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/com.apple.Accessibility.Collection.plist root@localhost:/mnt2/mobile/Library/Preferences/com.apple.Accessibility.Collection.plist
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/com.apple.Accessibility.plist root@localhost:/mnt2/mobile/Library/Preferences/com.apple.Accessibility.plist
                #"$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt1/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64 "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.raw 2> /dev/null
                #if [[ "$version" == "13.0"* || "$version" == "13.1"* || "$version" == "13.2"* || "$version" == "13.3"* ]]; then
                #    "$bin"/dsc64patcher "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.raw "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.patched -13
                #else
                #    "$bin"/dsc64patcher "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.raw "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.patched -134
                #fi
                #"$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.patched root@localhost:/mnt1/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mv /mnt1/sbin/fsck /mnt1/sbin/fsckBackup"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mv /mnt1/System/Library/Filesystems/apfs.fs /mnt1/System/Library/Filesystems/apfs.fsBackup"
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/apfs.fs_ios14.tar.gz root@localhost:/mnt1/
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "tar -xzvf /mnt1/apfs.fs_ios14.tar.gz -C /mnt1"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf /mnt1/apfs.fs_ios14.tar.gz"
            elif [[ "$version" == "14."* ]]; then
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf /mnt1/System/Library/DataClassMigrators/SystemAppMigrator.migrator/"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mv -v /mnt2/staged_system_apps/* /mnt1/Applications"
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/com.apple.Accessibility.Collection.plist root@localhost:/mnt2/mobile/Library/Preferences/com.apple.Accessibility.Collection.plist
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/com.apple.Accessibility.plist root@localhost:/mnt2/mobile/Library/Preferences/com.apple.Accessibility.plist
                #"$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt1/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64 "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.raw 2> /dev/null
                #"$bin"/dsc64patcher "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.raw "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.patched -14
                #"$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.patched root@localhost:/mnt1/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64 2> /dev/null
            fi
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt3" 2> /dev/null
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt1" 2> /dev/null
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt2" 2> /dev/null
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "bash -c mount_filesystems" 2> /dev/null
            #"$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/sbin/nvram oblit-inprogress=5"
        fi
        $("$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/reboot &" 2> /dev/null &)
        sleep 5
        if [[ ! -e "$dir"/$deviceid/0.0/activation_records/activation_record.plist || "$force_activation" == 1 ]]; then
            if [[ "$version" == "9.3"* || "$version" == "10."* || "$version" == "11."* || "$version" == "12."* ||  "$version" == "13."* || "$version" == "14."* ]]; then
                if [ -e "$dir"/$deviceid/$cpid/$version/iBSS.img4 ]; then
                    _wait_for_dfu
                    _dfuhelper
                    sudo killall -STOP -c usbd
                    cd "$dir"/$deviceid/$cpid/$version
                    _boot $deviceid $replace $version
                    cd "$dir"/
                fi
                _kill_if_running iproxy
                info "Step 1 of downwgrading to iOS/iPadOS $version is now done"
                info "The device should now boot without any issue and show a progress bar"
                info "When your device gets to the setup screen, put the device back into dfu mode"
                info "We will then activate your device to allow you to navigate to the home screen"
                sleep 5
                _dfuhelper
                sudo killall -STOP -c usbd
                if [[ "$version" == "7."* || "$version" == "8."* ]]; then
                    _download_ramdisk_boot_files $deviceid $replace 8.4.1
                    cd "$dir"/$deviceid/$cpid/ramdisk/8.4.1
                    _boot_ramdisk $deviceid $replace 8.4.1
                elif [[ "$version" == "10.3"* ]]; then
                    _download_ramdisk_boot_files $deviceid $replace 10.3.3
                    cd "$dir"/$deviceid/$cpid/ramdisk/10.3.3
                    _boot_ramdisk $deviceid $replace 10.3.3
                elif [[ "$version" == "11."* ||  "$version" == "12."* || "$version" == "13."* || "$version" == "14."* ]]; then
                    if [[ "$(./java/bin/java -jar ./Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -e 15.6 $deviceid)" == "true" ]]; then
                        _download_ramdisk_boot_files $deviceid $replace 15.6
                        cd "$dir"/$deviceid/$cpid/ramdisk/15.6
                        _boot_ramdisk $deviceid $replace 15.6
                    elif [[ "$deviceid" == "iPad"* && ! "$deviceid" == "iPad4"* ]]; then
                        _download_ramdisk_boot_files $deviceid $replace 15.6
                        cd "$dir"/$deviceid/$cpid/ramdisk/15.6
                        _boot_ramdisk $deviceid $replace 15.6
                    else
                        _download_ramdisk_boot_files $deviceid $replace 12.5.4
                        cd "$dir"/$deviceid/$cpid/ramdisk/12.5.4
                        _boot_ramdisk $deviceid $replace 12.5.4
                    fi
                elif [[ "$os" = "Darwin" && ! "$deviceid" == "iPhone6"* && ! "$deviceid" == "iPhone7"* && ! "$deviceid" == "iPad4"* && ! "$deviceid" == "iPad5"* && ! "$deviceid" == "iPod7"* && "$version" == "9."* ]]; then
                    _download_ramdisk_boot_files $deviceid $replace 9.3
                    cd "$dir"/$deviceid/$cpid/ramdisk/9.3
                    _boot_ramdisk $deviceid $replace 9.3
                else
                    _download_ramdisk_boot_files $deviceid $replace 11.4
                    cd "$dir"/$deviceid/$cpid/ramdisk/11.4
                    _boot_ramdisk $deviceid $replace 11.4
                fi
                cd "$dir"/
                _kill_if_running iproxy
                sudo killall -STOP -c usbd
                "$bin"/iproxy 2222 22 &
                while ! [[ $("$bin"/sshpass -p "alpine" ssh -o StrictHostKeyChecking=no -p2222 root@localhost "echo hello" 2> /dev/null) == "hello" ]]; do
                    sleep 1
                done
                if [[ "$version" == "9.3"* || "$version" == "10.0"* || "$version" == "10.1"* || "$version" == "10.2"* ]]; then
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount -w -t hfs /dev/disk0s1s1 /mnt1" 2> /dev/null
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount -w -t hfs /dev/disk0s1s2 /mnt2" 2> /dev/null
                    # /mnt2/containers/Data/System/58954F59-3AA2-4005-9C5B-172BE4ADEC98/Library/internal/data_ark.plist
                    dataarkplist=$(remote_cmd "/usr/bin/find /mnt2/containers/Data/System -name 'internal'" 2> /dev/null)
                    dataarkplist="$dataarkplist/data_ark.plist"
                    info $dataarkplist
                    if [ -e "$dir"/$deviceid/0.0/IC-Info.sisv ]; then
                        "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt2/mobile/Library/FairPlay/iTunes_Control/iTunes/"
                        "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/0.0/IC-Info.sisv root@localhost:/mnt2/mobile/Library/FairPlay/iTunes_Control/iTunes/IC-Info.sisv 2> /dev/null
                    fi
                    if [ -e "$dir"/$deviceid/0.0/com.apple.commcenter.device_specific_nobackup.plist ]; then
                        "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt2/wireless/Library/Preferences/"
                        "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/0.0/com.apple.commcenter.device_specific_nobackup.plist root@localhost:/mnt2/wireless/Library/Preferences/com.apple.commcenter.device_specific_nobackup.plist 2> /dev/null
                    fi
                    "$bin"/mobactivationd64patcher "$dir"/$deviceid/$cpid/$version/mobactivationd.raw "$dir"/$deviceid/$cpid/$version/mobactivationd.patched -b -c -d 2> /dev/null
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/mobactivationd.patched root@localhost:/mnt1/usr/libexec/mobileactivationd 2> /dev/null
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/data_ark.plis_ root@localhost:$dataarkplist
                    if [[ "$version" == "10."* ]]; then
                        "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/Meridian.app.tar.gz root@localhost:/mnt1/
                        "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'tar --preserve-permissions -xzvf /mnt1/Meridian.app.tar.gz -C /mnt1/Applications' 2> /dev/null
                        "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/Meridian.app.tar.gz' 2> /dev/null
                    fi
                else
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount_apfs /dev/disk0s1s1 /mnt1"
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount_apfs /dev/disk0s1s2 /mnt2"
                    # /mnt2/containers/Data/System/58954F59-3AA2-4005-9C5B-172BE4ADEC98/Library/internal/data_ark.plist
                    dataarkplist=$(remote_cmd "/usr/bin/find /mnt2/containers/Data/System -name 'data_ark.plist'" 2> /dev/null)
                    info $dataarkplist
                    if [ -e "$dir"/$deviceid/0.0/IC-Info.sisv ]; then
                        "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt2/mobile/Library/FairPlay/iTunes_Control/iTunes/"
                        "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/0.0/IC-Info.sisv root@localhost:/mnt2/mobile/Library/FairPlay/iTunes_Control/iTunes/IC-Info.sisv 2> /dev/null
                    fi
                    if [ -e "$dir"/$deviceid/0.0/com.apple.commcenter.device_specific_nobackup.plist ]; then
                        "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt2/wireless/Library/Preferences/"
                        "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/0.0/com.apple.commcenter.device_specific_nobackup.plist root@localhost:/mnt2/wireless/Library/Preferences/com.apple.commcenter.device_specific_nobackup.plist 2> /dev/null
                    fi
                    "$bin"/mobactivationd64patcher "$dir"/$deviceid/$cpid/$version/mobactivationd.raw "$dir"/$deviceid/$cpid/$version/mobactivationd.patched -b -c -d 2> /dev/null
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/mobactivationd.patched root@localhost:/mnt1/usr/libexec/mobileactivationd 2> /dev/null
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/data_ark.plis_ root@localhost:$dataarkplist
                    if [[ "$version" == "10."* ]]; then
                        "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/Meridian.app.tar.gz root@localhost:/mnt1/
                        "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'tar --preserve-permissions -xzvf /mnt1/Meridian.app.tar.gz -C /mnt1/Applications' 2> /dev/null
                        "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/Meridian.app.tar.gz' 2> /dev/null
                    fi
                fi
                $("$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/reboot &" 2> /dev/null &)
                sleep 5
            fi
        fi
        _kill_if_running iproxy
        if [ -e "$dir"/$deviceid/$cpid/$version/iBSS.img4 ]; then
            _wait_for_dfu
            _dfuhelper
            sudo killall -STOP -c usbd
            cd "$dir"/$deviceid/$cpid/$version
            _boot $deviceid $replace $version
            cd "$dir"/
        fi
    fi
    if [[ ! "$restore" == 1 ]]; then
        sleep 1
        sudo killall -STOP -c usbd
        rdversion="$version"
        if [[ "$version" == "10."* ]]; then
            rdversion="10.3.3"
        elif [[ "$version" == "7."* || "$version" == "8."* ]]; then
            rdversion="8.4.1"
        fi
        # only boots $r ramdisk if files required to downgrade arent backed up
        # and ios version prior to downgrade is said to be >=16.0
        _download_ramdisk_boot_files $deviceid $replace $r
        # otherwise boots $rdversion ramdisk
        _download_ramdisk_boot_files $deviceid $replace $rdversion
        cd "$dir"/$deviceid/$cpid/ramdisk/$rdversion
        _boot_ramdisk $deviceid $replace $r
        cd "$dir"/
        _kill_if_running iproxy
        sudo killall -STOP -c usbd
        "$bin"/iproxy 2222 22 &
        while ! [[ $("$bin"/sshpass -p "alpine" ssh -o StrictHostKeyChecking=no -p2222 root@localhost "echo hello" 2> /dev/null) == "hello" ]]; do
            sleep 1
        done
        if [[ "$restore_activation" == 1 ]]; then
            if [[ "$r" == "7."* || "$r" == "8."* || "$r" == "9."* || "$r" == "10.0"* || "$r" == "10.1"* || "$r" == "10.2"* ]]; then
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt1" 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt2" 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount -w -t hfs /dev/disk0s1s1 /mnt1" 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "bash -c mount_filesystems" 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount -w -t hfs /dev/disk0s1s2 /mnt1/private/var" 2> /dev/null
                if [ -e "$dir"/$deviceid/0.0/IC-Info.sisv ]; then
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt1/private/var/mobile/Library/FairPlay/iTunes_Control/iTunes/"
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/0.0/IC-Info.sisv root@localhost:/mnt1/IC-Info.sisv 2> /dev/null
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "cd /mnt1/private/var/mobile/Library/FairPlay/iTunes_Control/iTunes && ln -s ../../../../../../../IC-Info.sisv IC-Info.sisv && stat IC-Info.sisv"
                else
                    error ""$dir"/$deviceid/0.0/IC-Info.sisv does not exist"
                fi
                if [ -e "$dir"/$deviceid/0.0/com.apple.commcenter.device_specific_nobackup.plist ]; then
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt1/private/var/wireless/Library/Preferences/"
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf /mnt1/private/var/wireless/Library/Preferences/com.apple.commcenter.device_specific_nobackup.plist"
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/0.0/com.apple.commcenter.device_specific_nobackup.plist root@localhost:/mnt1/com.apple.commcenter.device_specific_nobackup.plist 2> /dev/null
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "cd /mnt1/private/var/wireless/Library/Preferences && ln -s ../../../../../com.apple.commcenter.device_specific_nobackup.plist com.apple.commcenter.device_specific_nobackup.plist && stat com.apple.commcenter.device_specific_nobackup.plist"
                else
                    error ""$dir"/$deviceid/0.0/com.apple.commcenter.device_specific_nobackup.plist does not exist"
                fi
                if [[ "$restore_factorydata" == 1 ]]; then
                    if [ -e "$dir"/$deviceid/0.0/com.apple.factorydata ]; then
                        "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf /mnt1/System/Library/Caches/com.apple.factorydata"
                        "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir /mnt1/System/Library/Caches/com.apple.factorydata"
                        "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -r -P 2222 "$dir"/$deviceid/0.0/com.apple.factorydata/* root@localhost:/mnt1/System/Library/Caches/com.apple.factorydata 2> /dev/null
                    fi
                fi
                if [[ -e "$dir"/$deviceid/0.0/activation_records ]]; then
                    if [[ "$version" == "9."* && "$force_activation" == 1 ]]; then
                        if [[ "$appleinternal" == 1 ]]; then
                            "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/AppleInternal.tar root@localhost:/mnt1/ 2> /dev/null
                            "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/PrototypeTools.framework_ios9.tar root@localhost:/mnt1/ 2> /dev/null
                            "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt1/System/Library/CoreServices/SystemVersion.plist "$dir"/$deviceid/$cpid/$version/SystemVersion.plist 2> /dev/null
                            LC_ALL=C sed -i -e 's/<\/dict>/<key>ReleaseType<\/key><string>Internal<\/string><key>ProductType<\/key><string>Internal<\/string><\/dict>/g' "$dir"/$deviceid/$cpid/$version/SystemVersion.plist 2> /dev/null
                            "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/SystemVersion.plist root@localhost:/mnt1/System/Library/CoreServices/SystemVersion.plist 2> /dev/null
                            "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/SpringBoard-Internal.strings root@localhost:/mnt1/System/Library/CoreServices/SpringBoard.app/en.lproj/ 2> /dev/null
                            "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/SpringBoard-Internal.strings root@localhost:/mnt1/System/Library/CoreServices/SpringBoard.app/en_GB.lproj/ 2> /dev/null
                            "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/com.apple.springboard_ios9.plist root@localhost:/mnt2/mobile/Library/Preferences/com.apple.springboard.plist 2> /dev/null
                            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'tar -xvf /mnt1/PrototypeTools.framework_ios9.tar -C /mnt1/System/Library/PrivateFrameworks/'
                            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost '/usr/sbin/chown -R root:wheel /mnt1/System/Library/PrivateFrameworks/PrototypeTools.framework' 2> /dev/null
                            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/PrototypeTools.framework_ios9.tar' 2> /dev/null
                            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'tar -xvf /mnt1/AppleInternal.tar -C /mnt1/'
                            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost '/usr/sbin/chown -R root:wheel /mnt1/AppleInternal/' 2> /dev/null
                            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/AppleInternal.tar' 2> /dev/null
                            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt2/mobile/Library/Caches/com.apple.MobileGestalt.plist' 2> /dev/null
                        fi
                    else
                        "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt1/activation_records"
                        "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -r -P 2222 "$dir"/$deviceid/0.0/activation_records/* root@localhost:/mnt1/activation_records 2> /dev/null
                        "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "stat /mnt1/activation_records/activation_record.plist"
                        "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt1/private/var/root/Library/Lockdown/activation_records"
                        "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "cd /mnt1/private/var/root/Library/Lockdown/activation_records && ln -s ../../../../../../activation_records/activation_record.plist activation_record.plist && stat activation_record.plist"
                        "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags -R schg /mnt1/private/var/root/Library/Lockdown/activation_records"
                        "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt1/private/var/mobile/Library/mad/activation_records"
                        "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "cd /mnt1/private/var/mobile/Library/mad/activation_records && ln -s ../../../../../../activation_records/activation_record.plist activation_record.plist && stat activation_record.plist"
                        "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags -R schg /mnt1/private/var/mobile/Library/mad/activation_records"
                    fi
                else
                    error ""$dir"/$deviceid/0.0/activation_records does not exist"
                fi
                if [[ -e "$dir"/$deviceid/0.0/activation_records/activation_record.plist ]]; then
                    if [ -e "$dir"/$deviceid/0.0/data_ark.plist ]; then
                        "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/0.0/data_ark.plist root@localhost:/mnt1/data_ark.plist 2> /dev/null
                        "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf /mnt1/private/var/root/Library/Lockdown/data_ark.plist"
                        "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "cd /mnt1/private/var/root/Library/Lockdown && ln -s ../../../../../data_ark.plist data_ark.plist && stat data_ark.plist"
                        "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags schg /mnt1/private/var/root/Library/Lockdown/data_ark.plist"
                    else
                        error ""$dir"/$deviceid/0.0/data_ark.plist does not exist"
                    fi
                else
                    error ""$dir"/$deviceid/0.0/activation_records/activation_record.plist does not exist"
                fi
                # /mnt1/private/var/containers/Data/System/58954F59-3AA2-4005-9C5B-172BE4ADEC98/Library/internal/data_ark.plist
                dataarkplist=$(remote_cmd "/usr/bin/find /mnt1/private/var/containers/Data/System -name 'internal'" 2> /dev/null)
                dataarkplist="$dataarkplist/data_ark.plist"
                info $dataarkplist
                if [[ "$version" == "9."* && "$force_activation" == 1 ]]; then
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf $dataarkplist"
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/data_ark.plis_ root@localhost:/mnt1/mob_data_ark.plist
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "cd $(remote_cmd "/usr/bin/find /mnt1/private/var/containers/Data/System -name 'internal'" 2> /dev/null) && ln -s ../../../../../../../../mob_data_ark.plist data_ark.plist && stat data_ark.plist"
                else
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf $dataarkplist"
                    info "Removed residual data_ark.plist from $dataarkplist"
                fi
                if [[ "$version" == "9.1"* || "$version" == "9.2"* ]]; then
                    if [[ "$version" == "9."* && "$force_activation" == 1 ]]; then
                        "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt1/System/Library/PrivateFrameworks/MobileActivation.framework/Support/mobactivationd "$dir"/$deviceid/$cpid/$version/mobactivationd.raw 2> /dev/null
                        "$bin"/mobactivationd64patcher "$dir"/$deviceid/$cpid/$version/mobactivationd.raw "$dir"/$deviceid/$cpid/$version/mobactivationd.patched -b -c -d 2> /dev/null
                        "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/mobactivationd.patched root@localhost:/mnt1/System/Library/PrivateFrameworks/MobileActivation.framework/Support/mobactivationd 2> /dev/null
                    fi
                elif [[ "$version" == "9.3"* ]]; then
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt1/usr/libexec/mobileactivationd "$dir"/$deviceid/$cpid/$version/mobactivationd.raw 2> /dev/null
                    if [[ "$version" == "9."* && "$force_activation" == 1 ]]; then
                        "$bin"/mobactivationd64patcher "$dir"/$deviceid/$cpid/$version/mobactivationd.raw "$dir"/$deviceid/$cpid/$version/mobactivationd.patched -b -c -d 2> /dev/null
                        "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/mobactivationd.patched root@localhost:/mnt1/usr/libexec/mobileactivationd 2> /dev/null
                    fi
                fi
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt1" 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt2" 2> /dev/null
                info "Disabling auto-boot in nvram to prevent effaceable storage issues . . ."
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/sbin/nvram auto-boot=false" 2> /dev/null
                info "You can enable auto-boot again at any time by running`if [ $EUID = 0 ]; then echo " sudo"; fi` $0 $version --fix-auto-boot"
                info "Done"
                info "Restored the activation records on your device"
                $("$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/reboot &" 2> /dev/null &)
                _kill_if_running iproxy
                exit 0
            else
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt1" 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt2" 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "bash -c mount_filesystems" 2> /dev/null
                if [ -e "$dir"/$deviceid/0.0/IC-Info.sisv ]; then
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt2/mobile/Library/FairPlay/iTunes_Control/iTunes/"
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/0.0/IC-Info.sisv root@localhost:/mnt2/mobile/Library/FairPlay/iTunes_Control/iTunes/IC-Info.sisv 2> /dev/null
                else
                    error ""$dir"/$deviceid/0.0/IC-Info.sisv does not exist"
                fi
                if [ -e "$dir"/$deviceid/0.0/com.apple.commcenter.device_specific_nobackup.plist ]; then
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt2/wireless/Library/Preferences/"
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/0.0/com.apple.commcenter.device_specific_nobackup.plist root@localhost:/mnt2/wireless/Library/Preferences/com.apple.commcenter.device_specific_nobackup.plist 2> /dev/null
                else
                    error ""$dir"/$deviceid/0.0/com.apple.commcenter.device_specific_nobackup.plist does not exist"
                fi
                if [[ -e "$dir"/$deviceid/0.0/activation_records ]]; then
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt2/root/Library/Lockdown/activation_records"
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -r -P 2222 "$dir"/$deviceid/0.0/activation_records/* root@localhost:/mnt2/root/Library/Lockdown/activation_records 2> /dev/null
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags -R schg /mnt2/root/Library/Lockdown/activation_records"
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt2/mobile/Library/mad/activation_records"
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -r -P 2222 "$dir"/$deviceid/0.0/activation_records/* root@localhost:/mnt2/mobile/Library/mad/activation_records 2> /dev/null
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags -R schg /mnt2/mobile/Library/mad/activation_records"
                else
                    error ""$dir"/$deviceid/0.0/activation_records does not exist"
                fi
                if [[ -e "$dir"/$deviceid/0.0/activation_records/activation_record.plist ]]; then
                    if [ -e "$dir"/$deviceid/0.0/data_ark.plist ]; then
                        "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/0.0/data_ark.plist root@localhost:/mnt2/root/Library/Lockdown/data_ark.plist 2> /dev/null
                        "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags schg /mnt2/root/Library/Lockdown/data_ark.plist"
                    else
                        error ""$dir"/$deviceid/0.0/data_ark.plist does not exist"
                    fi
                else
                    error ""$dir"/$deviceid/0.0/activation_records/activation_record.plist does not exist"
                fi
                # /mnt2/containers/Data/System/58954F59-3AA2-4005-9C5B-172BE4ADEC98/Library/internal/data_ark.plist
                dataarkplist=$(remote_cmd "/usr/bin/find /mnt2/containers/Data/System -name 'data_ark.plist'" 2> /dev/null)
                if [[ "$dataarkplist" == "/mnt2/containers/Data/System"* ]]; then
                    folder=$(echo $dataarkplist | sed 's/\/data_ark.plist//g')
                    folder=$(echo $folder | sed 's/\/internal//g')
                    # /mnt2/containers/Data/System/58954F59-3AA2-4005-9C5B-172BE4ADEC98/Library
                    if [[ "$folder" == "/mnt2/containers/Data/System"* ]]; then
                        "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf $folder/internal/data_ark.plist"
                        info "Removed residual data_ark.plist from $folder/internal/data_ark.plist"
                    fi
                fi
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt1" 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt2" 2> /dev/null
                info "Restored the activation records on your device"
            fi
        fi
        if [[ "$dump_activation" == 1 ]]; then
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt1" 2> /dev/null
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt2" 2> /dev/null
            if [[ "$r" == "7."* || "$r" == "8."* || "$r" == "9."* || "$r" == "10.0"* || "$r" == "10.1"* || "$r" == "10.2"* ]]; then
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount -w -t hfs /dev/disk0s1s1 /mnt1" 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "bash -c mount_filesystems" 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount -w -t hfs /dev/disk0s1s2 /mnt2" 2> /dev/null
            else
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "bash -c mount_filesystems" 2> /dev/null
            fi
            mkdir -p "$dir"/$deviceid/0.0/
			if [ ! -e "$dir"/$deviceid/0.0/apticket.der ]; then
				"$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt1/System/Library/Caches/apticket.der "$dir"/$deviceid/0.0/apticket.der 2> /dev/null
			fi
			if [ ! -e "$dir"/$deviceid/0.0/sep-firmware.img4 ]; then
				"$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt1/usr/standalone/firmware/sep-firmware.img4 "$dir"/$deviceid/0.0/sep-firmware.img4 2> /dev/null
			fi
			if [ ! -e "$dir"/$deviceid/0.0/FUD ]; then
				"$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -r -P 2222 root@localhost:/mnt1/usr/standalone/firmware/FUD "$dir"/$deviceid/0.0/FUD 2> /dev/null
			fi
			if [ ! -e "$dir"/$deviceid/0.0/Baseband ]; then
				"$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -r -P 2222 root@localhost:/mnt1/usr/local/standalone/firmware/Baseband "$dir"/$deviceid/0.0/Baseband 2> /dev/null
			fi
			if [ ! -e "$dir"/$deviceid/0.0/firmware ]; then
				"$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -r -P 2222 root@localhost:/mnt1/usr/standalone/firmware "$dir"/$deviceid/0.0/firmware 2> /dev/null
			fi
			if [ ! -e "$dir"/$deviceid/0.0/local ]; then
				"$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -r -P 2222 root@localhost:/mnt1/usr/local "$dir"/$deviceid/0.0/local 2> /dev/null
			fi
			if [ ! -e "$dir"/$deviceid/0.0/keybags ]; then
				"$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -r -P 2222 root@localhost:/mnt2/keybags "$dir"/$deviceid/0.0/keybags 2> /dev/null
			fi
			if [ ! -e "$dir"/$deviceid/0.0/wireless ]; then
				"$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -r -P 2222 root@localhost:/mnt2/wireless "$dir"/$deviceid/0.0/wireless 2> /dev/null
			fi
			if [ ! -e "$dir"/$deviceid/0.0/com.apple.factorydata ]; then
				"$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -r -P 2222 root@localhost:/mnt1/System/Library/Caches/com.apple.factorydata "$dir"/$deviceid/0.0/com.apple.factorydata 2> /dev/null
			fi
			if [ ! -e "$dir"/$deviceid/0.0/IC-Info.sisv ]; then
				"$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt2/mobile/Library/FairPlay/iTunes_Control/iTunes/IC-Info.sisv "$dir"/$deviceid/0.0/IC-Info.sisv 2> /dev/null
			fi
			if [ ! -e "$dir"/$deviceid/0.0/com.apple.commcenter.device_specific_nobackup.plist ]; then
				"$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt2/wireless/Library/Preferences/com.apple.commcenter.device_specific_nobackup.plist "$dir"/$deviceid/0.0/com.apple.commcenter.device_specific_nobackup.plist 2> /dev/null
			fi
            if [ ! -e "$dir"/$deviceid/0.0/data_ark.plist ]; then
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt2/root/Library/Lockdown/data_ark.plist "$dir"/$deviceid/0.0/data_ark.plist 2> /dev/null
            fi
            if [ ! -e "$dir"/$deviceid/0.0/SystemVersion.plist ]; then
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt1/System/Library/CoreServices/SystemVersion.plist "$dir"/$deviceid/0.0/SystemVersion.plist 2> /dev/null
            fi
            #if [ ! -e "$dir"/$deviceid/0.0/Carrier_Bundles.tar ]; then
            #    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "tar -cvf /mnt1/Carrier_Bundles.tar /mnt1/System/Library/Carrier\ Bundles/iPhone/" 2> /dev/null
            #    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt1/Carrier_Bundles.tar "$dir"/$deviceid/0.0/Carrier_Bundles.tar 2> /dev/null
            #fi
			# /mnt2/containers/Data/System/58954F59-3AA2-4005-9C5B-172BE4ADEC98/Library/internal/data_ark.plist
			dataarkplist=$(remote_cmd "/usr/bin/find /mnt2/containers/Data/System -name 'data_ark.plist'" 2> /dev/null)
			if [[ "$dataarkplist" == "/mnt2/containers/Data/System"* ]]; then
				folder=$(echo $dataarkplist | sed 's/\/data_ark.plist//g')
                folder=$(echo $folder | sed 's/\/internal//g')
				# /mnt2/containers/Data/System/58954F59-3AA2-4005-9C5B-172BE4ADEC98/Library
				if [[ "$folder" == "/mnt2/containers/Data/System"* ]]; then
					if [ ! -e "$dir"/$deviceid/0.0/activation_records ]; then
						"$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -r -P 2222 root@localhost:$folder/activation_records "$dir"/$deviceid/0.0/activation_records 2> /dev/null
					fi
				fi
			fi
			if [ ! -e "$dir"/$deviceid/0.0/activation_records ]; then
				"$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -r -P 2222 root@localhost:/mnt2/mobile/Library/mad/activation_records "$dir"/$deviceid/0.0/activation_records 2> /dev/null
			fi
			if [[ ! -e "$dir"/$deviceid/0.0/apticket.der ]]; then
				has_active=$(remote_cmd "ls /mnt6/active" 2> /dev/null)
				if [ ! "$has_active" = "/mnt6/active" ]; then
                    error "Active file does not exist! Please use SSH to create it"
                    error "    /mnt6/active should contain the name of the UUID in /mnt6"
                    error "    When done, type reboot in the SSH session, then rerun the script"
                    error "    ssh root@localhost -p 2222"
                    ramdisk=1
                else
                    active=$(remote_cmd "cat /mnt6/active" 2> /dev/null)
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt6/$active/System/Library/Caches/apticket.der "$dir"/$deviceid/0.0/apticket.der 2> /dev/null
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt6/$active/usr/standalone/firmware/sep-firmware.img4 "$dir"/$deviceid/0.0/sep-firmware.img4 2> /dev/null
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -r -P 2222 root@localhost:/mnt6/$active/usr/standalone/firmware/FUD "$dir"/$deviceid/0.0/FUD 2> /dev/null
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -r -P 2222 root@localhost:/mnt6/$active/usr/local/standalone/firmware/Baseband "$dir"/$deviceid/0.0/Baseband 2> /dev/null
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -r -P 2222 root@localhost:/mnt6/$active/usr/standalone/firmware "$dir"/$deviceid/0.0/firmware 2> /dev/null
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -r -P 2222 root@localhost:/mnt6/$active/usr/local "$dir"/$deviceid/0.0/local 2> /dev/null
				fi
			fi
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt1" 2> /dev/null
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt2" 2> /dev/null
            if [[ ! -e "$dir"/$deviceid/0.0/apticket.der || ! -e "$dir"/$deviceid/0.0/sep-firmware.img4 || ! -e "$dir"/$deviceid/0.0/keybags ]]; then
                info "An error occured while trying to back up the required files required to downgrade"
            else
                info "Backed up the required files required to downgrade"
            fi
        fi
        if [[ "$dump_blobs" == 1 ]]; then
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt1" 2> /dev/null
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt2" 2> /dev/null
            if [[ "$r" == "7."* || "$r" == "8."* || "$r" == "9."* || "$r" == "10.0"* || "$r" == "10.1"* || "$r" == "10.2"* ]]; then
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount -w -t hfs /dev/disk0s1s1 /mnt1" 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "bash -c mount_filesystems" 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount -w -t hfs /dev/disk0s1s2 /mnt2" 2> /dev/null
            else
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "bash -c mount_filesystems" 2> /dev/null
            fi
            mkdir -p "$dir"/$deviceid/0.0/
            if [[ ! -e "$dir"/$deviceid/0.0/apticket.der ]]; then
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt1/System/Library/Caches/apticket.der "$dir"/$deviceid/0.0/apticket.der 2> /dev/null
            fi
			if [[ ! -e "$dir"/$deviceid/0.0/apticket.der ]]; then
				has_active=$(remote_cmd "ls /mnt6/active" 2> /dev/null)
				if [ ! "$has_active" = "/mnt6/active" ]; then
                    error "Active file does not exist! Please use SSH to create it"
                    error "    /mnt6/active should contain the name of the UUID in /mnt6"
                    error "    When done, type reboot in the SSH session, then rerun the script"
                    error "    ssh root@localhost -p 2222"
                    ramdisk=1
                else
                    active=$(remote_cmd "cat /mnt6/active" 2> /dev/null)
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt6/$active/System/Library/Caches/apticket.der "$dir"/$deviceid/0.0/apticket.der 2> /dev/null
				fi
			fi
            if [[ -e "$dir"/$deviceid/0.0/apticket.der ]]; then
                info "$dir"/$deviceid/0.0/apticket.der
            fi
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt1" 2> /dev/null
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt2" 2> /dev/null
            pwd
            if [ "$os" = 'Darwin' ]; then
                "$bin"/timeout 5 "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "cat /dev/rdisk1" | dd of=dump.raw bs=256 count=$((0x4000))
            else
                timeout 5 "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "cat /dev/rdisk1" | dd of=dump.raw bs=256 count=$((0x4000))
            fi
            stat dump.raw
            "$bin"/img4tool --convert -s dumped.shsh dump.raw
            if [[ ! "$?" == "0" ]]; then
                warning "Failed with rdisk1, trying again with rdisk2..."
                if [ "$os" = 'Darwin' ]; then
                    "$bin"/timeout 5 "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "cat /dev/rdisk2" | dd of=dump.raw bs=256 count=$((0x4000))
                else
                    timeout 5 "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "cat /dev/rdisk2" | dd of=dump.raw bs=256 count=$((0x4000))
                fi
                stat dump.raw
                "$bin"/img4tool --convert -s dumped.shsh dump.raw
                if [[ ! "$?" == "0" ]]; then
                    error "Failed with rdisk2, cannot continue."
                fi
            fi
            stat dumped.shsh
            mv dumped.shsh "$dir"/$deviceid/0.0/shsh.shsh2
            rm -rf dump.raw
        fi
        if [[ "$dump_nand" == 1 ]]; then
            cd "$dir"/$deviceid/0.0/
            # dd if=/dev/sda bs=5M conv=fsync status=progress | gzip -c -9 | ssh user@DestinationIP 'gzip -d | dd of=/dev/sda bs=5M'
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt1" 2> /dev/null
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt2" 2> /dev/null
            info "Backing up /dev/disk0 to $dir/$deviceid/0.0/disk0.gz, this may take up to 15 minutes . . ."
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "dd if=/dev/disk0 bs=64k | gzip -1 -" | dd of=disk0.gz bs=64k
            info "Disabling auto-boot in nvram to prevent effaceable storage issues . . ."
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/sbin/nvram auto-boot=false" 2> /dev/null
            info "You can enable auto-boot again at any time by running`if [ $EUID = 0 ]; then echo " sudo"; fi` $0 $version --fix-auto-boot"
            info "Done"
            cd "$dir"/
        fi
        if [[ "$restore_nand" == 1 ]]; then
            cd "$dir"/$deviceid/0.0/
            # dd if=/dev/sda bs=5M conv=fsync status=progress | gzip -c -9 | ssh user@DestinationIP 'gzip -d | dd of=/dev/sda bs=5M'
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt1" 2> /dev/null
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt2" 2> /dev/null
            info "Restoring /dev/disk0 from $dir/$deviceid/0.0/disk0.gz, this may take up to 15 minutes . . ."
            dd if=disk0.gz bs=64k | "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "gzip -d | dd of=/dev/disk0 bs=64k"
            info "Enabling auto-boot in nvram to allow booting the restored nand after a reboot . . ."
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/sbin/nvram auto-boot=true" 2> /dev/null
            read -p "would you like to also run oblit on your device to ensure function after nand restore? " r
            if [[ ! "$r" == "no" && ! "$r" == "n" ]]; then
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/sbin/nvram oblit-inprogress=5" 2> /dev/null
            fi
            info "Done"
            cd "$dir"/
        fi
        if [[ "$disable_NoMoreSIGABRT" == 1 ]]; then
            # dd if=/dev/sda bs=5M conv=fsync status=progress | gzip -c -9 | ssh user@DestinationIP 'gzip -d | dd of=/dev/sda bs=5M'
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt1" 2> /dev/null
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt2" 2> /dev/null
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount -w -t hfs /dev/disk0s1s1 /mnt1" 2> /dev/null
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt2" 2> /dev/null
            info "Disabling NoMoreSIGABRT on /dev/disk0s1s2 . . ."
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost '/bin/dd if=/dev/disk0s1s2 of=/mnt1/out.img bs=512 count=8192'
            "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt1/out.img "$dir"/$deviceid/$cpid/$version/NoMoreSIGABRT.img
            "$bin"/Kernel64Patcher "$dir"/$deviceid/$cpid/$version/NoMoreSIGABRT.img "$dir"/$deviceid/$cpid/$version/NoMoreSIGABRT.patched -o
            "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/NoMoreSIGABRT.patched root@localhost:/mnt1/out.img
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost '/bin/dd if=/mnt1/out.img of=/dev/disk0s1s2 bs=512 count=8192'
            info "Done"
        fi
        if [[ "$NoMoreSIGABRT" == 1 ]]; then
            # dd if=/dev/sda bs=5M conv=fsync status=progress | gzip -c -9 | ssh user@DestinationIP 'gzip -d | dd of=/dev/sda bs=5M'
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt1" 2> /dev/null
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt2" 2> /dev/null
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount -w -t hfs /dev/disk0s1s1 /mnt1" 2> /dev/null
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt2" 2> /dev/null
            info "Enabling NoMoreSIGABRT on /dev/disk0s1s2 . . ."
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost '/bin/dd if=/dev/disk0s1s2 of=/mnt1/out.img bs=512 count=8192'
            "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt1/out.img "$dir"/$deviceid/$cpid/$version/NoMoreSIGABRT.img
            "$bin"/Kernel64Patcher "$dir"/$deviceid/$cpid/$version/NoMoreSIGABRT.img "$dir"/$deviceid/$cpid/$version/NoMoreSIGABRT.patched -n
            "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/NoMoreSIGABRT.patched root@localhost:/mnt1/out.img
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost '/bin/dd if=/mnt1/out.img of=/dev/disk0s1s2 bs=512 count=8192'
            info "Done"
        fi
        if [[ "$force_activation" == 1 ]]; then
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt1" 2> /dev/null
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt2" 2> /dev/null
            if [[ "$version" == "7."* || "$version" == "8."* || "$version" == "9."* || "$version" == "10.0"* || "$version" == "10.1"* || "$version" == "10.2"* ]]; then
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount -w -t hfs /dev/disk0s1s1 /mnt1" 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount -w -t hfs /dev/disk0s1s2 /mnt2" 2> /dev/null
            else
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount_apfs /dev/disk0s1s1 /mnt1"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount_apfs /dev/disk0s1s2 /mnt2"
            fi
            if [[ "$version" == "9.3"* || "$version" == "10.0"* || "$version" == "10.1"* || "$version" == "10.2"* ]]; then
                # /mnt2/containers/Data/System/58954F59-3AA2-4005-9C5B-172BE4ADEC98/Library/internal/data_ark.plist
                dataarkplist=$(remote_cmd "/usr/bin/find /mnt2/containers/Data/System -name 'internal'" 2> /dev/null)
                dataarkplist="$dataarkplist/data_ark.plist"
                info $dataarkplist
                if [ -e "$dir"/$deviceid/0.0/IC-Info.sisv ]; then
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt2/mobile/Library/FairPlay/iTunes_Control/iTunes/"
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/0.0/IC-Info.sisv root@localhost:/mnt2/mobile/Library/FairPlay/iTunes_Control/iTunes/IC-Info.sisv 2> /dev/null
                fi
                if [ -e "$dir"/$deviceid/0.0/com.apple.commcenter.device_specific_nobackup.plist ]; then
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt2/wireless/Library/Preferences/"
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/0.0/com.apple.commcenter.device_specific_nobackup.plist root@localhost:/mnt2/wireless/Library/Preferences/com.apple.commcenter.device_specific_nobackup.plist 2> /dev/null
                fi
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/data_ark.plis_ root@localhost:$dataarkplist
            else
                # /mnt2/containers/Data/System/58954F59-3AA2-4005-9C5B-172BE4ADEC98/Library/internal/data_ark.plist
                dataarkplist=$(remote_cmd "/usr/bin/find /mnt2/containers/Data/System -name 'data_ark.plist'" 2> /dev/null)
                info $dataarkplist
                if [ -e "$dir"/$deviceid/0.0/IC-Info.sisv ]; then
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt2/mobile/Library/FairPlay/iTunes_Control/iTunes/"
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/0.0/IC-Info.sisv root@localhost:/mnt2/mobile/Library/FairPlay/iTunes_Control/iTunes/IC-Info.sisv 2> /dev/null
                fi
                if [ -e "$dir"/$deviceid/0.0/com.apple.commcenter.device_specific_nobackup.plist ]; then
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt2/wireless/Library/Preferences/"
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/0.0/com.apple.commcenter.device_specific_nobackup.plist root@localhost:/mnt2/wireless/Library/Preferences/com.apple.commcenter.device_specific_nobackup.plist 2> /dev/null
                fi
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/data_ark.plis_ root@localhost:$dataarkplist
            fi
            "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/Meridian.app.tar.gz root@localhost:/mnt1/
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'tar --preserve-permissions -xzvf /mnt1/Meridian.app.tar.gz -C /mnt1/Applications' 2> /dev/null
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/Meridian.app.tar.gz' 2> /dev/null
            if [[ ! "$deviceid" == "iPad"* ]]; then
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/UnlimFileManager.app.tar.gz root@localhost:/mnt1/
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'tar --preserve-permissions -xzvf /mnt1/UnlimFileManager.app.tar.gz -C /mnt1/Applications' 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost '/usr/sbin/chown -R root:wheel /mnt1/Applications/UnlimFileManager.app'
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/UnlimFileManager.app.tar.gz' 2> /dev/null
            fi
            info "Done"
        fi
        if [[ "$ramdisk" == 1 ]]; then
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt1" 2> /dev/null
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt2" 2> /dev/null
            if [[ "$version" == "7."* || "$version" == "8."* || "$version" == "9."* || "$version" == "10.0"* || "$version" == "10.1"* || "$version" == "10.2"* ]]; then
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount -w -t hfs /dev/disk0s1s1 /mnt1" 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount -w -t hfs /dev/disk0s1s2 /mnt2" 2> /dev/null
            else
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount_apfs /dev/disk0s1s1 /mnt1"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount_apfs /dev/disk0s1s2 /mnt2"
            fi
            ssh -o StrictHostKeyChecking=no -p2222 root@localhost
        fi
        $("$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/reboot &" 2> /dev/null &)
        _kill_if_running iproxy
    else
        _kill_if_running iproxy
        echo "Done"
        exit 0
    fi
fi
#} | tee /dev/null