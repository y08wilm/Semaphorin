#!/bin/bash
mkdir -p logs
#set -x
verbose=1
{
echo "[*] Command ran:`if [ $EUID = 0 ]; then echo " sudo"; fi` ./semaphorin.sh $@"
os=$(uname)
maj_ver=$(echo "$os_ver" | awk -F. '{print $1}')
dir="$(pwd)"
bin="$(pwd)/$(uname)"
sshtars="$(pwd)/sshtars"
echo "Semaphorin | Version 1.0"
echo "Written by y08wilm and Mineek | Some code and ramdisk from Nathan"
echo ""
max_args=1
arg_count=0

# Check for required commands
if [ "$os" = 'Linux' ]; then
    linux_cmds='lsusb'
fi

for cmd in curl unzip python3 git ssh scp killall sudo grep pgrep ${linux_cmds}; do
    if ! command -v "${cmd}" > /dev/null; then
        if [ "$cmd" = "python3" ]; then
            echo "[-] Command '${cmd}' not installed, please install it!";
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
                echo "[-] Command '${cmd}' not installed, please install it!";
                cmd_not_found=1
            fi
        fi
    fi
done
if [ "$cmd_not_found" = "1" ]; then
    exit 1
fi

# Check for pyimg4
if ! python3 -c 'import pkgutil; exit(not pkgutil.find_loader("pyimg4"))'; then
    python3 -m pip install pyimg4
fi

# This would probably go better somewhere else, but I'm not sure where to put it since most of the script is just in functions.

clean_usbmuxd() {
    sudo killall usbmuxd 2>/dev/null
    if [[ $(which systemctl 2>/dev/null) ]]; then
        sleep 1
        sudo systemctl restart usbmuxd
    fi
}

if [[ $os =~ Darwin ]]; then
    echo "[*] Running on Darwin..."
    sudo xattr -cr .
    os_ver=$(sw_vers -productVersion)
    if [[ $os_ver =~ ^10\.1[3]\.* ]]; then
        echo "[!] macOS/OS X $os_ver is not supported by this script. Please install macOS 10.14 (Mojave) or later to continue if possible."
        sleep 1
        read -p "[*] You can press the enter key on your keyboard to skip this warning  " r1
        if [[ ! -e "$bin"/.compiled ]]; then
            rm -rf Kernel64Patcher
            git clone --recursive https://github.com/semaphorin-legacy/Kernel64Patcher
            cd Kernel64Patcher
            rm -rf ../Darwin/Kernel64Patcher
            make
            mv seprmvr64 Kernel64Patcher
            cp Kernel64Patcher ../Darwin/Kernel64Patcher
            cd ..
            rm -rf Kernel64Patcher
            rm -rf dsc64patcher
            git clone --recursive https://github.com/semaphorin-legacy/dsc64patcher
            cd dsc64patcher
            rm -rf ../Darwin/dsc64patcher
            gcc Kernel64Patcher.c -o ../Darwin/dsc64patcher
            touch ../Darwin/.compiled
            cd ..
            rm -rf dsc64patcher
        fi
    else
        echo "[*] You are running macOS $os_ver. Continuing..."
    fi
elif [[ $os =~ Linux ]]; then
    echo "[*] Running on Linux..."
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
    echo "[!] What operating system are you even using..."
    exit 1
fi

print_help() {
    cat << EOF
Usage: $0 [VERSION...] [OPTION...]
iOS 7.0.1-9.2.1 Downgrade & Jailbreak tool for older checkm8 devices using seprmvr64
Examples:
    $0 7.1.2 --restore
    $0 7.1.2 --boot

Main operation mode:
    --help                     Print this help
    --ramdisk                  Download& enter ramdisk
    --dump-blobs               Self explanatory
    --serial                   Enable serial debugging
    --ssh                      Tries to connect to ssh over usb interface to the connected device
    --restore                  Wipe device and downgrade ios
    --restore-activation       Copies the backed up activation records to /dev/disk0s1s2 on the iOS device
    --dump-nand                Backs up the entire contents of your iOS device to disk0.gz
    --dualboot-hfs             This is an experimental dualboot feature for iOS 10.3.3 devices only
    --appleinternal            Enables internalization during restore
    --NoMoreSIGABRT            Adds the "protect" flag to /dev/disk0s1s2
    --disable-NoMoreSIGABRT    Removes the "protect" flag from /dev/disk0s1s2
    --restore-factorydata      Copies the factory data from your backed up records folder to your iOS device
    --restore-nand             Copies the contents of disk0.gz to /dev/disk0 of the iOS device
    --restore-mnt1             Copies the contents of disk0s1s1.gz to /dev/disk0s1s1 of the iOS device
    --restore-mnt2             Copies the contents of disk0s1s2.gz to /dev/disk0s1s2 of the iOS device
    --boot                     Don't enter ramdisk or wipe device, just boot
    --boot-clean               Don't enter ramdisk or wipe device, just boot without seprmvr64
    --clean                    Delete all the created boot files for your device
    --force-activation         Forces FactoryActivation on your device during restore
    --fix-auto-boot            Fixes booting into the main OS on A11 devices such as the iPhone X

The iOS version argument should be the iOS version you are downgrading to.
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
        --restore-activation)
            restore_activation=1
            ;;
        --restore-factorydata)
            restore_factorydata=1
            ;;
        --restore-nand)
            restore_nand=1
            ;;
        --restore-mnt1)
            restore_mnt1=1
            ;;
        --dualboot-hfs)
            dualboot_hfs=1
            ;;
        --restore-mnt2)
            restore_mnt2=1
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
            echo "[-] Unknown option $1. Use $0 --help for help."
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
            if [[ "$version" == "8.0b4" ]]; then
                version="8.0"
            fi
            if [[ "$version" == "11.0b1" ]]; then
                version="11.0"
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
            echo "[-] Too many arguments. Use $0 --help for help.";
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
        echo "[-] Please attach only one device" > /dev/tty
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
            echo "[*] Waiting for device in DFU mode"
        fi

        while ! (system_profiler SPUSBDataType 2> /dev/null | grep ' Apple Mobile Device (DFU Mode)' >> /dev/null); do
            sleep 1
        done
    else
        if ! (lsusb | cut -d' ' -f6 | grep '05ac:' | cut -d: -f2 | grep 1227 >> /dev/null); then
            echo "[*] Waiting for device in DFU mode"
        fi

        while ! (lsusb | cut -d' ' -f6 | grep '05ac:' | cut -d: -f2 | grep 1227 >> /dev/null); do
            sleep 1
        done
    fi
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
                #gzip -d "$sshtars"/ssh.tar.gz
                gzip -dc "$sshtars"/ssh.tar.gz > "$sshtars"/ssh.tar
                sudo "$bin"/gnutar -xvf "$sshtars"/ssh.tar -C /tmp/ramdisk
                if [[ "$3" == "7."* || "$3" == "8."* || "$3" == "9."* || "$3" == "10."* || "$3" == "11."* ]]; then
                    # fix scp
                    sudo "$bin"/gnutar -xvf "$bin"/libcharset.1.dylib_libiconv.2.dylib.tar -C /tmp/ramdisk/usr/lib
                fi
                if [[ "$3" == "7."* || "$3" == "8."* || "$3" == "9."* || "$3" == "10."* || "$3" == "11."* || "$3" == "12."* || "$3" == "13.0"* || "$3" == "13.1"* || "$3" == "13.2"* || "$3" == "13.3"* ]]; then
                    # fix scp
                    sudo "$bin"/gnutar -xvf "$bin"/libresolv.9.dylib.tar -C /tmp/ramdisk/usr/lib
                fi
                # gptfdisk automation shenanigans
                sudo "$bin"/gnutar -xvf "$dir"/jb/gpt.txt_hfs_dualboot.tar -C /tmp/ramdisk
                sudo "$bin"/gnutar -xvf "$dir"/jb/gpt.txt.tar -C /tmp/ramdisk
                # fixup update partition script, i.e. changes all Update partitions to UpdateX partitions
                sudo "$bin"/gnutar -xvf "$dir"/jb/fixup_update_partition.tar -C /tmp/ramdisk
                hdiutil detach /tmp/ramdisk
                "$bin"/img4tool -c "$dir"/$1/$cpid/ramdisk/$3/ramdisk.im4p -t rdsk "$dir"/$1/$cpid/ramdisk/$3/RestoreRamDisk.dmg
                "$bin"/img4tool -c "$dir"/$1/$cpid/ramdisk/$3/ramdisk.img4 -p "$dir"/$1/$cpid/ramdisk/$3/ramdisk.im4p -m IM4M
                if [[ ! "$deviceid" == "iPhone6"* && ! "$deviceid" == "iPhone7"* && ! "$deviceid" == "iPad4"* && ! "$deviceid" == "iPad5"* && ! "$deviceid" == "iPod7"* && "$3" == "9."* ]]; then
                    "$bin"/kairos "$dir"/$1/$cpid/ramdisk/$3/iBSS.dec "$dir"/$1/$cpid/ramdisk/$3/iBSS.patched
                    "$bin"/kairos "$dir"/$1/$cpid/ramdisk/$3/iBEC.dec "$dir"/$1/$cpid/ramdisk/$3/iBEC.patched -b "rd=md0 debug=0x2014e amfi=0xff cs_enforcement_disable=1 $boot_args wdt=-1 `if [ "$check" = '0x8960' ] || [ "$check" = '0x7000' ] || [ "$check" = '0x7001' ]; then echo "-restore"; fi`" -n
                elif [[ "$3" == "9."* ]]; then
                    "$bin"/kairos "$dir"/$1/$cpid/ramdisk/$3/iBSS.dec "$dir"/$1/$cpid/ramdisk/$3/iBSS.patched
                    "$bin"/kairos "$dir"/$1/$cpid/ramdisk/$3/iBEC.dec "$dir"/$1/$cpid/ramdisk/$3/iBEC.patched -b "amfi=0xff cs_enforcement_disable=1 $boot_args rd=md0 nand-enable-reformat=1 -progress" -n
                else
                    "$bin"/ipatcher "$dir"/$1/$cpid/ramdisk/$3/iBSS.dec "$dir"/$1/$cpid/ramdisk/$3/iBSS.patched
                    "$bin"/ipatcher "$dir"/$1/$cpid/ramdisk/$3/iBEC.dec "$dir"/$1/$cpid/ramdisk/$3/iBEC.patched -b "amfi=0xff cs_enforcement_disable=1 $boot_args rd=md0 nand-enable-reformat=1 -progress"
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
                #gzip -d "$sshtars"/ssh.tar.gz
                gzip -dc "$sshtars"/ssh.tar.gz > "$sshtars"/ssh.tar
                sudo "$bin"/gnutar -xvf "$sshtars"/ssh.tar -C /tmp/ramdisk
                if [[ "$3" == "7."* || "$3" == "8."* || "$3" == "9."* || "$3" == "10."* || "$3" == "11."* ]]; then
                    # fix scp
                    sudo "$bin"/gnutar -xvf "$bin"/libcharset.1.dylib_libiconv.2.dylib.tar -C /tmp/ramdisk/usr/lib
                fi
                if [[ "$3" == "7."* || "$3" == "8."* || "$3" == "9."* || "$3" == "10."* || "$3" == "11."* || "$3" == "12."* || "$3" == "13.0"* || "$3" == "13.1"* || "$3" == "13.2"* || "$3" == "13.3"* ]]; then
                    # fix scp
                    sudo "$bin"/gnutar -xvf "$bin"/libresolv.9.dylib.tar -C /tmp/ramdisk/usr/lib
                fi
                # gptfdisk automation shenanigans
                sudo "$bin"/gnutar -xvf "$dir"/jb/gpt.txt_hfs_dualboot.tar -C /tmp/ramdisk
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
                    "$bin"/iBoot64Patcher "$dir"/$1/$cpid/ramdisk/$3/iBEC.dec "$dir"/$1/$cpid/ramdisk/$3/iBEC.patched -b "rd=md0 debug=0x2014e $boot_args wdt=-1 `if [ "$check" = '0x8960' ] || [ "$check" = '0x7000' ] || [ "$check" = '0x7001' ]; then echo "-restore"; fi`"
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
                "$bin"/kerneldiff "$dir"/$1/$cpid/ramdisk/$3/kcache.raw "$dir"/$1/$cpid/ramdisk/$3/kcache2.patched "$dir"/$1/$cpid/ramdisk/$3/kc.bpatch
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
                #gzip -d "$sshtars"/ssh.tar.gz
                gzip -dc "$sshtars"/ssh.tar.gz > "$sshtars"/ssh.tar
                "$bin"/hfsplus "$dir"/$1/$cpid/ramdisk/$3/RestoreRamDisk.dmg untar "$sshtars"/ssh.tar
                if [[ "$3" == "7."* || "$3" == "8."* || "$3" == "9."* || "$3" == "10."* || "$3" == "11."* ]]; then
                    # fix scp
                    "$bin"/hfsplus "$dir"/$1/$cpid/ramdisk/$3/RestoreRamDisk.dmg untar "$bin"/libcharset.1.dylib_libiconv.2.dylib.tar
                fi
                if [[ "$3" == "7."* || "$3" == "8."* || "$3" == "9."* || "$3" == "10."* || "$3" == "11."* || "$3" == "12."* || "$3" == "13.0"* || "$3" == "13.1"* || "$3" == "13.2"* || "$3" == "13.3"* ]]; then
                    # fix scp
                    "$bin"/hfsplus "$dir"/$1/$cpid/ramdisk/$3/RestoreRamDisk.dmg untar "$bin"/libresolv.9.dylib.tar
                fi
                # gptfdisk automation shenanigans
                "$bin"/hfsplus "$dir"/$1/$cpid/ramdisk/$3/RestoreRamDisk.dmg untar "$dir"/jb/gpt.txt_hfs_dualboot.tar
                "$bin"/hfsplus "$dir"/$1/$cpid/ramdisk/$3/RestoreRamDisk.dmg untar "$dir"/jb/gpt.txt.tar
                # fixup update partition script, i.e. changes all Update partitions to UpdateX partitions
                "$bin"/hfsplus "$dir"/$1/$cpid/ramdisk/$3/RestoreRamDisk.dmg untar "$dir"/jb/fixup_update_partition.tar
                "$bin"/img4tool -c "$dir"/$1/$cpid/ramdisk/$3/ramdisk.im4p -t rdsk "$dir"/$1/$cpid/ramdisk/$3/RestoreRamDisk.dmg
                "$bin"/img4tool -c "$dir"/$1/$cpid/ramdisk/$3/ramdisk.img4 -p "$dir"/$1/$cpid/ramdisk/$3/ramdisk.im4p -m IM4M
                if [[ ! "$deviceid" == "iPhone6"* && ! "$deviceid" == "iPhone7"* && ! "$deviceid" == "iPad4"* && ! "$deviceid" == "iPad5"* && ! "$deviceid" == "iPod7"* && "$3" == "9."* ]]; then
                    "$bin"/kairos "$dir"/$1/$cpid/ramdisk/$3/iBSS.dec "$dir"/$1/$cpid/ramdisk/$3/iBSS.patched
                    "$bin"/kairos "$dir"/$1/$cpid/ramdisk/$3/iBEC.dec "$dir"/$1/$cpid/ramdisk/$3/iBEC.patched -b "rd=md0 debug=0x2014e amfi=0xff cs_enforcement_disable=1 $boot_args wdt=-1 `if [ "$check" = '0x8960' ] || [ "$check" = '0x7000' ] || [ "$check" = '0x7001' ]; then echo "-restore"; fi`" -n
                elif [[ "$3" == "9."* ]]; then
                    "$bin"/kairos "$dir"/$1/$cpid/ramdisk/$3/iBSS.dec "$dir"/$1/$cpid/ramdisk/$3/iBSS.patched
                    "$bin"/kairos "$dir"/$1/$cpid/ramdisk/$3/iBEC.dec "$dir"/$1/$cpid/ramdisk/$3/iBEC.patched -b "amfi=0xff cs_enforcement_disable=1 $boot_args rd=md0 nand-enable-reformat=1 -progress" -n
                else
                    "$bin"/ipatcher "$dir"/$1/$cpid/ramdisk/$3/iBSS.dec "$dir"/$1/$cpid/ramdisk/$3/iBSS.patched
                    "$bin"/ipatcher "$dir"/$1/$cpid/ramdisk/$3/iBEC.dec "$dir"/$1/$cpid/ramdisk/$3/iBEC.patched -b "amfi=0xff cs_enforcement_disable=1 $boot_args rd=md0 nand-enable-reformat=1 -progress"
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
                #gzip -d "$sshtars"/ssh.tar.gz
                gzip -dc "$sshtars"/ssh.tar.gz > "$sshtars"/ssh.tar
                "$bin"/hfsplus "$dir"/$1/$cpid/ramdisk/$3/RestoreRamDisk.dmg untar "$sshtars"/ssh.tar
                if [[ "$3" == "7."* || "$3" == "8."* || "$3" == "9."* || "$3" == "10."* || "$3" == "11."* ]]; then
                    # fix scp
                    "$bin"/hfsplus "$dir"/$1/$cpid/ramdisk/$3/RestoreRamDisk.dmg untar "$bin"/libcharset.1.dylib_libiconv.2.dylib.tar
                fi
                if [[ "$3" == "7."* || "$3" == "8."* || "$3" == "9."* || "$3" == "10."* || "$3" == "11."* || "$3" == "12."* || "$3" == "13.0"* || "$3" == "13.1"* || "$3" == "13.2"* || "$3" == "13.3"* ]]; then
                    # fix scp
                    "$bin"/hfsplus "$dir"/$1/$cpid/ramdisk/$3/RestoreRamDisk.dmg untar "$bin"/libresolv.9.dylib.tar
                fi
                # gptfdisk automation shenanigans
                "$bin"/hfsplus "$dir"/$1/$cpid/ramdisk/$3/RestoreRamDisk.dmg untar "$dir"/jb/gpt.txt_hfs_dualboot.tar
                "$bin"/hfsplus "$dir"/$1/$cpid/ramdisk/$3/RestoreRamDisk.dmg untar "$dir"/jb/gpt.txt.tar
                # fixup update partition script, i.e. changes all Update partitions to UpdateX partitions
                "$bin"/hfsplus "$dir"/$1/$cpid/ramdisk/$3/RestoreRamDisk.dmg untar "$dir"/jb/fixup_update_partition.tar
                "$bin"/img4 -i "$dir"/$1/$cpid/ramdisk/$3/RestoreRamDisk.dmg -o "$dir"/$1/$cpid/ramdisk/$3/ramdisk.img4 -M IM4M -A -T rdsk
                "$bin"/iBoot64Patcher "$dir"/$1/$cpid/ramdisk/$3/iBSS.dec "$dir"/$1/$cpid/ramdisk/$3/iBSS.patched
                if [[ ! "$deviceid" == "iPhone6"* && ! "$deviceid" == "iPhone7"* && ! "$deviceid" == "iPad4"* && ! "$deviceid" == "iPad5"* && ! "$deviceid" == "iPod7"* ]]; then
                    "$bin"/iBoot64Patcher "$dir"/$1/$cpid/ramdisk/$3/iBEC.dec "$dir"/$1/$cpid/ramdisk/$3/iBEC.patched -b "rd=md0 debug=0x2014e $boot_args wdt=-1 `if [ "$check" = '0x8960' ] || [ "$check" = '0x7000' ] || [ "$check" = '0x7001' ]; then echo "-restore"; fi`"
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
                "$bin"/kerneldiff "$dir"/$1/$cpid/ramdisk/$3/kcache.raw "$dir"/$1/$cpid/ramdisk/$3/kcache2.patched "$dir"/$1/$cpid/ramdisk/$3/kc.bpatch
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
    buildid="$3"
    #if [[ "$3" == "9.3" ]]; then
    #    ipswurl="http://appldnld.apple.com/ios9.3seed/031-51522-20160222-4D0EDA22-D67B-11E5-A9AB-1E6E919DCAD8/iPhone6,1_9.3_13E5214d_Restore.ipsw"
    #    buildid="13E5214d"
    #fi
    meowing="$3"
    rm -rf BuildManifest.plist
    mkdir -p "$dir"/$1/$cpid/$3
    rm -rf "$dir"/work
    mkdir "$dir"/work
    cd "$dir"/work
    "$bin"/img4tool -e -s "$dir"/other/shsh/"${check}".shsh -m IM4M
    if [ ! -e "$dir"/$1/$cpid/$3/kernelcache ]; then
        if [[ "$3" == "10."* ]]; then
            if [[ "$deviceid" == "iPhone8,1" || "$deviceid" == "iPhone8,2" ]]; then
                ipswurl=$(curl -k -sL "https://api.ipsw.me/v4/device/$deviceid?type=ipsw" | "$bin"/jq '.firmwares | .[] | select(.version=="'11.1'")' | "$bin"/jq -s '.[0] | .url' --raw-output)
            else
                ipswurl=$(curl -k -sL "https://api.ipsw.me/v4/device/$deviceid?type=ipsw" | "$bin"/jq '.firmwares | .[] | select(.version=="'10.3.3'")' | "$bin"/jq -s '.[0] | .url' --raw-output)
            fi
        fi
        if [[ "$3" == "9."* ]]; then
            ipswurl=$(curl -k -sL "https://api.ipsw.me/v4/device/$deviceid?type=ipsw" | "$bin"/jq '.firmwares | .[] | select(.version=="'$meowing'")' | "$bin"/jq -s '.[0] | .url' --raw-output)
        fi
        "$bin"/pzb -g BuildManifest.plist "$ipswurl"
        if [ ! -e "$dir"/$1/$cpid/$3/iBSS.dec ]; then
            "$bin"/pzb -g $(awk "/""$replace""/{x=1}x&&/iBSS[.]/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1) "$ipswurl"
            fn="$(awk "/""$replace""/{x=1}x&&/iBSS[.]/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | sed 's/Firmware[/]dfu[/]//')"
            if [[ "$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -e $buildid $1)" == "true" ]]; then
                if [[ "$3" == "10."* ]]; then
                    if [[ "$deviceid" == "iPhone8,1" || "$deviceid" == "iPhone8,2" ]]; then
                        ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn 11.1 $1)"
                    else
                        ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn 10.3.3 $1)"
                    fi
                elif [[ "$3" == "9."* ]]; then
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $meowing $1)"
                else
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $buildid $1)"
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
            if [[ "$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -e $buildid $1)" == "true" ]]; then
                if [[ "$3" == "10."* ]]; then
                    if [[ "$deviceid" == "iPhone8,1" || "$deviceid" == "iPhone8,2" ]]; then
                        ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn 11.1 $1)"
                    else
                        ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn 10.3.3 $1)"
                    fi
                elif [[ "$3" == "9."* ]]; then
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $meowing $1)"
                else
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $buildid $1)"
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
        if [[ "$3" == "10."* || "$3" == "9."* ]]; then
            rm -rf BuildManifest.plist
            ipswurl=$(curl -k -sL "https://api.ipsw.me/v4/device/$deviceid?type=ipsw" | "$bin"/jq '.firmwares | .[] | select(.version=="'$3'")' | "$bin"/jq -s '.[0] | .url' --raw-output)
            "$bin"/pzb -g BuildManifest.plist "$ipswurl"
        fi
        if [ ! -e "$dir"/$1/$cpid/$3/kernelcache.dec ]; then
            "$bin"/pzb -g $(awk "/""$replace""/{x=1}x&&/kernelcache.release/{print;exit}" BuildManifest.plist | grep '<string>' | cut -d\> -f2 | cut -d\< -f1) "$ipswurl"
            if [[ "$3" == "7."* || "$3" == "8."* || "$3" == "9."* ]]; then
                fn="$(awk "/""$replace""/{x=1}x&&/kernelcache.release/{print;exit}" BuildManifest.plist | grep '<string>' | cut -d\> -f2 | cut -d\< -f1)"
                if [[ "$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -e $buildid $1)" == "true" ]]; then
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $buildid $1)"
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
                if [[ "$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -e $buildid $1)" == "true" ]]; then
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $buildid $1)"
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
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $buildid $1)"
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
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $buildid $1)"
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
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $buildid $1)"
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
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $buildid $1)"
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
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $buildid $1)"
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
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $buildid $1)"
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
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $buildid $1)"
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
                if [[ "$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -e $buildid $1)" == "true" ]]; then
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $buildid $1)"
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
        if [[ "$r" == "16"* || "$r" == "17"* ]]; then
            if [[ "$3" == "9."* ]]; then
                "$bin"/kairos "$dir"/$1/$cpid/$3/iBSS.dec "$dir"/$1/$cpid/$3/iBSS.patched
                "$bin"/kairos "$dir"/$1/$cpid/$3/iBEC.dec "$dir"/$1/$cpid/$3/iBEC.patched -b "$boot_args rd=disk0s1s1 amfi=0xff cs_enforcement_disable=1 keepsyms=1 debug=0x2014e PE_i_can_has_debugger=1 amfi_get_out_of_my_way=1 amfi_allow_any_signature=1" -n
            else
                "$bin"/iBoot64Patcher "$dir"/$1/$cpid/$3/iBSS.dec "$dir"/$1/$cpid/$3/iBSS.patched
                if [[ "$3" == "10.3"* || "$3" == "11."* || "$3" == "12."* ||  "$3" == "13."* || "$3" == "14."* ]]; then
                    "$bin"/iBoot64Patcher "$dir"/$1/$cpid/$3/iBEC.dec "$dir"/$1/$cpid/$3/iBEC.patched -b "$boot_args rd=disk0s1s9 amfi=0xff cs_enforcement_disable=1 keepsyms=1 debug=0x100 PE_i_can_has_debugger=1 amfi_get_out_of_my_way=1 amfi_allow_any_signature=1" -n
                else
                    "$bin"/iBoot64Patcher "$dir"/$1/$cpid/$3/iBEC.dec "$dir"/$1/$cpid/$3/iBEC.patched -b "$boot_args rd=disk0s1s9 amfi=0xff cs_enforcement_disable=1 keepsyms=1 debug=0x2014e PE_i_can_has_debugger=1 amfi_get_out_of_my_way=1 amfi_allow_any_signature=1" -n
                fi
            fi
        else
            if [[ "$dualboot_hfs" == 1 ]]; then
                if [[ "$3" == "7."* ]]; then
                    "$bin"/ipatcher "$dir"/$1/$cpid/$3/iBSS.dec "$dir"/$1/$cpid/$3/iBSS.patched
                    "$bin"/ipatcher "$dir"/$1/$cpid/$3/iBEC.dec "$dir"/$1/$cpid/$3/iBEC.patched -b "$boot_args rd=disk0s1s3 amfi=0xff cs_enforcement_disable=1 keepsyms=1 debug=0x2014e wdt=-1 PE_i_can_has_debugger=1 amfi_get_out_of_my_way=0x1 amfi_unrestrict_task_for_pid=0x0"
                elif [[ "$3" == "8."* ]]; then
                    "$bin"/ipatcher "$dir"/$1/$cpid/$3/iBSS.dec "$dir"/$1/$cpid/$3/iBSS.patched
                    "$bin"/ipatcher "$dir"/$1/$cpid/$3/iBEC.dec "$dir"/$1/$cpid/$3/iBEC.patched -b "$boot_args rd=disk0s1s3 amfi=0xff cs_enforcement_disable=1 keepsyms=1 debug=0x2014e PE_i_can_has_debugger=1"
                elif [[ "$3" == "9."* ]]; then
                    "$bin"/kairos "$dir"/$1/$cpid/$3/iBSS.dec "$dir"/$1/$cpid/$3/iBSS.patched
                    "$bin"/kairos "$dir"/$1/$cpid/$3/iBEC.dec "$dir"/$1/$cpid/$3/iBEC.patched -b "$boot_args rd=disk0s1s3 amfi=0xff cs_enforcement_disable=1 keepsyms=1 debug=0x2014e PE_i_can_has_debugger=1 amfi_get_out_of_my_way=1 amfi_allow_any_signature=1" -n
                fi
            else
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
                    if [[ "$3" == "10.3"* || "$3" == "11."* || "$3" == "12."* ||  "$3" == "13."* || "$3" == "14."* ]]; then
                        "$bin"/iBoot64Patcher "$dir"/$1/$cpid/$3/iBEC.dec "$dir"/$1/$cpid/$3/iBEC.patched -b "$boot_args rd=disk0s1s8 amfi=0xff cs_enforcement_disable=1 keepsyms=1 debug=0x100 PE_i_can_has_debugger=1 amfi_get_out_of_my_way=1 amfi_allow_any_signature=1" -n
                    else
                        "$bin"/iBoot64Patcher "$dir"/$1/$cpid/$3/iBEC.dec "$dir"/$1/$cpid/$3/iBEC.patched -b "$boot_args rd=disk0s1s1 amfi=0xff cs_enforcement_disable=1 keepsyms=1 debug=0x2014e PE_i_can_has_debugger=1 amfi_get_out_of_my_way=1 amfi_allow_any_signature=1" -n
                    fi
                fi
            fi
        fi
        if [[ "$3" == "8.4"* ]]; then
            "$bin"/img4 -i "$dir"/$1/$cpid/$3/iBSS.patched -o "$dir"/$1/$cpid/$3/iBSS.img4 -M IM4M -A -T ibss
            "$bin"/img4 -i "$dir"/$1/$cpid/$3/iBEC.patched -o "$dir"/$1/$cpid/$3/iBEC.img4 -M IM4M -A -T ibec
            "$bin"/Kernel64Patcher "$dir"/$1/$cpid/$3/kcache.raw "$dir"/$1/$cpid/$3/kcache.patched -u 8 -t -p -e 8 -f 84 -a -m 8 -g -s -d
            "$bin"/kerneldiff "$dir"/$1/$cpid/$3/kcache.raw "$dir"/$1/$cpid/$3/kcache.patched "$dir"/$1/$cpid/$3/kc.bpatch
            "$bin"/img4 -i "$dir"/$1/$cpid/$3/kernelcache.dec -o "$dir"/$1/$cpid/$3/kernelcache.img4 -M IM4M -T rkrn -P "$dir"/$1/$cpid/$3/kc.bpatch
            "$bin"/img4 -i "$dir"/$1/$cpid/$3/kernelcache.dec -o "$dir"/$1/$cpid/$3/kernelcache -M IM4M -T krnl -P "$dir"/$1/$cpid/$3/kc.bpatch
            "$bin"/dtree_patcher "$dir"/$1/$cpid/$3/DeviceTree.dec "$dir"/$1/$cpid/$3/DeviceTree.patched -n
            "$bin"/img4 -i "$dir"/$1/$cpid/$3/DeviceTree.patched -o "$dir"/$1/$cpid/$3/devicetree.img4 -A -M IM4M -T rdtr
        elif [[ "$3" == "8."* ]]; then
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
        elif [[ "$3" == "10.0"* || "$3" == "10.1"* || "$3" == "10.2"* ]]; then
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
        elif [[ "$3" == "10.3"* ]]; then
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
    buildid="$3"
    #if [[ "$3" == "9.3" ]]; then
    #    ipswurl="http://appldnld.apple.com/ios9.3seed/031-51522-20160222-4D0EDA22-D67B-11E5-A9AB-1E6E919DCAD8/iPhone6,1_9.3_13E5214d_Restore.ipsw"
    #    buildid="13E5214d"
    #fi
    rm -rf BuildManifest.plist
    mkdir -p "$dir"/$1/clean/$cpid/$3
    rm -rf "$dir"/work
    mkdir "$dir"/work
    cd "$dir"/work
    "$bin"/img4tool -e -s "$dir"/other/shsh/"${check}".shsh -m IM4M
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
            if [[ "$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -e $buildid $1)" == "true" ]]; then
                if [[ "$3" == "10."* ]]; then
                    if [[ "$deviceid" == "iPhone8,1" || "$deviceid" == "iPhone8,2" ]]; then
                        ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn 11.1 $1)"
                    else
                        ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn 10.3.3 $1)"
                    fi
                else
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $buildid $1)"
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
            if [[ "$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -e $buildid $1)" == "true" ]]; then
                if [[ "$3" == "10."* ]]; then
                    if [[ "$deviceid" == "iPhone8,1" || "$deviceid" == "iPhone8,2" ]]; then
                        ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn 11.1 $1)"
                    else
                        ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn 10.3.3 $1)"
                    fi
                else
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $buildid $1)"
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
                if [[ "$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -e $buildid $1)" == "true" ]]; then
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $buildid $1)"
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
                if [[ "$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -e $buildid $1)" == "true" ]]; then
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $buildid $1)"
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
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $buildid $1)"
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
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $buildid $1)"
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
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $buildid $1)"
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
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $buildid $1)"
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
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $buildid $1)"
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
                if [[ "$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -e $buildid $1)" == "true" ]]; then
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $buildid $1)"
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
            if [[ "$3" == "15."* ]]; then
                "$bin"/iBoot64Patcher "$dir"/$1/clean/$cpid/$3/iBEC.dec "$dir"/$1/clean/$cpid/$3/iBEC.patched -b "$boot_args rd=disk0s1s6 amfi=0xff cs_enforcement_disable=1 keepsyms=1 debug=0x2014e PE_i_can_has_debugger=1 amfi_get_out_of_my_way=1 amfi_allow_any_signature=1" -n
            elif [[ "$3" == "16."* ]]; then
                "$bin"/iBoot64Patcher "$dir"/$1/clean/$cpid/$3/iBEC.dec "$dir"/$1/clean/$cpid/$3/iBEC.patched -b "$boot_args rd=disk1s6 amfi=0xff cs_enforcement_disable=1 keepsyms=1 debug=0x2014e PE_i_can_has_debugger=1 amfi_get_out_of_my_way=1 amfi_allow_any_signature=1" -n
            else
                "$bin"/iBoot64Patcher "$dir"/$1/clean/$cpid/$3/iBEC.dec "$dir"/$1/clean/$cpid/$3/iBEC.patched -b "$boot_args rd=disk0s1s1 amfi=0xff cs_enforcement_disable=1 keepsyms=1 debug=0x2014e PE_i_can_has_debugger=1 amfi_get_out_of_my_way=1 amfi_allow_any_signature=1" -n
            fi
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
    buildid="$3"
    #if [[ "$3" == "9.3" ]]; then
    #    ipswurl="http://appldnld.apple.com/ios9.3seed/031-51522-20160222-4D0EDA22-D67B-11E5-A9AB-1E6E919DCAD8/iPhone6,1_9.3_13E5214d_Restore.ipsw"
    #    buildid="13E5214d"
    #fi
    rm -rf BuildManifest.plist
    mkdir -p "$dir"/$1/$cpid/$3
    rm -rf "$dir"/work
    mkdir "$dir"/work
    cd "$dir"/work
    "$bin"/img4tool -e -s "$dir"/other/shsh/"${check}".shsh -m IM4M
    if [[ "$3" == "10.3"* || "$3" == "11."* || "$3" == "12."* || "$3" == "13."* || "$3" == "14."* ]]; then
        if [ ! -e "$dir"/$1/$cpid/$3/OS.dmg ]; then
            local fn
            "$bin"/pzb -g BuildManifest.plist "$ipswurl"
            if [ "$os" = "Darwin" ]; then
                fn="$(/usr/bin/plutil -extract "BuildIdentities".0."Manifest"."OS"."Info"."Path" xml1 -o - BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | head -1)"
            else
                fn="$("$bin"/PlistBuddy -c "Print BuildIdentities:0:Manifest:OS:Info:Path" BuildManifest.plist | tr -d '"')"
            fi
            rm -rf BuildManifest.plist
            "$bin"/aria2c $ipswurl
            "$bin"/7z x $(find . -name '*.ipsw*')
            if [ "$os" = "Darwin" ]; then
                asr -source $fn -target "$dir"/$1/$cpid/$3/OS.dmg --embed -erase -noprompt --chunkchecksum --puppetstrings
            else
                cp $fn "$dir"/$1/$cpid/$3/OS.dmg
            fi
            if [[ "$deviceid" == "iPhone6"* || "$deviceid" == "iPad4"* ]]; then
               "$bin"/irecovery -f /dev/null
            fi
        fi
    else
        if [ ! -e "$dir"/$1/$cpid/$3/rw.dmg ]; then
            if [ ! -e "$dir"/$1/$cpid/$3/OS.dmg ]; then
                if [[ "$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -e $buildid $1)" == "true" ]]; then
                    local fn
                    "$bin"/pzb -g BuildManifest.plist "$ipswurl"
                    if [ "$os" = "Darwin" ]; then
                        fn="$(/usr/bin/plutil -extract "BuildIdentities".0."Manifest"."OS"."Info"."Path" xml1 -o - BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | head -1)"
                    else
                        fn="$("$bin"/PlistBuddy -c "Print BuildIdentities:0:Manifest:OS:Info:Path" BuildManifest.plist | tr -d '"')"
                    fi
                    "$bin"/pzb -g "$fn" "$ipswurl"
                    ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $3 $1)"
                    "$bin"/dmg extract $fn "$dir"/$1/$cpid/$3/OS.dmg -k $ivkey
                else
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
                    "$bin"/pzb -g "$fno" "$ipswurl"
                    if [ ! -e "$dir"/$1/$cpid/$3/RestoreRamDisk.dmg ]; then
                        "$bin"/pzb -g "$fnr" "$ipswurl"
                        if [[ "$3" == "7."* || "$3" == "8."* || "$3" == "9."* ]]; then
                            fn="$fnr"
                            if [[ "$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -e $buildid $1)" == "true" ]]; then
                                ivkey="$(../java/bin/java -jar ../Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -ivkey $fn $buildid $1)"
                                "$bin"/img4 -i $fn -o "$dir"/$1/$cpid/$3/RestoreRamDisk.dmg -k $ivkey
                            else
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
            if [ "$os" = "Darwin" ]; then
                hdiutil attach -mountpoint /tmp/ios "$dir"/$1/$cpid/$3/rw.dmg
                sudo diskutil enableOwnership /tmp/ios
                sudo "$bin"/gnutar -cvf "$dir"/$1/$cpid/$3/OS.tar -C /tmp/ios .
                hdiutil detach /tmp/ios
            fi
            rm -rf /tmp/ios
            if [[ "$deviceid" == "iPhone6"* || "$deviceid" == "iPad4"* ]]; then
               "$bin"/irecovery -f /dev/null
            fi
        fi
    fi
    cd ..
    rm -rf work
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
    echo "[-] Please connect a device in recovery mode or dfu mode to continue"
    exit 0
fi
if [[ ! "$(get_device_mode)" == "dfu" && ! "$(get_device_mode)" == "recovery" ]]; then
    echo "[-] You can not run $0 from $(get_device_mode), please put your device into recovery mode"
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
echo $cpid
echo $replace
echo $deviceid
echo $device_os
scid="$cpid"
scid=$(echo $cpid | sed 's/0x/s/g')
if [[ "$cpid" == "0x8000" || "$cpid" == "0x8001" || "$cpid" == 8003 ]]; then
    echo $scid
fi
if [[ "$deviceid" == "iPhone10"* || "$deviceid" == "iPad6"* || "$deviceid" == "iPad7"* ]]; then
    pongo=1
    if [[ ! -e "$bin"/checkra1n-kpf-pongo ]]; then
        cd "$bin"/
        pwd
        curl -k -SLO https://cdn.nickchan.lol/palera1n/artifacts/kpf/checkra1n-kpf-pongo
        cd "$dir"/
        pwd
    fi
fi
parse_cmdline "$@"
boot_args=""
if [ "$serial" = "1" ]; then
    boot_args="serial=3"
else
    boot_args="-v"
fi
if [[ "$version" == "8."* || "$version" == "9.3"* || "$version" == "10."* ]]; then
    if [[ ! "$ramdisk" == 1 ]]; then
        force_activation=1
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
    echo "[*] Removed the created boot files"
    exit 0
fi
if [ -z "$r" ]; then
    read -p "what ios version is or was installed on this device prior to downgrade? " r
fi
if [[ "$boot_clean" == 1 ]]; then
    _download_clean_boot_files $deviceid $replace $version
    _kill_if_running iproxy
    sudo killall -STOP -c usbd
    read -p "[*] You may need to unplug and replug your cable, would you like to? " r1
    if [[ "$r1" == "yes" || "$r1" == "y" ]]; then
        read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
        echo "[*] Waiting 10 seconds before continuing.."
        sleep 10
    elif [[ "$r1" == "no" || "$r1" == "n" ]]; then
        echo "[*] Ok no problem, continuing.."
    else
        echo "[*] That was not a response I was expecting, I'm going to treat that as a 'yes'.."
        read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
        echo "[*] Waiting 10 seconds before continuing.."
        sleep 10
    fi
    if [ -e "$dir"/$deviceid/clean/$cpid/$version/iBSS.img4 ]; then
        cd "$dir"/$deviceid/clean/$cpid/$version
        _boot
        cd "$dir"/
        exit 0
    fi
    exit 0
fi
if [[ "$boot" == 1 ]]; then
    _download_boot_files $deviceid $replace $version
    if [[ "$version" == "7."* && "$dualboot_hfs" == 1 ]]; then
        _kill_if_running iproxy
        sudo killall -STOP -c usbd
        read -p "[*] You may need to unplug and replug your cable, would you like to? " r1
        if [[ "$r1" == "yes" || "$r1" == "y" ]]; then
            read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
            echo "[*] Waiting 10 seconds before continuing.."
            sleep 10
        elif [[ "$r1" == "no" || "$r1" == "n" ]]; then
            echo "[*] Ok no problem, continuing.."
        else
            echo "[*] That was not a response I was expecting, I'm going to treat that as a 'yes'.."
            read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
            echo "[*] Waiting 10 seconds before continuing.."
            sleep 10
        fi
        _download_ramdisk_boot_files $deviceid $replace 8.4.1
        cd "$dir"/$deviceid/$cpid/ramdisk/8.4.1
        _boot_ramdisk
        cd "$dir"/
        read -p "[*] Press Enter once your device has fully booted into the SSH ramdisk " r1
        echo "[*] Waiting 6 seconds before continuing.."
        sleep 6
        sudo killall -STOP -c usbd
        read -p "[*] You may need to unplug and replug your cable, would you like to? " r1
        if [[ "$r1" == "yes" || "$r1" == "y" ]]; then
            read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
            echo "[*] Waiting 10 seconds before continuing.."
            sleep 10
        elif [[ "$r1" == "no" || "$r1" == "n" ]]; then
            echo "[*] Ok no problem, continuing.."
        else
            echo "[*] That was not a response I was expecting, I'm going to treat that as a 'yes'.."
            read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
            echo "[*] Waiting 10 seconds before continuing.."
            sleep 10
        fi
        "$bin"/iproxy 2222 22 &
        "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost '/sbin/fsck'
        echo "[*] Done"
        "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/sbin/nvram auto-boot=false" 2> /dev/null
        $("$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/reboot &" 2> /dev/null &)
        echo "[*] The device should now boot into recovery mode"
        echo "[*] Please follow the on screen instructions to put your device back into dfu mode"
        echo "[*] We will try to boot iOS $version on your device"
        echo "[*] You can enable auto-boot again at any time by running $0 $version --fix-auto-boot"
        sleep 5
        if [ "$os" = "Darwin" ]; then
            if ! (system_profiler SPUSBDataType 2> /dev/null | grep ' Apple Mobile Device (DFU Mode)' >> /dev/null); then
                if [[ "$deviceid" == "iPhone10"* || "$cpid" == "0x8015"* ]]; then
                    sleep 10
                    if [ "$(get_device_mode)" = "recovery" ]; then
                        "$bin"/dfuhelper.sh
                    else
                        "$bin"/dfuhelper4.sh
                        sleep 5
                        "$bin"/irecovery -c "setenv auto-boot false"
                        "$bin"/irecovery -c "saveenv"
                        "$bin"/dfuhelper.sh
                    fi
                elif [[ "$cpid" = 0x801* && "$deviceid" != *"iPad"* ]]; then
                    "$bin"/dfuhelper2.sh
                else
                    "$bin"/dfuhelper3.sh
                fi
            fi
        else
            if ! (lsusb | cut -d' ' -f6 | grep '05ac:' | cut -d: -f2 | grep 1227 >> /dev/null); then
                if [[ "$deviceid" == "iPhone10"* || "$cpid" == "0x8015"* ]]; then
                    sleep 10
                    if [ "$(get_device_mode)" = "recovery" ]; then
                        "$bin"/dfuhelper.sh
                    else
                        "$bin"/dfuhelper4.sh
                        sleep 5
                        "$bin"/irecovery -c "setenv auto-boot false"
                        "$bin"/irecovery -c "saveenv"
                        "$bin"/dfuhelper.sh
                    fi
                elif [[ "$cpid" = 0x801* && "$deviceid" != *"iPad"* ]]; then
                    "$bin"/dfuhelper2.sh
                else
                    "$bin"/dfuhelper3.sh
                fi
            fi
        fi
        _wait_for_dfu
    fi
    _kill_if_running iproxy
    sudo killall -STOP -c usbd
    read -p "[*] You may need to unplug and replug your cable, would you like to? " r1
    if [[ "$r1" == "yes" || "$r1" == "y" ]]; then
        read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
        echo "[*] Waiting 10 seconds before continuing.."
        sleep 10
    elif [[ "$r1" == "no" || "$r1" == "n" ]]; then
        echo "[*] Ok no problem, continuing.."
    else
        echo "[*] That was not a response I was expecting, I'm going to treat that as a 'yes'.."
        read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
        echo "[*] Waiting 10 seconds before continuing.."
        sleep 10
    fi
    if [ -e "$dir"/$deviceid/$cpid/$version/iBSS.img4 ]; then
        cd "$dir"/$deviceid/$cpid/$version
        _boot
        cd "$dir"/
        exit 0
    fi
    exit 0
fi
if [[ "$ramdisk" == 1 || "$restore" == 1 || "$dump_blobs" == 1 || "$force_activation" == 1 || "$restore_activation" == 1 || "$dump_nand" == 1 || "$restore_nand" == 1 || "$restore_mnt1" == 1 || "$restore_mnt2" == 1 || "$disable_NoMoreSIGABRT" == 1 || "$NoMoreSIGABRT" == 1 ]]; then
    _kill_if_running iproxy
    if [[ "$ramdisk" == 1 || "$dump_blobs" == 1 || "$dump_nand" == 1 || "$restore_activation" == 1 || "$restore_nand" == 1 || "$restore_mnt1" == 1 || "$restore_mnt2" == 1 || "$disable_NoMoreSIGABRT" == 1 || "$NoMoreSIGABRT" == 1 ]]; then
        rdversion="$version"
        if [[ "$version" == "10."* || "$version" == "11.0" ]]; then
            rdversion="10.3.3"
        elif [[ "$deviceid" == "iPhone8,1" && "$version" == "11.0" ]]; then
            rdversion="10.3.3"
        elif [[ "$version" == "7."* || "$version" == "8."* ]]; then
            rdversion="8.4.1"
        fi
        _download_ramdisk_boot_files $deviceid $replace $rdversion
        sleep 1
        if [ "$os" = "Darwin" ]; then
            if ! (system_profiler SPUSBDataType 2> /dev/null | grep ' Apple Mobile Device (DFU Mode)' >> /dev/null); then
                if [[ "$deviceid" == "iPhone10"* || "$cpid" == "0x8015"* ]]; then
                    sleep 10
                    if [ "$(get_device_mode)" = "recovery" ]; then
                        "$bin"/dfuhelper.sh
                    else
                        "$bin"/dfuhelper4.sh
                        sleep 5
                        "$bin"/irecovery -c "setenv auto-boot false"
                        "$bin"/irecovery -c "saveenv"
                        "$bin"/dfuhelper.sh
                    fi
                elif [[ "$cpid" = 0x801* && "$deviceid" != *"iPad"* ]]; then
                    "$bin"/dfuhelper2.sh
                else
                    "$bin"/dfuhelper3.sh
                fi
            fi
        else
            if ! (lsusb | cut -d' ' -f6 | grep '05ac:' | cut -d: -f2 | grep 1227 >> /dev/null); then
                if [[ "$deviceid" == "iPhone10"* || "$cpid" == "0x8015"* ]]; then
                    sleep 10
                    if [ "$(get_device_mode)" = "recovery" ]; then
                        "$bin"/dfuhelper.sh
                    else
                        "$bin"/dfuhelper4.sh
                        sleep 5
                        "$bin"/irecovery -c "setenv auto-boot false"
                        "$bin"/irecovery -c "saveenv"
                        "$bin"/dfuhelper.sh
                    fi
                elif [[ "$cpid" = 0x801* && "$deviceid" != *"iPad"* ]]; then
                    "$bin"/dfuhelper2.sh
                else
                    "$bin"/dfuhelper3.sh
                fi
            fi
        fi
        _wait_for_dfu
        sudo killall -STOP -c usbd
        read -p "[*] You may need to unplug and replug your cable, would you like to? " r1
        if [[ "$r1" == "yes" || "$r1" == "y" ]]; then
            read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
            echo "[*] Waiting 10 seconds before continuing.."
            sleep 10
        elif [[ "$r1" == "no" || "$r1" == "n" ]]; then
            echo "[*] Ok no problem, continuing.."
        else
            echo "[*] That was not a response I was expecting, I'm going to treat that as a 'yes'.."
            read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
            echo "[*] Waiting 10 seconds before continuing.."
            sleep 10
        fi
        cd "$dir"/$deviceid/$cpid/ramdisk/$rdversion
        pongo=0
    else
        if [[ "$version" == "7."* || "$version" == "8."* ]]; then
            if [ "$os" = "Darwin" ]; then
                _download_ramdisk_boot_files $deviceid $replace 8.4.1
            else
                _download_ramdisk_boot_files $deviceid $replace 8.4.1
                _download_ramdisk_boot_files $deviceid $replace 11.4
            fi
        elif [[ "$version" == "10.3"* ]]; then
            _download_ramdisk_boot_files $deviceid $replace 10.3.3
            if [[ "$(./java/bin/java -jar ./Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -e 14.3 $deviceid)" == "true" ]]; then
                _download_ramdisk_boot_files $deviceid $replace 14.3
            elif [[ "$deviceid" == "iPad"* && ! "$deviceid" == "iPad4"* ]]; then
                _download_ramdisk_boot_files $deviceid $replace 14.3
            else
                _download_ramdisk_boot_files $deviceid $replace 12.5.4
            fi
        elif [[ "$deviceid" == "iPhone8,1" && "$version" == "11.0" ]]; then
            _download_ramdisk_boot_files $deviceid $replace 10.3.3
            if [[ "$(./java/bin/java -jar ./Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -e 14.3 $deviceid)" == "true" ]]; then
                _download_ramdisk_boot_files $deviceid $replace 14.3
            elif [[ "$deviceid" == "iPad"* && ! "$deviceid" == "iPad4"* ]]; then
                _download_ramdisk_boot_files $deviceid $replace 14.3
            else
                _download_ramdisk_boot_files $deviceid $replace 12.5.4
            fi
        elif [[ "$version" == "11."* || "$version" == "12."* || "$version" == "13."* || "$version" == "14."* ]]; then
            if [[ "$(./java/bin/java -jar ./Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -e 14.3 $deviceid)" == "true" ]]; then
                _download_ramdisk_boot_files $deviceid $replace 14.3
            elif [[ "$deviceid" == "iPad"* && ! "$deviceid" == "iPad4"* ]]; then
                _download_ramdisk_boot_files $deviceid $replace 14.3
            else
                _download_ramdisk_boot_files $deviceid $replace 12.5.4
            fi
        elif [[ "$os" = "Darwin" && ! "$deviceid" == "iPhone6"* && ! "$deviceid" == "iPhone7"* && ! "$deviceid" == "iPad4"* && ! "$deviceid" == "iPad5"* && ! "$deviceid" == "iPod7"* && "$version" == "9."* ]]; then
            _download_ramdisk_boot_files $deviceid $replace 9.3
        else
            _download_ramdisk_boot_files $deviceid $replace 11.4
        fi
        if [[ ! -e "$dir"/$deviceid/0.0/apticket.der || ! -e "$dir"/$deviceid/0.0/sep-firmware.img4 || ! -e "$dir"/$deviceid/0.0/keybags ]]; then
            _download_ramdisk_boot_files $deviceid $replace $r
        fi
        if [[ "$version" == "10.3"* || "$version" == "11."* || "$version" == "12."* || "$version" == "13."* || "$version" == "14."* ]]; then
            _download_ramdisk_boot_files $deviceid $replace $r
        elif [[ "$deviceid" == "iPhone6"* || "$deviceid" == "iPad4"* ]]; then
            if [[ "$dualboot_hfs" == 1 ]]; then
                _download_ramdisk_boot_files $deviceid $replace $r
            fi
        fi
        _download_boot_files $deviceid $replace $version
        if [[ "$restore" == 1 ]]; then
            _download_root_fs $deviceid $replace $version
        fi
        echo "[*] Waiting for device in DFU mode"
        sleep 1
        if [ "$os" = "Darwin" ]; then
            if ! (system_profiler SPUSBDataType 2> /dev/null | grep ' Apple Mobile Device (DFU Mode)' >> /dev/null); then
                if [[ "$deviceid" == "iPhone10"* || "$cpid" == "0x8015"* ]]; then
                    sleep 10
                    if [ "$(get_device_mode)" = "recovery" ]; then
                        "$bin"/dfuhelper.sh
                    else
                        "$bin"/dfuhelper4.sh
                        sleep 5
                        "$bin"/irecovery -c "setenv auto-boot false"
                        "$bin"/irecovery -c "saveenv"
                        "$bin"/dfuhelper.sh
                    fi
                elif [[ "$cpid" = 0x801* && "$deviceid" != *"iPad"* ]]; then
                    "$bin"/dfuhelper2.sh
                else
                    "$bin"/dfuhelper3.sh
                fi
            fi
        else
            if ! (lsusb | cut -d' ' -f6 | grep '05ac:' | cut -d: -f2 | grep 1227 >> /dev/null); then
                if [[ "$deviceid" == "iPhone10"* || "$cpid" == "0x8015"* ]]; then
                    sleep 10
                    if [ "$(get_device_mode)" = "recovery" ]; then
                        "$bin"/dfuhelper.sh
                    else
                        "$bin"/dfuhelper4.sh
                        sleep 5
                        "$bin"/irecovery -c "setenv auto-boot false"
                        "$bin"/irecovery -c "saveenv"
                        "$bin"/dfuhelper.sh
                    fi
                elif [[ "$cpid" = 0x801* && "$deviceid" != *"iPad"* ]]; then
                    "$bin"/dfuhelper2.sh
                else
                    "$bin"/dfuhelper3.sh
                fi
            fi
        fi
        _wait_for_dfu
        sudo killall -STOP -c usbd
        read -p "[*] You may need to unplug and replug your cable, would you like to? " r1
        if [[ "$r1" == "yes" || "$r1" == "y" ]]; then
            read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
            echo "[*] Waiting 10 seconds before continuing.."
            sleep 10
        elif [[ "$r1" == "no" || "$r1" == "n" ]]; then
            echo "[*] Ok no problem, continuing.."
        else
            echo "[*] That was not a response I was expecting, I'm going to treat that as a 'yes'.."
            read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
            echo "[*] Waiting 10 seconds before continuing.."
            sleep 10
        fi
        if [[ ! -e "$dir"/$deviceid/0.0/apticket.der || ! -e "$dir"/$deviceid/0.0/sep-firmware.img4 || ! -e "$dir"/$deviceid/0.0/keybags ]]; then
            cd "$dir"/$deviceid/$cpid/ramdisk/$r
        elif [[ "$version" == "7."* || "$version" == "8."* ]]; then
            if [ "$os" = "Darwin" ]; then
                cd "$dir"/$deviceid/$cpid/ramdisk/8.4.1
            else
                cd "$dir"/$deviceid/$cpid/ramdisk/11.4
            fi
        elif [[ "$version" == "10.3"* ]]; then
            cd "$dir"/$deviceid/$cpid/ramdisk/10.3.3
        elif [[ "$deviceid" == "iPhone8,1" && "$version" == "11.0" ]]; then
            cd "$dir"/$deviceid/$cpid/ramdisk/10.3.3
        elif [[ "$version" == "11."* || "$version" == "12."* || "$version" == "13."* || "$version" == "14."* ]]; then
            if [[ "$(./java/bin/java -jar ./Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -e 14.3 $deviceid)" == "true" ]]; then
                cd "$dir"/$deviceid/$cpid/ramdisk/14.3
            elif [[ "$deviceid" == "iPad"* && ! "$deviceid" == "iPad4"* ]]; then
                cd "$dir"/$deviceid/$cpid/ramdisk/14.3
            else
                cd "$dir"/$deviceid/$cpid/ramdisk/12.5.4
            fi
        elif [[ "$os" = "Darwin" && ! "$deviceid" == "iPhone6"* && ! "$deviceid" == "iPhone7"* && ! "$deviceid" == "iPad4"* && ! "$deviceid" == "iPad5"* && ! "$deviceid" == "iPod7"* && "$version" == "9."* ]]; then
            cd "$dir"/$deviceid/$cpid/ramdisk/9.3
        else
            cd "$dir"/$deviceid/$cpid/ramdisk/11.4
        fi
        if [[ "$pongo" == 1 ]]; then
            if [[ -e "$dir"/$deviceid/0.0/apticket.der && -e "$dir"/$deviceid/0.0/sep-firmware.img4 && -e "$dir"/$deviceid/0.0/keybags ]]; then
                hit2=1
                pongo=0
            fi
        fi
    fi
    wd="$(pwd)"
    if [[ -e "$dir"/$deviceid/0.0/apticket.der && -e "$dir"/$deviceid/0.0/sep-firmware.img4 && -e "$dir"/$deviceid/0.0/keybags ]]; then
        if [[ "$cpid" == "0x8000" || "$cpid" == "0x8001" || "$cpid" == "0x8003" ]]; then
            if [[ "$pongo" == 1 ]]; then
                _download_ramdisk_boot_files $deviceid $replace 14.3
                pongo=0
                r="14.3"
                fuck=1
            fi
        fi
    fi
    cd "$wd"
    if [[ "$ramdisk" == 1 || "$dump_blobs" == 1 || "$dump_nand" == 1 || "$restore_activation" == 1 || "$restore_nand" == 1 || "$restore_mnt1" == 1 || "$restore_mnt2" == 1 || "$disable_NoMoreSIGABRT" == 1 || "$NoMoreSIGABRT" == 1 ]]; then
        if [[ "$version" == "16."* || "$version" == "17."* ]]; then
            pongo=1
        fi
    fi
    _boot_ramdisk $deviceid $replace $r
    if [[ "$hit2" == 1 ]]; then
        hit2=0
        pongo=1
    fi
    if [[ -e "$dir"/$deviceid/0.0/apticket.der && -e "$dir"/$deviceid/0.0/sep-firmware.img4 && -e "$dir"/$deviceid/0.0/keybags ]]; then
        if [[ "$cpid" == "0x8000" || "$cpid" == "0x8001" || "$cpid" == "0x8003" ]]; then
            if [[ "$pongo" == 1 ]]; then
                _download_ramdisk_boot_files $deviceid $replace 14.3
                pongo=0
                r="14.3"
                fuck=1
            fi
        fi
    fi
    cd "$dir"/
    read -p "[*] Press Enter once your device has fully booted into the SSH ramdisk " r1
    echo "[*] Waiting 6 seconds before continuing.."
    sleep 6
    sudo killall -STOP -c usbd
    read -p "[*] You may need to unplug and replug your cable, would you like to? " r1
    if [[ "$r1" == "yes" || "$r1" == "y" ]]; then
        read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
        echo "[*] Waiting 10 seconds before continuing.."
        sleep 10
    elif [[ "$r1" == "no" || "$r1" == "n" ]]; then
        echo "[*] Ok no problem, continuing.."
    else
        echo "[*] That was not a response I was expecting, I'm going to treat that as a 'yes'.."
        read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
        echo "[*] Waiting 10 seconds before continuing.."
        sleep 10
    fi
    "$bin"/iproxy 2222 22 &
    sleep 2
    if [[ "$restore" == 1 ]]; then
        if [[ "$deviceid" == "iPhone10"* || "$cpid" == "0x8015"* ]]; then
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/sbin/nvram auto-boot=false" 2> /dev/null
        fi
        mkdir -p "$dir"/$deviceid/0.0/
        hit=0
        if [[ ! -e "$dir"/$deviceid/0.0/apticket.der || ! -e "$dir"/$deviceid/0.0/sep-firmware.img4 || ! -e "$dir"/$deviceid/0.0/keybags ]]; then
            if [[ "$r" == "7."* || "$r" == "8."* || "$r" == "9."* || "$r" == "10.0"* || "$r" == "10.1"* || "$r" == "10.2"* ]]; then
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount -w -t hfs /dev/disk0s1s1 /mnt1" 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "bash -c mount_filesystems" 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount -w -t hfs /dev/disk0s1s2 /mnt2" 2> /dev/null
            else
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "bash -c mount_filesystems" 2> /dev/null
            fi
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
					echo "[*] An error occured while trying to back up the required files required to downgrade"
					$("$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/reboot &" 2> /dev/null &)
                    _kill_if_running iproxy
					exit 0
				fi
				active=$(remote_cmd "cat /mnt6/active" 2> /dev/null)
				"$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt6/$active/System/Library/Caches/apticket.der "$dir"/$deviceid/0.0/apticket.der 2> /dev/null
				"$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt6/$active/usr/standalone/firmware/sep-firmware.img4 "$dir"/$deviceid/0.0/sep-firmware.img4 2> /dev/null
				"$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -r -P 2222 root@localhost:/mnt6/$active/usr/standalone/firmware/FUD "$dir"/$deviceid/0.0/FUD 2> /dev/null
				"$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -r -P 2222 root@localhost:/mnt6/$active/usr/local/standalone/firmware/Baseband "$dir"/$deviceid/0.0/Baseband 2> /dev/null
				"$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -r -P 2222 root@localhost:/mnt6/$active/usr/standalone/firmware "$dir"/$deviceid/0.0/firmware 2> /dev/null
				"$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -r -P 2222 root@localhost:/mnt6/$active/usr/local "$dir"/$deviceid/0.0/local 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags -R schg /mnt6/$active/"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags schg /mnt6/active"
			fi
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt1" 2> /dev/null
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt2" 2> /dev/null
            if [[ ! -e "$dir"/$deviceid/0.0/apticket.der || ! -e "$dir"/$deviceid/0.0/sep-firmware.img4 || ! -e "$dir"/$deviceid/0.0/keybags ]]; then
                echo "[*] An error occured while trying to back up the required files required to downgrade"
                $("$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/reboot &" 2> /dev/null &)
                _kill_if_running iproxy
                exit 0
            else
                hit=1
                echo "[*] Backed up the required files required to downgrade"
            fi
        fi
        if [ ! -e "$dir"/$deviceid/0.0/apticket.der ]; then
            echo "missing ./apticket.der, which is required in order to proceed. exiting.."
            exit 0
        fi
        if [ ! -e "$dir"/$deviceid/0.0/sep-firmware.img4 ]; then
            echo "missing ./sep-firmware.img4, which is required in order to proceed. exiting.."
            exit 0
        fi
        if [ ! -e "$dir"/$deviceid/0.0/keybags ]; then
            echo "missing ./keybags, which is required in order to proceed. exiting.."
            exit 0
        fi
        if [ ! -e "$dir"/$deviceid/0.0/activation_records/activation_record.plist ]; then
            read -p "missing ./activation_records/activation_record.plist, which is recommended in order to proceed. press enter to continue.. " r1
            force_activation=1
        fi
        if [[ "$cpid" == "0x8000" || "$cpid" == "0x8001" || "$cpid" == "0x8003" ]]; then
            if [[ "$pongo" == 1 ]]; then
                _download_ramdisk_boot_files $deviceid $replace 14.3
                pongo=0
                r="14.3"
                fuck=1
            fi
        fi
        if [[ "$version" == "10.3"* || "$version" == "11."* || "$version" == "12."* || "$version" == "13."* || "$version" == "14."* ]]; then
            if [[ "$hit" == 1 ]]; then
                $("$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/reboot &" 2> /dev/null &)
                _kill_if_running iproxy
                if [ "$os" = "Darwin" ]; then
                    if ! (system_profiler SPUSBDataType 2> /dev/null | grep ' Apple Mobile Device (DFU Mode)' >> /dev/null); then
                        if [[ "$deviceid" == "iPhone10"* || "$cpid" == "0x8015"* ]]; then
                            sleep 10
                            if [ "$(get_device_mode)" = "recovery" ]; then
                                "$bin"/dfuhelper.sh
                            else
                                "$bin"/dfuhelper4.sh
                                sleep 5
                                "$bin"/irecovery -c "setenv auto-boot false"
                                "$bin"/irecovery -c "saveenv"
                                "$bin"/dfuhelper.sh
                            fi
                        elif [[ "$cpid" = 0x801* && "$deviceid" != *"iPad"* ]]; then
                            "$bin"/dfuhelper2.sh
                        else
                            "$bin"/dfuhelper3.sh
                        fi
                    fi
                else
                    if ! (lsusb | cut -d' ' -f6 | grep '05ac:' | cut -d: -f2 | grep 1227 >> /dev/null); then
                        if [[ "$deviceid" == "iPhone10"* || "$cpid" == "0x8015"* ]]; then
                            sleep 10
                            if [ "$(get_device_mode)" = "recovery" ]; then
                                "$bin"/dfuhelper.sh
                            else
                                "$bin"/dfuhelper4.sh
                                sleep 5
                                "$bin"/irecovery -c "setenv auto-boot false"
                                "$bin"/irecovery -c "saveenv"
                                "$bin"/dfuhelper.sh
                            fi
                        elif [[ "$cpid" = 0x801* && "$deviceid" != *"iPad"* ]]; then
                            "$bin"/dfuhelper2.sh
                        else
                            "$bin"/dfuhelper3.sh
                        fi
                    fi
                fi
                _wait_for_dfu
                sudo killall -STOP -c usbd
                read -p "[*] You may need to unplug and replug your cable, would you like to? " r1
                if [[ "$r1" == "yes" || "$r1" == "y" ]]; then
                    read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
                    echo "[*] Waiting 10 seconds before continuing.."
                    sleep 10
                elif [[ "$r1" == "no" || "$r1" == "n" ]]; then
                    echo "[*] Ok no problem, continuing.."
                else
                    echo "[*] That was not a response I was expecting, I'm going to treat that as a 'yes'.."
                    read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
                    echo "[*] Waiting 10 seconds before continuing.."
                    sleep 10
                fi
                if [[ "$version" == "7."* || "$version" == "8."* ]]; then
                    if [ "$os" = "Darwin" ]; then
                        cd "$dir"/$deviceid/$cpid/ramdisk/8.4.1
                    else
                        cd "$dir"/$deviceid/$cpid/ramdisk/11.4
                    fi
                elif [[ "$version" == "10.3"* ]]; then
                    cd "$dir"/$deviceid/$cpid/ramdisk/10.3.3
                elif [[ "$deviceid" == "iPhone8,1" && "$version" == "11.0" ]]; then
                    cd "$dir"/$deviceid/$cpid/ramdisk/10.3.3
                elif [[ "$version" == "11."* || "$version" == "12."* || "$version" == "13."* || "$version" == "14."* ]]; then
                    if [[ "$(./java/bin/java -jar ./Darwin/FirmwareKeysDl-1.0-SNAPSHOT.jar -e 14.3 $deviceid)" == "true" ]]; then
                        cd "$dir"/$deviceid/$cpid/ramdisk/14.3
                    elif [[ "$deviceid" == "iPad"* && ! "$deviceid" == "iPad4"* ]]; then
                        cd "$dir"/$deviceid/$cpid/ramdisk/14.3
                    else
                        cd "$dir"/$deviceid/$cpid/ramdisk/12.5.4
                    fi
                elif [[ "$os" = "Darwin" && ! "$deviceid" == "iPhone6"* && ! "$deviceid" == "iPhone7"* && ! "$deviceid" == "iPad4"* && ! "$deviceid" == "iPad5"* && ! "$deviceid" == "iPod7"* && "$version" == "9."* ]]; then
                    cd "$dir"/$deviceid/$cpid/ramdisk/9.3
                else
                    cd "$dir"/$deviceid/$cpid/ramdisk/11.4
                fi
                if [[ "$pongo" == 1 ]]; then
                    hit2=1
                    pongo=0
                fi
                _boot_ramdisk $deviceid $replace $r
                if [[ "$hit2" == 1 ]]; then
                    hit2=0
                    pongo=1
                fi
                cd "$dir"/
                read -p "[*] Press Enter once your device has fully booted into the SSH ramdisk " r1
                echo "[*] Waiting 6 seconds before continuing.."
                sleep 6
                sudo killall -STOP -c usbd
                read -p "[*] You may need to unplug and replug your cable, would you like to? " r1
                if [[ "$r1" == "yes" || "$r1" == "y" ]]; then
                    read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
                    echo "[*] Waiting 10 seconds before continuing.."
                    sleep 10
                elif [[ "$r1" == "no" || "$r1" == "n" ]]; then
                    echo "[*] Ok no problem, continuing.."
                else
                    echo "[*] That was not a response I was expecting, I'm going to treat that as a 'yes'.."
                    read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
                    echo "[*] Waiting 10 seconds before continuing.."
                    sleep 10
                fi
                "$bin"/iproxy 2222 22 &
            fi
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "bash -c fixup_update_partition" 2> /dev/null
            echo "[*] Testing for baseband presence"
            if [[ "$version" == "13."* || "$version" == "14."* ]]; then
                systemdisk=8
                datadisk=9
                prebootdisk=10
                if [ "$(remote_cmd "/usr/bin/mgask HasBaseband | grep -E 'true|false'")" = "true" ] && [[ "${cpid}" == *"0x700"* ]]; then
                    systemdisk=7
                    datadisk=8
                    prebootdisk=9
                elif [ "$(remote_cmd "/usr/bin/mgask HasBaseband | grep -E 'true|false'")" = "false" ]; then
                    if [[ "${cpid}" == *"0x700"* ]]; then
                        systemdisk=6
                        datadisk=7
                        prebootdisk=8
                    else
                        systemdisk=7
                        datadisk=8
                        prebootdisk=9
                    fi
                fi
                systemfs=disk0s1s$systemdisk
                datafs=disk0s1s$datadisk
                prebootfs=disk0s1s$prebootdisk
                rm -rf "$dir"/$deviceid/$cpid/$version/iBSS.patched
                rm -rf "$dir"/$deviceid/$cpid/$version/iBEC.patched
                rm -rf "$dir"/$deviceid/$cpid/$version/iBSS.img4
                rm -rf "$dir"/$deviceid/$cpid/$version/iBEC.img4
                mkdir -p "$dir"/work
                cd "$dir"/work
                "$bin"/img4tool -e -s "$dir"/other/shsh/"${check}".shsh -m IM4M
                "$bin"/iBoot64Patcher "$dir"/$deviceid/$cpid/$version/iBSS.dec "$dir"/$deviceid/$cpid/$version/iBSS.patched
                "$bin"/iBoot64Patcher "$dir"/$deviceid/$cpid/$version/iBEC.dec "$dir"/$deviceid/$cpid/$version/iBEC.patched -b "$boot_args rd=$systemfs amfi=0xff cs_enforcement_disable=1 keepsyms=1 debug=0x100 PE_i_can_has_debugger=1 amfi_get_out_of_my_way=1 amfi_allow_any_signature=1" -n
                "$bin"/img4 -i "$dir"/$deviceid/$cpid/$version/iBSS.patched -o "$dir"/$deviceid/$cpid/$version/iBSS.img4 -M IM4M -A -T ibss
                "$bin"/img4 -i "$dir"/$deviceid/$cpid/$version/iBEC.patched -o "$dir"/$deviceid/$cpid/$version/iBEC.img4 -M IM4M -A -T ibec
                cd "$dir"/
                rm -rf work
                sleep 2
            else
                if [[ "$r" == "16"* || "$r" == "17"* ]]; then
                    systemdisk=9
                    datadisk=10
                    systemfs=disk0s1s$systemdisk
                    datafs=disk0s1s$datadisk
                else
                    systemdisk=8
                    datadisk=9
                    systemfs=disk0s1s$systemdisk
                    datafs=disk0s1s$datadisk
                fi
            fi
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt4" 2> /dev/null
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt5" 2> /dev/null
            echo "[*] Deleting /dev/$systemfs"
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/apfs_deletefs /dev/$systemfs"
            sleep 1
            echo "[*] Creating /dev/$systemfs"
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/newfs_apfs -A -v SystemX /dev/disk0s1"
            sleep 2
            remote_cmd "/sbin/apfs_deletefs /dev/$systemfs" && {
                sleep 1
                echo "[*] Creating /dev/$systemfs"
                if [[ "$version" == "13."* || "$version" == "14."* ]]; then
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/newfs_apfs -o role=n -A -v SystemX /dev/disk0s1"
                else
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/newfs_apfs -A -v SystemX /dev/disk0s1"
                fi
                sleep 2
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "ls /dev/"
            } || {
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/newfs_apfs -A -v SystemX /dev/disk0s1"
                sleep 2
                remote_cmd "/sbin/apfs_deletefs /dev/$systemfs" && {
                    sleep 1
                    if [[ "$version" == "13."* || "$version" == "14."* ]]; then
                        "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/newfs_apfs -o role=n -A -v SystemX /dev/disk0s1"
                    else
                        "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/newfs_apfs -A -v SystemX /dev/disk0s1"
                    fi
                    sleep 2
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "ls /dev/"
                } || {
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/newfs_apfs -A -v SystemX /dev/disk0s1"
                    sleep 2
                    remote_cmd "/sbin/apfs_deletefs /dev/$systemfs" && {
                        sleep 1
                        if [[ "$version" == "13."* || "$version" == "14."* ]]; then
                            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/newfs_apfs -o role=n -A -v SystemX /dev/disk0s1"
                        else
                            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/newfs_apfs -A -v SystemX /dev/disk0s1"
                        fi
                        sleep 2
                        "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "ls /dev/"
                    } || {
                        "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/newfs_apfs -A -v SystemX /dev/disk0s1"
                        sleep 2
                        remote_cmd "/sbin/apfs_deletefs /dev/$systemfs" && {
                            sleep 1
                            if [[ "$version" == "13."* || "$version" == "14."* ]]; then
                                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/newfs_apfs -o role=n -A -v SystemX /dev/disk0s1"
                            else
                                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/newfs_apfs -A -v SystemX /dev/disk0s1"
                            fi
                            sleep 2
                            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "ls /dev/"
                        } || {
                            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/newfs_apfs -A -v SystemX /dev/disk0s1"
                            sleep 2
                            remote_cmd "/sbin/apfs_deletefs /dev/$systemfs" && {
                                sleep 1
                                if [[ "$version" == "13."* || "$version" == "14."* ]]; then
                                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/newfs_apfs -o role=n -A -v SystemX /dev/disk0s1"
                                else
                                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/newfs_apfs -A -v SystemX /dev/disk0s1"
                                fi
                                sleep 2
                                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "ls /dev/"
                            } || {
                                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/newfs_apfs -A -v SystemX /dev/disk0s1"
                                sleep 2
                                remote_cmd "/sbin/apfs_deletefs /dev/$systemfs" && {
                                    sleep 1
                                    if [[ "$version" == "13."* || "$version" == "14."* ]]; then
                                        "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/newfs_apfs -o role=n -A -v SystemX /dev/disk0s1"
                                    else
                                        "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/newfs_apfs -A -v SystemX /dev/disk0s1"
                                    fi
                                    sleep 2
                                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "ls /dev/"
                                } || {
                                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/newfs_apfs -A -v SystemX /dev/disk0s1"
                                    sleep 2
                                    remote_cmd "/sbin/apfs_deletefs /dev/$systemfs" && {
                                        sleep 1
                                        if [[ "$version" == "13."* || "$version" == "14."* ]]; then
                                            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/newfs_apfs -o role=n -A -v SystemX /dev/disk0s1"
                                        else
                                            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/newfs_apfs -A -v SystemX /dev/disk0s1"
                                        fi
                                        sleep 2
                                        "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "ls /dev/"
                                    } || {
                                        echo "[*] An error occured while trying to create /dev/$systemfs"
                                        exit 0
                                    }
                                }
                            }
                        }
                    }
                }
            }
            echo "[*] /dev/$systemfs created, continuing..."
            echo "[*] Deleting /dev/$datafs"
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/apfs_deletefs /dev/$datafs"
            sleep 1
            echo "[*] Creating /dev/$datafs"
            if [[ "$version" == "13."* || "$version" == "14."* ]]; then
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/newfs_apfs -o role=0 -A -v DataX /dev/disk0s1"
            else
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/newfs_apfs -A -v DataX /dev/disk0s1"
            fi
            sleep 2
            echo "[*] /dev/$datafs created, continuing..."
            if [[ "$version" == "14."* ]]; then
                echo "[*] Deleting /dev/$prebootfs"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/apfs_deletefs /dev/$prebootfs"
                sleep 1
                echo "[*] Creating /dev/$prebootfs"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/newfs_apfs -o role=D -A -v PrebootX /dev/disk0s1"
                sleep 2
                echo "[*] /dev/$prebootfs created, continuing..."
            fi
            echo "[*] Uploading $dir/$deviceid/$cpid/$version/OS.dmg, this may take up to 10 minutes.."
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount_apfs /dev/$systemfs /mnt4"
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount_apfs /dev/$datafs /mnt5"
            if [ "$os" = "Darwin" ]; then
                "$bin"/sshpass -p 'alpine' scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/OS.dmg root@localhost:/mnt4
            else
                "$bin"/sshpass -p 'alpine' scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/OS.dmg root@localhost:/mnt5
            fi
            if [[ "$r" == "16"* || "$r" == "17"* ]]; then
                systemdisk=9
                datadisk=10
                systemfs=disk1s$systemdisk
                datafs=disk1s$datadisk
            fi
        else
            if [[ "$dualboot_hfs" == 1 ]]; then
                if [[ ! -e "$dir"/$deviceid/0.0/mnt1.tar.gz ]]; then
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount_apfs /dev/disk0s1s1 /mnt1"
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount -w -t hfs /dev/disk0s1s1 /mnt1"
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "tar --preserve-permissions -czvf - /mnt1/" > "$dir"/$deviceid/0.0/mnt1.tar.gz
                fi
                if [[ ! -e "$dir"/$deviceid/0.0/mnt3.tar.gz ]]; then
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount_apfs /dev/disk0s1s3 /mnt3"
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount -w -t hfs /dev/disk0s1s3 /mnt3"
                    bbfs=$(remote_cmd "/usr/bin/find /mnt3 -name 'bbfs'" 2> /dev/null)
                    if [[ "$bbfs" == "/mnt3/bbfs" ]]; then
                        "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "cd /mnt3 && tar --preserve-permissions -czvf - *" > "$dir"/$deviceid/0.0/mnt3.tar.gz
                    fi
                fi
            fi
            if [[ "$hit" == 1 ]]; then
                if [[ ! "$deviceid" == "iPhone6"* && ! "$deviceid" == "iPhone7"* && ! "$deviceid" == "iPad4"* && ! "$deviceid" == "iPad5"* && ! "$deviceid" == "iPod7"* && "$version" == "9."* ]]; then
                    $("$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/reboot &" 2> /dev/null &)
                    sleep 5
                    _kill_if_running iproxy
                    echo "[*] Device should boot to Recovery mode. Please wait..."
                    if [ "$os" = "Darwin" ]; then
                        if ! (system_profiler SPUSBDataType 2> /dev/null | grep ' Apple Mobile Device (DFU Mode)' >> /dev/null); then
                            if [[ "$deviceid" == "iPhone10"* || "$cpid" == "0x8015"* ]]; then
                                sleep 10
                                if [ "$(get_device_mode)" = "recovery" ]; then
                                    "$bin"/dfuhelper.sh
                                else
                                    "$bin"/dfuhelper4.sh
                                    sleep 5
                                    "$bin"/irecovery -c "setenv auto-boot false"
                                    "$bin"/irecovery -c "saveenv"
                                    "$bin"/dfuhelper.sh
                                fi
                            elif [[ "$cpid" = 0x801* && "$deviceid" != *"iPad"* ]]; then
                                "$bin"/dfuhelper2.sh
                            else
                                "$bin"/dfuhelper3.sh
                            fi
                        fi
                    else
                        if ! (lsusb | cut -d' ' -f6 | grep '05ac:' | cut -d: -f2 | grep 1227 >> /dev/null); then
                            if [[ "$deviceid" == "iPhone10"* || "$cpid" == "0x8015"* ]]; then
                                sleep 10
                                if [ "$(get_device_mode)" = "recovery" ]; then
                                    "$bin"/dfuhelper.sh
                                else
                                    "$bin"/dfuhelper4.sh
                                    sleep 5
                                    "$bin"/irecovery -c "setenv auto-boot false"
                                    "$bin"/irecovery -c "saveenv"
                                    "$bin"/dfuhelper.sh
                                fi
                            elif [[ "$cpid" = 0x801* && "$deviceid" != *"iPad"* ]]; then
                                "$bin"/dfuhelper2.sh
                            else
                                "$bin"/dfuhelper3.sh
                            fi
                        fi
                    fi
                    _wait_for_dfu
                    sudo killall -STOP -c usbd
                    read -p "[*] You may need to unplug and replug your cable, would you like to? " r1
                    if [[ "$r1" == "yes" || "$r1" == "y" ]]; then
                        read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
                        echo "[*] Waiting 10 seconds before continuing.."
                        sleep 10
                    elif [[ "$r1" == "no" || "$r1" == "n" ]]; then
                        echo "[*] Ok no problem, continuing.."
                    else
                        echo "[*] That was not a response I was expecting, I'm going to treat that as a 'yes'.."
                        read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
                        echo "[*] Waiting 10 seconds before continuing.."
                        sleep 10
                    fi
                    if [[ "$version" == "7."* || "$version" == "8."* ]]; then
                        if [ "$os" = "Darwin" ]; then
                            cd "$dir"/$deviceid/$cpid/ramdisk/8.4.1
                        else
                            cd "$dir"/$deviceid/$cpid/ramdisk/11.4
                        fi
                    elif [[ "$version" == "10.3"* || "$version" == "11."* ||  "$version" == "12."* || "$version" == "13."* || "$version" == "14."* ]]; then
                        cd "$dir"/$deviceid/$cpid/ramdisk/$r
                    elif [[ "$os" = "Darwin" && ! "$deviceid" == "iPhone6"* && ! "$deviceid" == "iPhone7"* && ! "$deviceid" == "iPad4"* && ! "$deviceid" == "iPad5"* && ! "$deviceid" == "iPod7"* && "$version" == "9."* ]]; then
                        cd "$dir"/$deviceid/$cpid/ramdisk/9.3
                    else
                        cd "$dir"/$deviceid/$cpid/ramdisk/11.4
                    fi
                    _boot_ramdisk $deviceid $replace $r
                    cd "$dir"/
                    read -p "[*] Press Enter once your device has fully booted into the SSH ramdisk. " r1
                    echo "[*] Waiting 6 seconds before continuing.."
                    sleep 6
                    sudo killall -STOP -c usbd
                    read -p "[*] You may need to unplug and replug your cable, would you like to? " r1
                    if [[ "$r1" == "yes" || "$r1" == "y" ]]; then
                        read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
                        echo "[*] Waiting 10 seconds before continuing.."
                        sleep 10
                    elif [[ "$r1" == "no" || "$r1" == "n" ]]; then
                        echo "[*] Ok no problem, continuing.."
                    else
                        echo "[*] That was not a response I was expecting, I'm going to treat that as a 'yes'.."
                        read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
                        echo "[*] Waiting 10 seconds before continuing.."
                        sleep 10
                    fi
                    "$bin"/iproxy 2222 22 &
                fi
            fi
            if [[ "$dualboot_hfs" == 1 ]]; then
                remote_cmd "/sbin/mount -w -t hfs /dev/disk0s1s4 /mnt4 2> /dev/null" && {
                    echo "[*] /dev/disk0s1s4 already exists and is hfs, skipping lwvm init.."
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt4" 2> /dev/null
                    sleep 2
                    hit=1
                } || {
                    hit=0
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "lwvm init" 2> /dev/null
                    sleep 1
                    echo "[*] Wiped the device"
                    $("$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/reboot &" 2> /dev/null &)
                    sleep 5
                    _kill_if_running iproxy
                    echo "[*] Device should boot to Recovery mode. Please wait..."
                    if [ "$os" = "Darwin" ]; then
                        if ! (system_profiler SPUSBDataType 2> /dev/null | grep ' Apple Mobile Device (DFU Mode)' >> /dev/null); then
                            if [[ "$deviceid" == "iPhone10"* || "$cpid" == "0x8015"* ]]; then
                                sleep 10
                                if [ "$(get_device_mode)" = "recovery" ]; then
                                    "$bin"/dfuhelper.sh
                                else
                                    "$bin"/dfuhelper4.sh
                                    sleep 5
                                    "$bin"/irecovery -c "setenv auto-boot false"
                                    "$bin"/irecovery -c "saveenv"
                                    "$bin"/dfuhelper.sh
                                fi
                            elif [[ "$cpid" = 0x801* && "$deviceid" != *"iPad"* ]]; then
                                "$bin"/dfuhelper2.sh
                            else
                                "$bin"/dfuhelper3.sh
                            fi
                        fi
                    else
                        if ! (lsusb | cut -d' ' -f6 | grep '05ac:' | cut -d: -f2 | grep 1227 >> /dev/null); then
                            if [[ "$deviceid" == "iPhone10"* || "$cpid" == "0x8015"* ]]; then
                                sleep 10
                                if [ "$(get_device_mode)" = "recovery" ]; then
                                    "$bin"/dfuhelper.sh
                                else
                                    "$bin"/dfuhelper4.sh
                                    sleep 5
                                    "$bin"/irecovery -c "setenv auto-boot false"
                                    "$bin"/irecovery -c "saveenv"
                                    "$bin"/dfuhelper.sh
                                fi
                            elif [[ "$cpid" = 0x801* && "$deviceid" != *"iPad"* ]]; then
                                "$bin"/dfuhelper2.sh
                            else
                                "$bin"/dfuhelper3.sh
                            fi
                        fi
                    fi
                    _wait_for_dfu
                    sudo killall -STOP -c usbd
                    read -p "[*] You may need to unplug and replug your cable, would you like to? " r1
                    if [[ "$r1" == "yes" || "$r1" == "y" ]]; then
                        read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
                        echo "[*] Waiting 10 seconds before continuing.."
                        sleep 10
                    elif [[ "$r1" == "no" || "$r1" == "n" ]]; then
                        echo "[*] Ok no problem, continuing.."
                    else
                        echo "[*] That was not a response I was expecting, I'm going to treat that as a 'yes'.."
                        read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
                        echo "[*] Waiting 10 seconds before continuing.."
                        sleep 10
                    fi
                    if [[ "$version" == "7."* || "$version" == "8."* ]]; then
                        if [ "$os" = "Darwin" ]; then
                            cd "$dir"/$deviceid/$cpid/ramdisk/8.4.1
                        else
                            cd "$dir"/$deviceid/$cpid/ramdisk/11.4
                        fi
                    elif [[ "$version" == "10.3"* || "$version" == "11."* ||  "$version" == "12."* || "$version" == "13."* || "$version" == "14."* ]]; then
                        cd "$dir"/$deviceid/$cpid/ramdisk/$r
                    elif [[ "$os" = "Darwin" && ! "$deviceid" == "iPhone6"* && ! "$deviceid" == "iPhone7"* && ! "$deviceid" == "iPad4"* && ! "$deviceid" == "iPad5"* && ! "$deviceid" == "iPod7"* && "$version" == "9."* ]]; then
                        cd "$dir"/$deviceid/$cpid/ramdisk/9.3
                    else
                        cd "$dir"/$deviceid/$cpid/ramdisk/11.4
                    fi
                    _boot_ramdisk $deviceid $replace $r
                    cd "$dir"/
                    read -p "[*] Press Enter once your device has fully booted into the SSH ramdisk. " r1
                    echo "[*] Waiting 6 seconds before continuing.."
                    sleep 6
                    sudo killall -STOP -c usbd
                    read -p "[*] You may need to unplug and replug your cable, would you like to? " r1
                    if [[ "$r1" == "yes" || "$r1" == "y" ]]; then
                        read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
                        echo "[*] Waiting 10 seconds before continuing.."
                        sleep 10
                    elif [[ "$r1" == "no" || "$r1" == "n" ]]; then
                        echo "[*] Ok no problem, continuing.."
                    else
                        echo "[*] That was not a response I was expecting, I'm going to treat that as a 'yes'.."
                        read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
                        echo "[*] Waiting 10 seconds before continuing.."
                        sleep 10
                    fi
                    "$bin"/iproxy 2222 22 &
                }
            else
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "lwvm init" 2> /dev/null
                sleep 1
                echo "[*] Wiped the device"
                $("$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/reboot &" 2> /dev/null &)
                sleep 5
                _kill_if_running iproxy
                echo "[*] Device should boot to Recovery mode. Please wait..."
                if [ "$os" = "Darwin" ]; then
                    if ! (system_profiler SPUSBDataType 2> /dev/null | grep ' Apple Mobile Device (DFU Mode)' >> /dev/null); then
                        if [[ "$deviceid" == "iPhone10"* || "$cpid" == "0x8015"* ]]; then
                            sleep 10
                            if [ "$(get_device_mode)" = "recovery" ]; then
                                "$bin"/dfuhelper.sh
                            else
                                "$bin"/dfuhelper4.sh
                                sleep 5
                                "$bin"/irecovery -c "setenv auto-boot false"
                                "$bin"/irecovery -c "saveenv"
                                "$bin"/dfuhelper.sh
                            fi
                        elif [[ "$cpid" = 0x801* && "$deviceid" != *"iPad"* ]]; then
                            "$bin"/dfuhelper2.sh
                        else
                            "$bin"/dfuhelper3.sh
                        fi
                    fi
                else
                    if ! (lsusb | cut -d' ' -f6 | grep '05ac:' | cut -d: -f2 | grep 1227 >> /dev/null); then
                        if [[ "$deviceid" == "iPhone10"* || "$cpid" == "0x8015"* ]]; then
                            sleep 10
                            if [ "$(get_device_mode)" = "recovery" ]; then
                                "$bin"/dfuhelper.sh
                            else
                                "$bin"/dfuhelper4.sh
                                sleep 5
                                "$bin"/irecovery -c "setenv auto-boot false"
                                "$bin"/irecovery -c "saveenv"
                                "$bin"/dfuhelper.sh
                            fi
                        elif [[ "$cpid" = 0x801* && "$deviceid" != *"iPad"* ]]; then
                            "$bin"/dfuhelper2.sh
                        else
                            "$bin"/dfuhelper3.sh
                        fi
                    fi
                fi
                _wait_for_dfu
                sudo killall -STOP -c usbd
                read -p "[*] You may need to unplug and replug your cable, would you like to? " r1
                if [[ "$r1" == "yes" || "$r1" == "y" ]]; then
                    read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
                    echo "[*] Waiting 10 seconds before continuing.."
                    sleep 10
                elif [[ "$r1" == "no" || "$r1" == "n" ]]; then
                    echo "[*] Ok no problem, continuing.."
                else
                    echo "[*] That was not a response I was expecting, I'm going to treat that as a 'yes'.."
                    read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
                    echo "[*] Waiting 10 seconds before continuing.."
                    sleep 10
                fi
                if [[ "$version" == "7."* || "$version" == "8."* ]]; then
                    if [ "$os" = "Darwin" ]; then
                        cd "$dir"/$deviceid/$cpid/ramdisk/8.4.1
                    else
                        cd "$dir"/$deviceid/$cpid/ramdisk/11.4
                    fi
                elif [[ "$version" == "10.3"* || "$version" == "11."* ||  "$version" == "12."* || "$version" == "13."* || "$version" == "14."* ]]; then
                    cd "$dir"/$deviceid/$cpid/ramdisk/$r
                elif [[ "$os" = "Darwin" && ! "$deviceid" == "iPhone6"* && ! "$deviceid" == "iPhone7"* && ! "$deviceid" == "iPad4"* && ! "$deviceid" == "iPad5"* && ! "$deviceid" == "iPod7"* && "$version" == "9."* ]]; then
                    cd "$dir"/$deviceid/$cpid/ramdisk/9.3
                else
                    cd "$dir"/$deviceid/$cpid/ramdisk/11.4
                fi
                _boot_ramdisk $deviceid $replace $r
                cd "$dir"/
                read -p "[*] Press Enter once your device has fully booted into the SSH ramdisk. " r1
                echo "[*] Waiting 6 seconds before continuing.."
                sleep 6
                sudo killall -STOP -c usbd
                read -p "[*] You may need to unplug and replug your cable, would you like to? " r1
                if [[ "$r1" == "yes" || "$r1" == "y" ]]; then
                    read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
                    echo "[*] Waiting 10 seconds before continuing.."
                    sleep 10
                elif [[ "$r1" == "no" || "$r1" == "n" ]]; then
                    echo "[*] Ok no problem, continuing.."
                else
                    echo "[*] That was not a response I was expecting, I'm going to treat that as a 'yes'.."
                    read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
                    echo "[*] Waiting 10 seconds before continuing.."
                    sleep 10
                fi
                "$bin"/iproxy 2222 22 &
            fi
        fi
        if [[ "$version" == "10.3"* || "$version" == "11."* || "$version" == "12."* || "$version" == "13."* || "$version" == "14."* ]]; then
            $("$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/reboot &" 2> /dev/null &)
            sleep 5
            _kill_if_running iproxy
            echo "[*] Device should boot to Recovery mode. Please wait..."
            if [ "$os" = "Darwin" ]; then
                if ! (system_profiler SPUSBDataType 2> /dev/null | grep ' Apple Mobile Device (DFU Mode)' >> /dev/null); then
                    if [[ "$deviceid" == "iPhone10"* || "$cpid" == "0x8015"* ]]; then
                        sleep 10
                        if [ "$(get_device_mode)" = "recovery" ]; then
                            "$bin"/irecovery -c "setenv auto-boot true"
                            "$bin"/irecovery -c "saveenv"
                            "$bin"/dfuhelper.sh
                        else
                            "$bin"/dfuhelper4.sh
                            sleep 5
                            "$bin"/irecovery -c "setenv auto-boot true"
                            "$bin"/irecovery -c "saveenv"
                            "$bin"/dfuhelper.sh
                        fi
                    elif [[ "$cpid" = 0x801* && "$deviceid" != *"iPad"* ]]; then
                        "$bin"/dfuhelper2.sh
                    else
                        "$bin"/dfuhelper3.sh
                    fi
                fi
            else
                if ! (lsusb | cut -d' ' -f6 | grep '05ac:' | cut -d: -f2 | grep 1227 >> /dev/null); then
                    if [[ "$deviceid" == "iPhone10"* || "$cpid" == "0x8015"* ]]; then
                        sleep 10
                        if [ "$(get_device_mode)" = "recovery" ]; then
                            "$bin"/irecovery -c "setenv auto-boot true"
                            "$bin"/irecovery -c "saveenv"
                            "$bin"/dfuhelper.sh
                        else
                            "$bin"/dfuhelper4.sh
                            sleep 5
                            "$bin"/irecovery -c "setenv auto-boot true"
                            "$bin"/irecovery -c "saveenv"
                            "$bin"/dfuhelper.sh
                        fi
                    elif [[ "$cpid" = 0x801* && "$deviceid" != *"iPad"* ]]; then
                        "$bin"/dfuhelper2.sh
                    else
                        "$bin"/dfuhelper3.sh
                    fi
                fi
            fi
            _wait_for_dfu
            sudo killall -STOP -c usbd
            read -p "[*] You may need to unplug and replug your cable, would you like to? " r1
            if [[ "$r1" == "yes" || "$r1" == "y" ]]; then
                read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
                echo "[*] Waiting 10 seconds before continuing.."
                sleep 10
            elif [[ "$r1" == "no" || "$r1" == "n" ]]; then
                echo "[*] Ok no problem, continuing.."
            else
                echo "[*] That was not a response I was expecting, I'm going to treat that as a 'yes'.."
                read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
                echo "[*] Waiting 10 seconds before continuing.."
                sleep 10
            fi
            if [[ "$version" == "7."* || "$version" == "8."* ]]; then
                if [ "$os" = "Darwin" ]; then
                    cd "$dir"/$deviceid/$cpid/ramdisk/8.4.1
                else
                    cd "$dir"/$deviceid/$cpid/ramdisk/11.4
                fi
            elif [[ "$version" == "10.3"* || "$version" == "11."* ||  "$version" == "12."* || "$version" == "13."* || "$version" == "14."* ]]; then
                cd "$dir"/$deviceid/$cpid/ramdisk/$r
            elif [[ "$os" = "Darwin" && ! "$deviceid" == "iPhone6"* && ! "$deviceid" == "iPhone7"* && ! "$deviceid" == "iPad4"* && ! "$deviceid" == "iPad5"* && ! "$deviceid" == "iPod7"* && "$version" == "9."* ]]; then
                cd "$dir"/$deviceid/$cpid/ramdisk/9.3
            else
                cd "$dir"/$deviceid/$cpid/ramdisk/11.4
            fi
            _boot_ramdisk $deviceid $replace $r
            cd "$dir"/
            read -p "[*] Press Enter once your device has fully booted into the SSH ramdisk. " r1
            echo "[*] Waiting 6 seconds before continuing.."
            sleep 6
            sudo killall -STOP -c usbd
            read -p "[*] You may need to unplug and replug your cable, would you like to? " r1
            if [[ "$r1" == "yes" || "$r1" == "y" ]]; then
                read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
                echo "[*] Waiting 10 seconds before continuing.."
                sleep 10
            elif [[ "$r1" == "no" || "$r1" == "n" ]]; then
                echo "[*] Ok no problem, continuing.."
            else
                echo "[*] That was not a response I was expecting, I'm going to treat that as a 'yes'.."
                read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
                echo "[*] Waiting 10 seconds before continuing.."
                sleep 10
            fi
            "$bin"/iproxy 2222 22 &
            if [ "$os" = "Darwin" ]; then
                echo "[*] /System/Library/Filesystems/apfs.fs/apfs_invert -d /dev/disk0s1 -s $systemdisk -n OS.dmg"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/System/Library/Filesystems/apfs.fs/apfs_invert -d /dev/disk0s1 -s $systemdisk -n OS.dmg"
            else
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount_apfs /dev/$systemfs /mnt4"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount_apfs /dev/$datafs /mnt5"
                disktomount="$("$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost '/usr/sbin/hdik /mnt5/OS.dmg' | tail -n 1 | cut -d ' ' -f 1)"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount_apfs -o ro $disktomount /mnt3"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "cp -av /mnt3/* /mnt4"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/sbin/hdik -e $disktomount"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf /mnt5/OS.dmg"
            fi
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount_apfs /dev/$systemfs /mnt4"
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount_apfs /dev/$datafs /mnt5"
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mv -v /mnt4/private/var/* /mnt5"
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt4/usr/local/standalone/firmware/Baseband"
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir /mnt5/keybags"
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt5/wireless/baseband_data"
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt4/private/xarts"
            if [[ "$version" == "13."* || "$version" == "14."* ]]; then
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt4/private/preboot"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt4" 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt5" 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "bash -c mount_filesystems" 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt4" 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt5" 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount_apfs /dev/$systemfs /mnt4"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount_apfs /dev/$datafs /mnt5"
            fi
            if [[ "$version" == "14."* ]]; then
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount_apfs /dev/$prebootfs /mnt4/private/preboot"
            fi
            if [[ "$version" == "13."* || "$version" == "14."* ]]; then
                has_active=$(remote_cmd "ls /mnt6/active" 2> /dev/null)
                if [ ! "$has_active" = "/mnt6/active" ]; then
                    echo "[!] Active file does not exist! Please use SSH to create it"
                    echo "    /mnt6/active should contain the name of the UUID in /mnt6"
                    echo "    When done, type reboot in the SSH session, then rerun the script"
                    echo "    ssh root@localhost -p 2222"
                    $("$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/reboot &" 2> /dev/null &)
                    _kill_if_running iproxy
                    exit 0
                fi
                active=$(remote_cmd "cat /mnt6/active" 2> /dev/null)
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "cp -na /mnt6/* /mnt4/private/preboot"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags -R noschg /mnt4/private/preboot/*"
                if [[ ! "$version" == "14."* ]]; then
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/aopfw.img4 root@localhost:/mnt4/private/preboot/$active/usr/standalone/firmware/FUD/AOP.img4
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags schg /mnt4/private/preboot/$active/usr/standalone/firmware/FUD/AOP.img4"
                else
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf /mnt4/private/preboot/$active/usr/standalone/firmware/FUD/AOP.img4"
                fi
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/homerfw.img4 root@localhost:/mnt4/private/preboot/$active/usr/standalone/firmware/FUD/Homer.img4
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/trustcache root@localhost:/mnt4/private/preboot/$active/usr/standalone/firmware/FUD/StaticTrustCache.img4
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/multitouch.img4 root@localhost:/mnt4/private/preboot/$active/usr/standalone/firmware/FUD/Multitouch.img4
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/audiocodecfirmware.img4 root@localhost:/mnt4/private/preboot/$active/usr/standalone/firmware/FUD/AudioCodecFirmware.img4
                if [[ "$version" == "13."* || "$version" == "14."* ]]; then
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/ispfw.img4 root@localhost:/mnt4/private/preboot/$active/usr/standalone/firmware/FUD/ISP.img4
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags schg /mnt4/private/preboot/$active/usr/standalone/firmware/FUD/ISP.img4"
                else
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf /mnt4/private/preboot/$active/usr/standalone/firmware/FUD/ISP.img4"
                fi
                # ios 15
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf /mnt4/private/preboot/$active/usr/standalone/firmware/FUD/AVE.img4"
                # stop ios from deleting our files
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags schg /mnt4/private/preboot/$active/usr/standalone/firmware/FUD/ISP.img4"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags schg /mnt4/private/preboot/$active/usr/standalone/firmware/FUD/Homer.img4"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags schg /mnt4/private/preboot/$active/usr/standalone/firmware/FUD/StaticTrustCache.img4"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags schg /mnt4/private/preboot/$active/usr/standalone/firmware/FUD/Multitouch.img4"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags schg /mnt4/private/preboot/$active/usr/standalone/firmware/FUD/AudioCodecFirmware.img4"
            fi
            if [[ "$version" == "14."* ]]; then
                if [[ "$cpid" == "0x8010" ]]; then
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mv /mnt4/private/preboot/$active /mnt4/private/preboot/5C6BAFFDE32FC78BA07810AB3C6CB2E6ED0321BA28A016A1C656CA0FC3262B8CE069EE451F3750F8DC5C15C2A152252F"
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "echo '5C6BAFFDE32FC78BA07810AB3C6CB2E6ED0321BA28A016A1C656CA0FC3262B8CE069EE451F3750F8DC5C15C2A152252F' > /mnt4/private/preboot/active"
                fi
            fi 
            if [[ ! "$r" == "16."* && ! "$r" == "17."* ]]; then
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -r -P 2222 "$dir"/$deviceid/0.0/keybags root@localhost:/mnt5
            fi
            if [ -e "$dir"/$deviceid/0.0/Baseband ]; then
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -r -P 2222 "$dir"/$deviceid/0.0/Baseband root@localhost:/mnt4/usr/local/standalone/firmware
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags -R schg /mnt4/usr/local/standalone/firmware/Baseband"
            fi
            "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/0.0/apticket.der root@localhost:/mnt4/System/Library/Caches/
            "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/0.0/sep-firmware.img4 root@localhost:/mnt4/usr/standalone/firmware/
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags schg /mnt4/usr/standalone/firmware/sep-firmware.img4"
            if [ -e "$dir"/$deviceid/0.0/FUD ]; then
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt4/usr/standalone/firmware/FUD"
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -r -P 2222 "$dir"/$deviceid/0.0/FUD/* root@localhost:/mnt4/usr/standalone/firmware/FUD
            fi
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rv /mnt4/System/Library/Caches/com.apple.factorydata"
            if [ -e "$dir"/$deviceid/0.0/com.apple.factorydata ]; then
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt4/System/Library/Caches/com.apple.factorydata"
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -r -P 2222 "$dir"/$deviceid/0.0/com.apple.factorydata/* root@localhost:/mnt4/System/Library/Caches/com.apple.factorydata
            fi
            if [ -e "$dir"/$deviceid/0.0/IC-Info.sisv ]; then
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt5/mobile/Library/FairPlay/iTunes_Control/iTunes/"
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/0.0/IC-Info.sisv root@localhost:/mnt5/mobile/Library/FairPlay/iTunes_Control/iTunes/IC-Info.sisv 2> /dev/null
            fi
            if [ -e "$dir"/$deviceid/0.0/com.apple.commcenter.device_specific_nobackup.plist ]; then
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt5/wireless/Library/Preferences/"
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/0.0/com.apple.commcenter.device_specific_nobackup.plist root@localhost:/mnt5/wireless/Library/Preferences/com.apple.commcenter.device_specific_nobackup.plist 2> /dev/null
            fi
            cp "$dir"/jb/fstab_apfs "$dir"/$deviceid/$cpid/$version/fstab.patched
            LC_ALL=C sed -i -e "s/mnt4/disk0s1s$systemdisk/g" "$dir"/$deviceid/$cpid/$version/fstab.patched
            LC_ALL=C sed -i -e "s/mnt5/disk0s1s$datadisk/g" "$dir"/$deviceid/$cpid/$version/fstab.patched
            "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/fstab.patched root@localhost:/mnt4/etc/fstab
            "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/data_ark.plist_ios10.tar root@localhost:/mnt5/
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "tar -xvf /mnt5/data_ark.plist_ios10.tar -C /mnt5"
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf /mnt5/data_ark.plist_ios10.tar"
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags schg /mnt5/root/Library/Lockdown/device_private_key.pem"
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags schg /mnt5/root/Library/Lockdown/device_public_key.pem"
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt5/root/Library/Lockdown/escrow_records"
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt5/root/Library/Lockdown/pair_records"
            "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt4/usr/libexec/mobileactivationd "$dir"/$deviceid/$cpid/$version/mobactivationd.raw
            if [[ ! -e "$dir"/$deviceid/0.0/activation_records/activation_record.plist || "$force_activation" == 1 ]]; then
                "$bin"/mobactivationd64patcher "$dir"/$deviceid/$cpid/$version/mobactivationd.raw "$dir"/$deviceid/$cpid/$version/mobactivationd.patched -b -c -d
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/mobactivationd.patched root@localhost:/mnt4/usr/libexec/mobileactivationd
            fi
            "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/kernelcache root@localhost:/mnt4/System/Library/Caches/com.apple.kernelcaches
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf /mnt4/usr/lib/libmis.dylib"
            if [[ ! "$version" == "14."* ]]; then
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/aopfw.img4 root@localhost:/mnt4/usr/standalone/firmware/FUD/AOP.img4
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags schg /mnt4/usr/standalone/firmware/FUD/AOP.img4"
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/homerfw.img4 root@localhost:/mnt4/usr/standalone/firmware/FUD/Homer.img4
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/trustcache root@localhost:/mnt4/usr/standalone/firmware/FUD/StaticTrustCache.img4
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/multitouch.img4 root@localhost:/mnt4/usr/standalone/firmware/FUD/Multitouch.img4
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/audiocodecfirmware.img4 root@localhost:/mnt4/usr/standalone/firmware/FUD/AudioCodecFirmware.img4
                if [[ "$version" == "13."* ]]; then
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/ispfw.img4 root@localhost:/mnt4/usr/standalone/firmware/FUD/ISP.img4
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags schg /mnt4/usr/standalone/firmware/FUD/ISP.img4"
                else
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf /mnt4/usr/standalone/firmware/FUD/ISP.img4"
                fi
                # ios 15
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf /mnt4/usr/standalone/firmware/FUD/AVE.img4"
                # stop ios from deleting our files
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags schg /mnt4/usr/standalone/firmware/FUD/ISP.img4"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags schg /mnt4/usr/standalone/firmware/FUD/Homer.img4"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags schg /mnt4/usr/standalone/firmware/FUD/StaticTrustCache.img4"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags schg /mnt4/usr/standalone/firmware/FUD/Multitouch.img4"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags schg /mnt4/usr/standalone/firmware/FUD/AudioCodecFirmware.img4"
            fi
            # fix stuck on apple logo after long progress bar
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf /mnt4/System/Library/DataClassMigrators/CoreLocationMigrator.migrator/"
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf /mnt4/System/Library/DataClassMigrators/PassbookDataMigrator.migrator/"
            if [[ -e "$dir"/$deviceid/0.0/activation_records && ! "$force_activation" == 1 ]]; then
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt5/root/Library/Lockdown/activation_records"
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -r -P 2222 "$dir"/$deviceid/0.0/activation_records/* root@localhost:/mnt5/root/Library/Lockdown/activation_records 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags -R schg /mnt5/root/Library/Lockdown/activation_records"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt5/mobile/Library/mad/activation_records"
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -r -P 2222 "$dir"/$deviceid/0.0/activation_records/* root@localhost:/mnt5/mobile/Library/mad/activation_records 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags -R schg /mnt5/mobile/Library/mad/activation_records"
            fi
            if [[ -e "$dir"/$deviceid/0.0/activation_records/activation_record.plist && ! "$force_activation" == 1 ]]; then
                if [ -e "$dir"/$deviceid/0.0/data_ark.plist ]; then
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/0.0/data_ark.plist root@localhost:/mnt5/root/Library/Lockdown/data_ark.plist 2> /dev/null
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags schg /mnt5/root/Library/Lockdown/data_ark.plist"
                fi
            fi
            if [[ "$r" == "16."* || "$r" == "17."* ]]; then
                echo "[*] Enabling fixkeybag and putting it where /usr/libexec/keybagd should be.."
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'cp /mnt4/usr/libexec/keybagd /mnt4/usr/libexec/keybagd.bak' 2> /dev/null
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/fixkeybag root@localhost:/mnt4/usr/libexec/keybagd 2> /dev/null
                echo "[*] Done"
            fi
            if [[ "$version" == "10."* ]]; then
                if [[ "$appleinternal" == 1 ]]; then
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/AppleInternal.tar root@localhost:/mnt4/
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/PrototypeTools.framework_ios10.tar root@localhost:/mnt4/
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt4/System/Library/CoreServices/SystemVersion.plist "$dir"/$deviceid/$cpid/$version/SystemVersion.plist
                    LC_ALL=C sed -i -e 's/<\/dict>/<key>ReleaseType<\/key><string>Internal<\/string><key>ProductType<\/key><string>Internal<\/string><\/dict>/g' "$dir"/$deviceid/$cpid/$version/SystemVersion.plist
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/SystemVersion.plist root@localhost:/mnt4/System/Library/CoreServices/SystemVersion.plist
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/SpringBoard-Internal.strings root@localhost:/mnt4/System/Library/CoreServices/SpringBoard.app/en.lproj/
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/SpringBoard-Internal.strings root@localhost:/mnt4/System/Library/CoreServices/SpringBoard.app/en_GB.lproj/
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/com.apple.springboard_ios10.plist root@localhost:/mnt5/mobile/Library/Preferences/com.apple.springboard.plist
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'tar -xvf /mnt4/PrototypeTools.framework_ios10.tar -C /mnt4/System/Library/PrivateFrameworks/'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost '/usr/sbin/chown -R root:wheel /mnt4/System/Library/PrivateFrameworks/PrototypeTools.framework'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt4/PrototypeTools.framework_ios10.tar'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'tar -xvf /mnt4/AppleInternal.tar -C /mnt4/'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost '/usr/sbin/chown -R root:wheel /mnt4/AppleInternal/'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt4/AppleInternal.tar'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt5/mobile/Library/Caches/com.apple.MobileGestalt.plist'
                fi
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/Meridian.app.tar.gz root@localhost:/mnt4/
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'tar --preserve-permissions -xzvf /mnt4/Meridian.app.tar.gz -C /mnt4/Applications' 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt4/Meridian.app.tar.gz' 2> /dev/null
                if [[ ! "$deviceid" == "iPad"* ]]; then
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/UnlimFileManager.app.tar.gz root@localhost:/mnt4/
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'tar --preserve-permissions -xzvf /mnt4/UnlimFileManager.app.tar.gz -C /mnt4/Applications' 2> /dev/null
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost '/usr/sbin/chown -R root:wheel /mnt4/Applications/UnlimFileManager.app'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt4/UnlimFileManager.app.tar.gz' 2> /dev/null
                fi
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'mkdir -p /mnt5/mobile/Library/Preferences' 2> /dev/null
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/com.apple.Accessibility.Collection.plist root@localhost:/mnt5/mobile/Library/Preferences/com.apple.Accessibility.Collection.plist
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/com.apple.Accessibility.plist root@localhost:/mnt5/mobile/Library/Preferences/com.apple.Accessibility.plist
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt4/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64 "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.raw 2> /dev/null
                "$bin"/dsc64patcher "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.raw "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.patched -103
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.patched root@localhost:/mnt4/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64 2> /dev/null
                #"$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'cp /mnt4/usr/libexec/keybagd /mnt4/usr/libexec/keybagd.bak' 2> /dev/null
                #"$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/fixkeybag root@localhost:/mnt4/usr/libexec/keybagd 2> /dev/null
            elif [[ "$version" == "11."* ]]; then
                if [[ "$appleinternal" == 1 ]]; then
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/AppleInternal.tar root@localhost:/mnt4/
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/PrototypeTools.framework_ios11.tar root@localhost:/mnt4/
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt4/System/Library/CoreServices/SystemVersion.plist "$dir"/$deviceid/$cpid/$version/SystemVersion.plist
                    LC_ALL=C sed -i -e 's/<\/dict>/<key>ReleaseType<\/key><string>Internal<\/string><key>ProductType<\/key><string>Internal<\/string><\/dict>/g' "$dir"/$deviceid/$cpid/$version/SystemVersion.plist
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/SystemVersion.plist root@localhost:/mnt4/System/Library/CoreServices/SystemVersion.plist
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/SpringBoard-Internal.strings root@localhost:/mnt4/System/Library/CoreServices/SpringBoard.app/en.lproj/
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/SpringBoard-Internal.strings root@localhost:/mnt4/System/Library/CoreServices/SpringBoard.app/en_GB.lproj/
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/com.apple.springboard_ios10.plist root@localhost:/mnt5/mobile/Library/Preferences/com.apple.springboard.plist
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'tar -xvf /mnt4/PrototypeTools.framework_ios11.tar -C /mnt4/System/Library/PrivateFrameworks/'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost '/usr/sbin/chown -R root:wheel /mnt4/System/Library/PrivateFrameworks/PrototypeTools.framework'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt4/PrototypeTools.framework_ios11.tar'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'tar -xvf /mnt4/AppleInternal.tar -C /mnt4/'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost '/usr/sbin/chown -R root:wheel /mnt4/AppleInternal/'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt4/AppleInternal.tar'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt5/mobile/Library/Caches/com.apple.MobileGestalt.plist'
                fi
                if [[ "$r" == "16."* || "$r" == "17."* ]]; then
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/Undecimus.app_disk0s1s9.tar.gz root@localhost:/mnt4/
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "tar -xzvf /mnt4/Undecimus.app_disk0s1s9.tar.gz -C /mnt4/Applications/"
                else
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/Undecimus.app_disk0s1s8.tar.gz root@localhost:/mnt4/
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "tar -xzvf /mnt4/Undecimus.app_disk0s1s8.tar.gz -C /mnt4/Applications/"
                fi
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost '/usr/sbin/chown -R root:wheel /mnt4/Applications/Undecimus.app'
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf /mnt4/System/Library/DataClassMigrators/SystemAppMigrator.migrator/"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mv -v /mnt5/staged_system_apps/* /mnt4/Applications"
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/com.apple.Accessibility.Collection.plist root@localhost:/mnt5/mobile/Library/Preferences/com.apple.Accessibility.Collection.plist
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/com.apple.Accessibility.plist root@localhost:/mnt5/mobile/Library/Preferences/com.apple.Accessibility.plist
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/Certificates.bundle.tar.gz root@localhost:/mnt4/
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'tar --preserve-permissions -xzvf /mnt4/Certificates.bundle.tar.gz -C /mnt4/' 2> /dev/null
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt4/System/Library/Security/Certificates.bundle/Info.plist "$dir"/$deviceid/$cpid/$version/Info.plist 2> /dev/null
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
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/Info.plist root@localhost:/mnt4/System/Library/Security/Certificates.bundle/Info.plist 2> /dev/null
                if [[ "$version" == "11.3"* || "$version" == "11.4"* ]]; then
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt4/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64 "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.raw 2> /dev/null
                    "$bin"/dsc64patcher "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.raw "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.patched -113
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.patched root@localhost:/mnt4/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64 2> /dev/null
                else
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt4/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64 "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.raw 2> /dev/null
                    "$bin"/dsc64patcher "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.raw "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.patched -11
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.patched root@localhost:/mnt4/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64 2> /dev/null
                    if [[ -e "$dir"/$deviceid/0.0/activation_records/activation_record.plist ]]; then
                        # [*] Alert
                        # [*] If you boot now, you will get stuck at the \"screen time\" step in Setup.app
                        # [*] You must delete Setup.app if you want to be able to use iOS $1
                        # [*] See https://files.catbox.moe/96vhbl.mov for a video demonstration of the issue
                        # [*] You will only see this message if activation_records are present for your device
                        # Would you like to delete Setup.app? [y/n]:
                        "$bin"/setuphelper.sh $version
                    fi
                fi
            elif [[ "$version" == "12."* ]]; then
                if [[ "$appleinternal" == 1 ]]; then
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/AppleInternal.tar root@localhost:/mnt4/
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/PrototypeTools.framework_ios12.tar root@localhost:/mnt4/
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt4/System/Library/CoreServices/SystemVersion.plist "$dir"/$deviceid/$cpid/$version/SystemVersion.plist
                    LC_ALL=C sed -i -e 's/<\/dict>/<key>ReleaseType<\/key><string>Internal<\/string><key>ProductType<\/key><string>Internal<\/string><\/dict>/g' "$dir"/$deviceid/$cpid/$version/SystemVersion.plist
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/SystemVersion.plist root@localhost:/mnt4/System/Library/CoreServices/SystemVersion.plist
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/SpringBoard-Internal.strings root@localhost:/mnt4/System/Library/CoreServices/SpringBoard.app/en.lproj/
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/SpringBoard-Internal.strings root@localhost:/mnt4/System/Library/CoreServices/SpringBoard.app/en_GB.lproj/
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/com.apple.springboard_ios10.plist root@localhost:/mnt5/mobile/Library/Preferences/com.apple.springboard.plist
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'tar -xvf /mnt4/PrototypeTools.framework_ios12.tar -C /mnt4/System/Library/PrivateFrameworks/'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost '/usr/sbin/chown -R root:wheel /mnt4/System/Library/PrivateFrameworks/PrototypeTools.framework'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt4/PrototypeTools.framework_ios12.tar'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'tar -xvf /mnt4/AppleInternal.tar -C /mnt4/'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost '/usr/sbin/chown -R root:wheel /mnt4/AppleInternal/'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt4/AppleInternal.tar'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt5/mobile/Library/Caches/com.apple.MobileGestalt.plist'
                fi
                if [[ "$r" == "16."* || "$r" == "17."* ]]; then
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/Undecimus.app_disk0s1s9.tar.gz root@localhost:/mnt4/
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "tar -xzvf /mnt4/Undecimus.app_disk0s1s9.tar.gz -C /mnt4/Applications/"
                else
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/Undecimus.app_disk0s1s8.tar.gz root@localhost:/mnt4/
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "tar -xzvf /mnt4/Undecimus.app_disk0s1s8.tar.gz -C /mnt4/Applications/"
                fi
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf /mnt4/System/Library/DataClassMigrators/SystemAppMigrator.migrator/"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mv -v /mnt5/staged_system_apps/* /mnt4/Applications"
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/com.apple.Accessibility.Collection.plist root@localhost:/mnt5/mobile/Library/Preferences/com.apple.Accessibility.Collection.plist
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/com.apple.Accessibility.plist root@localhost:/mnt5/mobile/Library/Preferences/com.apple.Accessibility.plist
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/Certificates.bundle.tar.gz root@localhost:/mnt4/
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'tar --preserve-permissions -xzvf /mnt4/Certificates.bundle.tar.gz -C /mnt4/' 2> /dev/null
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt4/System/Library/Security/Certificates.bundle/Info.plist "$dir"/$deviceid/$cpid/$version/Info.plist 2> /dev/null
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
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt4/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64 "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.raw 2> /dev/null
                "$bin"/dsc64patcher "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.raw "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.patched -12
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.patched root@localhost:/mnt4/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64 2> /dev/null
                if [[ -e "$dir"/$deviceid/0.0/activation_records/activation_record.plist ]]; then
                    # [*] Alert
                    # [*] If you boot now, you will get stuck at the \"screen time\" step in Setup.app
                    # [*] You must delete Setup.app if you want to be able to use iOS $1
                    # [*] See https://files.catbox.moe/96vhbl.mov for a video demonstration of the issue
                    # [*] You will only see this message if activation_records are present for your device
                    # Would you like to delete Setup.app? [y/n]:
                    "$bin"/setuphelper.sh $version
                fi
            elif [[ "$version" == "13."* ]]; then
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf /mnt4/System/Library/DataClassMigrators/SystemAppMigrator.migrator/"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mv -v /mnt5/staged_system_apps/* /mnt4/Applications"
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/com.apple.Accessibility.Collection.plist root@localhost:/mnt5/mobile/Library/Preferences/com.apple.Accessibility.Collection.plist
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/com.apple.Accessibility.plist root@localhost:/mnt5/mobile/Library/Preferences/com.apple.Accessibility.plist
                #"$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt4/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64 "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.raw 2> /dev/null
                #if [[ "$version" == "13.0"* || "$version" == "13.1"* || "$version" == "13.2"* || "$version" == "13.3"* ]]; then
                #    "$bin"/dsc64patcher "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.raw "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.patched -13
                #else
                #    "$bin"/dsc64patcher "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.raw "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.patched -134
                #fi
                #"$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.patched root@localhost:/mnt4/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mv /mnt4/sbin/fsck /mnt4/sbin/fsckBackup"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mv /mnt4/System/Library/Filesystems/apfs.fs /mnt4/System/Library/Filesystems/apfs.fsBackup"
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/apfs.fs_ios14.tar.gz root@localhost:/mnt4/
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "tar -xzvf /mnt4/apfs.fs_ios14.tar.gz -C /mnt4"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf /mnt4/apfs.fs_ios14.tar.gz"
            elif [[ "$version" == "14."* ]]; then
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf /mnt4/System/Library/DataClassMigrators/SystemAppMigrator.migrator/"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mv -v /mnt5/staged_system_apps/* /mnt4/Applications"
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/com.apple.Accessibility.Collection.plist root@localhost:/mnt5/mobile/Library/Preferences/com.apple.Accessibility.Collection.plist
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/com.apple.Accessibility.plist root@localhost:/mnt5/mobile/Library/Preferences/com.apple.Accessibility.plist
                #"$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt4/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64 "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.raw 2> /dev/null
                #"$bin"/dsc64patcher "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.raw "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.patched -14
                #"$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/dyld_shared_cache_arm64.patched root@localhost:/mnt4/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64 2> /dev/null
            fi
            if [[ "$deviceid" == "iPhone10"* || "$cpid" == "0x8015"* ]]; then
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/sbin/nvram auto-boot=false" 2> /dev/null
                pongo=0
            fi
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt3" 2> /dev/null
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt4" 2> /dev/null
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt5" 2> /dev/null
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "bash -c mount_filesystems" 2> /dev/null
            #"$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/sbin/nvram oblit-inprogress=5"
        else
            if [[ "$dualboot_hfs" == 1 ]]; then
                remote_cmd "/sbin/mount -w -t hfs /dev/disk0s1s4 /mnt4 2> /dev/null" && {
                    echo "[*] /dev/disk0s1s4 already exists and is hfs, skipping apfs to hfs code.."
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt4" 2> /dev/null
                    sleep 2
                } || {
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "cat /gpt_hfs_dualboot.txt | gptfdisk /dev/rdisk0s1" 2> /dev/null
                    sleep 2
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/bin/sync" 2> /dev/null
                    sleep 1
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/bin/sync" 2> /dev/null
                    sleep 1
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/bin/sync" 2> /dev/null
                    sleep 1
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/newfs_hfs -s -v System -J -b 4096 -n a=4096,c=4096,e=4096 /dev/disk0s1s1"
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/newfs_hfs -s -v Data -J -b 4096 -n a=4096,c=4096,e=4096 /dev/disk0s1s2"
                }
            else
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "cat /gpt.txt | gptfdisk /dev/rdisk0s1" 2> /dev/null
                sleep 2
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/bin/sync" 2> /dev/null
                sleep 1
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/bin/sync" 2> /dev/null
                sleep 1
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/bin/sync" 2> /dev/null
                sleep 1
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/newfs_hfs -s -v System -J -b 4096 -n a=4096,c=4096,e=4096 /dev/disk0s1s1"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/newfs_hfs -s -v Data -J -b 4096 -n a=4096,c=4096,e=4096 /dev/disk0s1s2"
            fi
            if [[ "$dualboot_hfs" == 1 ]]; then
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/newfs_hfs -s -v SystemX -J -b 4096 -n a=4096,c=4096,e=4096 /dev/disk0s1s3"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/newfs_hfs -s -v DataX -J -b 4096 -n a=4096,c=4096,e=4096 /dev/disk0s1s4"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount -w -t hfs /dev/disk0s1s1 /mnt1" 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount -w -t hfs /dev/disk0s1s2 /mnt2" 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount -w -t hfs /dev/disk0s1s3 /mnt3" 2> /dev/null
                if [[ ! "$hit" == 1 ]]; then
                    echo "[*] Uploading "$dir"/$deviceid/0.0/mnt1.tar.gz, this may take up to 10 minutes.."
                    "$bin"/pv "$dir"/$deviceid/0.0/mnt1.tar.gz | "$bin"/sshpass -p "alpine" ssh -p2222 root@localhost 'cat | tar xz -C /'
                    echo "[*] Uploading "$dir"/jb/var.tar.gz, this may take up to 1 minute.."
                    "$bin"/pv "$dir"/jb/var.tar.gz | "$bin"/sshpass -p "alpine" ssh -p2222 root@localhost 'cat | tar xz -C /mnt1/private/var'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mv -v /mnt1/private/var/* /mnt2"
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt2/keybags"
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf /mnt2/log/asl/SweepStore" 2> /dev/null
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf /mnt2/mobile/Library/PreinstalledAssets/*" 2> /dev/null
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf /mnt2/mobile/Library/Preferences/.GlobalPreferences.plist" 2> /dev/null
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf /mnt2/mobile/.forward" 2> /dev/null
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt1/usr/standalone/firmware/FUD/AOP.img4 "$dir"/AOP.img4 2> /dev/null
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf /mnt1/usr/standalone/firmware/FUD/AOP.img4" 2> /dev/null
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/fstab root@localhost:/mnt1/etc/ 2> /dev/null
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt2/wireless/baseband_data"
                    #if [ -e "$dir"/$deviceid/0.0/mnt3.tar.gz ]; then
                    #    "$bin"/pv "$dir"/$deviceid/0.0/mnt3.tar.gz | "$bin"/sshpass -p "alpine" ssh -p2222 root@localhost 'cat | tar xz -C /mnt2/wireless/baseband_data'
                    #fi
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt2" 2> /dev/null
                    echo "[*] Enabling NoMoreSIGABRT on /dev/disk0s1s2.."
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost '/bin/dd if=/dev/disk0s1s2 of=/mnt1/out.img bs=512 count=8192'
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt1/out.img "$dir"/$deviceid/$cpid/$version/NoMoreSIGABRT.img
                    "$bin"/Kernel64Patcher "$dir"/$deviceid/$cpid/$version/NoMoreSIGABRT.img "$dir"/$deviceid/$cpid/$version/NoMoreSIGABRT.patched -n
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/NoMoreSIGABRT.patched root@localhost:/mnt1/out.img
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost '/bin/dd if=/mnt1/out.img of=/dev/disk0s1s2 bs=512 count=8192'
                    echo "[*] Done"
                    echo "[*] Enabling fixkeybag and putting it where /usr/libexec/keybagd should be.."
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'cp /mnt1/usr/libexec/keybagd /mnt1/usr/libexec/keybagd.bak' 2> /dev/null
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/fixkeybag.bak root@localhost:/mnt1/usr/libexec/keybagd 2> /dev/null
                    echo "[*] Done"
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt3/mnt1.tar.gz' 2> /dev/null
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt3/var.tar.gz' 2> /dev/null
                fi
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt1" 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt2" 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt3" 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount_hfs /dev/disk0s1s3 /mnt1" 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount -w -t hfs -o suid,dev /dev/disk0s1s4 /mnt2" 2> /dev/null
            else
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount_hfs /dev/disk0s1s1 /mnt1" 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount -w -t hfs -o suid,dev /dev/disk0s1s2 /mnt2" 2> /dev/null
            fi
            echo "[*] Uploading $dir/$deviceid/$cpid/$version/OS.tar, this may take up to 10 minutes.."
            if [ "$os" = "Darwin" ]; then
                "$bin"/pv "$dir"/$deviceid/$cpid/$version/OS.tar | "$bin"/sshpass -p "alpine" ssh -p2222 root@localhost 'cat | tar x -C /mnt1'
            else
                "$bin"/sshpass -p 'alpine' scp -o StrictHostKeyChecking=no -P 2222 -v "$dir"/$deviceid/$cpid/$version/rw.dmg root@localhost:/mnt2
                disktomount="$("$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost '/usr/sbin/hdik /mnt2/rw.dmg' | tail -n 1 | cut -d ' ' -f 1)"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount_hfs -o ro $disktomount /mnt3"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "cp -av /mnt3/* /mnt1"
                if [[ "$version" == "7."* || "$version" == "8."* ]]; then
                    $("$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/reboot &" 2> /dev/null &)
                    sleep 5
                    _kill_if_running iproxy
                    echo "[*] Device should boot to Recovery mode. Please wait..."
                    if [ "$os" = "Darwin" ]; then
                        if ! (system_profiler SPUSBDataType 2> /dev/null | grep ' Apple Mobile Device (DFU Mode)' >> /dev/null); then
                            if [[ "$deviceid" == "iPhone10"* || "$cpid" == "0x8015"* ]]; then
                                sleep 10
                                if [ "$(get_device_mode)" = "recovery" ]; then
                                    "$bin"/irecovery -c "setenv auto-boot true"
                                    "$bin"/irecovery -c "saveenv"
                                    "$bin"/dfuhelper.sh
                                else
                                    "$bin"/dfuhelper4.sh
                                    sleep 5
                                    "$bin"/irecovery -c "setenv auto-boot true"
                                    "$bin"/irecovery -c "saveenv"
                                    "$bin"/dfuhelper.sh
                                fi
                            elif [[ "$cpid" = 0x801* && "$deviceid" != *"iPad"* ]]; then
                                "$bin"/dfuhelper2.sh
                            else
                                "$bin"/dfuhelper3.sh
                            fi
                        fi
                    else
                        if ! (lsusb | cut -d' ' -f6 | grep '05ac:' | cut -d: -f2 | grep 1227 >> /dev/null); then
                            if [[ "$deviceid" == "iPhone10"* || "$cpid" == "0x8015"* ]]; then
                                sleep 10
                                if [ "$(get_device_mode)" = "recovery" ]; then
                                    "$bin"/irecovery -c "setenv auto-boot true"
                                    "$bin"/irecovery -c "saveenv"
                                    "$bin"/dfuhelper.sh
                                else
                                    "$bin"/dfuhelper4.sh
                                    sleep 5
                                    "$bin"/irecovery -c "setenv auto-boot true"
                                    "$bin"/irecovery -c "saveenv"
                                    "$bin"/dfuhelper.sh
                                fi
                            elif [[ "$cpid" = 0x801* && "$deviceid" != *"iPad"* ]]; then
                                "$bin"/dfuhelper2.sh
                            else
                                "$bin"/dfuhelper3.sh
                            fi
                        fi
                    fi
                    _wait_for_dfu
                    sudo killall -STOP -c usbd
                    read -p "[*] You may need to unplug and replug your cable, would you like to? " r1
                    if [[ "$r1" == "yes" || "$r1" == "y" ]]; then
                        read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
                        echo "[*] Waiting 10 seconds before continuing.."
                        sleep 10
                    elif [[ "$r1" == "no" || "$r1" == "n" ]]; then
                        echo "[*] Ok no problem, continuing.."
                    else
                        echo "[*] That was not a response I was expecting, I'm going to treat that as a 'yes'.."
                        read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
                        echo "[*] Waiting 10 seconds before continuing.."
                        sleep 10
                    fi
                    if [[ "$version" == "7."* || "$version" == "8."* ]]; then
                        cd "$dir"/$deviceid/$cpid/ramdisk/8.4.1
                    elif [[ "$version" == "10.3"* || "$version" == "11."* ||  "$version" == "12."* || "$version" == "13."* || "$version" == "14."* ]]; then
                        cd "$dir"/$deviceid/$cpid/ramdisk/$r
                    elif [[ "$os" = "Darwin" && ! "$deviceid" == "iPhone6"* && ! "$deviceid" == "iPhone7"* && ! "$deviceid" == "iPad4"* && ! "$deviceid" == "iPad5"* && ! "$deviceid" == "iPod7"* && "$version" == "9."* ]]; then
                        cd "$dir"/$deviceid/$cpid/ramdisk/9.3
                    else
                        cd "$dir"/$deviceid/$cpid/ramdisk/11.4
                    fi
                    _boot_ramdisk $deviceid $replace $r
                    cd "$dir"/
                    read -p "[*] Press Enter once your device has fully booted into the SSH ramdisk. " r1
                    echo "[*] Waiting 6 seconds before continuing.."
                    sleep 6
                    sudo killall -STOP -c usbd
                    read -p "[*] You may need to unplug and replug your cable, would you like to? " r1
                    if [[ "$r1" == "yes" || "$r1" == "y" ]]; then
                        read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
                        echo "[*] Waiting 10 seconds before continuing.."
                        sleep 10
                    elif [[ "$r1" == "no" || "$r1" == "n" ]]; then
                        echo "[*] Ok no problem, continuing.."
                    else
                        echo "[*] That was not a response I was expecting, I'm going to treat that as a 'yes'.."
                        read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
                        echo "[*] Waiting 10 seconds before continuing.."
                        sleep 10
                    fi
                    "$bin"/iproxy 2222 22 &
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost '/sbin/fsck'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount_hfs /dev/disk0s1s1 /mnt1" 2> /dev/null
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount -w -t hfs -o suid,dev /dev/disk0s1s2 /mnt2" 2> /dev/null
                fi
            fi
            if [[ "$version" == "7."* || "$version" == "8."* ]]; then
                "$bin"/sshpass -p 'alpine' scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/cydia_ios7.tar.gz root@localhost:/mnt2 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "tar -xzvf /mnt2/cydia_ios7.tar.gz -C /mnt1"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf /mnt2/cydia_ios7.tar.gz" 2> /dev/null
            fi
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mv -v /mnt1/private/var/* /mnt2"
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt1/usr/local/standalone/firmware/Baseband" 2> /dev/null
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir /mnt2/keybags" 2> /dev/null
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt2/wireless/baseband_data" 2> /dev/null
            if [[ "$fuck" == 1 || "$r" == "16."* || "$r" == "17."* ]]; then
                echo "[*] Enabling fixkeybag and putting it where /usr/libexec/keybagd should be.."
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'cp /mnt1/usr/libexec/keybagd /mnt1/usr/libexec/keybagd.bak' 2> /dev/null
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/fixkeybag root@localhost:/mnt1/usr/libexec/keybagd 2> /dev/null
                echo "[*] Done"
            else
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -r -P 2222 "$dir"/$deviceid/0.0/keybags root@localhost:/mnt2 2> /dev/null
            fi
            if [ -e "$dir"/$deviceid/0.0/Baseband ]; then
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -r -P 2222 "$dir"/$deviceid/0.0/Baseband root@localhost:/mnt1/usr/local/standalone/firmware 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags -R schg /mnt1/usr/local/standalone/firmware/Baseband"
            fi
            "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/0.0/apticket.der root@localhost:/mnt1/System/Library/Caches/ 2> /dev/null
            "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/0.0/sep-firmware.img4 root@localhost:/mnt1/usr/standalone/firmware/ 2> /dev/null
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags schg /mnt1/usr/standalone/firmware/sep-firmware.img4"
            if [ -e "$dir"/$deviceid/0.0/FUD ]; then
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir /mnt1/usr/standalone/firmware/FUD"
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -r -P 2222 "$dir"/$deviceid/0.0/FUD/* root@localhost:/mnt1/usr/standalone/firmware/FUD
            fi
            if [ -e "$dir"/$deviceid/0.0/com.apple.factorydata ]; then
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir /mnt1/System/Library/Caches/com.apple.factorydata"
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -r -P 2222 "$dir"/$deviceid/0.0/com.apple.factorydata/* root@localhost:/mnt1/System/Library/Caches/com.apple.factorydata 2> /dev/null
            fi
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
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags schg /mnt2/root/Library/Lockdown/device_private_key.pem"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags schg /mnt2/root/Library/Lockdown/device_public_key.pem"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt2/root/Library/Lockdown/escrow_records"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt2/root/Library/Lockdown/pair_records"
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt1/usr/libexec/mobileactivationd "$dir"/$deviceid/$cpid/$version/mobactivationd.raw
                if [[ ! -e "$dir"/$deviceid/0.0/activation_records/activation_record.plist || "$force_activation" == 1 ]]; then
                    "$bin"/mobactivationd64patcher "$dir"/$deviceid/$cpid/$version/mobactivationd.raw "$dir"/$deviceid/$cpid/$version/mobactivationd.patched -b -c -d
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/mobactivationd.patched root@localhost:/mnt1/usr/libexec/mobileactivationd
                fi
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/com.saurik.Cydia.Startup.plist root@localhost:/mnt1/System/Library/LaunchDaemons
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/sbin/chown root:wheel /mnt1/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist"
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
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/System/Library/DataClassMigrators/MobileNotes.migrator/' 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/System/Library/DataClassMigrators/MobileSlideShow.migrator/' 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/System/Library/DataClassMigrators/HealthMigrator.migrator/' 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/System/Library/DataClassMigrators/rolldMigrator.migrator//' 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/System/Library/DataClassMigrators/BuddyMigrator.migrator/' 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/System/Library/DataClassMigrators/Calendar.migrator/' 2> /dev/null
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/aopfw.img4 root@localhost:/mnt1/usr/standalone/firmware/FUD/AOP.img4
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/homerfw.img4 root@localhost:/mnt1/usr/standalone/firmware/FUD/Homer.img4
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/avefw.img4 root@localhost:/mnt1/usr/standalone/firmware/FUD/AVE.img4
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/trustcache root@localhost:/mnt1/usr/standalone/firmware/FUD/StaticTrustCache.img4
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/multitouch.img4 root@localhost:/mnt1/usr/standalone/firmware/FUD/Multitouch.img4
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/audiocodecfirmware.img4 root@localhost:/mnt1/usr/standalone/firmware/FUD/AudioCodecFirmware.img4
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags schg /mnt1/usr/standalone/firmware/FUD/AOP.img4"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags schg /mnt1/usr/standalone/firmware/FUD/Homer.img4"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags schg /mnt1/usr/standalone/firmware/FUD/AVE.img4"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags schg /mnt1/usr/standalone/firmware/FUD/StaticTrustCache.img4"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags schg /mnt1/usr/standalone/firmware/FUD/Multitouch.img4"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags schg /mnt1/usr/standalone/firmware/FUD/AudioCodecFirmware.img4"
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
            if [[ "$dualboot_hfs" == 1 ]]; then
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "sed -i -e 's/disk0s1s1/disk0s1s3/g' /mnt1/etc/fstab"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "sed -i -e 's/disk0s1s2/disk0s1s4/g' /mnt1/etc/fstab"
            fi
            "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/com.apple.Accessibility.Collection.plist root@localhost:/mnt2/mobile/Library/Preferences/com.apple.Accessibility.Collection.plist
            "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/com.apple.Accessibility.plist root@localhost:/mnt2/mobile/Library/Preferences/com.apple.Accessibility.plist
            if [[ -e "$dir"/$deviceid/0.0/activation_records/activation_record.plist && ! "$force_activation" == 1 ]]; then
                if [ -e "$dir"/$deviceid/0.0/data_ark.plist ]; then
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/0.0/data_ark.plist root@localhost:/mnt2/root/Library/Lockdown/data_ark.plist 2> /dev/null
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags schg /mnt2/root/Library/Lockdown/data_ark.plist"
                fi
            fi
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags -R schg /mnt1/usr/standalone/firmware/FUD"
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf /mnt1/usr/lib/libmis.dylib" 2> /dev/null
            if [[ "$version" == "9."* ]]; then
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/sbin/nvram -c" 2> /dev/null
            fi
            if [[ "$dualboot_hfs" == 1 && ! "$hit" == 1 ]]; then
                _download_clean_boot_files $deviceid $replace $r
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/sbin/nvram auto-boot=false" 2> /dev/null
                $("$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/reboot &" 2> /dev/null &)
                echo "[*] Step 1 of dualbooting to iOS $version is now done"
                echo "[*] The device should now boot into recovery mode"
                echo "[*] Please follow the on screen instructions to put your device back into dfu mode"
                echo "[*] We will try to boot iOS $r to generate new keybags for your device"
                sleep 5
                _kill_if_running iproxy
                if [ "$os" = "Darwin" ]; then
                    if ! (system_profiler SPUSBDataType 2> /dev/null | grep ' Apple Mobile Device (DFU Mode)' >> /dev/null); then
                        if [[ "$deviceid" == "iPhone10"* || "$cpid" == "0x8015"* ]]; then
                            sleep 10
                            if [ "$(get_device_mode)" = "recovery" ]; then
                                "$bin"/dfuhelper.sh
                            else
                                "$bin"/dfuhelper4.sh
                                sleep 5
                                "$bin"/irecovery -c "setenv auto-boot false"
                                "$bin"/irecovery -c "saveenv"
                                "$bin"/dfuhelper.sh
                            fi
                        elif [[ "$cpid" = 0x801* && "$deviceid" != *"iPad"* ]]; then
                            "$bin"/dfuhelper2.sh
                        else
                            "$bin"/dfuhelper3.sh
                        fi
                    fi
                else
                    if ! (lsusb | cut -d' ' -f6 | grep '05ac:' | cut -d: -f2 | grep 1227 >> /dev/null); then
                        if [[ "$deviceid" == "iPhone10"* || "$cpid" == "0x8015"* ]]; then
                            sleep 10
                            if [ "$(get_device_mode)" = "recovery" ]; then
                                "$bin"/dfuhelper.sh
                            else
                                "$bin"/dfuhelper4.sh
                                sleep 5
                                "$bin"/irecovery -c "setenv auto-boot false"
                                "$bin"/irecovery -c "saveenv"
                                "$bin"/dfuhelper.sh
                            fi
                        elif [[ "$cpid" = 0x801* && "$deviceid" != *"iPad"* ]]; then
                            "$bin"/dfuhelper2.sh
                        else
                            "$bin"/dfuhelper3.sh
                        fi
                    fi
                fi
                _wait_for_dfu
                sudo killall -STOP -c usbd
                read -p "[*] You may need to unplug and replug your cable, would you like to? " r1
                if [[ "$r1" == "yes" || "$r1" == "y" ]]; then
                    read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
                    echo "[*] Waiting 10 seconds before continuing.."
                    sleep 10
                elif [[ "$r1" == "no" || "$r1" == "n" ]]; then
                    echo "[*] Ok no problem, continuing.."
                else
                    echo "[*] That was not a response I was expecting, I'm going to treat that as a 'yes'.."
                    read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
                    echo "[*] Waiting 10 seconds before continuing.."
                    sleep 10
                fi
                cd "$dir"/$deviceid/clean/$cpid/$r
                _boot
                cd "$dir"/
                echo "[*] Step 2 of dualbooting to iOS $version is now done"
                echo '[*] The device should now show a bunch of AppleKeyStore: operation failed (pid: %d sel: %d ret: %x)'
                echo "[*] Please follow the on screen instructions to put your device back into dfu mode"
                echo "[*] We will then boot into a ramdisk to fixup iOS $r to allow it to be booted again as normal"
                sleep 5
                if [ "$os" = "Darwin" ]; then
                    if ! (system_profiler SPUSBDataType 2> /dev/null | grep ' Apple Mobile Device (DFU Mode)' >> /dev/null); then
                        if [[ "$deviceid" == "iPhone10"* || "$cpid" == "0x8015"* ]]; then
                            sleep 10
                            if [ "$(get_device_mode)" = "recovery" ]; then
                                "$bin"/dfuhelper.sh
                            else
                                "$bin"/dfuhelper4.sh
                                sleep 5
                                "$bin"/irecovery -c "setenv auto-boot false"
                                "$bin"/irecovery -c "saveenv"
                                "$bin"/dfuhelper.sh
                            fi
                        elif [[ "$cpid" = 0x801* && "$deviceid" != *"iPad"* ]]; then
                            "$bin"/dfuhelper2.sh
                        else
                            "$bin"/dfuhelper3.sh
                        fi
                    fi
                else
                    if ! (lsusb | cut -d' ' -f6 | grep '05ac:' | cut -d: -f2 | grep 1227 >> /dev/null); then
                        if [[ "$deviceid" == "iPhone10"* || "$cpid" == "0x8015"* ]]; then
                            sleep 10
                            if [ "$(get_device_mode)" = "recovery" ]; then
                                "$bin"/dfuhelper.sh
                            else
                                "$bin"/dfuhelper4.sh
                                sleep 5
                                "$bin"/irecovery -c "setenv auto-boot false"
                                "$bin"/irecovery -c "saveenv"
                                "$bin"/dfuhelper.sh
                            fi
                        elif [[ "$cpid" = 0x801* && "$deviceid" != *"iPad"* ]]; then
                            "$bin"/dfuhelper2.sh
                        else
                            "$bin"/dfuhelper3.sh
                        fi
                    fi
                fi
                _wait_for_dfu
                sudo killall -STOP -c usbd
                read -p "[*] You may need to unplug and replug your cable, would you like to? " r1
                if [[ "$r1" == "yes" || "$r1" == "y" ]]; then
                    read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
                    echo "[*] Waiting 10 seconds before continuing.."
                    sleep 10
                elif [[ "$r1" == "no" || "$r1" == "n" ]]; then
                    echo "[*] Ok no problem, continuing.."
                else
                    echo "[*] That was not a response I was expecting, I'm going to treat that as a 'yes'.."
                    read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
                    echo "[*] Waiting 10 seconds before continuing.."
                    sleep 10
                fi
                if [[ "$version" == "7."* || "$version" == "8."* ]]; then
                    cd "$dir"/$deviceid/$cpid/ramdisk/8.4.1
                elif [[ "$version" == "10.3"* || "$version" == "11."* ||  "$version" == "12."* ||  "$version" == "13."* || "$version" == "14."* ]]; then
                    cd "$dir"/$deviceid/$cpid/ramdisk/$r
                elif [[ "$os" = "Darwin" && ! "$deviceid" == "iPhone6"* && ! "$deviceid" == "iPhone7"* && ! "$deviceid" == "iPad4"* && ! "$deviceid" == "iPad5"* && ! "$deviceid" == "iPod7"* && "$version" == "9."* ]]; then
                    cd "$dir"/$deviceid/$cpid/ramdisk/9.3
                else
                    cd "$dir"/$deviceid/$cpid/ramdisk/11.4
                fi
                _boot_ramdisk $deviceid $replace $r
                cd "$dir"/
                read -p "[*] Press Enter once your device has fully booted into the SSH ramdisk " r1
                echo "[*] Waiting 6 seconds before continuing.."
                sleep 6
                sudo killall -STOP -c usbd
                read -p "[*] You may need to unplug and replug your cable, would you like to? " r1
                if [[ "$r1" == "yes" || "$r1" == "y" ]]; then
                    read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
                    echo "[*] Waiting 10 seconds before continuing.."
                    sleep 10
                elif [[ "$r1" == "no" || "$r1" == "n" ]]; then
                    echo "[*] Ok no problem, continuing.."
                else
                    echo "[*] That was not a response I was expecting, I'm going to treat that as a 'yes'.."
                    read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
                    echo "[*] Waiting 10 seconds before continuing.."
                    sleep 10
                fi
                "$bin"/iproxy 2222 22 &
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount -w -t hfs /dev/disk0s1s1 /mnt1" 2> /dev/null
                echo "[*] Disabling fixkeybag and putting back stock /usr/libexec/keybagd.."
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'mv /mnt1/usr/libexec/keybagd /mnt1/usr/libexec/fixkeybag' 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'mv /mnt1/usr/libexec/keybagd.bak /mnt1/usr/libexec/keybagd' 2> /dev/null
                echo "[*] Done"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/sbin/nvram auto-boot=false" 2> /dev/null
                $("$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/reboot &" 2> /dev/null &)
                echo "[*] Step 3 of dualbooting to iOS $version is now done"
                echo "[*] The device should now boot into recovery mode"
                echo "[*] Please follow the on screen instructions to put your device back into dfu mode"
                echo "[*] We will try to boot iOS $r for the first time with hfs filesystem on your device"
                sleep 5
                _kill_if_running iproxy
                if [ "$os" = "Darwin" ]; then
                    if ! (system_profiler SPUSBDataType 2> /dev/null | grep ' Apple Mobile Device (DFU Mode)' >> /dev/null); then
                        if [[ "$deviceid" == "iPhone10"* || "$cpid" == "0x8015"* ]]; then
                            sleep 10
                            if [ "$(get_device_mode)" = "recovery" ]; then
                                "$bin"/dfuhelper.sh
                            else
                                "$bin"/dfuhelper4.sh
                                sleep 5
                                "$bin"/irecovery -c "setenv auto-boot false"
                                "$bin"/irecovery -c "saveenv"
                                "$bin"/dfuhelper.sh
                            fi
                        elif [[ "$cpid" = 0x801* && "$deviceid" != *"iPad"* ]]; then
                            "$bin"/dfuhelper2.sh
                        else
                            "$bin"/dfuhelper3.sh
                        fi
                    fi
                else
                    if ! (lsusb | cut -d' ' -f6 | grep '05ac:' | cut -d: -f2 | grep 1227 >> /dev/null); then
                        if [[ "$deviceid" == "iPhone10"* || "$cpid" == "0x8015"* ]]; then
                            sleep 10
                            if [ "$(get_device_mode)" = "recovery" ]; then
                                "$bin"/dfuhelper.sh
                            else
                                "$bin"/dfuhelper4.sh
                                sleep 5
                                "$bin"/irecovery -c "setenv auto-boot false"
                                "$bin"/irecovery -c "saveenv"
                                "$bin"/dfuhelper.sh
                            fi
                        elif [[ "$cpid" = 0x801* && "$deviceid" != *"iPad"* ]]; then
                            "$bin"/dfuhelper2.sh
                        else
                            "$bin"/dfuhelper3.sh
                        fi
                    fi
                fi
                _wait_for_dfu
                sudo killall -STOP -c usbd
                read -p "[*] You may need to unplug and replug your cable, would you like to? " r1
                if [[ "$r1" == "yes" || "$r1" == "y" ]]; then
                    read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
                    echo "[*] Waiting 10 seconds before continuing.."
                    sleep 10
                elif [[ "$r1" == "no" || "$r1" == "n" ]]; then
                    echo "[*] Ok no problem, continuing.."
                else
                    echo "[*] That was not a response I was expecting, I'm going to treat that as a 'yes'.."
                    read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
                    echo "[*] Waiting 10 seconds before continuing.."
                    sleep 10
                fi
                cd "$dir"/$deviceid/clean/$cpid/$r
                _boot
                cd "$dir"/
                if [[ "$version" == "7."* ]]; then
                    echo "[*] Step 4 of dualbooting to iOS $version is now done"
                    echo "[*] The device should now boot into the setup screen on iOS $r"
                    echo "[*] You should wait until you get to setup screen before next step"
                    echo "[*] Then follow the on screen instructions to put your device back into dfu mode"
                    echo "[*] We will then boot into a ramdisk to run fsck before booting iOS $version"
                    sleep 5
                    if [ "$os" = "Darwin" ]; then
                        if ! (system_profiler SPUSBDataType 2> /dev/null | grep ' Apple Mobile Device (DFU Mode)' >> /dev/null); then
                            if [[ "$deviceid" == "iPhone10"* || "$cpid" == "0x8015"* ]]; then
                                sleep 10
                                if [ "$(get_device_mode)" = "recovery" ]; then
                                    "$bin"/dfuhelper.sh
                                else
                                    "$bin"/dfuhelper4.sh
                                    sleep 5
                                    "$bin"/irecovery -c "setenv auto-boot false"
                                    "$bin"/irecovery -c "saveenv"
                                    "$bin"/dfuhelper.sh
                                fi
                            elif [[ "$cpid" = 0x801* && "$deviceid" != *"iPad"* ]]; then
                                "$bin"/dfuhelper2.sh
                            else
                                "$bin"/dfuhelper3.sh
                            fi
                        fi
                    else
                        if ! (lsusb | cut -d' ' -f6 | grep '05ac:' | cut -d: -f2 | grep 1227 >> /dev/null); then
                            if [[ "$deviceid" == "iPhone10"* || "$cpid" == "0x8015"* ]]; then
                                sleep 10
                                if [ "$(get_device_mode)" = "recovery" ]; then
                                    "$bin"/dfuhelper.sh
                                else
                                    "$bin"/dfuhelper4.sh
                                    sleep 5
                                    "$bin"/irecovery -c "setenv auto-boot false"
                                    "$bin"/irecovery -c "saveenv"
                                    "$bin"/dfuhelper.sh
                                fi
                            elif [[ "$cpid" = 0x801* && "$deviceid" != *"iPad"* ]]; then
                                "$bin"/dfuhelper2.sh
                            else
                                "$bin"/dfuhelper3.sh
                            fi
                        fi
                    fi
                    _wait_for_dfu
                    sudo killall -STOP -c usbd
                    read -p "[*] You may need to unplug and replug your cable, would you like to? " r1
                    if [[ "$r1" == "yes" || "$r1" == "y" ]]; then
                        read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
                        echo "[*] Waiting 10 seconds before continuing.."
                        sleep 10
                    elif [[ "$r1" == "no" || "$r1" == "n" ]]; then
                        echo "[*] Ok no problem, continuing.."
                    else
                        echo "[*] That was not a response I was expecting, I'm going to treat that as a 'yes'.."
                        read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
                        echo "[*] Waiting 10 seconds before continuing.."
                        sleep 10
                    fi
                    if [[ "$version" == "7."* || "$version" == "8."* ]]; then
                        cd "$dir"/$deviceid/$cpid/ramdisk/8.4.1
                    elif [[ "$version" == "10.3"* || "$version" == "11."* ||  "$version" == "12."* ||  "$version" == "13."* || "$version" == "14."* ]]; then
                        cd "$dir"/$deviceid/$cpid/ramdisk/$r
                    elif [[ "$os" = "Darwin" && ! "$deviceid" == "iPhone6"* && ! "$deviceid" == "iPhone7"* && ! "$deviceid" == "iPad4"* && ! "$deviceid" == "iPad5"* && ! "$deviceid" == "iPod7"* && "$version" == "9."* ]]; then
                        cd "$dir"/$deviceid/$cpid/ramdisk/9.3
                    else
                        cd "$dir"/$deviceid/$cpid/ramdisk/11.4
                    fi
                    _boot_ramdisk $deviceid $replace $r
                    cd "$dir"/
                    read -p "[*] Press Enter once your device has fully booted into the SSH ramdisk " r1
                    echo "[*] Waiting 6 seconds before continuing.."
                    sleep 6
                    sudo killall -STOP -c usbd
                    read -p "[*] You may need to unplug and replug your cable, would you like to? " r1
                    if [[ "$r1" == "yes" || "$r1" == "y" ]]; then
                        read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
                        echo "[*] Waiting 10 seconds before continuing.."
                        sleep 10
                    elif [[ "$r1" == "no" || "$r1" == "n" ]]; then
                        echo "[*] Ok no problem, continuing.."
                    else
                        echo "[*] That was not a response I was expecting, I'm going to treat that as a 'yes'.."
                        read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
                        echo "[*] Waiting 10 seconds before continuing.."
                        sleep 10
                    fi
                    "$bin"/iproxy 2222 22 &
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost '/sbin/fsck'
                    echo "[*] Done"
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/sbin/nvram auto-boot=false" 2> /dev/null
                    $("$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/reboot &" 2> /dev/null &)
                    echo "[*] Step 5 of dualbooting to iOS $version is now done"
                    echo "[*] The device should now boot into recovery mode"
                    echo "[*] Please follow the on screen instructions to put your device back into dfu mode"
                    echo "[*] We will try to boot iOS $version for the first time on your device"
                    echo "[*] You can enable auto-boot again at any time by running $0 $r --fix-auto-boot"
                    sleep 5
                else
                    echo "[*] Step 4 of dualbooting to iOS $version is now done"
                    echo "[*] The device should now boot into the setup screen on iOS $r"
                    echo "[*] Please follow the on screen instructions to put your device back into dfu mode"
                    echo "[*] We will try to boot iOS $version for the first time on your device"
                    sleep 5
                fi

            fi
        fi
        if [[ ! "$dualboot_hfs" == 1 ]]; then
            $("$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/reboot &" 2> /dev/null &)
        fi
        sleep 5
        if [[ ! -e "$dir"/$deviceid/0.0/activation_records/activation_record.plist || "$force_activation" == 1 ]]; then
            if [[ "$version" == "9.3"* || "$version" == "10."* || "$version" == "11."* || "$version" == "12."* ||  "$version" == "13."* || "$version" == "14."* ]]; then
                if [ -e "$dir"/$deviceid/$cpid/$version/iBSS.img4 ]; then
                    if [ "$os" = "Darwin" ]; then
                        if ! (system_profiler SPUSBDataType 2> /dev/null | grep ' Apple Mobile Device (DFU Mode)' >> /dev/null); then
                            if [[ "$deviceid" == "iPhone10"* || "$cpid" == "0x8015"* ]]; then
                                sleep 10
                                if [ "$(get_device_mode)" = "recovery" ]; then
                                    "$bin"/dfuhelper.sh
                                else
                                    "$bin"/dfuhelper4.sh
                                    sleep 5
                                    "$bin"/irecovery -c "setenv auto-boot false"
                                    "$bin"/irecovery -c "saveenv"
                                    "$bin"/dfuhelper.sh
                                fi
                            elif [[ "$cpid" = 0x801* && "$deviceid" != *"iPad"* ]]; then
                                "$bin"/dfuhelper2.sh
                            else
                                "$bin"/dfuhelper3.sh
                            fi
                        fi
                    else
                        if ! (lsusb | cut -d' ' -f6 | grep '05ac:' | cut -d: -f2 | grep 1227 >> /dev/null); then
                            if [[ "$deviceid" == "iPhone10"* || "$cpid" == "0x8015"* ]]; then
                                sleep 10
                                if [ "$(get_device_mode)" = "recovery" ]; then
                                    "$bin"/dfuhelper.sh
                                else
                                    "$bin"/dfuhelper4.sh
                                    sleep 5
                                    "$bin"/irecovery -c "setenv auto-boot false"
                                    "$bin"/irecovery -c "saveenv"
                                    "$bin"/dfuhelper.sh
                                fi
                            elif [[ "$cpid" = 0x801* && "$deviceid" != *"iPad"* ]]; then
                                "$bin"/dfuhelper2.sh
                            else
                                "$bin"/dfuhelper3.sh
                            fi
                        fi
                    fi
                    _wait_for_dfu
                    sudo killall -STOP -c usbd
                    read -p "[*] You may need to unplug and replug your cable, would you like to? " r1
                    if [[ "$r1" == "yes" || "$r1" == "y" ]]; then
                        read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
                        echo "[*] Waiting 10 seconds before continuing.."
                        sleep 10
                    elif [[ "$r1" == "no" || "$r1" == "n" ]]; then
                        echo "[*] Ok no problem, continuing.."
                    else
                        echo "[*] That was not a response I was expecting, I'm going to treat that as a 'yes'.."
                        read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
                        echo "[*] Waiting 10 seconds before continuing.."
                        sleep 10
                    fi
                    cd "$dir"/$deviceid/$cpid/$version
                    _boot
                    cd "$dir"/
                fi
                _kill_if_running iproxy
                echo "[*] Step 1 of downwgrading to iOS $version is now done"
                echo "[*] The device should now boot without any issue and show a progress bar"
                echo "[*] When your device gets to the setup screen, put the device back into dfu mode"
                echo "[*] We will then activate your device to allow you to navigate to the home screen"
                sleep 5
                if [ "$os" = "Darwin" ]; then
                    if ! (system_profiler SPUSBDataType 2> /dev/null | grep ' Apple Mobile Device (DFU Mode)' >> /dev/null); then
                        if [[ "$deviceid" == "iPhone10"* || "$cpid" == "0x8015"* ]]; then
                            sleep 10
                            if [ "$(get_device_mode)" = "recovery" ]; then
                                "$bin"/dfuhelper.sh
                            else
                                "$bin"/dfuhelper4.sh
                                sleep 5
                                "$bin"/irecovery -c "setenv auto-boot false"
                                "$bin"/irecovery -c "saveenv"
                                "$bin"/dfuhelper.sh
                            fi
                        elif [[ "$cpid" = 0x801* && "$deviceid" != *"iPad"* ]]; then
                            "$bin"/dfuhelper2.sh
                        else
                            "$bin"/dfuhelper3.sh
                        fi
                    fi
                else
                    if ! (lsusb | cut -d' ' -f6 | grep '05ac:' | cut -d: -f2 | grep 1227 >> /dev/null); then
                        if [[ "$deviceid" == "iPhone10"* || "$cpid" == "0x8015"* ]]; then
                            sleep 10
                            if [ "$(get_device_mode)" = "recovery" ]; then
                                "$bin"/dfuhelper.sh
                            else
                                "$bin"/dfuhelper4.sh
                                sleep 5
                                "$bin"/irecovery -c "setenv auto-boot false"
                                "$bin"/irecovery -c "saveenv"
                                "$bin"/dfuhelper.sh
                            fi
                        elif [[ "$cpid" = 0x801* && "$deviceid" != *"iPad"* ]]; then
                            "$bin"/dfuhelper2.sh
                        else
                            "$bin"/dfuhelper3.sh
                        fi
                    fi
                fi
                _wait_for_dfu
                sudo killall -STOP -c usbd
                read -p "[*] You may need to unplug and replug your cable, would you like to? " r1
                if [[ "$r1" == "yes" || "$r1" == "y" ]]; then
                    read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
                    echo "[*] Waiting 10 seconds before continuing.."
                    sleep 10
                elif [[ "$r1" == "no" || "$r1" == "n" ]]; then
                    echo "[*] Ok no problem, continuing.."
                else
                    echo "[*] That was not a response I was expecting, I'm going to treat that as a 'yes'.."
                    read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
                    echo "[*] Waiting 10 seconds before continuing.."
                    sleep 10
                fi
                if [[ "$version" == "7."* || "$version" == "8."* ]]; then
                    cd "$dir"/$deviceid/$cpid/ramdisk/8.4.1
                elif [[ "$version" == "10.3"* || "$version" == "11."* ||  "$version" == "12."* ||  "$version" == "13."* || "$version" == "14."* ]]; then
                    cd "$dir"/$deviceid/$cpid/ramdisk/$r
                elif [[ "$os" = "Darwin" && ! "$deviceid" == "iPhone6"* && ! "$deviceid" == "iPhone7"* && ! "$deviceid" == "iPad4"* && ! "$deviceid" == "iPad5"* && ! "$deviceid" == "iPod7"* && "$version" == "9."* ]]; then
                    cd "$dir"/$deviceid/$cpid/ramdisk/9.3
                else
                    cd "$dir"/$deviceid/$cpid/ramdisk/11.4
                fi
                _boot_ramdisk $deviceid $replace $r
                cd "$dir"/
                read -p "[*] Press Enter once your device has fully booted into the SSH ramdisk " r1
                echo "[*] Waiting 6 seconds before continuing.."
                sleep 6
                sudo killall -STOP -c usbd
                read -p "[*] You may need to unplug and replug your cable, would you like to? " r1
                if [[ "$r1" == "yes" || "$r1" == "y" ]]; then
                    read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
                    echo "[*] Waiting 10 seconds before continuing.."
                    sleep 10
                elif [[ "$r1" == "no" || "$r1" == "n" ]]; then
                    echo "[*] Ok no problem, continuing.."
                else
                    echo "[*] That was not a response I was expecting, I'm going to treat that as a 'yes'.."
                    read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
                    echo "[*] Waiting 10 seconds before continuing.."
                    sleep 10
                fi
                "$bin"/iproxy 2222 22 &
                if [[ "$version" == "9.3"* || "$version" == "10.0"* || "$version" == "10.1"* || "$version" == "10.2"* ]]; then
                    if [[ "$dualboot_hfs" == 1 ]]; then
                        "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount -w -t hfs /dev/disk0s1s3 /mnt1" 2> /dev/null
                        "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount -w -t hfs /dev/disk0s1s4 /mnt2" 2> /dev/null
                    else
                        "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount -w -t hfs /dev/disk0s1s1 /mnt1" 2> /dev/null
                        "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount -w -t hfs /dev/disk0s1s2 /mnt2" 2> /dev/null
                    fi
                    # /mnt2/containers/Data/System/58954F59-3AA2-4005-9C5B-172BE4ADEC98/Library/internal/data_ark.plist
                    dataarkplist=$(remote_cmd "/usr/bin/find /mnt2/containers/Data/System -name 'internal'" 2> /dev/null)
                    dataarkplist="$dataarkplist/data_ark.plist"
                    echo $dataarkplist
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
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount_apfs /dev/$systemfs /mnt4"
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount_apfs /dev/$datafs /mnt5"
                    # /mnt5/containers/Data/System/58954F59-3AA2-4005-9C5B-172BE4ADEC98/Library/internal/data_ark.plist
                    dataarkplist=$(remote_cmd "/usr/bin/find /mnt5/containers/Data/System -name 'data_ark.plist'" 2> /dev/null)
                    echo $dataarkplist
                    if [ -e "$dir"/$deviceid/0.0/IC-Info.sisv ]; then
                        "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt5/mobile/Library/FairPlay/iTunes_Control/iTunes/"
                        "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/0.0/IC-Info.sisv root@localhost:/mnt5/mobile/Library/FairPlay/iTunes_Control/iTunes/IC-Info.sisv 2> /dev/null
                    fi
                    if [ -e "$dir"/$deviceid/0.0/com.apple.commcenter.device_specific_nobackup.plist ]; then
                        "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt5/wireless/Library/Preferences/"
                        "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/0.0/com.apple.commcenter.device_specific_nobackup.plist root@localhost:/mnt5/wireless/Library/Preferences/com.apple.commcenter.device_specific_nobackup.plist 2> /dev/null
                    fi
                    "$bin"/mobactivationd64patcher "$dir"/$deviceid/$cpid/$version/mobactivationd.raw "$dir"/$deviceid/$cpid/$version/mobactivationd.patched -b -c -d 2> /dev/null
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/mobactivationd.patched root@localhost:/mnt4/usr/libexec/mobileactivationd 2> /dev/null
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/data_ark.plis_ root@localhost:$dataarkplist
                    if [[ "$version" == "10."* ]]; then
                        "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/Meridian.app.tar.gz root@localhost:/mnt4/
                        "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'tar --preserve-permissions -xzvf /mnt4/Meridian.app.tar.gz -C /mnt4/Applications' 2> /dev/null
                        "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt4/Meridian.app.tar.gz' 2> /dev/null
                    fi
                fi
                $("$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/reboot &" 2> /dev/null &)
                sleep 5
            fi
        fi
        _kill_if_running iproxy
        if [ -e "$dir"/$deviceid/$cpid/$version/iBSS.img4 ]; then
            if [ "$os" = "Darwin" ]; then
                if ! (system_profiler SPUSBDataType 2> /dev/null | grep ' Apple Mobile Device (DFU Mode)' >> /dev/null); then
                    if [[ "$deviceid" == "iPhone10"* || "$cpid" == "0x8015"* ]]; then
                        sleep 10
                        if [ "$(get_device_mode)" = "recovery" ]; then
                            "$bin"/irecovery -c "setenv auto-boot true"
                            "$bin"/irecovery -c "saveenv"
                            "$bin"/dfuhelper.sh
                        else
                            "$bin"/dfuhelper4.sh
                            sleep 5
                            "$bin"/irecovery -c "setenv auto-boot true"
                            "$bin"/irecovery -c "saveenv"
                            "$bin"/dfuhelper.sh
                        fi
                    elif [[ "$cpid" = 0x801* && "$deviceid" != *"iPad"* ]]; then
                        "$bin"/dfuhelper2.sh
                    else
                        "$bin"/dfuhelper3.sh
                    fi
                fi
            else
                if ! (lsusb | cut -d' ' -f6 | grep '05ac:' | cut -d: -f2 | grep 1227 >> /dev/null); then
                    if [[ "$deviceid" == "iPhone10"* || "$cpid" == "0x8015"* ]]; then
                        sleep 10
                        if [ "$(get_device_mode)" = "recovery" ]; then
                            "$bin"/irecovery -c "setenv auto-boot true"
                            "$bin"/irecovery -c "saveenv"
                            "$bin"/dfuhelper.sh
                        else
                            "$bin"/dfuhelper4.sh
                            sleep 5
                            "$bin"/irecovery -c "setenv auto-boot true"
                            "$bin"/irecovery -c "saveenv"
                            "$bin"/dfuhelper.sh
                        fi
                    elif [[ "$cpid" = 0x801* && "$deviceid" != *"iPad"* ]]; then
                        "$bin"/dfuhelper2.sh
                    else
                        "$bin"/dfuhelper3.sh
                    fi
                fi
            fi
            _wait_for_dfu
            sudo killall -STOP -c usbd
            read -p "[*] You may need to unplug and replug your cable, would you like to? " r1
            if [[ "$r1" == "yes" || "$r1" == "y" ]]; then
                read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
                echo "[*] Waiting 10 seconds before continuing.."
                sleep 10
            elif [[ "$r1" == "no" || "$r1" == "n" ]]; then
                echo "[*] Ok no problem, continuing.."
            else
                echo "[*] That was not a response I was expecting, I'm going to treat that as a 'yes'.."
                read -p "[*] Unplug and replug the end of the cable that is attached to your Mac and then press the Enter key on your keyboard " r1
                echo "[*] Waiting 10 seconds before continuing.."
                sleep 10
            fi
            cd "$dir"/$deviceid/$cpid/$version
            _boot
            cd "$dir"/
        fi
        _kill_if_running iproxy
        echo "done"
        exit 0
    else
        if [[ "$ramdisk" == 1 || "$force_activation" == 1 || "$dump_blobs" == 1 ]]; then
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt1" 2> /dev/null
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt2" 2> /dev/null
            if [[ "$version" == "7."* || "$version" == "8."* || "$version" == "9."* || "$version" == "10.0"* || "$version" == "10.1"* || "$version" == "10.2"* ]]; then
                 if [[ "$dualboot_hfs" == 1 ]]; then
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount -w -t hfs /dev/disk0s1s3 /mnt1" 2> /dev/null
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount -w -t hfs /dev/disk0s1s4 /mnt2" 2> /dev/null
                else
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount -w -t hfs /dev/disk0s1s1 /mnt1" 2> /dev/null
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount -w -t hfs /dev/disk0s1s2 /mnt2" 2> /dev/null
                fi
            else
                echo "[*] Testing for baseband presence"
                if [[ "$r" == "16"* || "$r" == "17"* ]]; then
                    systemdisk=9
                    datadisk=10
                    systemfs=disk0s1s$systemdisk
                    datafs=disk0s1s$datadisk
                else
                    systemdisk=8
                    datadisk=9
                    systemfs=disk0s1s$systemdisk
                    datafs=disk0s1s$datadisk
                fi
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount_apfs /dev/$systemfs /mnt4"
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount_apfs /dev/$datafs /mnt5"
            fi
        fi
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
                    echo "[-] "$dir"/$deviceid/0.0/IC-Info.sisv does not exist"
                fi
                if [ -e "$dir"/$deviceid/0.0/com.apple.commcenter.device_specific_nobackup.plist ]; then
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt1/private/var/wireless/Library/Preferences/"
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf /mnt1/private/var/wireless/Library/Preferences/com.apple.commcenter.device_specific_nobackup.plist"
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/0.0/com.apple.commcenter.device_specific_nobackup.plist root@localhost:/mnt1/com.apple.commcenter.device_specific_nobackup.plist 2> /dev/null
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "cd /mnt1/private/var/wireless/Library/Preferences && ln -s ../../../../../com.apple.commcenter.device_specific_nobackup.plist com.apple.commcenter.device_specific_nobackup.plist && stat com.apple.commcenter.device_specific_nobackup.plist"
                else
                    echo "[-] "$dir"/$deviceid/0.0/com.apple.commcenter.device_specific_nobackup.plist does not exist"
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
                    echo "[-] "$dir"/$deviceid/0.0/activation_records does not exist"
                fi
                if [[ -e "$dir"/$deviceid/0.0/activation_records/activation_record.plist ]]; then
                    if [ -e "$dir"/$deviceid/0.0/data_ark.plist ]; then
                        "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/0.0/data_ark.plist root@localhost:/mnt1/data_ark.plist 2> /dev/null
                        "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf /mnt1/private/var/root/Library/Lockdown/data_ark.plist"
                        "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "cd /mnt1/private/var/root/Library/Lockdown && ln -s ../../../../../data_ark.plist data_ark.plist && stat data_ark.plist"
                        "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags schg /mnt1/private/var/root/Library/Lockdown/data_ark.plist"
                    else
                        echo "[-] "$dir"/$deviceid/0.0/data_ark.plist does not exist"
                    fi
                else
                    echo "[-] "$dir"/$deviceid/0.0/activation_records/activation_record.plist does not exist"
                fi
                # /mnt1/private/var/containers/Data/System/58954F59-3AA2-4005-9C5B-172BE4ADEC98/Library/internal/data_ark.plist
                dataarkplist=$(remote_cmd "/usr/bin/find /mnt1/private/var/containers/Data/System -name 'internal'" 2> /dev/null)
                dataarkplist="$dataarkplist/data_ark.plist"
                echo $dataarkplist
                if [[ "$version" == "9."* && "$force_activation" == 1 ]]; then
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf $dataarkplist"
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/data_ark.plis_ root@localhost:/mnt1/mob_data_ark.plist
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "cd $(remote_cmd "/usr/bin/find /mnt1/private/var/containers/Data/System -name 'internal'" 2> /dev/null) && ln -s ../../../../../../../../mob_data_ark.plist data_ark.plist && stat data_ark.plist"
                else
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf $dataarkplist"
                    echo "[*] Removed residual data_ark.plist from $dataarkplist"
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
                echo "[*] Disabling auto-boot in nvram to prevent effaceable storage issues.."
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/sbin/nvram auto-boot=false" 2> /dev/null
                echo "[*] You can enable auto-boot again at any time by running $0 $version --fix-auto-boot"
                echo "[*] Done"
                echo "[*] Restored the activation records on your device"
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
                    echo "[-] "$dir"/$deviceid/0.0/IC-Info.sisv does not exist"
                fi
                if [ -e "$dir"/$deviceid/0.0/com.apple.commcenter.device_specific_nobackup.plist ]; then
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt2/wireless/Library/Preferences/"
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/0.0/com.apple.commcenter.device_specific_nobackup.plist root@localhost:/mnt2/wireless/Library/Preferences/com.apple.commcenter.device_specific_nobackup.plist 2> /dev/null
                else
                    echo "[-] "$dir"/$deviceid/0.0/com.apple.commcenter.device_specific_nobackup.plist does not exist"
                fi
                if [[ -e "$dir"/$deviceid/0.0/activation_records ]]; then
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt2/root/Library/Lockdown/activation_records"
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -r -P 2222 "$dir"/$deviceid/0.0/activation_records/* root@localhost:/mnt2/root/Library/Lockdown/activation_records 2> /dev/null
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags -R schg /mnt2/root/Library/Lockdown/activation_records"
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt2/mobile/Library/mad/activation_records"
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -r -P 2222 "$dir"/$deviceid/0.0/activation_records/* root@localhost:/mnt2/mobile/Library/mad/activation_records 2> /dev/null
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags -R schg /mnt2/mobile/Library/mad/activation_records"
                else
                    echo "[-] "$dir"/$deviceid/0.0/activation_records does not exist"
                fi
                if [[ -e "$dir"/$deviceid/0.0/activation_records/activation_record.plist ]]; then
                    if [ -e "$dir"/$deviceid/0.0/data_ark.plist ]; then
                        "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/0.0/data_ark.plist root@localhost:/mnt2/root/Library/Lockdown/data_ark.plist 2> /dev/null
                        "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/bin/chflags schg /mnt2/root/Library/Lockdown/data_ark.plist"
                    else
                        echo "[-] "$dir"/$deviceid/0.0/data_ark.plist does not exist"
                    fi
                else
                    echo "[-] "$dir"/$deviceid/0.0/activation_records/activation_record.plist does not exist"
                fi
                # /mnt2/containers/Data/System/58954F59-3AA2-4005-9C5B-172BE4ADEC98/Library/internal/data_ark.plist
                dataarkplist=$(remote_cmd "/usr/bin/find /mnt2/containers/Data/System -name 'data_ark.plist'" 2> /dev/null)
                if [[ "$dataarkplist" == "/mnt2/containers/Data/System"* ]]; then
                    folder=$(echo $dataarkplist | sed 's/\/data_ark.plist//g')
                    folder=$(echo $folder | sed 's/\/internal//g')
                    # /mnt2/containers/Data/System/58954F59-3AA2-4005-9C5B-172BE4ADEC98/Library
                    if [[ "$folder" == "/mnt2/containers/Data/System"* ]]; then
                        "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "rm -rf $folder/internal/data_ark.plist"
                        echo "[*] Removed residual data_ark.plist from $folder/internal/data_ark.plist"
                    fi
                fi
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt1" 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt2" 2> /dev/null
                echo "[*] Restored the activation records on your device"
                $("$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/reboot &" 2> /dev/null &)
                _kill_if_running iproxy
                exit 0
            fi
        fi
        if [[ "$dump_blobs" == 1 ]]; then
            mkdir -p "$dir"/$deviceid/0.0/
            if [[ ! -e "$dir"/$deviceid/0.0/apticket.der ]]; then
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt1/System/Library/Caches/apticket.der "$dir"/$deviceid/0.0/apticket.der 2> /dev/null
            fi
            if [[ -e "$dir"/$deviceid/0.0/apticket.der ]]; then
                echo "$dir"/$deviceid/0.0/apticket.der
            fi
            pwd
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "cat /dev/rdisk1" | dd of=dump.raw bs=256 count=$((0x4000))
            stat dump.raw
            "$bin"/img4tool --convert -s dumped.shsh dump.raw
            stat dumped.shsh
            $("$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/reboot &" 2> /dev/null &)
            _kill_if_running iproxy
            exit 0
        elif [[ "$dump_nand" == 1 ]]; then
            # dd if=/dev/sda bs=5M conv=fsync status=progress | gzip -c -9 | ssh user@DestinationIP 'gzip -d | dd of=/dev/sda bs=5M'
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt1" 2> /dev/null
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt2" 2> /dev/null
            read -p "would you like to also back up /dev/disk0 to $dir/$deviceid/disk0.gz? " r
            if [[ ! "$r" == "no" && ! "$r" == "n" ]]; then
                echo "[*] Backing up /dev/disk0 to $dir/$deviceid/disk0.gz, this may take up to 15 minutes.."
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "dd if=/dev/disk0 bs=64k | gzip -1 -" | dd of=disk0.gz bs=64k
            fi
            read -p "would you like to also back up /dev/disk0s1s1 to $dir/$deviceid/disk0s1s1.gz? " r
            if [[ ! "$r" == "no" && ! "$r" == "n" ]]; then
                echo "[*] Backing up /dev/disk0s1s1 to $dir/$deviceid/disk0s1s1.gz, this may take up to 15 minutes.."
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "dd if=/dev/disk0s1s1 bs=64k | gzip -1 -" | dd of=disk0s1s1.gz bs=64k
            fi
            read -p "would you like to also back up /dev/disk0s1s2 to $dir/$deviceid/disk0s1s2.gz? " r
            if [[ ! "$r" == "no" && ! "$r" == "n" ]]; then
                 echo "[*] Backing up /dev/disk0s1s2 to $dir/$deviceid/disk0s1s2.gz, this may take up to 15 minutes.."
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "dd if=/dev/disk0s1s2 bs=64k | gzip -1 -" | dd of=disk0s1s2.gz bs=64k
            fi
            echo "[*] Disabling auto-boot in nvram to prevent effaceable storage issues.."
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/sbin/nvram auto-boot=false" 2> /dev/null
            echo "[*] You can enable auto-boot again at any time by running $0 $version --fix-auto-boot"
            echo "[*] Done"
            $("$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/reboot &" 2> /dev/null &)
            _kill_if_running iproxy
            exit 0
        elif [[ "$restore_nand" == 1 ]]; then
            # dd if=/dev/sda bs=5M conv=fsync status=progress | gzip -c -9 | ssh user@DestinationIP 'gzip -d | dd of=/dev/sda bs=5M'
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt1" 2> /dev/null
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt2" 2> /dev/null
            echo "[*] Restoring /dev/disk0 from $dir/disk0.gz, this may take up to 15 minutes.."
            dd if=disk0.gz bs=64k | "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "gzip -d | dd of=/dev/disk0 bs=64k"
            echo "[*] Enabling auto-boot in nvram to allow booting the restored nand after a reboot.."
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/sbin/nvram auto-boot=true" 2> /dev/null
            read -p "would you like to also run oblit on your device to ensure function after nand restore? " r
            if [[ ! "$r" == "no" && ! "$r" == "n" ]]; then
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/sbin/nvram oblit-inprogress=5" 2> /dev/null
            fi
            echo "[*] Done"
            $("$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/reboot &" 2> /dev/null &)
            _kill_if_running iproxy
            exit 0
        elif [[ "$restore_mnt1" == 1 ]]; then
            # dd if=/dev/sda bs=5M conv=fsync status=progress | gzip -c -9 | ssh user@DestinationIP 'gzip -d | dd of=/dev/sda bs=5M'
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt1" 2> /dev/null
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt2" 2> /dev/null
            echo "[*] Restoring /dev/disk0s1s1 from $dir/disk0s1s1.gz, this may take up to 15 minutes.."
            dd if=disk0s1s1.gz bs=64k | "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "gzip -d | dd of=/dev/disk0s1s1 bs=64k"
            echo "[*] Enabling auto-boot in nvram to allow booting the restored nand after a reboot.."
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/sbin/nvram auto-boot=true" 2> /dev/null
            echo "[*] Done"
            $("$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/reboot &" 2> /dev/null &)
            _kill_if_running iproxy
            exit 0
        elif [[ "$restore_mnt2" == 1 ]]; then
            # dd if=/dev/sda bs=5M conv=fsync status=progress | gzip -c -9 | ssh user@DestinationIP 'gzip -d | dd of=/dev/sda bs=5M'
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt1" 2> /dev/null
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt2" 2> /dev/null
            echo "[*] Restoring /dev/disk0s1s2 from $dir/disk0s1s2.gz, this may take up to 15 minutes.."
            dd if=disk0s1s2.gz bs=64k | "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "gzip -d | dd of=/dev/disk0s1s2 bs=64k"
            echo "[*] Enabling auto-boot in nvram to allow booting the restored nand after a reboot.."
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/usr/sbin/nvram auto-boot=true" 2> /dev/null
            echo "[*] Done"
            $("$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/reboot &" 2> /dev/null &)
            _kill_if_running iproxy
            exit 0
        elif [[ "$disable_NoMoreSIGABRT" == 1 ]]; then
            # dd if=/dev/sda bs=5M conv=fsync status=progress | gzip -c -9 | ssh user@DestinationIP 'gzip -d | dd of=/dev/sda bs=5M'
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount -w -t hfs /dev/disk0s1s1 /mnt1" 2> /dev/null
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt2" 2> /dev/null
            echo "[*] Disabling NoMoreSIGABRT on /dev/disk0s1s2.."
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost '/bin/dd if=/dev/disk0s1s2 of=/mnt1/out.img bs=512 count=8192'
            "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt1/out.img "$dir"/$deviceid/$cpid/$version/NoMoreSIGABRT.img
            "$bin"/Kernel64Patcher "$dir"/$deviceid/$cpid/$version/NoMoreSIGABRT.img "$dir"/$deviceid/$cpid/$version/NoMoreSIGABRT.patched -o
            "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/NoMoreSIGABRT.patched root@localhost:/mnt1/out.img
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost '/bin/dd if=/mnt1/out.img of=/dev/disk0s1s2 bs=512 count=8192'
            echo "[*] Done"
            $("$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/reboot &" 2> /dev/null &)
            _kill_if_running iproxy
            exit 0
        elif [[ "$NoMoreSIGABRT" == 1 ]]; then
            # dd if=/dev/sda bs=5M conv=fsync status=progress | gzip -c -9 | ssh user@DestinationIP 'gzip -d | dd of=/dev/sda bs=5M'
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/mount -w -t hfs /dev/disk0s1s1 /mnt1" 2> /dev/null
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/umount /mnt2" 2> /dev/null
            echo "[*] Enabling NoMoreSIGABRT on /dev/disk0s1s2.."
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost '/bin/dd if=/dev/disk0s1s2 of=/mnt1/out.img bs=512 count=8192'
            "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 root@localhost:/mnt1/out.img "$dir"/$deviceid/$cpid/$version/NoMoreSIGABRT.img
            "$bin"/Kernel64Patcher "$dir"/$deviceid/$cpid/$version/NoMoreSIGABRT.img "$dir"/$deviceid/$cpid/$version/NoMoreSIGABRT.patched -n
            "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/$cpid/$version/NoMoreSIGABRT.patched root@localhost:/mnt1/out.img
            "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost '/bin/dd if=/mnt1/out.img of=/dev/disk0s1s2 bs=512 count=8192'
            echo "[*] Done"
            $("$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/reboot &" 2> /dev/null &)
            _kill_if_running iproxy
            exit 0
        elif [[ "$force_activation" == 1 ]]; then
            if [[ "$version" == "9.3"* || "$version" == "10.0"* || "$version" == "10.1"* || "$version" == "10.2"* ]]; then
                # /mnt2/containers/Data/System/58954F59-3AA2-4005-9C5B-172BE4ADEC98/Library/internal/data_ark.plist
                dataarkplist=$(remote_cmd "/usr/bin/find /mnt2/containers/Data/System -name 'internal'" 2> /dev/null)
                dataarkplist="$dataarkplist/data_ark.plist"
                echo $dataarkplist
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
                # /mnt5/containers/Data/System/58954F59-3AA2-4005-9C5B-172BE4ADEC98/Library/internal/data_ark.plist
                dataarkplist=$(remote_cmd "/usr/bin/find /mnt5/containers/Data/System -name 'data_ark.plist'" 2> /dev/null)
                echo $dataarkplist
                if [ -e "$dir"/$deviceid/0.0/IC-Info.sisv ]; then
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt5/mobile/Library/FairPlay/iTunes_Control/iTunes/"
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/0.0/IC-Info.sisv root@localhost:/mnt5/mobile/Library/FairPlay/iTunes_Control/iTunes/IC-Info.sisv 2> /dev/null
                fi
                if [ -e "$dir"/$deviceid/0.0/com.apple.commcenter.device_specific_nobackup.plist ]; then
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "mkdir -p /mnt5/wireless/Library/Preferences/"
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/$deviceid/0.0/com.apple.commcenter.device_specific_nobackup.plist root@localhost:/mnt5/wireless/Library/Preferences/com.apple.commcenter.device_specific_nobackup.plist 2> /dev/null
                fi
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/data_ark.plis_ root@localhost:$dataarkplist
            fi
            if [[ "$version" == "10.3"* ]]; then
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/Meridian.app.tar.gz root@localhost:/mnt4/
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'tar --preserve-permissions -xzvf /mnt4/Meridian.app.tar.gz -C /mnt4/Applications' 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt4/Meridian.app.tar.gz' 2> /dev/null
                if [[ ! "$deviceid" == "iPad"* ]]; then
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/UnlimFileManager.app.tar.gz root@localhost:/mnt4/
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'tar --preserve-permissions -xzvf /mnt4/UnlimFileManager.app.tar.gz -C /mnt4/Applications' 2> /dev/null
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost '/usr/sbin/chown -R root:wheel /mnt4/Applications/UnlimFileManager.app'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt4/UnlimFileManager.app.tar.gz' 2> /dev/null
                fi
            elif [[ "$version" == "10."* ]]; then
                "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/Meridian.app.tar.gz root@localhost:/mnt1/
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'tar --preserve-permissions -xzvf /mnt1/Meridian.app.tar.gz -C /mnt1/Applications' 2> /dev/null
                "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/Meridian.app.tar.gz' 2> /dev/null
                if [[ ! "$deviceid" == "iPad"* ]]; then
                    "$bin"/sshpass -p "alpine" scp -o StrictHostKeyChecking=no -P 2222 "$dir"/jb/UnlimFileManager.app.tar.gz root@localhost:/mnt1/
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'tar --preserve-permissions -xzvf /mnt1/UnlimFileManager.app.tar.gz -C /mnt1/Applications' 2> /dev/null
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost '/usr/sbin/chown -R root:wheel /mnt1/Applications/UnlimFileManager.app'
                    "$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost 'rm -rf /mnt1/UnlimFileManager.app.tar.gz' 2> /dev/null
                fi
            fi
            $("$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/reboot &" 2> /dev/null &)
            _kill_if_running iproxy
            echo "done"
            exit 0
        fi
        ssh -o StrictHostKeyChecking=no -p2222 root@localhost
        $("$bin"/sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p2222 root@localhost "/sbin/reboot &" 2> /dev/null &)
        _kill_if_running iproxy
    fi
fi
} | tee logs/"$(date +%T)"-"$(date +%F)"-"$(uname)"-"$(uname -r)".log
