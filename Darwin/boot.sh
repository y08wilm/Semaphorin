#!/bin/bash
os=$(uname)
dir="$(pwd)"
bin="$(pwd)/$(uname)"
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
sudo killall -STOP AMPDevicesAgent AMPDeviceDiscoveryAgent MobileDeviceUpdater
sudo killall -STOP -c usbd
while (true);
do
    if ! (system_profiler SPUSBDataType 2> /dev/null | grep ' Apple Mobile Device (DFU Mode)' >> /dev/null); then
        echo "Please connect a device in dfu mode to continue"
    fi
    if [[ "$(get_device_mode)" == "pongo" ]]; then
        #bash -c "nohup sh -c '"$bin"/pongoterm <cmd.txt &' > /dev/null &"
        exit 0
    fi 
    "$bin"/USB\ Prober.app/Contents/Resources/reenumerate -v 0x05ac,0x1227
    sleep 1
    while ! (system_profiler SPUSBDataType 2> /dev/null | grep ' Apple Mobile Device (DFU Mode)' >> /dev/null);
    do
        if [[ "$(get_device_mode)" == "pongo" ]]; then
            #bash -c "nohup sh -c '"$bin"/pongoterm <cmd.txt &' > /dev/null &"
            exit 0
        fi 
        echo "Please reconnect your usb cable"
        sleep 1
    done
    "$bin"/irecovery -q | grep NONC
    cpid=$("$bin"/irecovery -q | grep CPID | sed 's/CPID: //')
    if [[ "$cpid" == "0x8010" ]]; then
        "$bin"/timeout 12 "$bin"/openra1n-a10 "$bin"/Pongo.bin
        sleep 5
        "$bin"/timeout 4 "$bin"/openra1n-a10 "$bin"/Pongo.bin boot
    elif [[ "$cpid" == "0x8003" ]]; then
        "$bin"/timeout 12 "$bin"/openra1n-a9 "$bin"/Pongo.bin
        "$bin"/timeout 4 "$bin"/openra1n-a9 "$bin"/Pongo.bin boot
    fi
    if [[ ! "$?" == "0" ]]; then
        #echo "Exploit failed, please reconnect device in dfu mode to continue"
        exit 1
    fi
done