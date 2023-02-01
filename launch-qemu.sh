#!/bin/bash

#
# user changeable parameters
#
HDA="/home/amd/fedora-30.raw"
MEM="2048"
SMP="4"
VNC=""
CONSOLE="serial"
USE_VIRTIO="1"

SEV="0"
SEV_ES="0"
SEV_SNP="0"
ALLOW_DEBUG="0"
USE_GDB="0"

EXEC_PATH="$PREFIX/usr/local"
UEFI_PATH="$EXEC_PATH/share/qemu"

usage() {
	echo "$0 [options]"
	echo "Available <commands>:"
	echo " -sev               launch SEV guest"
	echo " -sev-es            launch SEV guest"
	echo " -sev-snp           launch SNP guest"
	echo " -bios              the bios to use (default $UEFI_PATH)"
	echo " -hda PATH          hard disk file (default $HDA)"
	echo " -mem MEM           guest memory size in MB (default $MEM)"
	echo " -smp NCPUS         number of virtual cpus (default $SMP)"
	echo " -cdrom             CDROM image"
	echo " -allow-debug       dump vmcb on exit and enable the trace"
	exit 1
}

add_opts() {
	echo -n "$* " >> ${QEMU_CMDLINE}
}

exit_from_int() {
	stop_network
	rm -rf ${QEMU_CMDLINE}
	# restore the mapping
	stty intr ^c
	exit 1
}

run_cmd () {
	$*
	if [ $? -ne 0 ]; then
		echo "command $* failed"
		exit 1
	fi
}

get_cbitpos() {
	modprobe cpuid
	#
	# Get C-bit position directly from the hardware
	#   Reads of /dev/cpu/x/cpuid have to be 16 bytes in size
	#     and the seek position represents the CPUID function
	#     to read.
	#   The skip parameter of DD skips ibs-sized blocks, so
	#     can't directly go to 0x8000001f function (since it
	#     is not a multiple of 16). So just start at 0x80000000
	#     function and read 32 functions to get to 0x8000001f
	#   To get to EBX, which contains the C-bit position, skip
	#     the first 4 bytes (EAX) and then convert 4 bytes.
	#

	EBX=$(dd if=/dev/cpu/0/cpuid ibs=16 count=32 skip=134217728 | tail -c 16 | od -An -t u4 -j 4 -N 4 | sed -re 's|^ *||')
	CBITPOS=$((EBX & 0x3f))
}

trap exit_from_int SIGINT

if [ `id -u` -ne 0 ]; then
	echo "Must be run as root!"
	exit 1
fi

while [ -n "$1" ]; do
	case "$1" in
		-sev-snp)	SEV_SNP="1"
				SEV_ES="1"
				SEV="1"
				;;
		-sev-es)	SEV_ES="1"
				SEV="1"
				;;
		-sev)		SEV="1"
				;;
		-hda) 		HDA="$2"
				shift
				;;
		-cdrom)		CDROM_FILE="$2"
				shift
				;;
		-mem)  		MEM="$2"
				shift
				;;
		-smp)		SMP="$2"
				shift
				;;
		-vnc)		VNC="$2"
				shift
				if [ "$VNC" = "" ]; then
					usage
				fi
				;;
		-console)	CONSOLE="$2"
				shift
				;;
		-bios)          UEFI_PATH="$2"
				shift
				;;
		-allow-debug)   ALLOW_DEBUG="1"
				;;
		-novirtio)      USE_VIRTIO="0"
				;;
		-kernel)	KERNEL_FILE=$2
				shift
				;;
		-initrd)	INITRD_FILE=$2
				shift
				;;
		-append) 	APPEND="$2"
				shift
				;;
		*) 		echo "Calling usage, cannot understand argument $1"; usage
				;;
	esac

	shift
done

TMP="$EXEC_PATH/bin/qemu-system-x86_64"
QEMU_EXE="$(readlink -e $TMP)"
[ -z "$QEMU_EXE" ] && {
	echo "Can't locate qemu executable [$TMP]"
	usage
}

[ -n "$HDA" ] && {
	TMP="$HDA"
	HDA="$(readlink -e $TMP)"
	[ -z "$HDA" ] && {
		echo "Can't locate guest image file [$TMP]"
		usage
	}

	GUEST_NAME="$(basename $TMP | sed -re 's|\.[^\.]+$||')"
}

[ -n "$CDROM_FILE" ] && {
	TMP="$CDROM_FILE"
	CDROM_FILE="$(readlink -e $TMP)"
	[ -z "$CDROM_FILE" ] && {
		echo "Can't locate CD-Rom file [$TMP]"
		usage
	}

	[ -z "$GUEST_NAME" ] && GUEST_NAME="$(basename $TMP | sed -re 's|\.[^\.]+$||')"
}

setup_bridge_network() {
	BRIDGE_DEV="virbr0"
	# Get last tap device on host
	TAP_NUM=`ifconfig | grep tap | tail -1 | cut -c4- | cut -f1 -d ' ' | cut -f1 -d:`
	if [ "$TAP_NUM" = "" ]; then
		TAP_NUM="1"
	fi
	TAP_NUM=`echo $(( TAP_NUM + 1 ))`
	GUEST_TAP_NAME="tap${TAP_NUM}"

	[ "$USE_VIRTIO" = "1" ] && PREFIX="52:54:00" || PREFIX="02:16:1e"
	SUFFIX="$(ip address show dev ${BRIDGE_DEV} | grep link/ether | awk '{print $2}' | awk -F : '{print $4 ":" $5}')"
	GUEST_MAC_ADDR="$(printf "%s:%s:%02x" $PREFIX $SUFFIX $TAP_NUM)"

	echo "Starting network adapter '${GUEST_TAP_NAME}' MAC=$GUEST_MAC_ADDR"
	run_cmd "ip tuntap add $GUEST_TAP_NAME mode tap user `whoami`"
	run_cmd "ip link set $GUEST_TAP_NAME up"
	run_cmd "ip link set $GUEST_TAP_NAME master ${BRIDGE_DEV}"

	if [ "$USE_VIRTIO" = "1" ]; then
		add_opts "-netdev type=tap,script=no,downscript=no,id=net0,ifname=$GUEST_TAP_NAME"
		add_opts "-device virtio-net-pci,mac=${GUEST_MAC_ADDR},netdev=net0,disable-legacy=on,iommu_platform=true,romfile="
	else
		add_opts "-netdev tap,id=net0,ifname=$GUEST_TAP_NAME,script=no,downscript=no"
		add_opts "-device e1000,mac=${GUEST_MAC_ADDR},netdev=net0,romfile="
	fi
}
stop_network() {
	if [ "$GUEST_TAP_NAME" = "" ]; then
		return
	fi
	run_cmd "ip tuntap del ${GUEST_TAP_NAME} mode tap"
}

TMP="$UEFI_PATH/OVMF_CODE.fd"
UEFI_CODE="$(readlink -e $TMP)"
[ -z "$UEFI_CODE" ] && {
	echo "Can't locate UEFI code file [$TMP]"
	usage
}

[ -e "./$GUEST_NAME.fd" ] || {
	TMP="$UEFI_PATH/OVMF_VARS.fd"
	UEFI_VARS="$(readlink -e $TMP)"
	[ -z "$UEFI_VARS" ] && {
		echo "Can't locate UEFI variable file [$TMP]"
		usage
	}

	run_cmd "cp $UEFI_VARS ./$GUEST_NAME.fd"
}
UEFI_VARS="$(readlink -e ./$GUEST_NAME.fd)"

if [ "$ALLOW_DEBUG" = "1" ]; then
	# This will dump all the VMCB on VM exit
	echo 1 > /sys/module/kvm_amd/parameters/dump_all_vmcbs

	# Enable some KVM tracing to the debug
	#echo kvm: >/sys/kernel/debug/tracing/set_event
	#echo kvm:* >/sys/kernel/debug/tracing/set_event
	#echo kvm:kvm_page_fault >/sys/kernel/debug/tracing/set_event
	#echo >/sys/kernel/debug/tracing/set_event
	#echo > /sys/kernel/debug/tracing/trace
	#echo 1 > /sys/kernel/debug/tracing/tracing_on
fi

# we add all the qemu command line options into a file
QEMU_CMDLINE=/tmp/cmdline.$$
rm -rf $QEMU_CMDLINE

add_opts "taskset --cpu-list 2 $QEMU_EXE"

add_opts "-s"

#add_opts "-device vfio-pci,host=00:01.0,id=net10"

# Basic virtual machine property
add_opts "-enable-kvm -cpu EPYC-v4 -machine q35"

# add number of VCPUs
[ -n "${SMP}" ] && add_opts "-smp ${SMP},maxcpus=1"

# define guest memory
add_opts "-m ${MEM}M,slots=5,maxmem=30G"

# don't reboot for SEV-ES guest
add_opts "-no-reboot"

# The OVMF binary, including the non-volatile variable store, appears as a
# "normal" qemu drive on the host side, and it is exposed to the guest as a
# persistent flash device.
add_opts "-drive if=pflash,format=raw,unit=0,file=${UEFI_CODE},readonly"
add_opts "-drive if=pflash,format=raw,unit=1,file=${UEFI_VARS}"

# add CDROM if specified
[ -n "${CDROM_FILE}" ] && add_opts "-drive file=${CDROM_FILE},media=cdrom -boot d"

# check if host has bridge network
BR0_STATUS="$(ip link show virbr0 type bridge 2>/dev/null)"
if [ -n "$BR0_STATUS" ]; then
	setup_bridge_network
else
	# Louis: Added port forwarding
	add_opts "-netdev user,id=vmnic,hostfwd=tcp::8000-:22 -device e1000,netdev=vmnic,romfile="
fi

# add network support and fwd port 22 to 8000
# echo "guest port 22 is fwd to host 8000..."
# add_opts "-netdev user,id=vmnic,hostfwd=tcp::8000-:22 -device e1000,netdev=vmnic,romfile="
# add_opts "-netdev user,id=vmnic"
# add_opts " -device virtio-net-pci,disable-legacy=on,iommu_platform=true,netdev=vmnic,romfile="

# If harddisk file is specified then add the HDD drive
if [ -n "${HDA}" ]; then
	if [ "$USE_VIRTIO" = "1" ]; then
		if [[ ${HDA} = *"qcow2" ]]; then
			add_opts "-drive file=${HDA},if=none,id=disk0,format=qcow2"
		else
			add_opts "-drive file=${HDA},if=none,id=disk0,format=raw"
		fi
		add_opts "-device virtio-scsi-pci,id=scsi0,disable-legacy=on,iommu_platform=true"
		add_opts "-device scsi-hd,drive=disk0"
	else
		if [[ ${HDA} = *"qcow2" ]]; then
			add_opts "-drive file=${HDA},format=qcow2"
		else
			add_opts "-drive file=${HDA},format=raw"
		fi
	fi
fi

# If this is SEV guest then add the encryption device objects to enable support
if [ ${SEV} = "1" ]; then
	add_opts "-machine memory-encryption=sev0,vmport=off" 
	get_cbitpos

	if [ "${ALLOW_DEBUG}" = 1 -a "${SEV_SNP}" = 1 ]; then
		POLICY=$(((1<<17)|(1<<16))) # smt enable
		[ "${ALLOW_DEBUG}" = "1" ] && POLICY=$((POLICY | (1<<19)))
		SNP_POLICY=$(printf ",policy=%#x" $POLICY)
	elif [ "${ALLOW_DEBUG}" = "1" -o "${SEV_ES}" = "1" ]; then
		POLICY=$((0x01))
		[ "${ALLOW_DEBUG}" = "1" ] && POLICY=$((POLICY & ~0x01))
		[ "${SEV_ES}" = "1" ] && POLICY=$((POLICY | 0x04))
		SEV_POLICY=$(printf ",policy=%#x" $POLICY)
	fi

	if [ "${SEV_SNP}" = 1 ]; then
		add_opts "-object sev-snp-guest,id=sev0${SNP_POLICY},cbitpos=${CBITPOS},reduced-phys-bits=1"
	else
		add_opts "-object sev-guest,id=sev0${SEV_POLICY},cbitpos=${CBITPOS},reduced-phys-bits=1"
	fi
fi

# if -kernel arg is specified then use the kernel provided in command line for boot
if [ "${KERNEL_FILE}" != "" ]; then
	add_opts "-kernel $KERNEL_FILE"
	#add_opts "-append \"console=ttyS0 earlyprintk=serial root=/dev/sda2\""
	[ ! -z ${INITRD_FILE} ] && add_opts "-initrd ${INITRD_FILE}"
	if [[ -n "${APPEND}" ]]; then
		add_opts "-append \"${APPEND}\""
	fi
fi

# if console is serial then disable graphical interface
if [ "${CONSOLE}" = "serial" ]; then
	add_opts "-nographic"
else
	add_opts "-vga ${CONSOLE}"
fi




# start vnc server
[ -n "${VNC}" ] && add_opts "-vnc :${VNC}" && echo "Starting VNC on port ${VNC}"


# start monitor on pty and named socket 'monitor'
add_opts "-monitor pty -monitor unix:monitor,server,nowait"

# log the console  output in stdout.log
QEMU_CONSOLE_LOG=`pwd`/stdout.log

# save the command line args into log file
cat $QEMU_CMDLINE | tee ${QEMU_CONSOLE_LOG}
echo | tee -a ${QEMU_CONSOLE_LOG}

#touch /tmp/events
#add_opts "-trace events=/tmp/events"

# map CTRL-C to CTRL ]
echo "Mapping CTRL-C to CTRL-]"
stty intr ^]

echo "Launching VM ..."
echo "  $QEMU_CMDLINE"
sleep 1
bash ${QEMU_CMDLINE} 2>&1 | tee -a ${QEMU_CONSOLE_LOG}

# restore the mapping
stty intr ^c

rm -rf ${QEMU_CMDLINE}
if [ -n "$BR0_STATUS" ]; then
	stop_network
fi
