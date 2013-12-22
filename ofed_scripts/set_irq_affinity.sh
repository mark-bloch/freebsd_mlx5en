#! /bin/bash
if [ -z $1 ]; then
	echo "usage: $0 <interface> [2nd interface]"
	exit 1
fi

source common_irq_affinity.sh

CORES=$((`cat /proc/cpuinfo | grep processor | tail -1 | awk '{print $3}'`+1))
hop=1

ls /sys/class/net/$1 > /dev/null
rc=$?

if [[ "$rc" == "0" && "$( cat /proc/interrupts | grep $1 )" == "" ]];then
	INT1=$( ls -l /sys/class/net/$1/device | tr "/"  " " | awk '{ print $NF}' | cut -b -7 )
else
	INT1=$1
fi

if [ -z $2 ]; then
	limit_1=$CORES
	echo "---------------------------------------"
	echo "Optimizing IRQs for Single port traffic"
	echo "---------------------------------------"
else
	ls /sys/class/net/$2 > /dev/null
	rc=$?
	if [[ "$rc" == "0" && "$( cat /proc/interrupts | grep $2 )" == "" ]];then
		INT2=$( ls -l /sys/class/net/$2/device | tr "/"  " " | awk '{ print $NF}' | cut -b -7 )
	else	
		INT2=$2
	fi
	echo "-------------------------------------"
	echo "Optimizing IRQs for Dual port traffic"
	echo "-------------------------------------"
	limit_1=$((CORES/2))
	limit_2=$CORES
	IRQS_2=$(cat /proc/interrupts | grep $INT2 | awk '{print $1}' | sed 's/://')
fi



IRQS_1=$(cat /proc/interrupts | grep $INT1 | awk '{print $1}' | sed 's/://')

if [ -z "$IRQS_1" ] ; then
	echo No IRQs found for $1.
else
	echo Discovered irqs for $1: $IRQS_1
	core_id=0
	for IRQ in $IRQS_1
	do
		echo Assign irq $IRQ core_id $core_id
		affinity=$( core_to_affinity $core_id )
		echo $affinity > /proc/irq/$IRQ/smp_affinity
		core_id=$(( core_id + $hop ))
		if [ $core_id -ge $limit_1 ] ; then core_id=0; fi
	done
fi

echo 

if [ "$2" != "" ]; then
	if [ -z "$IRQS_2" ]; then
		echo No IRQs found for $2.
	else
		echo Discovered irqs for $2: $IRQS_2
		core_id=$limit_1
		for IRQ in $IRQS_2
		do
			echo Assign irq $IRQ core_id $core_id
			affinity=$( core_to_affinity $core_id )
			echo $affinity > /proc/irq/$IRQ/smp_affinity
			core_id=$(( core_id + $hop ))
			if [ $core_id -ge $limit_2 ] ; then core_id=$limit_1; fi
		done
	fi
fi
echo 
echo done.

