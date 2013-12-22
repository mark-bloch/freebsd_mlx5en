#! /bin/bash
if [ -z $2 ]; then
	echo "usage: $0 <cpu list> <interface> "
	echo "       <cpu list> can be either a comma separated list of single core numbers (0,1,2,3) or core groups (0-3)"
	exit 1
fi
cpulist=$1
interface=$2
NCPUS=$(cat /proc/cpuinfo | grep -c processor)

source common_irq_affinity.sh

ls /sys/class/net/$interface > /dev/null
rc=$?
if [[ "$rc" == "0" && "$( cat /proc/interrupts | grep $interface )" == "" ]];then
	interface=$( ls -l /sys/class/net/$interface/device | tr "/"  " " | awk '{ print $NF}' | cut -b -7 )
fi

IRQS=$(cat /proc/interrupts | grep $interface | awk '{print $1}' | sed 's/://')

CORES=$( echo $cpulist | sed 's/,/ /g' | wc -w )
for word in $(seq 1 $CORES)
do
	SEQ=$(echo $cpulist | cut -d "," -f $word | sed 's/-/ /')	
	if [ "$(echo $SEQ | wc -w)" != "1" ]; then
		CPULIST="$CPULIST $( echo $(seq $SEQ) | sed 's/ /,/g' )"
	fi
done
if [ "$CPULIST" != "" ]; then
	cpulist=$(echo $CPULIST | sed 's/ /,/g')
fi
CORES=$( echo $cpulist | sed 's/,/ /g' | wc -w )


echo Discovered irqs for $interface: $IRQS
I=1
for IRQ in $IRQS
do 
	core_id=$(echo $cpulist | cut -d "," -f $I)
	if [ $core_id -ge $NCPUS ]; then
		echo "irq $IRQ: Error - core $core_id does not exist"
	else
		echo Assign irq $IRQ core_id $core_id
	        affinity=$( core_to_affinity $core_id )
	        echo $affinity > /proc/irq/$IRQ/smp_affinity
	fi
	I=$(( (I%CORES) + 1 ))
done
echo 
echo done.


