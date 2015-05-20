#! /bin/bash
if [ -z $1 ]; then
	echo "usage: $0 <interface> <source> <numa/cores>"
        echo "source can be either ALL, NUMA or LIST"
	exit 1
fi

function get_irq_list
{
        intf=$1
        device=$(sysctl hw.$intf.conf.device_name | cut -d " " -f 2)
        IRQS=$(vmstat -ia | grep $device | awk '{print $1}' | sed s/irq// | sed s/://)
        echo $IRQS
}

function get_cores_list_all
{
        OIFS=$IFS
        IFS=", "
        ALL_CORES=$(sysctl kern.sched.topology_spec | grep -A 1 "group level=\"1\"" | tail -1 | cut -d ">" -f 2 | cut -d "<" -f 1)
        echo ${ALL_CORES[@]}
        IFS=$OIFS
}

function get_cores_list_numa
{
        OIFS=$IFS
        IFS=", "
        numa=$1
        line_location=$((3*(1-$numa)+1))
        ALL_CORES=$(sysctl kern.sched.topology_spec | grep -A 1 "group level=\"2\"" | tail -$line_location | head -1 | cut -d ">" -f 2 | cut -d "<" -f 1)
        echo ${ALL_CORES[@]}
        IFS=$OIFS
}

function get_cores_list
{
        cpulist=$1
        CORES=$( echo $cpulist | sed 's/,/ /g' )
        echo $CORES
}

INT=$1
CORES_SOURCE=$2

if [ "$CORES_SOURCE" == "ALL" ]; then
        CORES=$( get_cores_list_all )
elif [ "$CORES_SOURCE" == "NUMA" ]; then
        if [ -z $3 ]; then
                echo "usage: $0 <interface> <source> <numa/cores>"
                echo "source can be either ALL, NUMA or LIST"
                exit 1
        fi
        CORES=$( get_cores_list_numa $3 )
elif [ "$CORES_SOURCE" == "LIST" ]; then
        if [ -z $3 ]; then
                echo "usage: $0 <interface> <source> <numa/cores>"
                echo "source can be either ALL, NUMA or LIST"
                exit 1
        fi
        CORES=$( get_cores_list $3 )
else
        echo "usage: $0 <interface> <source> <numa/cores>"
        echo "source can be either ALL, NUMA or LIST"
        exit 1
fi

CORES_ARRAY=()
for C in ${CORES[@]}
do
        CORES_ARRAY+=($C)
done

echo "---------------------------------------"
echo "Optimizing IRQs for Single port traffic"
echo "---------------------------------------"

IRQS=$( get_irq_list $INT )

if [ -z "$IRQS" ] ; then
	echo No IRQs found for $INT.
else
	echo Discovered irqs for $INT: $IRQS
        CORE_INDEX=0
	for IRQ in $IRQS
	do
                echo Assign irq $IRQ core ${CORES_ARRAY[$CORE_INDEX]}
                cpuset -x $IRQ -l ${CORES_ARRAY[$CORE_INDEX]}
                CORE_INDEX=$(( $((CORE_INDEX + 1)) % ${#CORES_ARRAY[@]}))
	done
fi

echo 

echo done.


