#
# Copyright (c) 2012 Mellanox Technologies. All rights reserved.
#
# This Software is licensed under one of the following licenses:
#
# 1) under the terms of the "Common Public License 1.0" a copy of which is
#    available from the Open Source Initiative, see
#    http://www.opensource.org/licenses/cpl.php.
#
# 2) under the terms of the "The BSD License" a copy of which is
#    available from the Open Source Initiative, see
#    http://www.opensource.org/licenses/bsd-license.php.
#
# 3) under the terms of the "GNU General Public License (GPL) Version 2" a
#    copy of which is available from the Open Source Initiative, see
#    http://www.opensource.org/licenses/gpl-license.php.
#
# Licensee has the right to choose one of the above licenses.
#
# Redistributions of source code must retain the above copyright
# notice and one of the license notices.
#
# Redistributions in binary form must reproduce both the above copyright
# notice, one of the license notices in the documentation
# and/or other materials provided with the distribution.
#
#

%{!?configure_options: %define configure_options %{nil}}

# %{!?MEMTRACK: %define MEMTRACK 0}
%define MEMTRACK %(if ( echo %{configure_options} | grep "with-memtrack" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)
%define MADEYE %(if ( echo %{configure_options} | grep "with-madeye-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)

%{!?KVERSION: %define KVERSION %(uname -r)}
%define krelver %(echo -n %{KVERSION} | sed -e 's/-/_/g')

# Select packages to build
%{!?modprobe_update: %define modprobe_update %(if ( echo %{configure_options} | grep "without-modprobe" > /dev/null ); then echo -n '0'; else echo -n '1'; fi)}

# Kernel module packages to be included into kernel-ib
%define build_mthca %(if ( echo %{configure_options} | grep "with-mthca-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)
%define build_qib %(if ( echo %{configure_options} | grep "with-qib-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)
%define build_ipath %(if ( echo %{configure_options} | grep "with-ipath_inf-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)
%define build_ehca %(if ( echo %{configure_options} | grep "with-ehca-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)
%define build_ipoib %(if ( echo %{configure_options} | grep "with-ipoib-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)
%define build_eipoib %(if ( echo %{configure_options} | grep "with-e_ipoib-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)
%define build_sdp %(if ( echo %{configure_options} | grep "with-sdp-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)
%define build_srp %(if ( echo %{configure_options} | grep "with-srp-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)
%define build_iser %(if ( echo %{configure_options} | grep "with-iser-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)
%define build_oiscsi %(if ( echo %{configure_options} | grep "with-iscsi-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)
%define build_rds %(if ( echo %{configure_options} | grep "with-rds-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)
%define build_cxgb3 %(if ( echo %{configure_options} | grep "with-cxgb3-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)
%define build_cxgb4 %(if ( echo %{configure_options} | grep "with-cxgb4-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)
%define build_nes %(if ( echo %{configure_options} | grep "with-nes-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)
%define build_mlx4 %(if ( echo %{configure_options} | grep "with-mlx4-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)
%define build_mlx5 %(if ( echo %{configure_options} | grep "with-mlx5-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)
%define build_mlx4_en %(if ( echo %{configure_options} | grep "with-mlx4_en-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)
%define build_mlx4_vnic %(if ( echo %{configure_options} | grep "with-mlx4_vnic-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)
%define build_qlgc_vnic %(if ( echo %{configure_options} | grep "with-qlgc_vnic-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)
%define build_nfsrdma %(if ( echo %{configure_options} | grep "with-nfsrdma-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)

%{!?sysctl_update: %define sysctl_update 0}

%{!?IB_CONF_DIR: %define IB_CONF_DIR /etc/infiniband}
%{!?MLXNET_CONF_DIR: %define MLXNET_CONF_DIR /etc/mlxethernet}

%{!?K_SRC: %define K_SRC /lib/modules/%{KVERSION}/build}

%{!?KERNEL_SOURCES: %define KERNEL_SOURCES /lib/modules/%{KVERSION}/source}

# Do not include srp.h if it exist in the kernel
%define include_srp_h %(if [ -e %{KERNEL_SOURCES}/include/scsi/srp.h ]; then echo -n 0; else echo -n 1; fi )
%define include_rdma %(if [ -d %{KERNEL_SOURCES}/include/rdma ]; then echo -n 1; else echo -n 0; fi )

%define include_udev_rules %(eval `grep udev_rules /etc/udev/udev.conf | grep -v '^#'` ; if test -d $udev_rules; then echo -n 1; else echo -n 0; fi)

# Disable debugging
%define debug_package %{nil}
%define __check_files %{nil}

# Disable brp-lib64-linux
%ifarch x86_64 ia64
%define __arch_install_post %{nil}
%endif

%{!?_name: %define _name ofa_kernel}
%{!?_version: %define _version @VERSION@}
%{!?_release: %define _release @RELEASE@}

Summary: Infiniband HCA Driver
Name: %{_name}
Version: %{_version}
Release: %{_release}
License: GPL/BSD
Url: http://openfabrics.org/
Group: System Environment/Base
Source: %{_name}-%{_version}.tgz
BuildRoot: %{?build_root:%{build_root}}%{!?build_root:/var/tmp/OFED}
Vendor: OpenFabrics
%description 
InfiniBand "verbs", Access Layer  and ULPs

BuildRequires: sysfsutils-devel

%package -n kernel-ib
Requires: coreutils
Requires: pciutils
Requires: grep
Requires: perl
Requires: procps
Requires: module-init-tools
Version: %{_version}
Release: %{krelver}_%{_release}
Summary: Infiniband Driver and ULPs kernel modules
Group: System Environment/Libraries
%description -n kernel-ib
Core, HW and ULPs kernel modules

%package -n kernel-ib-devel
Requires: coreutils
Requires: pciutils
Requires: kernel-ib
Version: %{_version}
Release: %{krelver}_%{_release}
Summary: Infiniband Driver and ULPs kernel modules sources
Group: System Environment/Libraries
%description -n kernel-ib-devel
Core, HW and ULPs kernel modules sources

%if "%{_vendor}" == "suse"
%define install_mod_dir updates
%endif

%if "%{_vendor}" == "redhat"
%if 0%{?fedora}
%define install_mod_dir updates
%else
%define install_mod_dir extra/mlnx-%{name}
%endif
%define __find_requires %{nil}
%endif

%{!?LIB_MOD_DIR: %define LIB_MOD_DIR /lib/modules/%{KVERSION}/%install_mod_dir}
#################################################################################################################################

%prep
%setup -n %{_name}-%{_version}

###
### build
###
%build
rm -rf $RPM_BUILD_ROOT
cd $RPM_BUILD_DIR/%{_name}-%{_version}

# Save clean sources for kernel-ib-devel
mkdir -p $RPM_BUILD_DIR/src
cp -a $RPM_BUILD_DIR/%{_name}-%{_version} $RPM_BUILD_DIR/src/

./configure --prefix=%{_prefix} --kernel-version %{KVERSION} --kernel-sources %{K_SRC} --modules-dir %{LIB_MOD_DIR} %{configure_options}

# Copy InfniBand include files after applying backport patches (if required)
mkdir -p $RPM_BUILD_DIR/src/%{_name}
cp -a $RPM_BUILD_DIR/%{_name}-%{_version}/include/ $RPM_BUILD_DIR/src/%{_name}
cp -a $RPM_BUILD_DIR/%{_name}-%{_version}/config* $RPM_BUILD_DIR/src/%{_name}
cp -a $RPM_BUILD_DIR/%{_name}-%{_version}/compat*  $RPM_BUILD_DIR/src/%{_name}
cp -a $RPM_BUILD_DIR/%{_name}-%{_version}/ofed_scripts  $RPM_BUILD_DIR/src/%{_name}

export INSTALL_MOD_DIR=%install_mod_dir
make kernel

###
### install
###
%install
mkdir -p $RPM_BUILD_ROOT/%{_prefix}/src
cp -a $RPM_BUILD_DIR/src/%{_name}-%{_version} $RPM_BUILD_ROOT/%{_prefix}/src
cp -a $RPM_BUILD_DIR/src/%{_name} $RPM_BUILD_ROOT/%{_prefix}/src
cp -a $RPM_BUILD_DIR/%{_name}-%{_version}/include/linux/compat_autoconf.h $RPM_BUILD_ROOT/%{_prefix}/src/%{_name}/include/linux/compat_autoconf.h
rm -rf $RPM_BUILD_DIR/src
# Link created for compatibility with KMP RPMs
cd $RPM_BUILD_ROOT/%{_prefix}/src/%{_name}
ln -s ./ default
cd -

# Support external modules include dir for backward compatibility
cd $RPM_BUILD_ROOT/%{_prefix}/src/
ln -s %{_name} openib
cd -

export INSTALL_MOD_DIR=%install_mod_dir
export INSTALL_MOD_PATH=$RPM_BUILD_ROOT
make install_kernel KERNELRELEASE=%{KVERSION}

modsyms=`find $RPM_BUILD_DIR/%{_name}-%{_version} -name Module.symvers -o -name Modules.symvers`
if [ -n "$modsyms" ]; then
	for modsym in $modsyms
	do
	        cat $modsym >> $RPM_BUILD_ROOT/%{_prefix}/src/%{_name}/Module.symvers
	done
else
	./ofed_scripts/create_Module.symvers.sh
	cp ./Module.symvers $RPM_BUILD_ROOT/%{_prefix}/src/%{_name}/Module.symvers
fi

%if "%{_vendor}" == "redhat"
# Set the module(s) to be executable, so that they will be stripped when packaged.
find %{buildroot} -type f -name \*.ko -exec %{__chmod} u+x \{\} \;
%else
find %{buildroot} -type f -name \*.ko -exec %{__strip} -p --strip-debug --discard-locals -R .comment -R .note \{\} \;
%endif

INFO=${RPM_BUILD_ROOT}%{IB_CONF_DIR}/info
/bin/rm -f ${INFO}
mkdir -p ${RPM_BUILD_ROOT}%{IB_CONF_DIR}
touch ${INFO}

cat >> ${INFO} << EOFINFO
#!/bin/bash

echo prefix=%{_prefix}
echo Kernel=%{KVERSION}
echo
echo "Configure options: %{configure_options}"
echo
EOFINFO

chmod +x ${INFO} > /dev/null 2>&1

# Copy infiniband configuration
install -d $RPM_BUILD_ROOT/%{IB_CONF_DIR}
install -m 0644 $RPM_BUILD_DIR/%{_name}-%{_version}/ofed_scripts/openib.conf $RPM_BUILD_ROOT/%{IB_CONF_DIR}

# Install openib service script
install -d $RPM_BUILD_ROOT/etc/init.d
install -m 0755 $RPM_BUILD_DIR/%{_name}-%{_version}/ofed_scripts/openibd $RPM_BUILD_ROOT/etc/init.d
install -d $RPM_BUILD_ROOT/sbin
install -m 0755 $RPM_BUILD_DIR/%{_name}-%{_version}/ofed_scripts/sysctl_perf_tuning $RPM_BUILD_ROOT/sbin
install -d $RPM_BUILD_ROOT/%{_sbindir}
install -m 0755 $RPM_BUILD_DIR/%{_name}-%{_version}/ofed_scripts/*affinity* $RPM_BUILD_ROOT/%{_sbindir}

install -d $RPM_BUILD_ROOT/etc/modprobe.d
install -m 0644 $RPM_BUILD_DIR/%{_name}-%{_version}/ofed_scripts/mlnx.conf $RPM_BUILD_ROOT/etc/modprobe.d

%if %{build_mlx4} || %{build_mlx5}
install -d $RPM_BUILD_ROOT/%{_bindir}
install -m 0755 $RPM_BUILD_DIR/%{_name}-%{_version}/ofed_scripts/ibdev2netdev $RPM_BUILD_ROOT/%{_bindir}
%endif

%if %{build_mlx4_en}
install -d $RPM_BUILD_ROOT/sbin
install -m 0755 $RPM_BUILD_DIR/%{_name}-%{_version}/ofed_scripts/connectx_port_config $RPM_BUILD_ROOT/sbin
touch $RPM_BUILD_ROOT/%{IB_CONF_DIR}/connectx.conf
%endif

%if %{build_qib}
install -m 0644 $RPM_BUILD_DIR/%{_name}-%{_version}/ofed_scripts/truescale.cmds $RPM_BUILD_ROOT/%{IB_CONF_DIR}
%endif

%if %{build_ipoib}
%if %{modprobe_update}
install -d $RPM_BUILD_ROOT/etc/modprobe.d
install -m 0644 $RPM_BUILD_DIR/%{_name}-%{_version}/ofed_scripts/ib_ipoib.conf $RPM_BUILD_ROOT/etc/modprobe.d
%endif
%endif

%if %{build_eipoib}
install -m 0755 $RPM_BUILD_DIR/%{_name}-%{_version}/ofed_scripts/ipoibd $RPM_BUILD_ROOT/sbin
%endif

%if %{build_sdp}
%if %{modprobe_update}
install -d $RPM_BUILD_ROOT/etc/modprobe.d
install -m 0644 $RPM_BUILD_DIR/%{_name}-%{_version}/ofed_scripts/ib_sdp.conf $RPM_BUILD_ROOT/etc/modprobe.d
%endif
%endif

%if %{build_mlx4_vnic}
install -d $RPM_BUILD_ROOT/sbin
install -m 0755 $RPM_BUILD_DIR/%{_name}-%{_version}/ofed_scripts/mlx4_vnic_info $RPM_BUILD_ROOT/sbin
install -m 0755 $RPM_BUILD_DIR/%{_name}-%{_version}/ofed_scripts/mlx4_vnicd $RPM_BUILD_ROOT/sbin
install -m 0755 $RPM_BUILD_DIR/%{_name}-%{_version}/ofed_scripts/mlx4_vnic_confd $RPM_BUILD_ROOT/etc/init.d
%endif

%if %{include_udev_rules}
install -d $RPM_BUILD_ROOT/etc/udev/rules.d
install -m 0644 $RPM_BUILD_DIR/%{_name}-%{_version}/ofed_scripts/90-ib.rules $RPM_BUILD_ROOT/etc/udev/rules.d
case "$(udevinfo -V 2> /dev/null | awk '{print $NF}' 2> /dev/null)" in
0[1-4]*)
sed -i -e 's/KERNEL==/KERNEL=/g'  $RPM_BUILD_ROOT/etc/udev/rules.d/90-ib.rules
;;
esac
%endif
	
%clean
#Remove installed driver after rpm build finished
rm -rf $RPM_BUILD_ROOT
rm -rf $RPM_BUILD_DIR/%{_name}-%{_version}

###
### pre section
###

%pre -n kernel-ib

%pre -n kernel-ib-devel

###
### post section
###

%post -n kernel-ib
if [ $1 -ge 1 ]; then # 1 : This package is being installed or reinstalled
count_ib_ports()
{
    local cnt=0
    local tmp_cnt=0
    
    tmp_cnt=$(/sbin/lspci -n | grep "15b3:6282" | wc -l | tr -d '[:space:]') # Arbel mode
    cnt=$[ $cnt + 2*${tmp_cnt} ]
    
    tmp_cnt=$(/sbin/lspci -n | grep -E "15b3:5e8c|15b3:6274" | wc -l | tr -d '[:space:]') # Sinai
    cnt=$[ $cnt + ${tmp_cnt} ]

    tmp_cnt=$(/sbin/lspci -n | grep -E "15b3:5a44|15b3:6278" | wc -l | tr -d '[:space:]') # Tavor mode
    cnt=$[ $cnt + 2*${tmp_cnt} ]

    tmp_cnt=$(/sbin/lspci -n | grep -E "1fc1:|1077:7220" | wc -l | tr -d '[:space:]') # QLogic SDR and DDR HCA
    cnt=$[ $cnt + ${tmp_cnt} ]
    
    tmp_cnt=$(/sbin/lspci -n | grep -E "1077:7322" | wc -l | tr -d '[:space:]') # QLogic QDR HCA
    cnt=$[ $cnt + 2*${tmp_cnt} ]
    return $cnt
}

count_ib_ports
ports_num=$?

# Set default number of ports to 2 if no HCAs found
if [ $ports_num -eq 0 ]; then
    ports_num=2
fi    
#############################################################################################################
#                                       Modules configuration                                               #
#############################################################################################################

%if ! %{include_udev_rules}
    if [ -e /etc/udev/udev.rules ]; then
        perl -ni -e 'if (/\# Infiniband devices \#$/) { $filter = 1 }' -e 'if (!$filter) { print }' -e 'if (/\# End Infiniband devices \#$/){ $filter = 0 }' /etc/udev/udev.rules
        cat >> /etc/udev/udev.rules << EOF
# Infiniband devices #
KERNEL="umad*", NAME="infiniband/%k"
KERNEL="issm*", NAME="infiniband/%k"
KERNEL="ucm*", NAME="infiniband/%k", MODE="0666"
KERNEL="uverbs*", NAME="infiniband/%k", MODE="0666"
KERNEL="uat", NAME="infiniband/%k", MODE="0666"
KERNEL="ucma", NAME="infiniband/%k", MODE="0666"
KERNEL="rdma_cm", NAME="infiniband/%k", MODE="0666"
# End Infiniband devices #
EOF
    fi
%endif

%if %{modprobe_update}
%if %{build_ipoib}
for (( i=0 ; i < $ports_num ; i++ ))
do
cat >> /etc/modprobe.d/ib_ipoib.conf << EOF
alias netdev-ib${i} ib_ipoib
EOF
done
%endif
%endif

%if %{sysctl_update}

sysctl -w net.ipv4.tcp_timestamps=0
sysctl -w net.ipv4.tcp_sack=0
sysctl -w net.core.netdev_max_backlog=250000
sysctl -w net.core.rmem_max=16777216
sysctl -w net.core.wmem_max=16777216
sysctl -w net.core.rmem_default=16777216
sysctl -w net.core.wmem_default=16777216
sysctl -w net.core.optmem_max=16777216
sysctl -w net.ipv4.tcp_mem="16777216 16777216 16777216"
sysctl -w net.ipv4.tcp_rmem="4096 87380 16777216"
sysctl -w net.ipv4.tcp_wmem="4096 65536 16777216"
sysctl -w net.ipv4.tcp_low_latency=1

if [ -f /etc/sysctl.conf ]; then
perl -ni -e 'if (/\#\# OFED Network tuning parameters \#\#$/) { $filter = 1 }' -e 'if (!$filter) { print }' -e 'if (/\#\# END of OFED parameters \#\#$/){ $filter = 0 }' /etc/sysctl.conf
cat << EOF >> /etc/sysctl.conf
## OFED Network tuning parameters ##
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_sack = 0
net.core.netdev_max_backlog = 250000
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 16777216
net.core.wmem_default = 16777216
net.core.optmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_low_latency = 1
## END of OFED parameters ##
EOF
fi

%endif

    /sbin/depmod %{KVERSION}

#############################################################################################################


if [[ -f /etc/redhat-release || -f /etc/rocks-release ]]; then        
perl -i -ne 'if (m@^#!/bin/bash@) {
        print q@#!/bin/bash
#
# Bring up/down openib
#
# chkconfig: 2345 05 95
# description: Activates/Deactivates InfiniBand Driver to \
#              start at boot time.
#
### BEGIN INIT INFO
# Provides:       openibd
### END INIT INFO
@;
                 } else {
                     print;
                 }' /etc/init.d/openibd

        if ! ( /sbin/chkconfig --del openibd > /dev/null 2>&1 ); then
                true
        fi
        if ! ( /sbin/chkconfig --add openibd > /dev/null 2>&1 ); then
                true
        fi
fi

if [ -f /etc/SuSE-release ]; then
    local_fs='$local_fs'
    openiscsi=''
    %if %{build_oiscsi}
        openiscsi='open-iscsi'
    %endif
        perl -i -ne "if (m@^#!/bin/bash@) {
        print q@#!/bin/bash
### BEGIN INIT INFO
# Provides:       openibd
# Required-Start: $local_fs
# Required-Stop: opensmd $openiscsi
# Default-Start:  2 3 5
# Default-Stop: 0 1 2 6
# Description:    Activates/Deactivates InfiniBand Driver to \
#                 start at boot time.
### END INIT INFO
@;
                 } else {
                     print;
                 }" /etc/init.d/openibd

        if ! ( /sbin/insserv openibd > /dev/null 2>&1 ); then
                true
        fi
fi

if [ -f /etc/debian_version ]; then
    local_fs='$local_fs'
    openiscsi=''
    %if %{build_oiscsi}
        openiscsi='open-iscsi'
    %endif
        perl -i -ne "if (m@^#!/bin/bash@) {
        print q@#!/bin/bash
### BEGIN INIT INFO
# Provides:       openibd
# Required-Start: $local_fs
# Required-Stop: opensmd $openiscsi
# Default-Start:  2 3 5
# Default-Stop: 0 1 2 6
# Description:    Activates/Deactivates InfiniBand Driver to \
#                 start at boot time.
### END INIT INFO
@;
                 } else {
                     print;
                 }" /etc/init.d/openibd

        if ! ( /usr/sbin/update-rc.d openibd defaults > /dev/null 2>&1 ); then
                true
        fi
fi

    echo >> %{IB_CONF_DIR}/openib.conf
    echo "# Load UCM module" >> %{IB_CONF_DIR}/openib.conf
    echo "UCM_LOAD=yes" >> %{IB_CONF_DIR}/openib.conf
    echo >> %{IB_CONF_DIR}/openib.conf
    echo "# Load RDMA_CM module" >> %{IB_CONF_DIR}/openib.conf
    echo "RDMA_CM_LOAD=yes" >> %{IB_CONF_DIR}/openib.conf
    echo >> %{IB_CONF_DIR}/openib.conf
    echo "# Load RDMA_UCM module" >> %{IB_CONF_DIR}/openib.conf
    echo "RDMA_UCM_LOAD=yes" >> %{IB_CONF_DIR}/openib.conf
    echo >> %{IB_CONF_DIR}/openib.conf
    echo "# Increase ib_mad thread priority" >> %{IB_CONF_DIR}/openib.conf
    echo "RENICE_IB_MAD=no" >> %{IB_CONF_DIR}/openib.conf
    echo >> %{IB_CONF_DIR}/openib.conf
    echo "# Run sysctl performance tuning script" >> %{IB_CONF_DIR}/openib.conf
    echo "RUN_SYSCTL=yes" >> %{IB_CONF_DIR}/openib.conf

%if %{build_mthca}
       echo >> %{IB_CONF_DIR}/openib.conf                                                
       echo "# Load MTHCA" >> %{IB_CONF_DIR}/openib.conf
       echo "MTHCA_LOAD=no" >> %{IB_CONF_DIR}/openib.conf
%endif

%if %{build_qib}
       echo >> %{IB_CONF_DIR}/openib.conf
       echo "# Load QIB" >> %{IB_CONF_DIR}/openib.conf
       echo "QIB_LOAD=no" >> %{IB_CONF_DIR}/openib.conf
%endif

%if %{build_ipath}
       echo >> %{IB_CONF_DIR}/openib.conf                                                
       echo "# Load IPATH" >> %{IB_CONF_DIR}/openib.conf
       echo "IPATH_LOAD=no" >> %{IB_CONF_DIR}/openib.conf
%endif

%if %{build_ehca}
       echo >> %{IB_CONF_DIR}/openib.conf                                                
       echo "# Load eHCA" >> %{IB_CONF_DIR}/openib.conf
       echo "EHCA_LOAD=no" >> %{IB_CONF_DIR}/openib.conf
%endif

%if %{build_mlx4}
       echo >> %{IB_CONF_DIR}/openib.conf
       echo "# Load MLX4 modules" >> %{IB_CONF_DIR}/openib.conf
       echo "MLX4_LOAD=yes" >> %{IB_CONF_DIR}/openib.conf
%endif

%if %{build_mlx5}
       echo >> %{IB_CONF_DIR}/openib.conf
       echo "# Load MLX5 modules" >> %{IB_CONF_DIR}/openib.conf
       echo "MLX5_LOAD=yes" >> %{IB_CONF_DIR}/openib.conf
%endif

%if %{build_mlx4_en}
       echo >> %{IB_CONF_DIR}/openib.conf
       echo "# Load MLX4_EN module" >> %{IB_CONF_DIR}/openib.conf
       echo "MLX4_EN_LOAD=yes" >> %{IB_CONF_DIR}/openib.conf
%endif

%if %{build_mlx4_vnic}
       echo >> %{IB_CONF_DIR}/openib.conf
       echo "# Load MLX4_VNIC module" >> %{IB_CONF_DIR}/openib.conf
       echo "MLX4_VNIC_LOAD=no" >> %{IB_CONF_DIR}/openib.conf

#       if [[ -f /etc/redhat-release || -f /etc/rocks-release ]]; then        
#               if ! ( /sbin/chkconfig --del mlx4_vnic_confd > /dev/null 2>&1 ); then
#                       true
#               fi
#               if ! ( /sbin/chkconfig --add mlx4_vnic_confd > /dev/null 2>&1 ); then
#                       true
#               fi
#       fi
       
#       if [ -f /etc/SuSE-release ]; then
#               if ! ( /sbin/insserv mlx4_vnic_confd > /dev/null 2>&1 ); then
#                       true
#               fi
#       fi
       
#       if [ -f /etc/debian_version ]; then
#               if ! ( /usr/sbin/update-rc.d mlx4_vnic_confd defaults > /dev/null 2>&1 ); then
#                       true
#               fi
#       fi
%endif

%if %{build_cxgb3}
       echo >> %{IB_CONF_DIR}/openib.conf                                                
       echo "# Load CXGB3 modules" >> %{IB_CONF_DIR}/openib.conf
       echo "CXGB3_LOAD=no" >> %{IB_CONF_DIR}/openib.conf
%endif

%if %{build_cxgb4}
       echo >> %{IB_CONF_DIR}/openib.conf
       echo "# Load CXGB4 modules" >> %{IB_CONF_DIR}/openib.conf
       echo "CXGB4_LOAD=no" >> %{IB_CONF_DIR}/openib.conf
%endif

%if %{build_nes}
       echo >> %{IB_CONF_DIR}/openib.conf                                                
       echo "# Load NES modules" >> %{IB_CONF_DIR}/openib.conf
       echo "NES_LOAD=no" >> %{IB_CONF_DIR}/openib.conf
%endif

%if %{build_ipoib}
       echo >> %{IB_CONF_DIR}/openib.conf                                                
       echo "# Load IPoIB" >> %{IB_CONF_DIR}/openib.conf
       echo "IPOIB_LOAD=yes" >> %{IB_CONF_DIR}/openib.conf
       echo >> %{IB_CONF_DIR}/openib.conf                                                
       echo "# Enable IPoIB Connected Mode" >> %{IB_CONF_DIR}/openib.conf
       echo "SET_IPOIB_CM=auto" >> %{IB_CONF_DIR}/openib.conf
%endif

%if %{build_eipoib}
       echo >> /etc/infiniband/openib.conf
       echo "# Load E_IPoIB" >> /etc/infiniband/openib.conf
       echo "E_IPOIB_LOAD=no" >> /etc/infiniband/openib.conf
       echo >> /etc/infiniband/openib.conf
%endif

%if %{build_sdp}
       echo >> %{IB_CONF_DIR}/openib.conf                                                
       echo "# Load SDP module" >> %{IB_CONF_DIR}/openib.conf
       echo "SDP_LOAD=no" >> %{IB_CONF_DIR}/openib.conf
%endif

%if %{build_srp}
       echo >> %{IB_CONF_DIR}/openib.conf                                                
       echo "# Load SRP module" >> %{IB_CONF_DIR}/openib.conf
       echo "SRP_LOAD=no" >> %{IB_CONF_DIR}/openib.conf
%endif

%if %{build_rds}
       echo >> %{IB_CONF_DIR}/openib.conf                                                
       echo "# Load RDS module" >> %{IB_CONF_DIR}/openib.conf
       echo "RDS_LOAD=no" >> %{IB_CONF_DIR}/openib.conf
%endif

%if %{build_qlgc_vnic}
       echo >> %{IB_CONF_DIR}/openib.conf
       echo "# Load QLogic VNIC module" >> %{IB_CONF_DIR}/openib.conf
       echo "QLGC_VNIC_LOAD=no" >> %{IB_CONF_DIR}/openib.conf
%endif

fi # 1 : closed
# END of post -n kernel-ib

%post -n kernel-ib-devel

###
### preun section
###

%preun -n kernel-ib
if [ $1 = 0 ]; then  # 1 : Erase, not upgrade
          if [[ -f /etc/redhat-release || -f /etc/rocks-release ]]; then        
                if ! ( /sbin/chkconfig --del openibd  > /dev/null 2>&1 ); then
                        true
                fi
          fi
          if [ -f /etc/SuSE-release ]; then
                if ! ( /sbin/insserv -r openibd > /dev/null 2>&1 ); then
                        true
                fi
          fi
          if [ -f /etc/debian_version ]; then
                if ! ( /usr/sbin/update-rc.d openibd remove > /dev/null 2>&1 ); then
                        true
                fi
          fi
fi

###
### post uninstall section
###
%postun -n kernel-ib
if [ $1 = 0 ]; then  # 1 : Erase, not upgrade
        # Clean /etc/modprobe.d/ofed.conf   
        # Remove previous configuration if exist
        /sbin/depmod %{KVERSION}

# Clean udev.rules
%if ! %{include_udev_rules}
    if [ -e /etc/udev/udev.rules ]; then
        perl -ni -e 'if (/\# Infiniband devices \#$/) { $filter = 1 }' -e 'if (!$filter) { print }' -e 'if (/\# End Infiniband devices \#$/){ $filter = 0 }' /etc/udev/udev.rules
    fi
%endif

# Clean sysctl.conf
if [ -f /etc/sysctl.conf ]; then
perl -ni -e 'if (/\#\# OFED Network tuning parameters \#\#$/) { $filter = 1 }' -e 'if (!$filter) { print }' -e 'if (/\#\# END of OFED parameters \#\#$/){ $filter = 0 }' /etc/sysctl.conf
fi

fi

%postun -n kernel-ib-devel

###
### Files
###
%files -n kernel-ib
%defattr(-,root,root,-)
%dir %{IB_CONF_DIR}
%config(noreplace) %{IB_CONF_DIR}/openib.conf
%{IB_CONF_DIR}/info
/etc/init.d/openibd
/sbin/sysctl_perf_tuning
/etc/modprobe.d/mlnx.conf
%{_sbindir}/*
%if %{include_udev_rules}
/etc/udev/rules.d/90-ib.rules
%endif
%{LIB_MOD_DIR}
%if %{build_qib}
%config(noreplace) %{IB_CONF_DIR}/truescale.cmds
%endif
%if %{build_ipoib}
%if %{modprobe_update}
/etc/modprobe.d/ib_ipoib.conf
%if %{build_eipoib}
/sbin/ipoibd
%endif
%endif
%endif
%if %{build_sdp}
%if %{modprobe_update}
/etc/modprobe.d/ib_sdp.conf
%endif
%endif
%if %{build_mlx4} || %{build_mlx5}
%{_bindir}/ibdev2netdev
%endif
%if %{build_mlx4_en}
/sbin/connectx_port_config
%config(noreplace) %{IB_CONF_DIR}/connectx.conf
%endif
%if %{build_mlx4_vnic}
/etc/init.d/mlx4_vnic_confd
/sbin/mlx4_vnic_info
/sbin/mlx4_vnicd
%endif

%files -n kernel-ib-devel
%defattr(-,root,root,-)
%dir %{_prefix}/src
%{_prefix}/src/%{_name}-%{_version}
%{_prefix}/src/%{_name}
%{_prefix}/src/openib

# END Files

%changelog
* Thu Aug 14 2013 Vladimir Sokolovsky <vlad@mellanox.com>
- Remove weak updates support. weak updates is supported by KMP package only.
* Tue Apr 24 2012 Vladimir Sokolovsky <vlad@mellanox.com>
- Remove FC support
* Tue Mar 6 2012 Vladimir Sokolovsky <vlad@mellanox.com>
- Add weak updates support
* Tue Aug 9 2011 Vladimir Sokolovsky <vlad@mellanox.co.il>
- Simplify spec
* Mon Oct 4 2010 Vladimir Sokolovsky <vlad@mellanox.co.il>
- Add mlx4_fc and mlx4_vnic support
* Mon May 10 2010 Vladimir Sokolovsky <vlad@mellanox.co.il>
- Support install macro that removes RPM_BUILD_ROOT
* Thu Feb 4 2010 Vladimir Sokolovsky <vlad@mellanox.co.il>
- Added ibdev2netdev script
* Wed Sep 8 2008 Vladimir Sokolovsky <vlad@mellanox.co.il>
- Added nfsrdma support
* Wed Aug 13 2008 Vladimir Sokolovsky <vlad@mellanox.co.il>
- Added mlx4_en support
* Tue Aug 21 2007 Vladimir Sokolovsky <vlad@mellanox.co.il>
- Added %build macro
* Sun Jan 28 2007 Vladimir Sokolovsky <vlad@mellanox.co.il>
- Created spec file for kernel-ib
