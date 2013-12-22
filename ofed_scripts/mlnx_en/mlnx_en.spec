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

%{!?KVERSION: %define KVERSION %(uname -r)}

%{!?sysctl_update: %define sysctl_update 1}
%{!?MEMTRACK: %define MEMTRACK 0}

%{!?LIB_MOD_DIR: %define LIB_MOD_DIR /lib/modules/%{KVERSION}}

# Disable debugging
%define debug_package %{nil}
%define __check_files %{nil}

# Disable brp-lib64-linux
%ifarch x86_64 ia64
%define __arch_install_post %{nil}
%endif

%{!?_name: %define _name mlnx_en}
%{!?_version: %define _version @VERSION@}
%{!?_release: %define _release @RELEASE@}

Summary: Ethernet NIC Driver
Name: %{_name}
Requires: coreutils
Requires: kernel
Requires: pciutils
Requires: grep
Requires: perl
Requires: procps
Requires: module-init-tools
Version: %{_version}
Release: %{_release}
License: GPL/BSD
Url: http://www.mellanox.com
Group: System Environment/Base
Source: %{_name}-%{_version}.tgz
BuildRoot: %{?build_root:%{build_root}}%{!?build_root:/var/tmp/MLNX_EN}
Vendor: Mellanox technologies 
%description
ConnectX Ehternet device driver
The driver sources are located at: http://www.mellanox.com/downloads/Drivers/mlnx-en-@VERSION@-@MAJOR_RELEASE@.tgz

%package -n mlnx_en-devel
Requires: coreutils
Requires: kernel
Requires: pciutils
Version: %{_version}
Release: %{_release}
Summary: ConnectX Ehternet device driver kernel modules sources
Group: System Environment/Libraries
%description -n mlnx_en-devel
Kernel modules sources
The driver sources are located at: http://www.mellanox.com/downloads/Drivers/mlnx-en-@VERSION@-@MAJOR_RELEASE@.tgz

%if "%{_host_vendor}" == "suse"
%define install_mod_dir updates/%{name}
%else
%if 0%{?fedora}
%define install_mod_dir updates
%else
%define install_mod_dir extra/%{name}
%endif
%endif

%prep
%setup -n %{_name}-%{_version}

%build
rm -rf $RPM_BUILD_ROOT

# Save clean sources
cp -a $RPM_BUILD_DIR/%{_name}-%{_version}/ $RPM_BUILD_DIR/src

cd $RPM_BUILD_DIR/%{_name}-%{_version}

MLNX_EN_PATCH_PARAMS=""

%if %{MEMTRACK}
MLNX_EN_PATCH_PARAMS=(${MLNX_EN_PATCH_PARAMS} " --with-memtrack")
%endif

scripts/mlnx_en_patch.sh $MLNX_EN_PATCH_PARAMS
make 
gzip -c scripts/mlx4_en.7 > mlx4_en.7.gz

cd ofed_scripts/utils
python setup.py build
cd -

%install
install -d $RPM_BUILD_ROOT/%{_prefix}/src
cp -a $RPM_BUILD_DIR/src $RPM_BUILD_ROOT/%{_prefix}/src/%{_name}-%{_version}
rm -rf $RPM_BUILD_DIR/src
export INSTALL_MOD_PATH=$RPM_BUILD_ROOT
export INSTALL_MOD_DIR=%install_mod_dir
make install MODULES_DIR=$INSTALL_MOD_DIR INSTALL_MOD_PATH=$RPM_BUILD_ROOT KERNELRELEASE=%{KVERSION}

touch ofed-files
cd ofed_scripts/utils
python setup.py install -O1 --root=$RPM_BUILD_ROOT --record ../../ofed-files
cd -

%if "%{_vendor}" == "redhat"
# Set the module(s) to be executable, so that they will be stripped when packaged.
find %{buildroot} -type f -name \*.ko -exec %{__chmod} u+x \{\} \;
%else
find %{buildroot} -type f -name \*.ko -exec %{__strip} -p --strip-debug --discard-locals -R .comment -R .note \{\} \;
%endif

install -D -m 644 mlx4_en.7.gz $RPM_BUILD_ROOT/%{_mandir}/man7/mlx4_en.7.gz
install -D -m 755 ofed_scripts/set_irq_affinity.sh $RPM_BUILD_ROOT/%{_sbindir}/set_irq_affinity.sh
install -D -m 755 ofed_scripts/common_irq_affinity.sh $RPM_BUILD_ROOT/%{_sbindir}/common_irq_affinity.sh
install -D -m 755 ofed_scripts/show_irq_affinity.sh $RPM_BUILD_ROOT/%{_sbindir}/show_irq_affinity.sh
install -D -m 755 ofed_scripts/set_irq_affinity_bynode.sh $RPM_BUILD_ROOT/%{_sbindir}/set_irq_affinity_bynode.sh
install -D -m 755 ofed_scripts/set_irq_affinity_cpulist.sh $RPM_BUILD_ROOT/%{_sbindir}/set_irq_affinity_cpulist.sh
install -D -m 755 ofed_scripts/sysctl_perf_tuning $RPM_BUILD_ROOT/sbin/sysctl_perf_tuning

install -D -m 644 scripts/mlx4_en.modprobe.conf $RPM_BUILD_ROOT/etc/modprobe.d/mlx4_en.conf

%clean
#Remove installed driver after rpm build finished
rm -rf $RPM_BUILD_ROOT
rm -rf $RPM_BUILD_DIR/%{_name}-%{_version}

%post -n mlnx_en
%if %{sysctl_update}

sysctl -q -w net.ipv4.tcp_timestamps=0
sysctl -q -w net.ipv4.tcp_sack=0
sysctl -q -w net.ipv4.tcp_low_latency=1
sysctl -q -w net.core.netdev_max_backlog=250000
sysctl -q -w net.core.rmem_max=16777216
sysctl -q -w net.core.wmem_max=16777216
sysctl -q -w net.core.rmem_default=16777216
sysctl -q -w net.core.wmem_default=16777216
sysctl -q -w net.core.optmem_max=16777216
sysctl -q -w net.ipv4.tcp_rmem="4096 87380 16777216"
sysctl -q -w net.ipv4.tcp_wmem="4096 65536 16777216"

if [ -f /etc/sysctl.conf ]; then
perl -ni -e 'if (/\#\# MLXNET tuning parameters \#\#$/) { $filter = 1 }' -e 'if (!$filter) { print }' -e 'if (/\#\# END MLXNET \#\#$/){ $filter = 0 }' /etc/sysctl.conf
cat << EOF >> /etc/sysctl.conf
## MLXNET tuning parameters ##
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_sack = 0
net.ipv4.tcp_low_latency = 1
net.core.netdev_max_backlog = 250000
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 16777216
net.core.wmem_default = 16777216
net.core.optmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
## END MLXNET ##
EOF
fi

%endif

/sbin/depmod -r -ae %{KVERSION}

# END of post -n mlnx_en 

%postun -n mlnx_en
if [ $1 = 0 ]; then  # 1 : Erase, not upgrade
        # Remove previous configuration if exist
        /sbin/depmod -r -ae %{KVERSION}


# Clean sysctl.conf
if [ -f /etc/sysctl.conf ]; then
perl -ni -e 'if (/\#\# MLXNET tuning parameters \#\#$/) { $filter = 1 }' -e 'if (!$filter) { print }' -e 'if (/\#\# END MLXNET \#\#$/){ $filter = 0 }' /etc/sysctl.conf
fi

fi

%files -n mlnx_en -f ofed-files
%defattr(-,root,root,-)
%{LIB_MOD_DIR}/%{install_mod_dir}
%{_mandir}/man7/mlx4_en.7.gz
%{_sbindir}/*
/sbin/*
/etc/modprobe.d/*

%files -n mlnx_en-devel
%defattr(-,root,root,-)
%{_prefix}/src/%{_name}-%{_version}

# END Files

%changelog
* Tue May 1 2012 Vladimir Sokolovsky <vlad@mellanox.com>
- Created spec file for mlnx_en
