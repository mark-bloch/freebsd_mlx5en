%{!?_name: %define _name mellanox-mlnx-en}
%{!?_version: %define _version @VERSION@}
%{!?_release: %define _release @RELEASE@}

Name: %{_name}
Group: System Environment
Version: %{_version}
Release: %{_release}%{?_dist}
License: GPL/BSD
Url: http://www.mellanox.com
Group: System Environment/Kernel
Vendor: Mellanox Technologies Ltd.
Source0: %{_name}-%{_version}.tgz
Source1: mlx4.files
Source2: kmp-tool.sh
Source3: mlx4_core.conf
Source4: mlx4_en.conf
Source5: mlx4_ib.conf
Source6: mlx4.files.sles10
Source7: mlx4.files.sles11
Source10: kmodtool.rh5
Source11: kmodtool.rh7
Provides: %{_name}
Conflicts: mlnx_en
BuildRoot: %{_tmppath}/%{name}-%{version}-build
Summary: mellanox-mlnx-en kernel module(s)

%package KMP
Summary: mellanox-mlnx-en kernel module(s)
Group: System/Kernel
%description KMP
mellanox-mlnx-en kernel module(s)
The driver sources are located at: http://www.mellanox.com/downloads/Drivers/mlnx-en-@VERSION@-@MAJOR_RELEASE@.tgz

%package doc
Summary: Documentation for the Mellanox Ethernet Driver for Linux
Group: System/Kernel

%description doc
Documentation for the Mellanox Ethernet Driver for Linux
The driver sources are located at: http://www.mellanox.com/downloads/Drivers/mlnx-en-@VERSION@-@MAJOR_RELEASE@.tgz

%package sources
Summary: Sources for the Mellanox Ethernet Driver for Linux
Group: System Environment/Libraries

%description sources
Sources for the Mellanox Ethernet Driver for Linux
The driver sources are located at: http://www.mellanox.com/downloads/Drivers/mlnx-en-@VERSION@-@MAJOR_RELEASE@.tgz

%package utils
Summary: Utilities for the Mellanox Ethernet Driver for Linux
Group: System Environment/Libraries

%description utils
Utilities for the Mellanox Ethernet Driver for Linux
The driver sources are located at: http://www.mellanox.com/downloads/Drivers/mlnx-en-@VERSION@-@MAJOR_RELEASE@.tgz

%define __find_requires %{nil}
%define debug_package %{nil}
%define distro_major %(%_sourcedir/kmp-tool.sh get-distro-major)
%define distro %(%_sourcedir/kmp-tool.sh get-distro)

%if "%{_vendor}" == "suse"
%if %{!?KVER:1}%{?KVER:0}
%ifarch x86_64
%define flav debug default kdump smp xen
%else
%define flav bigsmp debug default kdump kdumppae smp vmi vmipae xen xenpae pae
%endif
%endif

%if %{!?KVER:0}%{?KVER:1}
%define flav %(echo %{KVER} | awk -F"-" '{print $3}')
%endif
%endif

%if "%{_vendor}" == "redhat"
%if %{!?KVER:1}%{?KVER:0}
%define flav ""
%endif
%if %{!?KVER:0}%{?KVER:1}
%define flav %(echo %{KVER} | awk -F"el5" '{print $2}')
%define kvariants %(echo %{KVER} | awk -F"el5" '{print $2}')
%if "%{flav}" == ""
%define flav default
%define kvariants default
%endif
%endif
%endif

%if "%{_host_vendor}" == "suse"
BuildRequires: kernel-source kernel-syms
%define install_mod_dir updates/%{name}
%if "%{distro_major}" == "sles10"
%{suse_kernel_module_package -f %{SOURCE6} -x %flav}
%else
%{suse_kernel_module_package -f %{SOURCE7} -x %flav}
%endif
%else
BuildRequires: %kernel_module_package_buildreqs
%define install_mod_dir extra/%{name}
%if "%{distro_major}" == "rhel5"
%{!?kvariants: %define kvariants %(%{SOURCE10} kvariants 2>/dev/null)}
%define kverrel %(%{SOURCE10} verrel %{?KVER} 2>/dev/null)
%global kernel_source() /usr/src/kernels/%kverrel-$([ %{1} = default ] || echo "%{1}-")%_target_cpu
%{expand:%(sh %{SOURCE10} rpmtemplate_kmp %{name} %{kverrel} %{kvariants})}
%global flavors_to_build %{kvariants}
%else
%if "%{distro_major}" == "rhel7"
%{!?kvariant: %define kvariant default}
%define kverrel %(%{SOURCE11} verrel %{?KVER} 2>/dev/null)
%global kernel_source() /usr/src/kernels/%kverrel$([ %{1} = default ] || echo ".%{1}")
%{expand:%(sh %{SOURCE11} rpmtemplate %{name} %{kverrel} %{kvariant})}
%global flavors_to_build %{kvariant}
%else
%kernel_module_package -f %{SOURCE1} %flav
%endif
%endif
%if "%{distro}" == "rhel6.3"
%define __find_provides %{nil}
%endif
%endif

%if %{!?KVER:0}%{?KVER:1}
%define flavors %{flav}
%else
%define flavors %{flavors_to_build}
%endif

%description
This package contains the Linux driver for ConnectX EN Based Network Interface Card with 10GigE Support
The driver sources are located at: http://www.mellanox.com/downloads/Drivers/mlnx-en-@VERSION@-@MAJOR_RELEASE@.tgz

%prep
%setup
set -- *
mkdir source
# mv drivers include scripts/mlnx_en_patch.sh Module.supported kernel_patches kernel_addons makefile Makefile source
mv "$@" source/
mkdir obj

%build
rm -rf $RPM_BUILD_ROOT
export EXTRA_CFLAGS='-DVERSION=\"%version\"'
for flavor in %{flavors}; do
	rm -rf obj/$flavor
	cp -r source obj/$flavor
	cd $PWD/obj/$flavor
	export KSRC=%{kernel_source $flavor}
	export KVERSION=`make -C $KSRC kernelrelease | grep -v make`
	./scripts/mlnx_en_patch.sh
	make KSRC=$KSRC V=0
	cd -
done
gzip -c source/scripts/mlx4_en.7 > mlx4_en.7.gz

cd source/ofed_scripts/utils
python setup.py build
cd -

%install
export INSTALL_MOD_PATH=$RPM_BUILD_ROOT
export INSTALL_MOD_DIR=%install_mod_dir
for flavor in %{flavors}; do 
	cd $PWD/obj/$flavor
	export KSRC=%{kernel_source $flavor}
	export KVERSION=`make -C $KSRC kernelrelease | grep -v make`
	make install KSRC=$KSRC MODULES_DIR=$INSTALL_MOD_DIR DESTDIR=$RPM_BUILD_ROOT
	cd -
done

%if "%{_vendor}" == "redhat"
# Set the module(s) to be executable, so that they will be stripped when packaged.
find %{buildroot} -type f -name \*.ko -exec %{__chmod} u+x \{\} \;
%else
find %{buildroot} -type f -name \*.ko -exec %{__strip} -p --strip-debug --discard-locals -R .comment -R .note \{\} \;
%endif

install -D -m 644 mlx4_en.7.gz $RPM_BUILD_ROOT/%{_mandir}/man7/mlx4_en.7.gz

install -D -m 755 source/ofed_scripts/common_irq_affinity.sh $RPM_BUILD_ROOT/%{_sbindir}/common_irq_affinity.sh
install -D -m 755 source/ofed_scripts/set_irq_affinity.sh $RPM_BUILD_ROOT/%{_sbindir}/set_irq_affinity.sh
install -D -m 755 source/ofed_scripts/show_irq_affinity.sh $RPM_BUILD_ROOT/%{_sbindir}/show_irq_affinity.sh
install -D -m 755 source/ofed_scripts/set_irq_affinity_bynode.sh $RPM_BUILD_ROOT/%{_sbindir}/set_irq_affinity_bynode.sh
install -D -m 755 source/ofed_scripts/set_irq_affinity_cpulist.sh $RPM_BUILD_ROOT/%{_sbindir}/set_irq_affinity_cpulist.sh
install -D -m 755 source/ofed_scripts/sysctl_perf_tuning $RPM_BUILD_ROOT/sbin/sysctl_perf_tuning

install -D -m 644 source/scripts/mlx4_en.modprobe.conf $RPM_BUILD_ROOT/etc/modprobe.d/mlx4_en.conf

mkdir -p $RPM_BUILD_ROOT/%{_prefix}/src
cp -r source $RPM_BUILD_ROOT/%{_prefix}/src/%{name}-%{version}

%if "%{_vendor}" == "redhat"
install -m 644 -D %{SOURCE3} $RPM_BUILD_ROOT/etc/depmod.d/mlx4_core.conf
install -m 644 -D %{SOURCE4} $RPM_BUILD_ROOT/etc/depmod.d/mlx4_en.conf
install -m 644 -D %{SOURCE5} $RPM_BUILD_ROOT/etc/depmod.d/mlx4_ib.conf
%endif

touch ofed-files
cd source/ofed_scripts/utils
python setup.py install -O1 --root=$RPM_BUILD_ROOT --record ../../../ofed-files
cd -

%postun doc
if [ -f %{_mandir}/man7/mlx4_en.7.gz ]; then
        exit 0
fi

%clean
rm -rf %{buildroot}

%files doc
%defattr(-,root,root,-)
%{_mandir}/man7/mlx4_en.7.gz

%files sources
%defattr(-,root,root,-)
%{_prefix}/src/%{name}-%{version}

%files utils -f ofed-files
%defattr(-,root,root,-)
%{_sbindir}/*
/sbin/*

%changelog
* Fri Sep 9 2009 Yevgeny Petrilin <yevgenyp@mellanox.co.il>
- Modified spec file to conform to KMP specifications
