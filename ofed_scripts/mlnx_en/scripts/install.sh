#!/bin/bash
# install.sh - installation script for mlnx_en driver

# Initial sanity checks

if [ $UID -ne 0 ]; then
    echo Must be root to run this script.
    exit 1
fi

# Initial value
batch="no"
with_sysctl="1"
with_memtrack="0"
disable_kmp=0
build_only=0
err=0

usage()
{
cat << EOF

    Usage: `basename $0` [--help]: Prints this message
			 [--batch]: Remove all installed components without promt
			 [--disable-kmp]: Disable kernel module package (KMP) support
EOF
}

###############################################################################
#                          Parsing command line                               #
###############################################################################
while [ ! -z "$1" ]; do
        case "$1" in
		-h|--help)
                        usage
                        exit 0
                        ;;
		-b|--batch)
                        batch="yes"
                        ;;
		--build-only)
                        build_only=1
                        ;;
		--without-sysctl)
			with_sysctl="0"
			;;
		--disable-kmp)
			disable_kmp=1
			;;
		--with-memtrack)
			with_memtrack="1"
			;;
		*)
			echo "Bad input parameter: $1"
			usage
			exit 1
			;;
	esac
	shift
done

name=`basename $0`
cd `dirname $0`
package_dir=`pwd`

LOGFILE=/tmp/install-mlx4_en.log.$$

### Local functions

incr_err() {
    let err=$err+1
}

ex() {
    echo "EXEC: $@" >> $LOGFILE
    eval $@ >> $LOGFILE 2>&1
    if [ "$?" != "0" ]; then
        echo "$@   FAILED"
        echo "Please review $LOGFILE"
        exit 1
    fi
}

check_input() {
    if [ "x$1" == "xy" ] \
            || [ "x$1" == "xyes" ] \
            || [ "x$1" == "xY" ] \
            || [ "x$1" == "xYES" ] \
            || [ "x$1" == "x" ]  ; then
            return 1
    else
            return 0
    fi
}


check_prev_install() {
	# Uninstall ofed
	INFO=/etc/infiniband/info
        if [ -x ${INFO} ]; then
                info_prefix=$(${INFO} | grep -w prefix | cut -d '=' -f 2)
                if [ -x ${info_prefix}/sbin/ofed_uninstall.sh ]; then
			if [ "$batch" == "no" ]; then
                                echo -n "Remove currently installed ofed components (${info_prefix}/sbin/ofed_uninstall.sh) (y/n) [y] ? "
                                read force
                        else
                                force="yes"
                        fi
                        check_input $force
                        RC=$?
			if [ $RC == 1 ]; then
                                echo "Cleaning an old distribution at ${info_prefix}"
                                echo "Running: yes | ${info_prefix}/uninstall.sh" >> $LOGFILE
				yes | ${info_prefix}/sbin/ofed_uninstall.sh --unload-modules --force > /dev/null 2>&1
				if [ $? -ne 0 ]; then
					yes | ${info_prefix}/sbin/ofed_uninstall.sh > /dev/null 2>&1
				fi
				if ( ls ${info_prefix}/uninstall*.sh > /dev/null 2>&1 ); then
	                                yes | ${info_prefix}/uninstall*.sh > /dev/null 2>&1
				fi
			else
                        	echo "Cannot continue without removing ofed first."
                        	exit 1
                	fi
		fi
	fi

        # Uninstall ofed rpm
        if (rpm -q ofed-kmp-default > /dev/null 2>&1); then
		if [ "$batch" == "no" ]; then
			echo "Remove currently OFED RPM?"
                        echo -n "This operation is ireversable  (y/n) [y] ? "
                        read force
                else
                        force="yes"
                fi
                check_input $force
                RC=$?
		if [ $RC == 1 ]; then
                        echo "Uninstalling OFED rpm"
			echo "Removing OFED" >> $LOGFILE 2>&1
			rpm -e ofed-kmp-default > /dev/null 2>&1
		else
			echo "Cannot continue without uninstalling OFED first."
      			exit 1
		fi
        fi

	# Uninstall mtnic driver
        if [ -d /lib/modules/${KER_UNAME_R}/kernel/drivers/net/mtnic ]; then
                echo Removing mtnic driver ...
                rmmod mtnic > /dev/null 2>&1
                rm -rf /lib/modules/${KER_UNAME_R}/kernel/drivers/net/mtnic
        fi

	# Uninstall mlnx_en
	if [ -d /tmp/mlnx_en ] ; then
		if [ "$batch" == "no" ]; then
			echo -n "Remove currently installed mlnx_en  (y/n) [y] ? "
                        read force
                else
                        force="yes"
                fi
                check_input $force
                RC=$?
		if [ $RC == 1 ]; then
                        echo "Cleaning an old distribution at /tmp/mlnx_en"
			echo "Removing $src_path" >> $LOGFILE 2>&1
        		/sbin/mlnx_en_uninstall.sh >> $LOGFILE 2>&1
			/bin/rm -rf $src_path > /dev/null 2>&1
			/bin/rm -rf $include_path > /dev_null 2>&1
		else
			echo "Cannot continue without removing $target_path first."
      			exit 1
		fi
	fi

	if (rpm -q mlnx_en > /dev/null 2>&1 || rpm -q mlnx-en-devel > /dev/null 2>&1 || rpm -q mlnx-ofc > /dev/null 2>&1); then
                if [ "$batch" == "no" ]; then
                        echo -n "Remove currently installed mlnx_en  (y/n) [y] ? "
                        read force
                else
                        force="yes"
                fi
                check_input $force
                RC=$?
		if [ $RC == 1 ]; then
			echo "Removing previous installation"
			cp mlnx_en_uninstall.sh /sbin/
			/sbin/mlnx_en_uninstall.sh
                else
                        echo "Cannot continue without removing previous installation."
                        exit 1
                fi
        fi

	if (rpm -qa 2> /dev/null | grep -q "mlnx-en" || dpkg --list 2> /dev/null | grep -q "mlnx"); then
                if [ "$batch" == "no" ]; then
                        echo -n "Remove currently installed mlnx-en package  (y/n) [y] ? "
                        read force
                else
                        force="yes"
                fi
                check_input $force
                RC=$?
		if [ $RC == 1 ]; then
			echo "Removing mlnx-en package"
			if ( grep "Ubuntu" /etc/issue > /dev/null 2>&1); then
				rpm -e --force-debian `rpm -qa 2> /dev/null | grep -E "mstflint|mlnx.en"` > /dev/null 2>&1
				apt-get remove -y `dpkg --list | grep -E "mstflint|mlnx" | awk '{print $2}'` > /dev/null 2>&1
			else
				rpm -e `rpm -qa 2> /dev/null | grep -E "mstflint|mlnx.en"` > /dev/null 2>&1
			fi
		else
			echo "Cannot continue without removing mlnx-en package."
			exit 1
		fi
	fi
}

is_installed()
{
	/bin/rpm -q $1 > /dev/null 2>&1
}

#Gives a warning if Network Manager is set
check_network_manager() {
	local R="\[\033[0;31m\]"    # red
	local manager=""
	if [ -f "/etc/sysconfig/network/config" ]; then
		manager=`cat /etc/sysconfig/network/config | grep "^NETWORKMANAGER=yes"`
		if [ "$manager" != "" ]; then
			echo
			echo "WARNING: Please set NETWORKMANAGER=no in the /etc/sysconfig/network/config"
			echo
		fi
	fi
}

# Check that a previous version is loaded
check_loaded_modules() {
    if ( `/sbin/lsmod | grep mlx4 > /dev/null 2>&1`); then
        if [ "$batch" == "no" ]; then
            echo; echo "   In order for newly installed mlx4 modules to load, "
            echo "   previous modules must first be unloaded."
            echo -n "   Do you wish to reload the driver now? (y/n) [y] "
            read force
        else
            force="yes"
        fi
        check_input $force
        RC=$?
        if [ $RC == 1 ]; then
            echo "Reloading mlx4 modules"
            if [ "$with_memtrack" == "1" ]; then
                /sbin/rmmod memtrack > /dev/null 2>&1
            fi
            /sbin/rmmod mlx4_fc > /dev/null 2>&1
            /sbin/rmmod mlx4_en > /dev/null 2>&1
            /sbin/rmmod mlx4_ib > /dev/null 2>&1
            /sbin/rmmod mlx4_core > /dev/null 2>&1

            # load the new driver
            /sbin/modprobe mlx4_en > /dev/null 2>&1
        else
            echo "WARNING: Loading the new installed modules could cause symbol confilcts"
            echo "         Please unload all prevoius versions of mlx4 modules"
            echo
        fi
    fi
}

TOPDIR=/tmp/MLNX_EN
ARCH=`rpm --eval %{_target_cpu} 2> /dev/null || uname -m`
KER_UNAME_R=`uname -r`
KER_PATH=/lib/modules/${KER_UNAME_R}/build

if [ ! -d "${KER_PATH}/" ]; then
	echo
	echo "ERROR: No kernel sources/headers found for $KER_UNAME_R kernel."
	echo "Cannot continue..."
	exit 1
fi

cd ${package_dir}

if [ $build_only -eq 0 ]; then
	echo "Installing mlnx_en for Linux"
	echo "Starting installation at `date`..." | tee -a $LOGFILE

	# Clean old source code
	check_prev_install

	# Add th uninstall script
	cp mlnx_en_uninstall.sh /sbin/
fi

# Create installation dir
if [ -d $TOPDIR ]; then
	ex /bin/rm -rf $TOPDIR
fi

ex /bin/mkdir $TOPDIR
ex /bin/mkdir ${TOPDIR}/BUILD
ex /bin/mkdir ${TOPDIR}/SRPMS
ex /bin/mkdir ${TOPDIR}/RPMS
ex /bin/mkdir ${TOPDIR}/SOURCES

distro_rpm=`rpm -qf /etc/issue 2> /dev/null | head -1`
case $distro_rpm in
	redhat-release-5Server-5.2*|centos-release-5-2.el5.centos*)
	distro=rhel5.2
	dist_rpm=rhel5u2
	;;
	redhat-release-5Server-5.3*|redhat-release-5Client-5.3*|centos-release-5-3*)
	distro=rhel5.3
	dist_rpm=rhel5u3
	;;
	redhat-release-5Server-5.4*|redhat-release-5Client-5.4*|entos-release-5-4*)
	distro=rhel5.4
	dist_rpm=rhel5u4
	;;
	redhat-release-5Server-5.5*|redhat-release-5Client-5.5*|centos-release-5-5*|enterprise-release-5*)
	if (grep -q XenServer /etc/issue 2> /dev/null); then
		distro=xenserver6
		dist_rpm=xenserver6
	else
		distro=rhel5.5
		dist_rpm=rhel5u5
	fi
	;;
	redhat-release-5Server-5.6*|redhat-release-5Client-5.6*|centos-release-5-6*)
	distro=rhel5.6
	dist_rpm=rhel5u6
	;;
	redhat-release-5Server-5.7*|redhat-release-5Client-5.7*|centos-release-5-7*)
	if (grep -q XenServer /etc/issue 2> /dev/null); then
		distro=xenserver6.1
		dist_rpm=xenserver6u1
	else
		distro=rhel5.7
		dist_rpm=rhel5u7
	fi
	;;
	redhat-release-5Server-5.8*|redhat-release-5Client-5.8*|centos-release-5-8*)
	distro=rhel5.8
	dist_rpm=rhel5u8
	;;
	redhat-release-5Server-5.9*|redhat-release-5Client-5.9*|centos-release-5-9*)
	distro=rhel5.9
	dist_rpm=rhel5u9
	;;
	redhat-release-server-*6.0*|redhat-release-client-*6.0*|centos-release-6-0*|centos-*6Server-*6.0*|enterprise-release-*6.0*)
	distro=rhel6.0
	dist_rpm=rhel6u0
	;;
	redhat-release-server-*6.1*|redhat-release-client-*6.1*|centos-*6Server-*6.1*|centos-release-6-1*|enterprise-release-*6.1*)
	distro=rhel6.1
	dist_rpm=rhel6u1
	;;
	redhat-release-server-*6.2*|redhat-release-client-*6.2*|centos-*6Server-*6.2*|centos-release-6-2*|enterprise-release-*6.2*)
	distro=rhel6.2
	dist_rpm=rhel6u2
	;;
	redhat-release-server-*6.3*|redhat-release-client-*6.3*|centos-*6Server-*6.3*|centos-release-6-3*|enterprise-release-*6.3*)
	distro=rhel6.3
	dist_rpm=rhel6u3
	;;
	redhat-release-server-*6.4*|redhat-release-client-*6.4*|centos-*6Server-*6.4*|centos-release-6-4*|enterprise-release-*6.4*)
	distro=rhel6.4
	dist_rpm=rhel6u4
	;;
	redhat-release-server-*6.5*|redhat-release-client-*6.5*|centos-*6Server-*6.5*|centos-release-6-5*|enterprise-release-*6.5*)
	distro=rhel6.5
	dist_rpm=rhel6u5
	;;
	redhat-release-server-*6.9*)
	distro=rhel7.0
	dist_rpm=rhel7u0
	;;
	oraclelinux-release-6Server-4*)
	distro=oel6.4
	dist_rpm=oel6u4
	;;
	oraclelinux-release-6Server-3*)
	distro=oel6.3
	dist_rpm=oel6u3
	;;
	oraclelinux-release-6Server-2*)
	distro=oel6.2
	dist_rpm=oel6u2
	;;
	oraclelinux-release-6Server-1*)
	distro=oel6.1
	dist_rpm=oel6u1
	;;
	sles-release-10-15.35)
	distro=sles10sp2
	dist_rpm=sles10sp2
	;;
	sles-release-10-15.45.8)
	distro=sles10sp3
	dist_rpm=sles10sp3
	;;
	sles-release-10-15.57.1)
	distro=sles10sp4
	dist_rpm=sles10sp4
	;;
	sles-release-11-72.13)
	distro=sles11
	dist_rpm=sles11sp0
	;;
	sles-release-11.1-1.152)
	distro=sles11sp1
	dist_rpm=sles11sp1
	;;
	sles-release-11.2*)
	distro=sles11sp2
	dist_rpm=sles11sp2
	;;
	sles-release-11.3*)
	distro=sles11sp3
	dist_rpm=sles11sp3
	;;
	fedora-release-14*)
	distro=fc14
	dist_rpm=fc14
	;;
	fedora-release-15*)
	distro=fc15
	dist_rpm=fc15
	;;
	fedora-release-16*)
	distro=fc16
	dist_rpm=fc16
	;;
	fedora-release-17*)
	distro=fc17
	dist_rpm=fc17
	;;
	fedora-release-18*)
	distro=fc18
	dist_rpm=fc18
	;;
	fedora-release-19*)
	distro=fc19
	dist_rpm=fc19
	;;
	openSUSE-release-11.1*)
	distro=openSUSE11sp1
	dist_rpm=openSUSE11sp1
	;;
	openSUSE-release-12.1*)
	distro=openSUSE12sp1
	dist_rpm=openSUSE12sp1
	;;
	openSUSE-release-13.1*)
	distro=openSUSE13sp1
	dist_rpm=openSUSE13sp1
	;;
	*)
	if [ -f "/etc/lsb-release" ]; then
		dist_rpm=`lsb_release -s -i | tr '[:upper:]' '[:lower:]'`
		dist_rpm_ver=`lsb_release -s -r`
		distro=$dist_rpm$dist_rpm_ver
	else
		distro=unsupported
		dist_rpm=unsupported
	fi
	;;
esac

build_requires_common="gcc make patch"
build_requires_redhat="$build_requires_common redhat-rpm-config"
build_requires_suse="$build_requires_common kernel-syms"
missing_rpms=""

echo "Verifying dependencies"
case "$distro" in
	rhel*)
		for package in $build_requires_redhat; do
			if ! is_installed "$package"; then
				missing_rpms="$missing_rpms $package"
			fi
		done
	;;
	sles*)
		for package in $build_requires_suse; do
			if ! is_installed "$package"; then
				missing_rpms="$missing_rpms $package"
			fi
		done
	;;
esac

if [ ! -z "$missing_rpms" ]; then
	echo "mlnx_en requires the following RPM(s) to be installed: $missing_rpms"
	exit 1
fi


if [ "$dist_rpm" == "ubuntu" ]; then
	DPKG_BUILDPACKAGE="/usr/bin/dpkg-buildpackage"
	for package in mlnx-en mstflint
	do
		debs=`/bin/ls DEBS/${package}* 2> /dev/null`
		if [ -n "$debs" ]; then
			if [ $build_only -eq 0 ]; then
				ex "dpkg -i $DPKG_FLAGS $debs"
			fi
		else
			gz=`ls -1 ${package_dir}/SOURCES/${package}*`
			cd ${TOPDIR}/BUILD
			ex "cp $gz ."
			ex "tar xzf $gz"
			cd ${package}*
			ex "$DPKG_BUILDPACKAGE -us -uc"
			mkdir -p $package_dir/DEBS > /dev/null 2>&1
			cp -a ${TOPDIR}/BUILD/*.deb $package_dir/DEBS > /dev/null 2>&1
			if [ $build_only -eq 0 ]; then
				ex "dpkg -i $DPKG_FLAGS ${TOPDIR}/BUILD/${package}*.deb"
			fi
		fi
	done
else # not ubuntu
	echo "Building mlnx_en binary RPMs"
	target_cpu=`rpm --eval %_target_cpu`
	case "$dist_rpm" in
		rhel5*)
		if [ "$target_cpu" == "i386" ]; then
			target_cpu=i686
		fi
		;;
	esac

	kmp=1

	if ! ( /bin/rpm -qf /lib/modules/$KER_UNAME_R/build/scripts > /dev/null 2>&1 ); then
		kmp=0
	fi

	if [ $kmp -eq 1 ]; then
		case $distro in
		rhel5.2 | oel* | fc* | xenserver*)
		kmp=0
		;;
		esac
	
		case $KER_UNAME_R in
		*xs*|*fbk*|*fc*|*debug*|*uek*)
		kmp=0
		;;
		esac
	fi

	if [[ "$distro" == "rhel6.5" && ! "$KER_UNAME_R" =~ "2.6.32-422" ]] ||
	   [[ "$distro" == "rhel6.4" && ! "$KER_UNAME_R" =~ "2.6.32-358" ]] ||
	   [[ "$distro" == "rhel6.3" && ! "$KER_UNAME_R" =~ "2.6.32-279" ]] ||
	   [[ "$distro" == "rhel6.2" && ! "$KER_UNAME_R" =~ "2.6.32-220" ]] ||
	   [[ "$distro" == "rhel6.1" && ! "$KER_UNAME_R" =~ "2.6.32-131" ]]; then
		kmp=0
	fi


	if [ $disable_kmp -eq 1 ]; then
		kmp=0
	fi

	case $distro in
	xenserver*)
	TOPDIR="/usr/src/redhat"
	;;
	esac

	cmd="rpmbuild --rebuild \
		 --define '_dist .${dist_rpm}' --define '_target_cpu $target_cpu' \
		 --define '_topdir $TOPDIR' --define 'sysctl_update $with_sysctl' --define 'MEMTRACK $with_memtrack'"

	if [ $kmp -eq 1 ]; then
		SRPM=`ls -1 ${package_dir}/SRPMS/*mlnx-en*`
	else
		SRPM=`ls -1 ${package_dir}/SRPMS/*mlnx_en*`
		rel=`rpm --queryformat "[%{RELEASE}]\n" -qp $SRPM`
		cmd="$cmd --define '_release ${rel}.${KER_UNAME_R//-/_}'"
	fi

	case $distro in
	rhel6.3)
	cmd="$cmd --define '__find_provides %{nil}'"
	;;
	esac

	cmd="$cmd $SRPM"

	ex $cmd

	mkdir -p $package_dir/RPMS/$dist_rpm/$target_cpu/ > /dev/null 2>&1
	cp -a ${TOPDIR}/RPMS/${target_cpu}/*mlnx* $package_dir/RPMS/$dist_rpm/$target_cpu/ > /dev/null 2>&1

	if [ $build_only -eq 0 ]; then
		echo "Installing RPMs"
		ex "rpm -ivh --nodeps ${TOPDIR}/RPMS/${target_cpu}/*mlnx*"

		/sbin/depmod

		# Install mstflint
		if (rpm -q zlib-devel > /dev/null); then
		    echo "Installing mstflint"
		    rpm -e mstflint > /dev/null 2>&1
		    rpm -e mstflint-debuginfo > /dev/null 2>&1
		    cmd="rpmbuild --rebuild --define '_topdir $TOPDIR' ${package_dir}/SRPMS/mstflint*"
		    ex $cmd
		    ex "rpm -ivh ${TOPDIR}/RPMS/${ARCH}/mstflint*"
		else
		    echo "no zlib on the machine, skipping mstflint installation"
		fi

		cp -a ${TOPDIR}/RPMS/${ARCH}/mstflint* $package_dir/RPMS/$dist_rpm/$target_cpu/ > /dev/null 2>&1

		# Check Network Manager
		check_network_manager
	fi
fi # ubuntu

# Check that a previous version is loaded
if [ $build_only -eq 0 ]; then
	check_loaded_modules

	if [ $err -eq 0 ]; then
	    echo "Installation finished successfully."
	    /bin/rm $LOGFILE
	    /bin/rm -rf $TOPDIR
	else
	    echo "Installation finished with errors."
	    echo "See $LOGFILE"
	fi
fi
