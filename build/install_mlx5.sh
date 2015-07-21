#!/bin/bash

BUILD_SCRIPT="mlx5_build.sh"
#Get sys path from uname
BASE=$(sysctl kern.version | grep sys | awk -v FS="(obj|sys)" '{print $2}')
MAKEFILES_TO_INCLUDE_PATH=${BASE}/share/mk
SYSDIR=${BASE}/sys
export SYSDIR="${SYSDIR}"


cd ${SYSDIR}/modules/linuxapi
make -m ${MAKEFILES_TO_INCLUDE_PATH} all install
cd -
cd ..
bash ${BUILD_SCRIPT} ${BASE}
