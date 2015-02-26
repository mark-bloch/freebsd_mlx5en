#!/bin/bash

#Get sys path from uname
BASE=$(sysctl kern.version | grep sys | awk -v FS="(obj|sys)" '{print $2}')
MAKEFILES_TO_INCLUDE_PATH=${BASE}/share/mk
SYSDIR=${BASE}sys
export SYSDIR="${SYSDIR}"

declare -A _MODULES=(
        [mlx4]="../drivers/net/mlx4"
        [mlxen]="../drivers/net/mlx4"
        [ibcore]="../drivers/infiniband/core"
        [mlx4ib]="../drivers/infiniband/hw/mlx4"
        [ipoib]="../drivers/infiniband/ulp/ipoib"
)

_MODULES_ORDER=("mlx4" "mlxen" "ibcore" "mlx4ib" "ipoib")

declare -A _MODULES_BUILD_FLAGS=(
        [mlx4]="-j16"
        [mlxen]="-f Makefile.mlxen -j16"
        [ibcore]=""
        [mlx4ib]=""
        [ipoib]=""
)

upvar()
{
    if unset -v "$1"; then           # Unset & validate varname
        if (( $# == 2 )); then
                eval $1=\"\$2\"          # Return single value
        else
                eval $1=\(\"\${@:2}\"\)  # Return array
        fi
    fi
}

remove_duplicates()
{
        local b="$1"
        shift
        upvar $b $( echo "${@}" | tr ' ' '\n' | nl | sort -u -k2 | sort -n | cut -f2-)
}
########################################################
#####                                           ########
#####        INSTALL PACKS                      ########
#####                                           ########
########################################################


remove_duplicates _EN "mlx4" "mlxen"
remove_duplicates _IB "mlx4" "ibcore" "mlx4ib"
remove_duplicates _EN_IB "${_EN[@]}" "${_IB[@]}"
remove_duplicates _IB_IPOIB "${_IB[@]}" "ipoib"
remove_duplicates _ALL "${_IB_IPOIB[@]}" "${_EN[@]}"

INSTALL=false
CLEAN=false
IAM=${0##*/}

usage()
{
        printf "Usage: ./%s [OPTIONS]\n" "${IAM}"
        printf "Script to load FreeBsd mellanox modules.\n"
        printf "Options:\n"
        printf "\t-i                            : Install modules.\n"
        printf "\t-c                            : Run 'make clean cleandepend' before build.\n"
        printf "\t-m <en|ib|en_ib|ib_ipoib|all> : Modules to load.\n"
        printf "\t      \t en       :\tmlx4,mlxen.\n"
        printf "\t      \t ib       :\tmlx4,ibcore,mlx4ib.\n"
        printf "\t      \t en_ib    :\tmlx4,mlxen,ibcore,mlx4ib.\n"
        printf "\t      \t ib_ipoib :\tmlx4,ibcore,mlx4ib,ipoib.\n"
        printf "\t      \t all      :\tdefault, will build and load all modules.\n"
        printf "\t-h                            : Show usage.\n"
}

read_args()
{
        while getopts :m:ihc FLAG; do
                case ${FLAG} in
                        h) usage
                           exit
                           ;;
                        i) INSTALL=true
                           ;;
                        m) case ${OPTARG} in
                                "en") _TO_LOAD=${_EN[@]}
                                        ;;
                                "ib") _TO_LOAD=${_IB[@]}
                                        ;;
                                "en_ib") _TO_LOAD=${_EN_IB[@]}
                                        ;;
                                "ib_ipoib") _TO_LOAD=${_IB_IPOIB[@]}
                                        ;;
                                "all") _TO_LOAD=${_ALL[@]}
                                        ;;
                                \?) exit
                           esac
                           ;;
                        c) CLEAN=true
                           ;;
                        \?)exit
                esac
        done
        if [[ -z "${_TO_LOAD}" ]]; then
                _TO_LOAD=${_ALL[@]}
        fi

}

unload_modules()
{
        for ((i = ${#_MODULES_ORDER[@]} -1 ; i >= 0 ; i--)); do
                kldunload ${_MODULES_ORDER[i]} &> /dev/null
        done
}

containsElement ()
{
        for e in i ${_TO_LOAD[@]}; do
                [[ "$e" == "${1}" ]] && return 0
        done
        return -1
}

build_load()
{
        for ((i = 0 ; i < ${#_MODULES_ORDER[@]} ; i++)); do
                if containsElement "${_MODULES_ORDER[i]}"; then
                        set -e
                        cd ${_MODULES[${_MODULES_ORDER[$i]}]}

                        if ${CLEAN}; then
                                make -m ${MAKEFILES_TO_INCLUDE_PATH} ${_MODULES_BUILD_FLAGS[${_MODULES_ORDER[i]}]} clean cleandepend
                        fi
                        make -m ${MAKEFILES_TO_INCLUDE_PATH} ${_MODULES_BUILD_FLAGS[${_MODULES_ORDER[$i]}]}

                        if ${INSTALL}; then
                                make -m ${MAKEFILES_TO_INCLUDE_PATH} ${_MODULES_BUILD_FLAGS[${_MODULES_ORDER[i]}]} install
                        fi

                        kldload ./${_MODULES_ORDER[$i]}.ko
                        cd -

                        set +e
                fi
        done
}

main()
{
        read_args "$@"
        unload_modules
        build_load
}

main "$@"
