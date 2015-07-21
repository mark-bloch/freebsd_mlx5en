#!/bin/bash

RELEASE_DIR="/mswg/release/freebsd/src"
BUILD_PACK_MLX4_SCRIPT="build_pack.sh"
BUILD_PACK_MLX5_SCRIPT="build_mlx5_pack.sh"
BUILD_PACK_SCRIPT=""
DEFAULT_RELEASE="latest"
RELEASE=""
#default branch to create release pack of.
BRANCH=$(git symbolic-ref HEAD | sed -e "s/^refs\/heads\///")
IAM=${0##*/}
set -e

usage()
{
        printf "Usage: ./${IAM} [OPTIONS] \n"
        printf "Script to push release to mswg dir.\n"
        printf "Options:\n"
        printf "\t-b <branch>         : what branch to tar.gz.\n"
        printf "\t-b <tag>            : what tag to tar.gz.\n"
        printf "\t-b <commit_sha>     : What commit to use as head , that tree will be tar.gz.\n"
        printf "\t-r <release>        : What symbol link to create/change, default latest\n"
       printf "\t-v <mlx4/mlx5>      : What release to publish, mlx4/mlx5\n"
        printf "\t-h                  : Show usage.\n"
}


read_args()
{
        while getopts :v:b:r:h flag; do
                case ${flag} in
                        b)      BRANCH=$OPTARG
                                ;;

                        h)      usage
                                exit
                                ;;

                        r)      RELEASE=$OPTARG
                                ;;

                       v)      case ${OPTARG} in
                                       "mlx4") BUILD_PACK_SCRIPT=${BUILD_PACK_MLX4_SCRIPT}
                                               ;;

                                       "mlx5") BUILD_PACK_SCRIPT=${BUILD_PACK_MLX5_SCRIPT}
                                               ;;
                                       \?) exit
                               esac
                               ;;

                        \?)     exit
                esac
        done
       if [ -z "${BUILD_PACK_SCRIPT}" ]; then
		echo "Must give mlx4/mlx5 arg"
		exit
       fi
       if [ "${BUILD_PACK_SCRIPT}" == "${BUILD_PACK_MLX5_SCRIPT}" ] && [ -z "${RELEASE}" ]; then
               DEFAULT_RELEASE+="-mlx5"
       fi
}


main()
{
        read_args $*

        if [ -z "${RELEASE}" ]; then
                RELEASE=${DEFAULT_RELEASE}
        fi
        NAME=${BRANCH}
        bash ${BUILD_PACK_SCRIPT} -b ${BRANCH}
        FILE=$(ls *${NAME}* | head -n 1)

        FINAL_FILE_NAME=$(date +"%m_%d_%Y-%H_%M")-${FILE}
        mkdir -p ${RELEASE_DIR}/${BRANCH}
        FINAL_FILE_PATH=${RELEASE_DIR}/${BRANCH}/${FINAL_FILE_NAME}
        cp ${FILE} ${FINAL_FILE_PATH}

        if [ -f "${RELEASE_DIR}/${RELEASE}" ]; then
                rm -f "${RELEASE_DIR}/${RELEASE}"
        fi

        ln -s ${FINAL_FILE_PATH} ${RELEASE_DIR}/${RELEASE}
        rm ${FILE}
}

main "$@"
