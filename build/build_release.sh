#!/bin/bash

RELEASE_DIR="/mswg/release/freebsd/src"
BUILD_PACK_SCRIPT="build_pack.sh"
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
        printf "\t-h                  : Show usage.\n"
}


read_args()
{
        while getopts :b:r:h flag; do
                case ${flag} in
                        b)      BRANCH=$OPTARG
                                ;;

                        h)      usage
                                exit
                                ;;

                        r)      RELEASE=$OPTARG
                                ;;

                        \?)     exit
                esac
        done
}


main()
{
        read_args $*

        if [ -z "${RELEASE}" ]; then
                RELEASE=${DEFAULT_RELEASE}
        fi
        NAME=freebsd-${BRANCH}
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
