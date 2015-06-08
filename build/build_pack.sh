#!/bin/bash

# Which files/dirs to include in the final packge file.
_DEFAULT=("include" \
          "drivers" \
          "build/install.sh")

_EN_ONLY=("include" \
          "drivers/net/mlx4" \
          "build/install.sh")

_IB_ONLY=("include" \
          "drivers/net/mlx4" \
          "drivers/infiniband/hw/mlx4" \
          "drivers/infiniband/core" \
          "build/install.sh")

_IB_AND_IPOIB=("include" \
               "drivers/net/mlx4" \
               "drivers/infiniband/hw/mlx4" \
               "drivers/infiniband/core" \
               "drivers/infiniband/ulp/ipoib" \
               "build/install.sh")

_TO_INCLUDE=("${_DEFAULT[@]}")


##############################################
####  We assume we are inside a git repo  ####
##############################################
#default branch to tar.gz is the current branch.
BRANCH=$(git symbolic-ref HEAD | sed -e "s/^refs\/heads\///")
# The git repo url.
GIT_REPO=$(git config --get remote.origin.url)

##################################
## BLACK MAGIC, DON'T LOOK DOWN ##
##################################
#   #     #     #     #     #   ##
#  # #   # #   # #   # #   # #  ##
# #   # #   # #   # #   # #   # ##
##     #     #     #     #     ###
##################################

IAM=${0##*/}
LOCAL=false
set -e

usage()
{
        printf "Usage: ./${IAM} [OPTIONS] \n"
        printf "Script to clone and tar.gz a git repo.\n"
        printf "Options:\n"
        printf "\t-b <branch>         : what branch to tar.gz.\n"
        printf "\t-b <tag>            : what tag to tar.gz.\n"
        printf "\t-b <commit_sha>     : What commit to use as head , that tree will be tar.gz.\n"
        printf "\t-c <en|ib|ib_ipoib> : include just those modules:\n"
        printf "\t                    \ten:       mlx4, mlxen.\n"
        printf "\t                    \tib:       mlx4,ibcore,mlx4ib.\n"
        printf "\t                    \tib_ipoib: mlx4,ibcore,mlx4ib,ipoib.\n"
        printf "\t-l                  : use local git repo as source.\n"
        printf "\t-h                  : Show usage.\n"
}

cleanup_local()
{
        rm -f ${TMP_DIR}/${FILE_NAME}
        rm -f ${TMP_DIR}/${FILE_NAME}.tar.gz
}
cleanup_remote()
{
        rm -rf ${TMP_DIR}
}

clone_repo_and_switch_branch()
{
        git clone ${GIT_REPO} ${FILE_NAME}
        cd ${FILE_NAME}
        git checkout ${BRANCH}
        cd ..
}

tar_repo()
{
        tar -czf ${FILE_NAME}.tar.gz \
                        $(eval echo ${FILE_NAME}/{$(echo "${_TO_INCLUDE[@]}" | tr ' ' , )})
}

read_args()
{
        while getopts :b:c:hl FLAG; do
                case ${FLAG} in
                        b)      BRANCH=$OPTARG
                                ;;

                        h)      usage
                                exit
                                ;;

                        c)      case ${OPTARG} in
                                        "en") _TO_INCLUDE=("${_EN_ONLY[@]}")
                                                ;;
                                        "ib") _TO_INCLUDE=("${_IB_ONLY[@]}")
                                                ;;
                                        "ib_ipoib") _TO_INCLUDE=("${_IB_AND_IPOIB[@]}")
                                                ;;
                                        \?) exit
                                esac
                                ;;
                        l)      TMP_DIR=$(git rev-parse --show-toplevel)
                                LOCAL=true
                                ;;

                        \?)     exit
                esac
        done

}

main()
{
        read_args $*

        #if we use the local repo, no need to create dir and set trap.
        if ! ${LOCAL}; then
                TMP_DIR=`mktemp -d`
                trap cleanup_remote 0
        else
                trap cleanup_local 0
        fi

        FILE_NAME=freebsd-${BRANCH}
        pushd ${TMP_DIR}

        #if we use the local repo, no need to clone.
        if ! ${LOCAL}; then
                clone_repo_and_switch_branch
        else
                #because we don't clone and create a dir,
                #create a symbol link for the tar process to use as the root dir.
                ln -s . ${FILE_NAME}
        fi

        tar_repo
        popd
        cp ${TMP_DIR}/${FILE_NAME}.tar.gz ${FILE_NAME}.tar.gz
}

main "$@"
