#!/bin/bash

DISTRO=$1
case $DISTRO in
    fedora-35|ubuntu-20.10|arch-20210321|alpine-20210212)
        ;;
    *)
        echo "error: unknown distro. choose one of <ubuntu-20.10|fedora-35|arch-20210321>" >&2
        exit 1
        ;;
esac

if [[ -z $KERNEL_SOURCE ]]; then
    KERNEL_SOURCE=/lib/modules/$(uname -r)
fi

if ! [[ -e $KERNEL_SOURCE ]]; then
    echo "error: kernel headers not found" >&2
    exit 1
fi

BINDIR=$(readlink -f $(dirname $0))
cd $BINDIR
ROOTDIR=$(git rev-parse --show-toplevel)
cd $ROOTDIR
UNIQUE=$(tr -dc '[:alnum:]' < /dev/urandom |head -c 16)
TEMPDIR=$(mktemp -p $ROOTDIR -d)
git archive --prefix=redbpf/ --format=tar -o $TEMPDIR/$UNIQUE.tar HEAD
while read SM_TAR; do
    tar -Af $TEMPDIR/${UNIQUE}.tar ${SM_TAR}
    rm -f ${SM_TAR}
done < <(git submodule foreach -q \
             "git archive --prefix=redbpf/\$sm_path/ --format=tar -o ${UNIQUE}.tar HEAD; echo \$sm_path/${UNIQUE}.tar")
cd $TEMPDIR
KERNEL_HEADERS_TAR=$(uname -r).tar
tar -hcf $KERNEL_HEADERS_TAR $KERNEL_SOURCE

cp $BINDIR/Dockerfile-${DISTRO} Dockerfile
docker build -t redbpf-build-env:${DISTRO} \
       --build-arg REDBPF_TAR=${UNIQUE}.tar \
       --build-arg KERNEL_HEADERS_TAR=${KERNEL_HEADERS_TAR} .

rm -rf ${TEMPDIR:?}
