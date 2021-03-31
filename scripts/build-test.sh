#!/bin/bash

BINDIR=$(dirname $(readlink -f $0))
cd $BINDIR
for DISTRO in fedora-35 ubuntu-20.10 arch-20210321 alpine-20210212; do
    ./build-image.sh $DISTRO
done

# Make a machine sounds like a jet or melt CPUs..
docker-compose up
