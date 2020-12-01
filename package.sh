#!/bin/bash
tag="$(git describe --tags)"
tag="$(echo "${tag}" | sed -E 's/^v//')"
VERSION="${VERSION:-$tag}"
arch="$(dpkg --print-architecture)"
ARCH="${ARCH:-$arch}"
set -eux
SCRIPT=$(readlink -f "$0")
# Absolute path this script is in, thus /home/user/bin
SCRIPTPATH=$(dirname "$SCRIPT")
pushd "${SCRIPTPATH}"
goarch=$ARCH
if [ $goarch == 'armhf' ] 
then 
  goarch='arm'
fi
GOARCH=$goarch go build
mkdir -p ./DEBIAN/usr/bin
cp hpsdrconnector ./DEBIAN/usr/bin
export ARCH
export VERSION
envsubst <DEBIAN/control.template >DEBIAN/control
DEB_FILE="hpsdrconnector_${VERSION}_${ARCH}.deb"
dpkg-deb -b . "$DEB_FILE"
popd