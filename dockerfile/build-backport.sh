#!/bin/sh
# Build Alpine's stable port with its original patches, package layout and checks.
# Only the upstream release and its verified archive checksum change.
set -eu
name=$1
version=$2
case "$name/$version" in
    freeunit/1.37.3)
        port=community/freeunit
        checksum=4d2970c5977b10b00d7c57acb54839ee019931173d8aafba79a4840a9738de487b5c664fd6c11780784ae3c53e0d1ea6e560309523decb84f67c122e531826b5
        set -- freeunit freeunit-php85 ;;
    xl2tpd/1.3.21)
        port=main/xl2tpd
        checksum=f77fec98fd06aa98bfae0af1dc179023bbf95fde5c81f5219d3b76976a86a66dfcee40c8f2bf0718ded70b871c4c5616ae9b941d0c801888bed1109008a154f5
        set -- xl2tpd ;;
    *) echo 'Missing reviewed Alpine backport' >&2; exit 1 ;;
esac
ref=42ba8ec62e02237ada5c2cd32db902a3f17942e5
apk add --no-cache alpine-sdk curl
sh /build-tools/download-file.sh "https://codeload.github.com/alpinelinux/aports/tar.gz/$ref" /tmp/aports.tar.gz
echo 'b8a2cd694f5261b5220641a14c3d11cd78d376718bf610a0fd5ca2e85537d614  /tmp/aports.tar.gz' | sha256sum -c -
mkdir -p /work /out
tar xzf /tmp/aports.tar.gz -C /work --strip-components=1 "aports-$ref/$port"
cd "/work/$port"
old=$(sed -n 's/^pkgver=//p' APKBUILD)
sed -i -e "s/^pkgver=.*/pkgver=$version/" -e "s/^pkgrel=.*/pkgrel=0/" \
    -e "s|^[0-9a-f]\{128\}  $name-$old.tar.gz$|$checksum  $name-$version.tar.gz|" APKBUILD
grep -Fxq "$checksum  $name-$version.tar.gz" APKBUILD
if [ "$name" = freeunit ]; then
    # The PHP 8.4 and 8.5 embed libraries share a SONAME. Loading both adapters
    # in the same Unit discovery process can bind php85 to the older library.
    # Build and test the one PHP adapter shipped by this image.
    sed -i -e '/^\s*\.\/configure php --module=php\$_phpver[34] /d' \
        -e 's/php\$_phpver[34]-\(dev\|embed\|opcache\)//g' \
        -e 's/php\$_phpver3 php\$_phpver4 //g' APKBUILD
fi
adduser -D -G abuild build
chown -R build:abuild /work /home/build
# The throwaway signing identity lives on the tmpfs mounted by the Dockerfile.
apk update
su build -c 'abuild-keygen -an >/dev/null 2>&1'
cp /home/build/.abuild/*.pub /etc/apk/keys/
su build -c 'abuild -r'
for package do
    cp "/home/build/packages/${port%/*}/$(apk --print-arch)/$package-$version-r0.apk" /out/
done
cp /home/build/.abuild/*.pub /out/
