#!/bin/bash

set -o errexit
set -x

CFLAGS="-Werror"
SPARSE_FLAGS=""
EXTRA_OPTS=""
TARGET="x86_64-native-linuxapp-gcc"

function configure_ovs()
{
    git clone https://github.com/openvswitch/ovs.git ovs_src
    pushd ovs_src
    ./boot.sh && ./configure $* || { cat config.log; exit 1; }
    make -j4
    popd
}

function configure_ovn()
{
    configure_ovs
    ./boot.sh && ./configure --with-ovs-source=$PWD/ovs_src $* || \
    { cat config.log; exit 1; }
}

OPTS="$EXTRA_OPTS $*"

if [ "$CC" = "clang" ]; then
    export OVS_CFLAGS="$CFLAGS -Wno-error=unused-command-line-argument"
elif [[ $BUILD_ENV =~ "-m32" ]]; then
    # Disable sparse for 32bit builds on 64bit machine
    export OVS_CFLAGS="$CFLAGS $BUILD_ENV"
else
    OPTS="$OPTS --enable-sparse"
    export OVS_CFLAGS="$CFLAGS $BUILD_ENV $SPARSE_FLAGS"
fi

if [ "$TESTSUITE" ]; then
    # 'distcheck' will reconfigure with required options.
    # Now we only need to prepare the Makefile without sparse-wrapped CC.
    configure_ovn

    export DISTCHECK_CONFIGURE_FLAGS="$OPTS --with-ovs-source=$PWD/ovs_src"
    if ! make distcheck -j4 TESTSUITEFLAGS="-j4 -k ovn" RECHECK=yes; then
        # testsuite.log is necessary for debugging.
        echo "******** NUMS : echoing 168 result **********"
        pwd
        ls -l
        cat ovn-2.12.90/_build/sub/tests/testsuite.dir/168/testsuite.log
        echo "******* NUMS : echoing 169 result ***********"
        cat ovn-2.12.90/_build/sub/tests/testsuite.dir/169/testsuite.log
        echo "******* NUMS 3333 : echoing 170 result **********"
        cat ovn-2.12.90/_build/sub/tests/testsuite.dir/170/testsuite.log
        echo "*** NUMS 444 : echoing 171 result *********"
        cat ovn-2.12.90/_build/sub/tests/testsuite.dir/171/testsuite.log
        echo "**** NUMS 5555 : echoing 178 result *********"
        cat ovn-2.12.90/_build/sub/tests/testsuite.dir/178/testsuite.log
        echo "***********SIDDIQUE **************"
        cat ovn-2.12.90/_build/sub/tests/testsuite.log
        exit 1
    fi
else
    configure_ovn $OPTS
    make selinux-policy

    make -j4
fi

exit 0
