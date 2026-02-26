#!/bin/bash

# NOTE: This build script is designed to run within a Docker environment,
# with the corresponding Dockerfile located in the project root folder.

# Arguments:
#   -f: Soft clean, ensuring re-build of CST
#   -F: Hard clean, ensuring checkout and build of all dependencies
#   -with-pkcs11: Build CST without PKCS#11 OpenSSL engine
#   -no-pqc: Build CST without PQC support
#   -with-usb: Build CST without USB support
#   -verbose: Enable verbose build output
#
# Environment Variables:
#   OPENSSL_PATH: Path to the OpenSSL installation. If not set, OpenSSL will be built from source.
#   libp11_DIR: Path to libp11 installation. If not set, libp11, will be built from source.
#   json_c_DIR: Specifies the path to an existing JSON-C installation. If not provided, JSON-C will be built from source.
#   liboqs_DIR: Path to the liboqs installation. If not set, liboqs will be built from source.
#   oqsprovider_DIR: Path to the oqsprovider installation. If not set, oqsprovider will be built from source.
#   hidapi_DIR: Path to the hidapi installation. If not set, hidapi will be built from source.
#   OSTYPE: Specifies the operating system type. Possible values: linux32, linux64, mingw32, mingw64.

SRC_DIR=$(pwd)
BUILD_DIR="build"
DEPS_DIR=".deps"
VERBOSE=false
PKCS11_SUPPORT=false
PQC_SUPPORT=true
USB_SUPPORT=false
JSON_SUPPORT=true
CMAKE_GENERATOR="Unix Makefiles"
EXTRA_CONFIG=""
EXTRA_CFLAGS=""
EXTRA_LDFLAGS=""

# Check for arguments
for arg in "$@"
do
    case $arg in
        -f)
            rm -rf $BUILD_DIR
            ;;
        -F)
            rm -rf $BUILD_DIR $DEPS_DIR
            ;;
        -with-pkcs11)
            PKCS11_SUPPORT=true
            ;;
        -no-pqc)
            PQC_SUPPORT=false
            ;;
        -with-usb)
            USB_SUPPORT=true
            ;;
        -no-json)
            JSON_SUPPORT=false
            ;;
        -verbose)
            VERBOSE=true
            ;;
    esac
done

if [ "$OSTYPE" == "mingw32" ]; then
    CMAKE_TOOLCHAIN_FILE="-DCMAKE_TOOLCHAIN_FILE=$(pwd)/cmake/mingw-w64-i686-toolchain.cmake"
elif [ "$OSTYPE" == "mingw64" ]; then
    CMAKE_TOOLCHAIN_FILE="-DCMAKE_TOOLCHAIN_FILE=$(pwd)/cmake/mingw-w64-x86_64-toolchain.cmake"
elif [ "$OSTYPE" == "linux32" ]; then
    CMAKE_TOOLCHAIN_FILE="-DCMAKE_TOOLCHAIN_FILE=$(pwd)/cmake/linux-i386-gcc-toolchain.cmake"
elif [ "$OSTYPE" == "linux64" ]; then
    CMAKE_TOOLCHAIN_FILE="-DCMAKE_TOOLCHAIN_FILE=$(pwd)/cmake/linux-x86_64-gcc-toolchain.cmake"
else
    CMAKE_TOOLCHAIN_FILE=""
fi

if [ "$OSTYPE" == "mingw32" ]; then
    OPENSSL_CONFIG="mingw --cross-compile-prefix=i686-w64-mingw32-"
    EXTRA_CONFIG="--host=i686-w64-mingw32"

elif [ "$OSTYPE" == "mingw64" ]; then
    OPENSSL_CONFIG="mingw64 --cross-compile-prefix=x86_64-w64-mingw32-"
    EXTRA_CONFIG="--host=x86_64-w64-mingw32"

elif [ "$OSTYPE" == "linux32" ]; then
    OPENSSL_CONFIG="linux-generic32 -m32"
    EXTRA_CFLAGS="-m32"
    EXTRA_LDFLAGS="-m32"
    EXTRA_CONFIG="--host=i686-pc-linux-gnu"

elif [ "$OSTYPE" == "linux64" ]; then
    OPENSSL_CONFIG="linux-x86_64 -m64"
    EXTRA_CFLAGS="-m64"
    EXTRA_LDFLAGS="-m64"
    EXTRA_CONFIG="--host=x86_64-pc-linux-gnu"

fi

function build_step() {
    if [ "$VERBOSE" = true ]; then
        "$@"
    else
        "$@" > /dev/null 2>&1 &
        step_pid=$!

        while kill -0 "$step_pid" 2> /dev/null; do
            printf "."
            sleep 1
        done

        wait "$step_pid"
        step_status=$?

        echo ""
        return $step_status
    fi
}

###########################################################
# OpenSSL Setup and Build
###########################################################

OPENSSL_VERSION="3.2.0"
OPENSSL_URL="https://github.com/openssl/openssl.git"
OPENSSL_SRC_DIR="$(pwd)/$DEPS_DIR/openssl"
OPENSSL_INSTALL_DIR="$OPENSSL_SRC_DIR"
OPENSSL_CONFIG="$OPENSSL_CONFIG no-shared no-pinshared no-apps no-tests no-threads no-idea no-docs"

# Check and build OpenSSL if necessary
if [ -z "$OPENSSL_PATH" ]; then
    openssl version | grep "OpenSSL $OPENSSL_VERSION" > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "OpenSSL 3 not found, will build from source version openssl-$OPENSSL_VERSION."

        if [ ! -d "$OPENSSL_SRC_DIR" ]; then
            echo "OpenSSL not found where expected: Cloning and building..."
            build_step git clone --depth 1 --branch openssl-$OPENSSL_VERSION $OPENSSL_URL $OPENSSL_SRC_DIR
            if [ $? -ne 0 ]; then
                echo "OpenSSL clone failed. Exiting." >&2
                exit -1
            fi
            cd $OPENSSL_SRC_DIR
            echo "Building OpenSSL ..."
            LDFLAGS="-Wl,-rpath -Wl,${OPENSSL_INSTALL_DIR}/lib64" \
            build_step ./Configure \
             --prefix=/opt/cst \
             --openssldir=/opt/cst \
             $OPENSSL_CONFIG && \
            build_step make

            if [ $? -ne 0 ]; then
                echo "OpenSSL build failed. Exiting." >&2
                exit -1
            fi
            echo "OpenSSL build completed successfully."
            cd ../..

            cd $OPENSSL_INSTALL_DIR
            if [ -d "lib64" ]; then
                ln -s lib64 lib
            fi

            cp $OPENSSL_SRC_DIR/ms/applink.c $OPENSSL_INSTALL_DIR/include/openssl/

            cd ../..
        fi
        export OPENSSL_PATH=$OPENSSL_INSTALL_DIR
    else
        export OPENSSL_PATH=""
    fi
fi

# Print the final OPENSSL_PATH for verification
echo "Using OpenSSL at: $OPENSSL_PATH"

if [ -z "$OPENSSL_PATH" ]; then
    CMAKE_OPENSSL_ROOT_DIR=""
else
    CMAKE_OPENSSL_ROOT_DIR="-DOPENSSL_ROOT_DIR=$OPENSSL_PATH"
fi

if $PKCS11_SUPPORT; then

###########################################################
# LIBP11 pkcs11 shared library setup and build
###########################################################

LIBP11_VERSION="0.4.12"
LIBP11_URL="https://github.com/OpenSC/libp11.git"
LIBP11_SRC_DIR="$(pwd)/$DEPS_DIR/libp11"
LIBP11_INSTALL_DIR="$(pwd)/$DEPS_DIR"
LIBP11_BUILD_DIR="build"

# Check whether libp11 is built or has been configured:
if [ -z "$libp11_DIR" ]; then
    if [ ! -f "$LIBP11_INSTALL_DIR/lib/libpkcs11.a" ]; then
        echo "Need to re-build pkcs11 engine ..."
        if [ ! -d $LIBP11_SRC_DIR ]; then
            echo "Cloning libp11 $LIBP11_VERSION..."
            build_step git clone --depth 1 --branch libp11-$LIBP11_VERSION $LIBP11_URL $LIBP11_SRC_DIR
            if [ $? -ne 0 ]; then
                echo "libp11 download failure for libp11-$LIBP11_VERSION. Exiting." >&2
                exit -1
            fi
            # Build static pkcs11 engine
            sed -i 's/lib_LTLIBRARIES = libp11.la/lib_LTLIBRARIES = libp11.la libpkcs11.la/' $LIBP11_SRC_DIR/src/Makefile.am
            sed -i '/pkcs11_la_LDFLAGS = $(AM_LDFLAGS) -module -shared -shrext $(SHARED_EXT)/a\
            # Create a static version of the engine as well to allow applications to statically link into it.\n\
            libpkcs11_la_SOURCES = $(pkcs11_la_SOURCES)\n\
            libpkcs11_la_CFLAGS = $(pkcs11_la_CFLAGS)\n\
            libpkcs11_la_LIBADD = $(pkcs11_la_LIBADD)\n' $LIBP11_SRC_DIR/src/Makefile.am
        fi
        cd $LIBP11_SRC_DIR
        echo "Building libp11"
        build_step autoreconf --verbose --install --force && \
        build_step ./configure $EXTRA_CONFIG PKG_CONFIG_PATH="$OPENSSL_PATH" \
        CFLAGS="$EXTRA_CFLAGS -I$OPENSSL_PATH/include" \
        LDFLAGS="$EXTRA_LDFLAGS -L$OPENSSL_PATH -L$OPENSSL_PATH/lib -L$OPENSSL_PATH/lib64 -lssl -lcrypto" \
        --enable-static \
        --with-enginesdir=$LIBP11_INSTALL_DIR/lib \
        --enable-api-doc=no \
        --with-pkcs11-module="" \
        --prefix=$LIBP11_INSTALL_DIR && \
        sed -i '/^SUBDIRS/s/\bexamples\b//g' Makefile &&
        build_step make clean && \
        build_step make && \
        build_step make install-exec

        if [ $? -ne 0 ]; then
            echo "libp11 build failed. Exiting." >&2
            exit -1
        fi
        echo "libp11 build completed successfully."
        cd $LIBP11_INSTALL_DIR
        if [ -d "lib64" ]; then
            ln -sf lib64 lib
        fi
        cd ..
    fi
    export libp11_DIR=$LIBP11_INSTALL_DIR
fi

echo "Using libp11 at: $libp11_DIR"

fi

if $PQC_SUPPORT; then
    ###########################################################
    # liboqs Setup and Build
    ###########################################################

    LIBOQS_VERSION="0.13.0"
    LIBOQS_URL="https://github.com/open-quantum-safe/liboqs.git"
    LIBOQS_SRC_DIR="$(pwd)/$DEPS_DIR/liboqs"
    LIBOQS_INSTALL_DIR="$(pwd)/$DEPS_DIR"
    LIBOQS_BUILD_DIR="build"

    # Check whether liboqs is built or has been configured:
    if [ -z "$liboqs_DIR" ]; then
        if [ ! -f "$LIBOQS_INSTALL_DIR/lib/liboqs.a" ]; then
            echo "Need to re-build static liboqs..."
            if [ ! -d $LIBOQS_SRC_DIR ]; then
                echo "Cloning liboqs $LIBOQS_VERSION..."
                build_step git clone --depth 1 --branch $LIBOQS_VERSION $LIBOQS_URL $LIBOQS_SRC_DIR
                if [ $? -ne 0 ]; then
                    echo "liboqs clone failure for branch $LIBOQS_VERSION. Exiting." >&2
                    exit -1
                fi
            fi

            cd $LIBOQS_SRC_DIR
            echo "Building liboqs"
            build_step cmake -G "$CMAKE_GENERATOR" \
                $CMAKE_TOOLCHAIN_FILE \
                -DOQS_ALGS_ENABLED=STD \
                -DOQS_BUILD_ONLY_LIB=ON \
                -DOQS_MINIMAL_BUILD="SIG_dilithium_3;SIG_dilithium_5;SIG_ml_dsa_65;SIG_ml_dsa_87" \
                -DOQS_DIST_BUILD=ON \
                -DOQS_USE_OPENSSL=ON \
                $CMAKE_OPENSSL_ROOT_DIR \
                -DOQS_USE_PTHREADS=OFF \
                -DCMAKE_INSTALL_PREFIX=$LIBOQS_INSTALL_DIR \
                -S . \
                -B $LIBOQS_BUILD_DIR && \
            build_step cmake --build $LIBOQS_BUILD_DIR && \
            build_step cmake --install $LIBOQS_BUILD_DIR

            if [ $? -ne 0 ]; then
                echo "liboqs build failed. Exiting." >&2
                exit -1
            fi
            echo "liboqs build completed successfully."
            cd $LIBOQS_INSTALL_DIR
            if [ -d "lib64" ]; then
                ln -sf lib64 lib
            fi
            cd ..
        fi
        export liboqs_DIR=$LIBOQS_INSTALL_DIR
    fi

    echo "Using liboqs at: $liboqs_DIR"

    ###########################################################
    # oqsprovider Setup and Build
    ###########################################################

    OQSPROVIDER_VERSION="0.8.0"
    OQSPROVIDER_URL="https://github.com/open-quantum-safe/oqs-provider.git"
    OQSPROVIDER_SRC_DIR="$(pwd)/$DEPS_DIR/oqsprovider"
    OQSPROVIDER_INSTALL_DIR="$(pwd)/$DEPS_DIR"
    OQSPROVIDER_BUILD_DIR="build"

    # Check whether oqsprovider is built or has been configured:
    if [ -z "$oqsprovider_DIR" ]; then
        if [ ! -f "$OQSPROVIDER_INSTALL_DIR/lib/oqsprovider.a" ]; then
            echo "Need to re-build static oqsprovider..."
            if [ ! -d $OQSPROVIDER_SRC_DIR ]; then
                echo "Cloning oqsprovider $OQSPROVIDER_VERSION..."
                build_step git clone --depth 1 --branch $OQSPROVIDER_VERSION $OQSPROVIDER_URL $OQSPROVIDER_SRC_DIR
                if [ $? -ne 0 ]; then
                    echo "oqsprovider clone failure for branch $OQSPROVIDER_VERSION. Exiting." >&2
                    exit -1
                fi
            fi
            cd $OQSPROVIDER_SRC_DIR
            echo "Building oqsprovider"
            liboqs_DIR=$liboqs_DIR build_step cmake -G "$CMAKE_GENERATOR" \
                $CMAKE_TOOLCHAIN_FILE \
                -DCMAKE_BUILD_TYPE=Release \
                $CMAKE_OPENSSL_ROOT_DIR \
                -DOQS_PROVIDER_BUILD_STATIC=ON \
	        -DBUILD_TESTING=OFF \
                -DCMAKE_INSTALL_PREFIX=$OQSPROVIDER_INSTALL_DIR \
                -S . -B $OQSPROVIDER_BUILD_DIR && \
                build_step cmake --build $OQSPROVIDER_BUILD_DIR && \
                build_step cmake --install $OQSPROVIDER_BUILD_DIR

            if [ $? -ne 0 ]; then
                echo "oqsprovider build failed. Exiting." >&2
                exit -1
            fi
            echo "oqsprovider build completed successfully."
            cd $OQSPROVIDER_INSTALL_DIR
            if [ -d "lib64" ]; then
                ln -sf lib64 lib
            fi
            cd ..
        fi
        export oqsprovider_DIR=$OQSPROVIDER_INSTALL_DIR
    fi

    echo "Using oqsprovider at: $oqsprovider_DIR"
fi

if $JSON_SUPPORT; then
    ###########################################################
    # json-c Setup and Build
    ###########################################################

    JSON_C_VERSION="json-c-0.17"
    JSON_C_URL="https://github.com/json-c/json-c.git"
    JSON_C_SRC_DIR="$(pwd)/$DEPS_DIR/json-c"
    JSON_C_INSTALL_DIR="$(pwd)/$DEPS_DIR"
    JSON_C_BUILD_DIR="build"

    # Check whether json-c is built or has been configured:
    if [ -z "$json_c_DIR" ]; then
        if [ ! -f "$JSON_C_INSTALL_DIR/lib/libjson-c.a" ]; then
            echo "Need to re-build static json-c..."
            if [ ! -d $JSON_C_SRC_DIR ]; then
                echo "Cloning json-c $JSON_C_VERSION..."
                build_step git clone --depth 1 --branch $JSON_C_VERSION $JSON_C_URL $JSON_C_SRC_DIR
                if [ $? -ne 0 ]; then
                    echo "json-c clone failure for branch $JSON_C_VERSION. Exiting." >&2
                    exit -1
                fi
            fi
            cd $JSON_C_SRC_DIR
            echo "Building json-c"
            build_step cmake -G "$CMAKE_GENERATOR" \
                $CMAKE_TOOLCHAIN_FILE \
                -DCMAKE_BUILD_TYPE=Release \
                -DBUILD_SHARED_LIBS=OFF \
                -DBUILD_STATIC_LIBS=ON \
                -DDISABLE_EXTRA_LIBS=ON \
                -DENABLE_THREADING=OFF \
                -DBUILD_TESTING=OFF \
                -DCMAKE_INSTALL_PREFIX=$JSON_C_INSTALL_DIR \
                -S . -B $JSON_C_BUILD_DIR && \
                build_step cmake --build $JSON_C_BUILD_DIR && \
                build_step cmake --install $JSON_C_BUILD_DIR

            if [ $? -ne 0 ]; then
                echo "json-c build failed. Exiting." >&2
                exit -1
            fi
            echo "json-c build completed successfully."
            cd $JSON_C_INSTALL_DIR
            if [ -d "lib64" ]; then
                ln -sf lib64 lib
            fi
            cd ..
        fi
        export json_c_DIR=$JSON_C_INSTALL_DIR
    fi

    echo "Using json-c at: $json_c_DIR"
fi

if $USB_SUPPORT; then
    ###########################################################
    # libusb Setup and Build
    ###########################################################

    LIBUSB_VERSION="v1.0.27"
    LIBUSB_URL="https://github.com/libusb/libusb.git"
    LIBUSB_SRC_DIR="$(pwd)/$DEPS_DIR/libusb"
    LIBUSB_INSTALL_DIR="$(pwd)/$DEPS_DIR"
    LIBUSB_BUILD_DIR="build"

    # Check whether libusb is built or has been configured:
    if [ -z "$libusb_DIR" ]; then
        if [ ! -f "$LIBUSB_INSTALL_DIR/lib/libusb-1.0.a" ]; then
            echo "Need to re-build static libusb..."
            if [ ! -d $LIBUSB_SRC_DIR ]; then
                echo "Cloning libusb $LIBUSB_VERSION..."
                build_step git clone --depth 1 --branch $LIBUSB_VERSION $LIBUSB_URL $LIBUSB_SRC_DIR
                if [ $? -ne 0 ]; then
                    echo "libusb clone failure for branch $LIBUSB_VERSION. Exiting." >&2
                    exit -1
                fi
            fi
            cd $LIBUSB_SRC_DIR
            build_step autoreconf --verbose --install --force && \
            build_step ./configure $EXTRA_CONFIG \
            CFLAGS="$EXTRA_CFLAGS" \
            LDFLAGS="$EXTRA_LDFLAGS" \
            --disable-shared \
            --enable-static \
            --disable-udev \
            --prefix=$LIBP11_INSTALL_DIR && \
            build_step make clean && \
            build_step make && \
            build_step make install-exec

            if [ $? -ne 0 ]; then
                echo "libusb build failed. Exiting." >&2
                exit -1
            fi
            echo "libusb build completed successfully."
            cd $LIBUSB_INSTALL_DIR
            if [ -d "lib64" ]; then
                ln -sf lib64 lib
            fi
            cd ..
        fi
        export libusb_DIR=$LIBUSB_INSTALL_DIR
    fi

    ###########################################################
    # hidapi Setup and Build
    ###########################################################

    HIDAPI_VERSION="0.13.0"
    HIDAPI_URL="https://github.com/libusb/hidapi.git"
    HIDAPI_SRC_DIR="$(pwd)/$DEPS_DIR/hidapi"
    HIDAPI_INSTALL_DIR="$(pwd)/$DEPS_DIR"
    HIDAPI_BUILD_DIR="build"

    # Check whether libhidapi is built or has been configured:
    if [ -z "$hidapi_DIR" ]; then
        if [ ! -f "$HIDAPI_INSTALL_DIR/lib/libhidapi-libusb.a" ] && [ ! -f "$HIDAPI_INSTALL_DIR/lib/libhidapi.a" ]; then
            echo "Need to re-build static hidapi..."
            if [ ! -d $HIDAPI_SRC_DIR ]; then
                echo "Cloning hidapi $HIDAPI_VERSION..."
                build_step git clone --depth 1 --branch hidapi-$HIDAPI_VERSION $HIDAPI_URL $HIDAPI_SRC_DIR
                if [ $? -ne 0 ]; then
                    echo "hidapi clone failure for branch $HIDAPI_VERSION. Exiting." >&2
                    exit -1
                fi
            fi
            cd $HIDAPI_SRC_DIR
            echo "Building hidapi"
            build_step cmake -G "$CMAKE_GENERATOR" \
                $CMAKE_TOOLCHAIN_FILE \
                -DCMAKE_BUILD_TYPE=Release \
                -DBUILD_SHARED_LIBS=OFF \
                -DHIDAPI_WITH_HIDRAW=OFF \
                -DHIDAPI_WITH_LIBUSB=ON \
                -DCMAKE_INSTALL_PREFIX=$HIDAPI_INSTALL_DIR \
                -S . -B $HIDAPI_BUILD_DIR && \
                build_step cmake --build $HIDAPI_BUILD_DIR && \
                build_step cmake --install $HIDAPI_BUILD_DIR

            if [ $? -ne 0 ]; then
                echo "hidapi build failed. Exiting." >&2
                exit -1
            fi
            echo "hidapi build completed successfully."
            cd $HIDAPI_INSTALL_DIR
            if [ -d "lib64" ]; then
                ln -sf lib64 lib
            fi
            cd ..
        fi
        export hidapi_DIR=$HIDAPI_INSTALL_DIR
    fi

    echo "Using HIDAPI at: $hidapi_DIR"
fi

# Check whether CST is built:
if [ ! -f "$BUILD_DIR/bin/cst" ]; then
    echo "CST ($BUILD_DIR/bin/cst) not built: Building..."

    if $PKCS11_SUPPORT; then
        CMAKE_PKCS11_SUPPORT="-DCST_WITH_PKCS11=ON -Dlibp11_DIR=$libp11_DIR"
    else
        CMAKE_PKCS11_SUPPORT=""
    fi

    if $PQC_SUPPORT; then
        CMAKE_PQC_SUPPORT="-DCST_WITH_PQC=ON -Dliboqs_DIR=$liboqs_DIR -Doqsprovider_DIR=$oqsprovider_DIR"
    else
        CMAKE_PQC_SUPPORT=""
    fi

    if $USB_SUPPORT; then
        CMAKE_USB_SUPPORT="-Dhidapi_DIR=$hidapi_DIR -Dlibusb_DIR=$libusb_DIR"
    else
        CMAKE_USB_SUPPORT=""
    fi

    if $JSON_SUPPORT; then
        CMAKE_JSON_SUPPORT="-Djson_c_DIR=$json_c_DIR"
    else
        CMAKE_JSON_SUPPORT=""
    fi

    echo "Building CST"
    build_step cmake -G "$CMAKE_GENERATOR" \
        -DCMAKE_PREFIX_PATH="$(realpath $DEPS_DIR/lib/cmake)" \
        -DOSTYPE=$OSTYPE \
        $CMAKE_TOOLCHAIN_FILE \
        $CMAKE_OPENSSL_ROOT_DIR \
        $CMAKE_PKCS11_SUPPORT \
        $CMAKE_PQC_SUPPORT \
        $CMAKE_USB_SUPPORT \
        $CMAKE_JSON_SUPPORT \
        -S . \
        -B $BUILD_DIR && \
        build_step cmake --build $BUILD_DIR

    if [ $? -ne 0 ]; then
        echo "CST build failed. Exiting." >&2
        exit -1
    fi
    echo "CST build completed successfully."
else
    echo "CST ($BUILD_DIR/bin/cst) is already built."
fi
