

# Build CST

This document explains how to create a build environment using the Dockerfile and build the CST source code.

---

## Create a Build Environment

This guide assumes familiarity with Docker. If unfamiliar, you may want to review the basics of Docker Images and Containers. The provided `Dockerfile` accepts arguments to create a user, ensuring consistent permissions and ownership when mounting a local volume on the Docker host.

### Dockerfile Arguments

- **`hostUserName`**: Specifies the username to be created inside the container.
- **`hostUID`**: Specifies the user ID (UID) for the created user.
- **`hostGID`**: Specifies the group ID (GID) for the created user.

### Build the Docker Image

To create the Docker image, use the following command:

```bash
docker build --build-arg hostUserName="$USER" \
             --build-arg hostUID=$(id -u) \
             --build-arg hostGID=$(id -g) \
             -t cst:build -f Dockerfile .
```

### Create the Docker Container

Once the Docker image is built, create a container based on it. Mount a volume from the Docker host to access the source code and build artifacts. Replace the path in the `-v` option with your desired host directory:

```bash
docker run -it -v $(pwd):/home/$USER/cst cst:build /bin/bash
```

This will place you inside a bash shell running in the container.

---

## Build CST

The CST build system uses CMake and includes a helper script, `scripts/build.sh`, to streamline the process of downloading, configuring, and building CST with its dependencies.

### Dependency Management

The script manages dependencies in two ways:

1. **Environment Variables**: If set, the script uses the specified library path.
2. **Automatic Build**: If unset, the script automatically downloads and builds the dependency.

### Environment Variables

| Variable      | Purpose                                                                                     |
|---------------|---------------------------------------------------------------------------------------------|
| `OPENSSL_PATH` | Path to the OpenSSL installation. If unset, the script will build OpenSSL.                 |
| `libp11_DIR`   | Path to the libp11 installation. If unset, the script will build it.                       |
| `json_c_DIR`   | Path to a JSON-C installation. If unset, the script will build it.                         |
| `liboqs_DIR`   | Path to the liboqs library. If unset, the script will build it.                            |
| `oqsprovider_DIR` | Path to the oqsprovider library. If unset, the script will build it.                    |
| `hidapi_DIR`   | Path to the HIDAPI library. If unset, the script will build it.                            |

### Usage

Run the script as follows:

```bash
./scripts/build.sh
```

The script:

1. Checks if an environment variable is set for each dependency.
2. Uses the specified path if the variable is set.
3. Builds the library if the variable is unset.

#### Example: Using Environment Variables

To specify a custom OpenSSL path:

```bash
export OPENSSL_PATH=/custom/path/to/openssl
./scripts/build.sh
```

---

### Build Configuration Options

The CST build system supports the following host operating system types via the `OSTYPE` environment variable:

| OS Type   | Description         |
|-----------|---------------------|
| `linux64` | 64-bit Linux        |
| `linux32` | 32-bit Linux        |
| `mingw32` | 32-bit Windows      |
| `mingw64` | 64-bit Windows      |

#### Example: Building for 32-bit Windows

```bash
OSTYPE=mingw32 ./scripts/build.sh
```

---

### Script Options

The `scripts/build.sh` script supports the following options:

| Option          | Purpose                                                              |
|-----------------|----------------------------------------------------------------------|
| `-f`            | Soft clean: Rebuild CST without re-checking dependencies.            |
| `-F`            | Hard clean: Rebuild CST and re-check all dependencies.               |
| `-verbose`      | Enable verbose output during the build process.                      |
| `-with-pkcs11`  | Enables support for PKCS#11 back-end.                                |
| `-with-usb`     | Enables USB support for tools like `hab_log_parser`.                 |

#### Example: Combining Options

Perform a hard clean and verbose build for 32-bit Windows:

```bash
OSTYPE=mingw32 ./scripts/build.sh -F -verbose
```

**Note**: The `linux32`, `linux64`, `mingw32`, and `mingw64` builds are tested in the Docker container. Native Windows builds are not tested.

---

## Build Without `scripts/build.sh`

To manually configure and compile the project without the helper script:

```bash
cmake -S . -B build && cmake --build build
```

### Common CMake Options

| Option                 | Purpose                                                                 |
|------------------------|-------------------------------------------------------------------------|
| `OSTYPE`               | Specifies the target operating system type.                            |
| `CST_WITH_PKCS11`      | Build CST with PKCS#11 support.                                         |
| `CST_WITH_PQC`         | Build CST with PQC support.                                            |
| `OPENSSL_ROOT_DIR`     | Specifies the root directory of the OpenSSL installation.              |
| `libp11_DIR`           | Path to the PKCS#11 library (if `CST_WITH_PKCS11` is ON, otherwise searched). |
| `liboqs_DIR`           | Path to the liboqs library (if `CST_WITH_PQC` is ON, otherwise searched). |
| `oqsprovider_DIR`      | Path to the OQS provider (if `CST_WITH_PQC` is ON, otherwise searched). |
| `hidapi_DIR`           | Path to the HIDAPI library (if `BUILD_HAB_LOG_PARSER` is ON, otherwise searched). |
| `libusb_DIR`           | Path to the libusb library (if `BUILD_HAB_LOG_PARSER` is ON, otherwise searched). |
| `json_c_DIR`           | Path to the JSON-C library (if `BUILD_AHAB_SIGNED_MESSAGE` is ON, otherwise searched). |

#### Example: Manual Build with Selected Options

```bash
cmake -DOPENSSL_ROOT_DIR=/custom/path/to/openssl \
      -DCST_WITH_PKCS11=ON \
      -S . -B build && cmake --build build
```

---

## License

© 2025 NXP
