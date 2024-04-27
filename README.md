# Modul KeyGen

Implementation of key generation algorithm for multivariate signature scheme.

The implementation can be used directly in code.

### KeyGen

1. `KeyPair generateKey(int lambda, bool arng)`

    - **Description:** Generates a cryptographic key pair.
    - **Parameters:**
        - `lambda`: Security parameter indicating the desired level of security.
        - `arng`: Boolean flag indicating whether to use an additional random number generator.
    - **Returns:** An instance of the `KeyPair` struct representing the generated key pair.

2. `bool saveKeyPair(KeyPair keyPair, std::string path)`

    - **Description:** Saves a cryptographic key pair to a file.
    - **Parameters:**
        - `keyPair`: The key pair to be saved.
        - `path`: The path to the file where the key pair will be saved.
    - **Returns:** `true` if the key pair was successfully saved, `false` otherwise.

3. `KeyPair readKeyPair(std::string path)`

    - **Description:** Reads a cryptographic key pair from a file.
    - **Parameters:**
        - `path`: The path to the file containing the key pair.
    - **Returns:** An instance of the `KeyPair` struct representing the read key pair.

## Usage Example

~~~cpp
#include "keygen.h"

int main() {
    // generate keypair with 256-bit security, arng = false -> not using hardware generator
    KeyPair key = generateKey(256, false);
    saveKeyPair(key, "example");
    KeyPair k = readKeyPair("example");
    return 0;
}
~~~

## How To Use

### KeyGen_modul

When using KeyGen_modul download whole package and put into code. For this version static NTL library wil be needed.

**CMakeLists.txt**

~~~
cmake_minimum_required(VERSION 3.24)
project(<project name>)
include_directories(.)
link_directories(.)

set(CMAKE_CXX_STANDARD 17)
file(GLOB SRCS src/*.cpp)
add_executable(<project name> ${SRCS})
target_link_libraries(<project name> <NTL library name>.a)
~~~

### KeyGen_library

To use implementation as library add all NTL src files and build static library. Use the code the same way as in direct implementation.

**CMakeLists.txt**

~~~
cmake_minimum_required(VERSION 3.24)
project(KeyGenLib)
include_directories(.)
link_directories(.)

set(CMAKE_CXX_STANDARD 17)

file(GLOB SRCS src/*.cpp)
include_directories(PQ NTL)
add_library(KeyGenLib ${SRCS})
~~~
