#include <iostream>
#include "PQ/KeyGen.h"

int main() {
    // generate keypair with 256-bit security, arng = false -> not using hardware generator
    KeyPair key = generateKey(256, false);
    saveKeyPair(key, "example");
    KeyPair k = readKeyPair("example");
    return 0;
}
