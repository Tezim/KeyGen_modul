//
// Created by Tatiana on 4/27/2024.
//

#ifndef KEYGENLIB_KEYGEN_H
#define KEYGENLIB_KEYGEN_H

#include <string>
#include "PQ/KeyPair.h"

KeyPair generateKey(int lambda, bool arng);
bool saveKeyPair(KeyPair keyPair, std::string path);
KeyPair readKeyPair(std::string path);

#endif //KEYGENLIB_KEYGEN_H
