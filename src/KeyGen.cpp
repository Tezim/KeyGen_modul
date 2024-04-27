//
// Created by Tatiana on 4/27/2024.
//

#include <windows.h>
#include <fstream>
#include "PQ/KeyPair.h"

KeyPair generateKey(int lambda, bool arng){
    return generateRandomKeypair(lambda, lambda, arng);
}

KeyPair readKeyPair(std::string path){
    std::string fd_private = path + "_private";
    std::string fd_public = path + "_public";

    NTL::vec_GF2 SK;
    NTL::Vec<Polynomial> VK;

    std::ifstream privateKey(fd_private);
    if (!privateKey.is_open()) {
        return {};
    }
    char skBit;
    while (privateKey >> skBit) {
        SK.append(NTL::GF2(skBit == '1' ? 1 : 0));
    }
    privateKey.close();

    int lambda = SK.length();
    std::ifstream publicKey(fd_public);
    if (!publicKey.is_open()) {
        return {};
    }

    for (long i = 0; i < lambda; i++){
        Polynomial poly = Polynomial();
        NTL::mat_GF2 quadratic;
        quadratic.SetDims(lambda, lambda);
        for (long j = 0; j < 256; ++j) {
            std::string line;
            std::getline(publicKey, line);
            NTL::vec_GF2 row;
            for (char bit : line) {
                row.append(NTL::GF2(bit == '1' ? 1 : 0));
            }
            quadratic[i] = row;
        }
        std::string line;
        std::getline(publicKey, line);
        NTL::vec_GF2 linear;
        for (char bit : line) {
            linear.append(NTL::GF2(bit == '1' ? 1 : 0));
        }
        poly.setQuadratic(quadratic);
        poly.setLinear(linear);
        VK.append(poly);
    }
    publicKey.close();
    KeyPair keyPair = KeyPair();
    keyPair.setVk(VK);
    keyPair.setSk(SK);
    return keyPair;
}


bool saveKeyPair(KeyPair keyPair, std::string path){
    std::string fd_private = path + "_private";
    std::string fd_public = path + "_public";

    std::ofstream privateKey(fd_private);
    if (!privateKey.is_open()) {
        return FALSE;
    }

    for (auto i : keyPair.getSk()) {
        privateKey << i;
    }
    privateKey << std::endl;
    privateKey.close();

    std::ofstream publicKey(fd_public);
    if (!publicKey.is_open()) {
        return FALSE;
    }
    for (const auto& i : keyPair.getVk()) {
        // quadratic
        for (int j = 0; j < i.getQuadratic().NumRows(); j++){
            for (long k = 0; k < i.getQuadratic().NumCols(); ++k) {
                publicKey << i.getQuadratic()[j][k];
            }
            publicKey << std::endl; // Move to the next line after each row
        }
        // linear
        for (auto j : i.getLinear()){
            publicKey << j;
        }
        publicKey << std::endl;
    }
    publicKey.close();
    return TRUE;
}