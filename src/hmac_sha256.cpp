/*
 *  HMAC_SHA256 implementacia podla FIPS 198-1
 *
 *  
 */

#include "PQ/hmac_sha256.h"
#include "PQ/sha256.h"
#include <string.h>
#include <stdlib.h>


int HMAC_SHA256(/*out*/ uint8_t* digest, /*in*/ uint8_t* K, /*in*/ uint32_t kLen, /*in*/ uint8_t* text, /*in*/ uint32_t textLen)
{
	uint8_t K0[64]; 		//64bajtov je velkost bloku SHA-256, HMAC musi upravit vstupny kluc K na prislusnu velkost!
	uint8_t temp[32]; 		//pouzite vzdy, ked je potrebne docasne uchovat niekde nejaky hash
	sha256_context sha_ctx;
	uint8_t *K_ipad_text;  	// K0 XOR ipad
	uint8_t *K_opad_text;  	// K0 XOR opad

	K_ipad_text = (uint8_t*) malloc (64 + textLen);
	K_opad_text = (uint8_t*) malloc (64 + 32);
	if ((K_ipad_text == NULL) || (K_opad_text == NULL)) return -1;	

	/*K0 musi mat velkost 64 bajtov, podla FIPS 198-1 sa odvodi z K a upravi, ak je vstupny K mensi alebo vacsi*/	
	if (kLen == 64)
	{
		memcpy(K0, K, 64);	
	}
	else if (kLen < 64)	//K sa skopiruje do K0 a doplni sa nulami na 64 bajtov
	{
		memcpy(K0,K,kLen);	
		memset(K0 + kLen,0x00,64-kLen);	
	}
	else	//K je vacsi ako 64 bajtov, zahashuje sa na 32B a doplni sa nulami
	{
		sha256_starts(&sha_ctx); 
    	sha256_update(&sha_ctx, K, kLen);
    	sha256_finish(&sha_ctx, temp);
    	memcpy(K0, temp, 32);
		memset(K0 + 32, 0x00, 32);
	}
	
	//inner MAC
	for (int i = 0; i < 64; i++)
	{
		K_ipad_text[i] = (K0[i]) ^ (uint8_t)0x36;
	}
	memcpy(K_ipad_text + 64, text, textLen);	
	
	sha256_starts(&sha_ctx); 
	sha256_update(&sha_ctx, K_ipad_text, 64+textLen);
    sha256_finish(&sha_ctx, temp);
    
	//outer MAC
	for (int i = 0; i < 64; i++)
	{
		K_opad_text[i] = K0[i] ^ 0x5c;
	}
	memcpy(K_opad_text + 64, temp, 32);

    sha256_starts(&sha_ctx); 
    sha256_update(&sha_ctx, K_opad_text, 64+32);
    sha256_finish(&sha_ctx, digest);
   
    free(K_ipad_text); free(K_opad_text); 
	return 0;
}
