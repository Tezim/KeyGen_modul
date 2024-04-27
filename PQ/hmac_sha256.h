#ifndef _HMAC_SHA256
#define _HMAC_SHA256

#include <stdint.h>

/**
\brief HMAC_SHA256 podla FIPS 198-1

\param digest			vypocitany odtlacok (digest) spravy podla kluca
\param K				kluc pouzity na vypocet odtlacku
\param kLen				velkost kluca v Bajtoch
\param text				sprava, ktorej odtlacok sa pocita
\param textLen			velkost spravy v Bajtoch

\return -1 ak nastal nejaky problem s malloc 
\return 0  ak nenastal problem

\comment		Pouziva HMAC_SHA256 a su v nej natvrdo nastavene velkosti na 32B (=256bitov).
\comment		Predpokladame, ze L je nasobok 8, t.j. velkost vysledneho klucoveho materialu v Bajtoch je cele cislo
*/

int HMAC_SHA256(/*out*/ uint8_t* digest, /*in*/ uint8_t* K, /*in*/ uint32_t kLen, /*in*/ uint8_t* text, /*in*/ uint32_t textLen);

#endif /* hmac_sha256.h */

