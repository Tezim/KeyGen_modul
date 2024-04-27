#ifndef _HMAC_DRBG
#define _HMAC_DRBG

#include <stdint.h>

/* 
Datova struktura hmac_drbg_ctx obsahujuca context generatora: pracovny stav (V, Key, reseed_counter) a administrativne informacie (security_strength, prediction_resistance_flag) - polozky v sulade s NIST SP 800-90Ar1
*/
typedef struct
{
	/* working_state */
    uint8_t V[32];
    uint8_t Key[32];
    uint32_t reseed_counter;
    /* Administrative information */
    uint32_t security_strength;
    uint8_t prediction_resistance_flag;
}
hmac_drbg_ctx;

/**
\brief Ziskanie entropie

\param entropy_input			pole bajtov, kam sa ulozi nova entropia
\param entropy_input_length		pozadovany pocet bajtov novej entropie

\return -1 ak nastal problem pri volani funkcie BCryptGenRandom
\return 0  ak nenastal problem

\comment		Tato funkcia NIE JE PRENOSITELNA. Win verzia pouziva Windowsovu kniznicu CNG a volanie BCryptGenRandom
\comment		BCryptGenRandom ziskava cerstvu entropiu z OS, je implementovana podla NIST SP 800-90Ar1 cez CTR_DRBG a vracia PLNU entropiu
*/
int get_entropy_input(/*out*/ uint8_t *entropy_input, /*in*/ uint32_t entropy_input_length);


/**
\brief Nastavenie novej instancie generatora (nastavenie pociatocnych hodnot)

\param ctx							context generatora (pointer na datovu strukturu obsahujucu pracovny stav a informacie o generatore
\param personalization_string		personalizacny retazec (moze byt NULL) - moze blizsie popisovat generator
\param personalization_stringLen 	pocet Bajtov personalizacneho retazca

\return -1 ak nastala chyba pri volani malloc
\return -2 ak nastala chyba pri internom volani get_entropy_input
\return -3 ak nastala chyba pri internom volani update funkcie
\return -4 ak je velkost personalizacneho retazca vacsia nez povolene maximum
\return 0  ak nenastal problem

\comment		Parameter requested_instantiation_security_strength je 256 (parameter je v popise DRBG podla NIST SP 800-90Ar1)
\comment		Parameter prediction_resistance_flag je nastaveny na 0x01, kedze prediction_resistance je vzdy podporovana (lebo get_entropy_input VZDY vracia cerstvu entropiu)
\comment		Vstupna entropia a aj nonce sa generuju volanim get_entropy_input
*/
int hmac_drbg_instantiate(/*inout*/ hmac_drbg_ctx* ctx, /*in*/ uint8_t* personalization_string, /*in*/ uint32_t personalization_stringLen);


/**
\brief Update funkcia generatora HMAC_DRBG (vid. NIST SP 800-90Ar1 10.1.2.2), aktualizacia vnutorneho stavu generatora

\param ctx							context generatora (pointer na datovu strukturu obsahujucu pracovny stav a informacie o generatore
\param provided_data				dodatocne vstupne data (mozu byt aj NULL, zavisi od pouzitia a kontextu volania funkcie update)
\param provided_dataLen 			velkost dodatocnych dat v Bajtoch

\return -1 ak nastala chyba pri alokacii pamate
\return -2 ak nastala chyba pri internom volani HMAC_SHA256
\return 0  ak nenastal problem

*/
int hmac_drbg_update(/*inout*/ hmac_drbg_ctx *ctx, /*in*/ uint8_t *provided_data , /*in*/ uint32_t provided_dataLen);


/**
\brief Reseed generatora

\param ctx							context generatora (pointer na datovu strukturu obsahujucu pracovny stav a informacie o generatore

\return -1 ak nastala chyba pri alokacii pamate
\return -2 ak nastala chyba pri internom volani get_entropy_input
\return -3 ak nastala chyba pri internom volani hmac_drbg_update
\return 0  ak nenastal problem

\comment		NEPOUZIVA additional_input
\comment		Parameter prediction_resistance_request je VZDY true, pretoze get_entropy_input vracia VZDY cerstvu entropiu
*/
int hmac_drbg_reseed( /*inout*/ hmac_drbg_ctx *ctx);


/**
\brief Generovanie pseudonahodnych bajtov z generatora

\param ctx								context generatora (pointer na datovu strukturu obsahujucu pracovny stav a informacie o generatore
\param pseudorandom_bits				Vygenerovane pseudonahodne bajty		
\param requested_number_of_bits			Pozadovana velkost vygenerovanych dat v bitoch
\param prediction_resistance_request	Flag, ci je pozadovany reseed (t.j. zabezpecenie prediction resistance).

\return -1 ak bola poziadavka na generovanie viac ako 2**19 bitov = 64kB (max podla NISTu)
\return -2 ak nastala chyba pri internom volani reseed funkcie
\return -3 ak nastala chyba pri internom volani HMAC_SHA256
\return -4 ak nastala chyba pri internom volani hmac_drbg_update
\return 0  ak nenastal problem

\comment		NEPOUZIVA additional_input
*/
int hmac_drbg_generate( /*inout*/ hmac_drbg_ctx *ctx, /*out*/ uint8_t *pseudorandom_bits, /*in*/ uint32_t requested_number_of_bits, /*in*/ uint8_t prediction_resistance_request);


/**
\brief Zrusenie instancie generatora (vynulovanie parametrov)

\param ctx								context generatora (pointer na datovu strukturu obsahujucu pracovny stav a informacie o generatore
*/
void hmac_drbg_uninstantiate( /*inout*/ hmac_drbg_ctx* ctx);

#endif /* hmac_drbg.h */

