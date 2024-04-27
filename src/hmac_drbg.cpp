/*
 *  HMAC_DRBG implementacia podla NIST SP 800-90Ar1
 *
 *  
 *
 *  Tato implementacia HMAC_DRBG podla NIST SP 800-90Ar1 pouziva HMAC_SHA256 a je nastavena NATVRDO na 256-bitovu bezpecnost, t.j.
 *  Hodnoty konstant v zmysle s. 38 v NIST SP 800-90Ar1 su nasledovne:
 *		highest_supported_security_strength = 256
 *  	outlen 	   						    = 256
 * 		min_length 							= 256
 *		max_length 							= 2**32 - 2 ( v norme je 2**35, tu sme ju znizili pre jednoduchsiu implementaciu )
 *		max_personalization_string_length   = 2**32 - 2 ( v norme je 2**35, tu sme ju znizili pre jednoduchsiu implementaciu )
 *		max_additional_input_length		    = 2**32 - 2 ( v norme je 2**35, tu sme ju znizili pre jednoduchsiu implementaciu )
 *		max_number_of_bits_per_request      = 2**19
 *		reseed_interval					    = 2**32 - 2 ( v norme je 2**48, tu sme ju znizili pre jednoduchsiu implementaciu )
 
 *	 Implementacia navyse podporuje PREDICTION RESISTANCE
 */

#include "PQ/hmac_drbg.h"
#include <string.h>
#include <stdlib.h>
#include "PQ/hmac_sha256.h"

//nasledujuci header file sa zmaze pri realnom pouzivani, je tu len kvoli dummy getovaniu aktualneho casu pri inicializacii srand
#include <time.h>
#include "PQ/helpers.h"

int get_entropy_input(/*out*/ uint8_t *entropy_input, /*in*/ uint32_t entropy_input_length)
{
    /*for (int i = 0; i< entropy_input_length; i++){
        entropy_input[i] = rand() % 256;
    }*/
    generator_read(entropy_input, entropy_input_length);
	return 0;
}

int hmac_drbg_instantiate(/*inout*/ hmac_drbg_ctx* ctx, /*in*/ uint8_t* personalization_string, /*in*/ uint32_t personalization_stringLen)
{
	/* 9.1 */
	if (personalization_stringLen > 0xFFFFFFFE) return -4;	// personalization_stringLen > max_personalization_string_length
	ctx->security_strength = 256;
	ctx->prediction_resistance_flag = 0x01;	//ocakavame, ze aj na Windows, aj Linux bude VZDY k dispozicii cerstva entropia cez prislusne mechanizmy
	
	uint8_t *entropy_input;
	entropy_input = (uint8_t*) malloc (86);
	if (entropy_input == NULL) return -1;
	if (get_entropy_input(entropy_input, 86)) return -2;
	
	uint8_t *nonce;
	nonce = (uint8_t*) malloc (16);
	if (nonce == NULL) return -1;
	if (get_entropy_input(nonce, 16)) return -2;
	
	/*10.1.2.3*/
		
	uint8_t *seed_material;
	seed_material = (uint8_t*) malloc (86 + 16 + personalization_stringLen);
	if (seed_material == NULL) return -1;
	memcpy(seed_material, entropy_input, 86);
    memcpy(seed_material + 86, nonce, 16);
	if (personalization_stringLen > 0)
		memcpy(seed_material + 86 + 16, personalization_string, personalization_stringLen);
		
	for (int i = 0; i < 32; i++) {
		ctx->Key[i] = 0x00;
		ctx->V[i] = 0x01;
	}
	if (hmac_drbg_update(ctx, seed_material, 86+16+personalization_stringLen)) return -3;
	ctx->reseed_counter = 1;
	
	free(entropy_input);
	free(nonce);
	free(seed_material);
	return 0;
}

int hmac_drbg_update(/*inout*/ hmac_drbg_ctx *ctx, /*in*/ uint8_t *provided_data , /*in*/ uint32_t provided_dataLen)
{
	uint8_t *tmp;
	if (provided_dataLen == 0)
	{
		tmp = (uint8_t*) malloc (32 + 1);
		if (tmp == NULL) return -1;
		memcpy(tmp, ctx->V, 32); memset(tmp + 32, 0x00, 1);
		if(HMAC_SHA256(ctx->Key, ctx->Key, 32, tmp, 32 + 1)) return -2;
		if(HMAC_SHA256(ctx->V, ctx->Key, 32, ctx->V, 32)) return -2;
	}
	else /* provided_dataLen > 0 */
	{
		tmp = (uint8_t*) malloc (32 + 1 + provided_dataLen);
		if (tmp == NULL) return -1;
		memcpy(tmp, ctx->V, 32); memset(tmp + 32, 0x00, 1); memcpy(tmp + 32 + 1, provided_data, provided_dataLen);
		if(HMAC_SHA256(ctx->Key, ctx->Key, 32, tmp, 32 + 1 + provided_dataLen)) return -2;
		if(HMAC_SHA256(ctx->V, ctx->Key, 32, ctx->V, 32)) return -2;
		memcpy(tmp, ctx->V, 32); memset(tmp + 32, 0x01, 1); memcpy(tmp + 32 + 1, provided_data, provided_dataLen);
		if(HMAC_SHA256(ctx->Key, ctx->Key, 32, tmp, 32 + 1 + provided_dataLen)) return -2;
		if(HMAC_SHA256(ctx->V, ctx->Key, 32, ctx->V, 32)) return -2;
	}
	free(tmp);
	return 0;
}

int hmac_drbg_reseed( /*inout*/ hmac_drbg_ctx *ctx)
{
	/* 9.2 */
	uint8_t *entropy_input;
	entropy_input = (uint8_t*) malloc (32);
	if (entropy_input == NULL) return -1;
	if (get_entropy_input(entropy_input, 32)) return -2;
	
	/* 10.1.2.4 */
	if (hmac_drbg_update(ctx, entropy_input, 32)) return -3;
	ctx->reseed_counter = 1;
	free(entropy_input);
	return 0;
}

int hmac_drbg_generate( /*inout*/ hmac_drbg_ctx *ctx, /*out*/ uint8_t *pseudorandom_bits, /*in*/ uint32_t requested_number_of_bits, /*in*/ uint8_t prediction_resistance_request)
{
	/* 9.3 */
	/*ak sa vyziada viac, ako 2**19 bitov, t.j. maximalny mozny pocet bitov na jedno generovanie, tak nastavi CHYBU*/
	if (requested_number_of_bits > 0x80000ul)
	{
		pseudorandom_bits = NULL;
		return -1;
	}
	
	uint8_t reseed_required = 0x00;
	if (prediction_resistance_request == 0x01)
	{
		if (hmac_drbg_reseed(ctx) != 0)
		{
			pseudorandom_bits = NULL;
			return -2;
		}
	}
	
	/* 10.1.2.5 */
	if (ctx->reseed_counter > 0xFFFFFFFE)
	{
		/*je potrebny reseed, lebo bol prekroceny pocet volani generatora s jednym seedom*/
		if (hmac_drbg_reseed(ctx) != 0)
		{
			pseudorandom_bits = NULL;
			return -2;
		}
	}
	/* Generovanie potrebneho poctu bytov */
	uint32_t requested_number_of_bytes = requested_number_of_bits/8;
	uint32_t i;
	for (i = 0; i < requested_number_of_bytes/32; i++)
	{
		if (HMAC_SHA256(ctx->V, ctx->Key, 32, ctx->V, 32) != 0)
		{
			pseudorandom_bits = NULL;
			return -3;
		}
		memcpy(pseudorandom_bits + i*32, ctx->V, 32);
	}
	/* V pripade, ze pozadovany pocet bajtov nie je nasobok 32B (velkost digestu HMAC_SHA256), tak este dogenerujeme chybajuci podiel */
	if ((requested_number_of_bytes % 32) != 0)
	{
		if (HMAC_SHA256(ctx->V, ctx->Key, 32, ctx->V, 32) != 0)
		{
			pseudorandom_bits = NULL;
			return -3;
		}
		memcpy(pseudorandom_bits + i*32, ctx->V, requested_number_of_bytes % 32);
	}
	/* Update generatora */
	if (hmac_drbg_update(ctx, NULL, 0) != 0)
	{
		pseudorandom_bits = NULL;
		return -4;
	}
	ctx->reseed_counter += 1;
	return 0;	
}

void hmac_drbg_uninstantiate(/*inout*/ hmac_drbg_ctx* ctx)
{
	memset(ctx->Key,0x00, 32); memset(ctx->V,0x00, 32); ctx->reseed_counter = 0; ctx->security_strength = 0; ctx->prediction_resistance_flag = 0;
}

