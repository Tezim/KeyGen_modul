#ifndef SVOC_KEYGEN_HELPERS_H
#define SVOC_KEYGEN_HELPERS_H

#include "hmac_drbg.h"
#include "NTL/vec_GF2.h"
#include "NTL/mat_GF2.h"
#include "Polynomial.h"

NTL::vec_GF2 randomLinear(uint32_t n, hmac_drbg_ctx* ctx);
NTL::vec_GF2 randomLinear(uint32_t n);
NTL::mat_GF2 randomQuadratic(uint32_t n, hmac_drbg_ctx* ctx);
NTL::mat_GF2 randomQuadratic(uint32_t n);
NTL::Vec<Polynomial> randomSystem(uint32_t n, uint32_t m, NTL::vec_GF2 s, hmac_drbg_ctx* ctx);
NTL::Vec<Polynomial> randomSystem(uint32_t n, uint32_t m, NTL::vec_GF2 s);
int32_t findLastNonZeroIndex(const NTL::vec_GF2& S);
NTL::GF2 calculate_result(const Polynomial& polynomial, const NTL::vec_GF2& vector);
NTL::GF2 absolute_s(const int32_t & absolute, const NTL::vec_GF2& vector);
NTL::GF2 linear_s(const NTL::vec_GF2& linear, const NTL::vec_GF2& vector);
NTL::GF2 quadratic_s(const NTL::mat_GF2& quadratic, const NTL::vec_GF2& vector);
void modify_polynomial(Polynomial& linear, long t, const NTL::GF2& S, const NTL::GF2& v);
std::string checkGeneratorAvailability();
int generator_read(uint8_t * buffer_out, size_t bufferSize);

#endif //SVOC_KEYGEN_HELPERS_H
