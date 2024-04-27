//
// Created by Tatiana on 11/24/2023.
//

#include "PQ/Polynomial.h"
#include "PQ/helpers.h"

#include <utility>

Polynomial::Polynomial(NTL::vec_GF2 linear, NTL::mat_GF2 quadratic)
        : absolute(0), linear(std::move(linear)), quadratic(std::move(quadratic)) {}

Polynomial::Polynomial(){ absolute = 0; linear(0); quadratic(0); }

void Polynomial::setAbsolute(int32_t absolute) {
    Polynomial::absolute = absolute;
}
void Polynomial::setLinear(const NTL::vec_GF2 &linear) {
    Polynomial::linear = linear;
}
void Polynomial::setQuadratic(const NTL::mat_GF2 &quadratic) {
    Polynomial::quadratic = quadratic;
}

int32_t Polynomial::getAbsolute() const {
    return absolute;
}
const NTL::vec_GF2 &Polynomial::getLinear() const {
    return linear;
}
const NTL::mat_GF2 &Polynomial::getQuadratic() const {
    return quadratic;
}

Polynomial generateRandomPolynomial(uint32_t n, hmac_drbg_ctx* ctx){
    Polynomial p = Polynomial();
    p.setAbsolute(0);
    p.setLinear(randomLinear(n, ctx));
    p.setQuadratic(randomQuadratic(n, ctx));
    return p;
}

Polynomial generateRandomPolynomial(uint32_t n){
    Polynomial p = Polynomial();
    p.setAbsolute(0);
    p.setLinear(randomLinear(n));
    p.setQuadratic(randomQuadratic(n));
    return p;
}
