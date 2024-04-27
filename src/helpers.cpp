#include "PQ/helpers.h"
#include "PQ/Polynomial.h"
#include <windows.h>
#include <string>
#include "PQ/hmac_drbg.h"
#include <fstream>
#include <random>

NTL::vec_GF2 randomLinear(uint32_t n, hmac_drbg_ctx* ctx) {

    NTL::vec_GF2 result;

    unsigned char* buffer_drbg_output;
    unsigned long num_bytes = 32;
    buffer_drbg_output = (unsigned char*) calloc (num_bytes, sizeof(unsigned char));
    hmac_drbg_generate(ctx, buffer_drbg_output, 8 * num_bytes, 0x00);

    for (size_t i = 0; i < num_bytes; ++i) {
        unsigned char byte = buffer_drbg_output[i];
        for (int j = 7; j >= 0; --j) {
            result.append(NTL::GF2(byte >> j & 1));
        }
    }
    free(buffer_drbg_output);
    return result;
}

NTL::vec_GF2 randomLinear(uint32_t n) {
    NTL::vec_GF2 result;
    result.SetLength(n);

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 1);

    for (uint32_t i = 0; i < n; ++i) {
        result[i] = dis(gen);
    }
    return result;
}

NTL::mat_GF2 randomQuadratic(uint32_t n, hmac_drbg_ctx* ctx) {
    NTL::mat_GF2 result;
    result.SetDims(n,n);
    for (uint32_t i = 0; i < n; ++i){
        result[i] = randomLinear(n, ctx);
    }
    return result;
}

NTL::mat_GF2 randomQuadratic(uint32_t n) {
    NTL::mat_GF2 result;
    result.SetDims(n,n);
    for (uint32_t i = 0; i < n; ++i){
        result[i] = randomLinear(n);
    }
    long size = result.NumRows();
    for (long i = 0; i < size; ++i) {
        for (long j = i + 1; j < size; ++j) {
            result[j][i] = 0;
        }
    }
    return result;
}


NTL::Vec<Polynomial> randomSystem(uint32_t n, uint32_t m, NTL::vec_GF2 s, hmac_drbg_ctx* ctx){
    NTL::Vec<Polynomial> P_system;
    P_system.SetLength(m);
    for (uint32_t i = 0; i < m; ++i){
        P_system[i] = generateRandomPolynomial(n, ctx);
    }
    int32_t t = findLastNonZeroIndex(s);

    NTL::Vec<NTL::GF2> v;
    v.SetLength(m);

    for (long j = 0; j < m; ++j) {
        v[j] = calculate_result(P_system[j], s);
    }

    for (long j = 0; j < m; ++j) {
        if (v[j] != 0) {
            modify_polynomial(P_system[j], t, s[t], v[j]);
        }
    }
    return P_system;
}

NTL::Vec<Polynomial> randomSystem(uint32_t n, uint32_t m, NTL::vec_GF2 s){
    NTL::Vec<Polynomial> P_system;
    P_system.SetLength(m);
    for (uint32_t i = 0; i < m; ++i){
        P_system[i] = generateRandomPolynomial(n);
    }
    int32_t t = findLastNonZeroIndex(s);

    NTL::Vec<NTL::GF2> v;
    v.SetLength(m);

    for (long j = 0; j < m; ++j) {
        v[j] = calculate_result(P_system[j], s);
    }

    for (long j = 0; j < m; ++j) {
        if (v[j] != 0) {
            modify_polynomial(P_system[j], t, s[t], v[j]);
        }
    }
    return P_system;
}

int32_t findLastNonZeroIndex(const NTL::vec_GF2& S) {
    uint32_t t = S.length() - 1;
    for (long i = S.length() - 1; i >= 0; --i) {
        if (S[i] == 1) {
            t = i;
            break;
        }
    }
    return t;
}

NTL::GF2 calculate_result(const Polynomial& polynomial, const NTL::vec_GF2& vector) {
    return (quadratic_s(polynomial.getQuadratic(), vector) + linear_s(polynomial.getLinear(), vector) + absolute_s(
            polynomial.getAbsolute(), vector));
}

NTL::GF2 absolute_s(const int32_t & absolute, const NTL::vec_GF2& vector) {
    NTL::GF2 sum;
    for (auto i : vector){
        sum += absolute * i;
    }
    return sum;
}

NTL::GF2 linear_s(const NTL::vec_GF2& linear, const NTL::vec_GF2& vector) {
    NTL::GF2 result;
    for (long i = 0; i < linear.length(); ++i) {
        result += linear[i] * vector[i];
    }
    return result;
}

NTL::GF2 quadratic_s(const NTL::mat_GF2& quadratic, const NTL::vec_GF2& vector) {
    NTL::GF2 result;
    for (long i = 0; i < quadratic.NumRows(); ++i) {
        for (long j = 0; j < quadratic.NumCols(); ++j) {
            result += vector[i] * quadratic[i][j] * vector[j];
        }
    }
    return result;
}

void modify_polynomial(Polynomial &polynomial, long t, const NTL::GF2& S, const NTL::GF2& v) {
    NTL::vec_GF2 tmp = polynomial.getLinear();
    tmp[t] = (polynomial.getLinear()[t] + (v / S));
    polynomial.setLinear(tmp);
}

bool checkArduinoConnection(const std::string& portName) {
    HANDLE arduino = CreateFileA(portName.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (arduino == INVALID_HANDLE_VALUE) {
        return false;
    }

    CloseHandle(arduino);
    return true;
}

std::string checkGeneratorAvailability(){
    const std::string portPrefix = "COM";
    const int maxPortNumber = 10;

    for (int i = 1; i <= maxPortNumber; ++i) {
        std::string portName = portPrefix + std::to_string(i);
        if (checkArduinoConnection(portName)) {
            return portName;
        }
    }
    return NULL;
}

// size is constant due to min-entropy calculations
int generator_read(uint8_t * buffer_out, size_t bufferSize){
    HANDLE serial = CreateFile("COM9", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (serial == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open serial port." << std::endl;
        return 1;
    }

    DCB dcbSerialParams = {0};
    dcbSerialParams.DCBlength = sizeof(dcbSerialParams);
    if (!GetCommState(serial, &dcbSerialParams)) {
        std::cerr << "Failed to get serial port settings." << std::endl;
        CloseHandle(serial);
        return 1;
    }
    dcbSerialParams.BaudRate = CBR_9600; // Adjust baud rate as needed
    dcbSerialParams.ByteSize = 8;
    dcbSerialParams.StopBits = ONESTOPBIT;
    dcbSerialParams.Parity = NOPARITY;
    if (!SetCommState(serial, &dcbSerialParams)) {
        std::cerr << "Failed to set serial port settings." << std::endl;
        CloseHandle(serial);
        return 1;
    }

    COMMTIMEOUTS timeouts = {0};
    timeouts.ReadIntervalTimeout = 0;
    timeouts.ReadTotalTimeoutConstant = 0;
    timeouts.ReadTotalTimeoutMultiplier = 0;
    timeouts.WriteTotalTimeoutConstant = 0;
    timeouts.WriteTotalTimeoutMultiplier = 0;
    if (!SetCommTimeouts(serial, &timeouts)) {
        std::cerr << "Failed to set serial port timeouts." << std::endl;
        CloseHandle(serial);
        return 1;
    }

    DWORD bytesRead;
    uint8_t buffer[bufferSize];
    while (true) {
        if (!ReadFile(serial, buffer, sizeof(buffer), &bytesRead, NULL)) {
            std::cerr << "Failed to read from serial port." << std::endl;
            CloseHandle(serial);
            return 1;
        }

        if (bytesRead == bufferSize) {
            buffer[bytesRead] = '\0';
            std::memcpy(buffer_out, buffer, sizeof(buffer));
            CloseHandle(serial);
            return 0;
        }
    }
}
