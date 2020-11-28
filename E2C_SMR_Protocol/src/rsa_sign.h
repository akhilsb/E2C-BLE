#ifndef SIGN_H  // To make sure you don't declare the function more than once by including the header multiple times.
#define SIGN_H

#include "mbed.h"
#include "mbedtls/platform.h"
#include "mbedtls/entropy.h"
#include "mbedtls/bignum.h"
#include "mbedtls/x509.h"
#include "mbedtls/rsa.h"

unsigned char* RSA_sign(unsigned char hash[32]);
unsigned char* RSA_Verify(unsigned char hash[32],unsigned char buf[MBEDTLS_MPI_MAX_SIZE]);

#endif