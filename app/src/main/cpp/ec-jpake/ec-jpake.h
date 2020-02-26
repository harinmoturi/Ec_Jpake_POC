
#pragma once
#include "pointCalc.h"
#include "sha256_.h"

#define MAX_SIGNER_SIZE 16
#define SEND_BIG_ENDIAN 1
#ifndef SHARED_KEY_GEN
#define SHARED_KEY_GEN 1
#endif // !SHARED_KEY_GEN


typedef enum {
	sect163k1 = 1, 
	sect163r1,
	sect163r2,
	sect193r1,
	sect193r2,
	sect233k1,
	sect233r1,
	sect239k1,
	sect283k1,
	sect283r1,
	sect409k1,
	sect409r1,
	sect571k1,
	sect571r1,
	secp160k1,
	secp160r1,
	secp160r2,
	secp192k1,
	secp192r1,
	secp224k1,
	secp224r1,
	secp256k1,
	secp256r1,
	secp384r1,
	secp521r1
} CURVE_TYPE;

typedef enum
{
	ECJPAKE_CLIENT,
	ECJPAKE_SERVER
} ECC_ROLE;

typedef struct {
	uECC_word_t ephmKey[2 * MAX_KEY_SIZE];
	uECC_word_t r[MAX_KEY_SIZE];
} ZKPPack;

typedef struct {
	uECC_word_t X[2 * MAX_KEY_SIZE];
} eccPoint;


#define BUFFER_MAX_SIZE (2 * (2 * uECC_WORD_SIZE * uECC_MAX_WORDS + 2 * uECC_WORD_SIZE * uECC_MAX_WORDS + uECC_WORD_SIZE * (uECC_MAX_WORDS + 1)))
typedef uint8_t BUFFER_MSG;


typedef union _dbuffer
{
	struct
	{
		size_t size;
		BUFFER_MSG buffer[BUFFER_MAX_SIZE];
	}round1;
	struct
	{
		size_t size;
		BUFFER_MSG buffer[BUFFER_MAX_SIZE>>1];
		eccPoint key;
	}round2;

}_dbuffer;

typedef struct {
	uECC_word_t X[2 * MAX_KEY_SIZE];
} ecjpake_point_t;


typedef struct
{
	size_t size;
		struct
		{
			uint8_t buffer[BUFFER_MAX_SIZE];
			size_t size;
		} round1;
		struct
		{
			//uint8_t buffer[BUFFER_MAX_SIZE >> 1];
			//ecjpake_point_t key;
			uint8_t buffer[BUFFER_MAX_SIZE];
			size_t size;
		} round2;
		struct
		{
			uint8_t buffer[BUFFER_MAX_SIZE >> 1];
			ecjpake_point_t key;
			size_t size;
		} round3;

} ecjpake_buffer_t __attribute__((aligned(4)));

typedef struct {
	uECC_word_t ephmKey[16];    //2 * MAX_KEY_SIZE];
	uECC_word_t r[8]; //MAX_KEY_SIZE];
} ecjpake_ZKPPack_t;

extern const struct uECC_Curve_t* curve __attribute__ ((aligned(4)));

void hashPack(uECC_word_t* out, eccPoint* toProve, eccPoint* basePoint, ZKPPack* pack, char* curr_sign);

int ECjpakeSetup(CURVE_TYPE c_type, ECC_ROLE role, const uint8_t* sharedSecret, size_t passLen);

int setSigns(char* mySign, char* recSign);

int makeZKPPack(eccPoint* pubKey, uECC_word_t* privKey, eccPoint* basePoint, ZKPPack* pack);

int checkPack(eccPoint* pubKey, eccPoint* basePoint, ZKPPack* pack);

int EphemKeys(eccPoint* x1, eccPoint* x2, uECC_word_t* p1, uECC_word_t* p2, ZKPPack* pack1, ZKPPack* pack2);

int EphemKeysFirst(eccPoint* x1, uECC_word_t* p1, ZKPPack* pack1);

int EphemKeysSecond(eccPoint* x2, uECC_word_t* p2, ZKPPack* pack2);

int EphemKeysWith(eccPoint* x1, eccPoint* x2, uECC_word_t* p1, uECC_word_t* p2, ZKPPack* pack1, ZKPPack* pack2);

int RoundTwo(eccPoint* x1, eccPoint* x3, eccPoint* x4, uECC_word_t* p2, eccPoint* xs, ZKPPack *pack);

void materialKeyGen(eccPoint* x4, eccPoint* B, uECC_word_t* p2, eccPoint* keyK);

unsigned _store_data(uint8_t *dst, const uECC_word_t *words, uint32_t bytes);

int writeRoundOne_Two(void* buffer, int Round_number);

int writeRoundOneWith(uECC_word_t* p1, uECC_word_t* p2, void* buffer);

int readRoundOne(void* buffer, int Round_Number);

int writeRoundTwo(void* buffer);

int readRoundThree(void* buffer);

int writePoint(uECC_word_t* point, uint8_t** buffer);

int readScalar(uECC_word_t* mpi, uint8_t** buffer);
