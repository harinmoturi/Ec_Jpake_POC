

#include "ec-jpake.h"

const struct uECC_Curve_t* curve __attribute__ ((aligned(4)));
static ECC_ROLE myRole;
char my_sign[16], b_sign[16], *curr_sign;

eccPoint _x1 ={0}, _x2 ={0}, _x3 ={0}, _x4 ={0};
uECC_word_t _p2[MAX_KEY_SIZE];
uECC_word_t shared_secret[MAX_KEY_SIZE];

void hashPack(uECC_word_t* out,  eccPoint* toProve, eccPoint* basePoint, ZKPPack* pack) 
{
	uint8_t hasharg[3 * (sizeof(uint32_t) + uECC_WORD_SIZE * MAX_KEY_SIZE) + sizeof(uint32_t) + MAX_SIGNER_SIZE]__attribute__ ((aligned(4)));
	uint8_t tmpstring[32];

	uint32_t j = 0, size;

	/* Base point*/
	size = curve->num_bytes;
	for (int i = 0; i < sizeof(uint32_t); i++)
		hasharg[j++] = size >> ((sizeof(uint32_t) - 1 - i) * 8);
	//uECC_vli_clear((uECC_word_t*)tmpstring, MAX_KEY_SIZE);
	uECC_vli_nativeToBytes(&hasharg[j], size, (uECC_word_t*)basePoint);
	//memcpy(&hasharg[j], tmpstring, size);
	j += size;

	/* Ephimeral Key */
	for (int i = 0; i < sizeof(uint32_t); i++)
		hasharg[j++] = size >> ((sizeof(uint32_t) - 1 - i) * 8);
	//uECC_vli_clear((uECC_word_t*)tmpstring, MAX_KEY_SIZE);
	uECC_vli_nativeToBytes(&hasharg[j], size, pack->ephmKey);
	//memcpy(&hasharg[j], tmpstring, size);
	j += size;

	/* To prove key */
	for (int i = 0; i < sizeof(uint32_t); i++)
		hasharg[j++] = size >> ((sizeof(uint32_t) - 1 - i) * 8);
	//uECC_vli_clear((uECC_word_t*)tmpstring, MAX_KEY_SIZE);
	uECC_vli_nativeToBytes(&hasharg[j], size, (uECC_word_t*)toProve);
	//memcpy(&hasharg[j], tmpstring, size);
	j += size;

	/* Signer ID */
	for (size = 0; curr_sign[size] != '\0'; size++)
		hasharg[j + sizeof(uint32_t) + size] = curr_sign[size];
	for (int i = 0; i < sizeof(uint32_t); i++)
		hasharg[j++] = size >> ((sizeof(uint32_t) - 1 - i) * 8);
	//memcpy(&hasharg[j], curr_sign, size);
	j += size;

	SHA256_CTX ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, hasharg, j);
	sha256_final(&ctx, tmpstring);

	uECC_word_t tmp[2 * uECC_MAX_WORDS];
	uECC_vli_clear(tmp + BITS_TO_WORDS(256), 2 * uECC_MAX_WORDS - BITS_TO_WORDS(256));
	uECC_vli_bytesToNative(tmp, tmpstring, 32);

	uECC_vli_mmod(out, tmp, curve->n, BITS_TO_WORDS(curve->num_n_bits));
}

int setSigns(char* mySign, char* recSign) 
{
	int i;
	for (i = 0; mySign[i] != 0; i++)
	{
		if (i == 15)
			return -1;
		my_sign[i] = mySign[i];
	}
	my_sign[i] = 0;
	for (i = 0; recSign[i] != 0; i++)
	{
		if (i == 15)
			return -1;
		b_sign[i] = recSign[i];
	}
	b_sign[i] = 0;
	return 0;
}

int ECjpakeSetup(CURVE_TYPE c_type, ECC_ROLE role, const uint8_t* sharedSecret, size_t passLen)
{
	myRole = role;
	
	switch(c_type)
	{
#if	uECC_SUPPORTS_secp256k1 == 1
		case secp256k1:
			curve = uECC_secp256k1();
			break;
#endif
#if	uECC_SUPPORTS_secp256r1 == 1
		case secp256r1:
			curve = uECC_secp256r1();
			break;
#endif
#if	uECC_SUPPORTS_secp224r1 == 1
		case secp224r1:
			curve = uECC_secp224r1();
			break;
#endif
#if	uECC_SUPPORTS_secp192r1 == 1
		case secp192r1:
			curve = uECC_secp192r1();
			break;
#endif
#if	uECC_SUPPORTS_secp160r1 == 1
		case secp160r1:
			curve = uECC_secp160r1();
			break;
#endif
		default:
			return -1;
	}

	uECC_word_t tmp[2 * uECC_MAX_WORDS];
	size_t min = passLen > 2 * uECC_MAX_WORDS * uECC_WORD_SIZE ? 2 * uECC_MAX_WORDS * uECC_WORD_SIZE : passLen;
	uECC_vli_bytesToNative(tmp, sharedSecret, min);
	memset((uint8_t*)tmp + min, 0, 2 * uECC_MAX_WORDS * uECC_WORD_SIZE - min);

	uECC_vli_mmod(shared_secret, tmp, curve->n, BITS_TO_WORDS(curve->num_n_bits));

	return 0;
}

int makeZKPPack(eccPoint* pubKey, uECC_word_t* privKey, eccPoint* basePoint, ZKPPack *pack) 
{
	int err = 0;
	curr_sign = my_sign;

	uECC_word_t v[MAX_KEY_SIZE];

	err = !uECC_generate_random_int(v, curve->n, BITS_TO_WORDS(curve->num_n_bits));
	if (err == 0)
		err = !Ecc_Point_mult(pack->ephmKey, (uECC_word_t*)basePoint, v, curve);

	if (err == 0) {
		uECC_word_t h[MAX_KEY_SIZE];
		hashPack(h, pubKey, basePoint, pack);

		/* r = v - xh */
		uECC_vli_modMult(pack->r, privKey, h, curve->n, BITS_TO_WORDS(curve->num_n_bits));
		uECC_vli_modSub(pack->r, v, pack->r, curve->n, BITS_TO_WORDS(curve->num_n_bits));
	}
	
	return err;
}

int checkPack(eccPoint* pubKey, eccPoint* basePoint, ZKPPack * pack) 
{
	int err = 0;
	uECC_word_t h[MAX_KEY_SIZE], vv[2 * MAX_KEY_SIZE] __attribute__ ((aligned(4)));
	curr_sign = b_sign;
	hashPack(h, pubKey, basePoint, pack);

	/* r*G + h*V */
	multoadd(vv, pack->r, (uECC_word_t*)basePoint, h, (uECC_word_t *)pubKey, curve);

	err = !uECC_vli_equal(pack->ephmKey, vv, 2 * curve->num_words);
	return err;
}

int EphemKeys(eccPoint* x1, eccPoint* x2, uECC_word_t* p1, uECC_word_t* p2, ZKPPack* pack1, ZKPPack* pack2)
{
	int err = 0;

	err = EphemKeysFirst(x1, p1, pack1);
	if (err == 0)
		err = EphemKeysSecond(x2, p2, pack2);

	return err;
}

int EphemKeysFirst(eccPoint* x1, uECC_word_t* p1, ZKPPack* pack1)
{
	int err = 0;

	uint8_t* _private = (uint8_t*)p1;
	uint8_t* _public = (uint8_t*)x1;

	err = !uECC_make_key(_public, _private, curve);

	if (err == 0)
		err = makeZKPPack(x1, p1, (eccPoint*)curve->G, pack1);

	return err;
}


int EphemKeysSecond(eccPoint* x2, uECC_word_t* p2, ZKPPack* pack2)
{
	int err = 0;

	uint8_t* _private = (uint8_t*)p2;
	uint8_t* _public = (uint8_t*)x2;

	if (err == 0)
		err = !uECC_make_key(_public, _private, curve);

	if (err == 0)
		err = makeZKPPack(x2, p2, (eccPoint*)curve->G, pack2);

	return err;
}

// Initialize the round one with fix p1 and p2 passed by the arguments
int EphemKeysWith(eccPoint* x1, eccPoint* x2, uECC_word_t* p1, uECC_word_t* p2, ZKPPack* pack1, ZKPPack* pack2) // test
{
	int err = 0;

	err = !Ecc_Point_mult((uECC_word_t*)x1, curve->G, p1, curve);

	if (err == 0)
		err = makeZKPPack(x1, p1, (eccPoint*)curve->G, pack1);

	if (err == 0)
		err = !Ecc_Point_mult((uECC_word_t*)x2, curve->G, p2, curve);

	if (err == 0)
		err = makeZKPPack(x2, p2, (eccPoint*)curve->G, pack2);

	return err;
}

int RoundTwo(eccPoint* x1, eccPoint* x3, eccPoint* x4, uECC_word_t* p2, eccPoint* xs, ZKPPack *pack) 
{
	int err = 0;
	uECC_word_t x2s[MAX_KEY_SIZE];
	uECC_vli_modMult(x2s, p2, shared_secret, curve->n, BITS_TO_WORDS(curve->num_n_bits));
	
	eccPoint sum;

	/* G1 + G3 + G4 */
	Ecc_Point_add((uECC_word_t*)&sum, (uECC_word_t*)x1, (uECC_word_t*)x3, curve);
	Ecc_Point_add((uECC_word_t*)&sum, (uECC_word_t*)&sum, (uECC_word_t*)x4, curve);

	/* SUM * x2s */
	Ecc_Point_mult((uECC_word_t*)xs, (uECC_word_t*)&sum, (uECC_word_t*)x2s, curve);
	
	err = makeZKPPack(xs, x2s, &sum, pack);

	return err;
}

void materialKeyGen(eccPoint* x4, eccPoint* B, uECC_word_t* p2, eccPoint* keyK)
{
	uECC_word_t x2s[MAX_KEY_SIZE];
	uECC_vli_modMult(x2s, p2, shared_secret, curve->n, BITS_TO_WORDS(curve->num_n_bits));

	// multiply by -1
	uECC_vli_modSub(x2s, curve->n, x2s, curve->n, BITS_TO_WORDS(curve->num_n_bits));

	// G4 * (-x2s)
	Ecc_Point_mult((uECC_word_t*)keyK, (uECC_word_t*)x4, (uECC_word_t*)x2s, curve);

	// B - G4 x2s
	Ecc_Point_add((uECC_word_t*)keyK, (uECC_word_t*)B, (uECC_word_t*)keyK, curve);

	// Mult by x2
	Ecc_Point_mult((uECC_word_t*)keyK, (uECC_word_t*)keyK, p2, curve);
}


int writeRoundOne(void* buffer)
{
	int err = 0;
	uECC_word_t _p1[MAX_KEY_SIZE];
	ZKPPack pack1, pack2;
	EphemKeys(&_x1, &_x2, _p1, _p2, &pack1, &pack2);
	((_dbuffer*)buffer)->round1.size = 0;
#if SEND_BIG_ENDIAN
	uECC_vli_nativeToBytes(((_dbuffer*)buffer)->round1.buffer + ((_dbuffer*)buffer)->round1.size, curve->num_bytes, (uECC_word_t*)&_x1);
	((_dbuffer*)buffer)->round1.size += curve->num_bytes;
	uECC_vli_nativeToBytes(((_dbuffer*)buffer)->round1.buffer + ((_dbuffer*)buffer)->round1.size, curve->num_bytes, (uECC_word_t*)&_x1 + curve->num_words);
	((_dbuffer*)buffer)->round1.size += curve->num_bytes;

	uECC_vli_nativeToBytes(((_dbuffer*)buffer)->round1.buffer + ((_dbuffer*)buffer)->round1.size, curve->num_bytes, pack1.ephmKey);
	((_dbuffer*)buffer)->round1.size += curve->num_bytes;
	uECC_vli_nativeToBytes(((_dbuffer*)buffer)->round1.buffer + ((_dbuffer*)buffer)->round1.size, curve->num_bytes, pack1.ephmKey + curve->num_words);
	((_dbuffer*)buffer)->round1.size += curve->num_bytes;

	uECC_vli_nativeToBytes(((_dbuffer*)buffer)->round1.buffer + ((_dbuffer*)buffer)->round1.size, uECC_WORD_SIZE * BITS_TO_WORDS(curve->num_n_bits), pack1.r);
	((_dbuffer*)buffer)->round1.size += uECC_WORD_SIZE * BITS_TO_WORDS(curve->num_n_bits);

	uECC_vli_nativeToBytes(((_dbuffer*)buffer)->round1.buffer + ((_dbuffer*)buffer)->round1.size, curve->num_bytes, (uECC_word_t*)&_x2);
	((_dbuffer*)buffer)->round1.size += curve->num_bytes;
	uECC_vli_nativeToBytes(((_dbuffer*)buffer)->round1.buffer + ((_dbuffer*)buffer)->round1.size, curve->num_bytes, (uECC_word_t*)&_x2 + curve->num_words);
	((_dbuffer*)buffer)->round1.size += curve->num_bytes;

	uECC_vli_nativeToBytes(((_dbuffer*)buffer)->round1.buffer + ((_dbuffer*)buffer)->round1.size, curve->num_bytes, pack2.ephmKey);
	((_dbuffer*)buffer)->round1.size += curve->num_bytes;
	uECC_vli_nativeToBytes(((_dbuffer*)buffer)->round1.buffer + ((_dbuffer*)buffer)->round1.size, curve->num_bytes, &pack2.ephmKey[curve->num_words]);
	((_dbuffer*)buffer)->round1.size += curve->num_bytes;

	uECC_vli_nativeToBytes(((_dbuffer*)buffer)->round1.buffer + ((_dbuffer*)buffer)->round1.size, uECC_WORD_SIZE * BITS_TO_WORDS(curve->num_n_bits), pack2.r);
	((_dbuffer*)buffer)->round1.size += uECC_WORD_SIZE * BITS_TO_WORDS(curve->num_n_bits);
#else
	memcpy(((_dbuffer*)buffer)->round1.buffer + ((_dbuffer*)buffer)->round1.size, &_x1, 2 * curve->num_bytes); //Copy X1
	((_dbuffer*)buffer)->round1.size += 2 * curve->num_bytes;
	memcpy(((_dbuffer*)buffer)->round1.buffer + ((_dbuffer*)buffer)->round1.size, pack1.ephmKey, 2 * curve->num_bytes); //Copy pack1.ephmKey
	((_dbuffer*)buffer)->round1.size += 2 * curve->num_bytes;
	memcpy(((_dbuffer*)buffer)->round1.buffer + ((_dbuffer*)buffer)->round1.size, pack1.r, uECC_WORD_SIZE * BITS_TO_WORDS(curve->num_n_bits)); //Copy pack1.r
	((_dbuffer*)buffer)->round1.size += uECC_WORD_SIZE * BITS_TO_WORDS(curve->num_n_bits);
	
	memcpy(((_dbuffer*)buffer)->round1.buffer + ((_dbuffer*)buffer)->round1.size, &_x2, 2 * curve->num_bytes); //Copy X2
	((_dbuffer*)buffer)->round1.size += 2 * curve->num_bytes;
	memcpy(((_dbuffer*)buffer)->round1.buffer + ((_dbuffer*)buffer)->round1.size, pack2.ephmKey, 2 * curve->num_bytes); //Copy pack2.ephmKey
	((_dbuffer*)buffer)->round1.size += 2 * curve->num_bytes;
	memcpy(((_dbuffer*)buffer)->round1.buffer + ((_dbuffer*)buffer)->round1.size, pack2.r, uECC_WORD_SIZE * BITS_TO_WORDS(curve->num_n_bits)); //Copy pack2.r
	((_dbuffer*)buffer)->round1.size += uECC_WORD_SIZE * BITS_TO_WORDS(curve->num_n_bits);
#endif
	return err;
}


int writeRoundOneWith(uECC_word_t* p1, uECC_word_t* p2, void* buffer)
{
	int err = 0;
	memcpy(_p2, p2, curve->num_bytes);
	ZKPPack pack1, pack2;
	EphemKeysWith(&_x1, &_x2, p1, p2, &pack1, &pack2);
	((_dbuffer*)buffer)->round1.size = 0;
#if SEND_BIG_ENDIAN
	uECC_vli_nativeToBytes(((_dbuffer*)buffer)->round1.buffer + ((_dbuffer*)buffer)->round1.size, curve->num_bytes, (uECC_word_t*)&_x1);
	((_dbuffer*)buffer)->round1.size += curve->num_bytes;
	uECC_vli_nativeToBytes(((_dbuffer*)buffer)->round1.buffer + ((_dbuffer*)buffer)->round1.size, curve->num_bytes, (uECC_word_t*)&_x1 + curve->num_words);
	((_dbuffer*)buffer)->round1.size += curve->num_bytes;

	uECC_vli_nativeToBytes(((_dbuffer*)buffer)->round1.buffer + ((_dbuffer*)buffer)->round1.size, curve->num_bytes, pack1.ephmKey);
	((_dbuffer*)buffer)->round1.size += curve->num_bytes;
	uECC_vli_nativeToBytes(((_dbuffer*)buffer)->round1.buffer + ((_dbuffer*)buffer)->round1.size, curve->num_bytes, pack1.ephmKey + curve->num_words);
	((_dbuffer*)buffer)->round1.size += curve->num_bytes;

	uECC_vli_nativeToBytes(((_dbuffer*)buffer)->round1.buffer + ((_dbuffer*)buffer)->round1.size, uECC_WORD_SIZE * BITS_TO_WORDS(curve->num_n_bits), pack1.r);
	((_dbuffer*)buffer)->round1.size += uECC_WORD_SIZE * BITS_TO_WORDS(curve->num_n_bits);

	uECC_vli_nativeToBytes(((_dbuffer*)buffer)->round1.buffer + ((_dbuffer*)buffer)->round1.size, curve->num_bytes, (uECC_word_t*)&_x2);
	((_dbuffer*)buffer)->round1.size += curve->num_bytes;
	uECC_vli_nativeToBytes(((_dbuffer*)buffer)->round1.buffer + ((_dbuffer*)buffer)->round1.size, curve->num_bytes, (uECC_word_t*)&_x2 + curve->num_words);
	((_dbuffer*)buffer)->round1.size += curve->num_bytes;

	uECC_vli_nativeToBytes(((_dbuffer*)buffer)->round1.buffer + ((_dbuffer*)buffer)->round1.size, curve->num_bytes, pack2.ephmKey);
	((_dbuffer*)buffer)->round1.size += curve->num_bytes;
	uECC_vli_nativeToBytes(((_dbuffer*)buffer)->round1.buffer + ((_dbuffer*)buffer)->round1.size, curve->num_bytes, &pack2.ephmKey[curve->num_words]);
	((_dbuffer*)buffer)->round1.size += curve->num_bytes;

	uECC_vli_nativeToBytes(((_dbuffer*)buffer)->round1.buffer + ((_dbuffer*)buffer)->round1.size, uECC_WORD_SIZE * BITS_TO_WORDS(curve->num_n_bits), pack2.r);
	((_dbuffer*)buffer)->round1.size += uECC_WORD_SIZE * BITS_TO_WORDS(curve->num_n_bits);
#else
	memcpy(((_dbuffer*)buffer)->round1.buffer + ((_dbuffer*)buffer)->round1.size, &_x1, 2 * curve->num_bytes); //Copy X1
	((_dbuffer*)buffer)->round1.size += 2 * curve->num_bytes;
	memcpy(((_dbuffer*)buffer)->round1.buffer + ((_dbuffer*)buffer)->round1.size, pack1.ephmKey, 2 * curve->num_bytes); //Copy pack1.ephmKey
	((_dbuffer*)buffer)->round1.size += 2 * curve->num_bytes;
	memcpy(((_dbuffer*)buffer)->round1.buffer + ((_dbuffer*)buffer)->round1.size, pack1.r, uECC_WORD_SIZE * BITS_TO_WORDS(curve->num_n_bits)); //Copy pack1.r
	((_dbuffer*)buffer)->round1.size += uECC_WORD_SIZE * BITS_TO_WORDS(curve->num_n_bits);
	
	memcpy(((_dbuffer*)buffer)->round1.buffer + ((_dbuffer*)buffer)->round1.size, &_x2, 2 * curve->num_bytes); //Copy X2
	((_dbuffer*)buffer)->round1.size += 2 * curve->num_bytes;
	memcpy(((_dbuffer*)buffer)->round1.buffer + ((_dbuffer*)buffer)->round1.size, pack2.ephmKey, 2 * curve->num_bytes); //Copy pack2.ephmKey
	((_dbuffer*)buffer)->round1.size += 2 * curve->num_bytes;
	memcpy(((_dbuffer*)buffer)->round1.buffer + ((_dbuffer*)buffer)->round1.size, pack2.r, uECC_WORD_SIZE * BITS_TO_WORDS(curve->num_n_bits)); //Copy pack2.r
	((_dbuffer*)buffer)->round1.size += uECC_WORD_SIZE * BITS_TO_WORDS(curve->num_n_bits);
#endif
	return err;
}

int readRoundOne(void* buffer) {
	ZKPPack pack;
	size_t size = 0;
	if (((_dbuffer*)buffer)->round1.size != (8 * curve->num_bytes + 2* uECC_WORD_SIZE * BITS_TO_WORDS(curve->num_n_bits)))
		return -1;
#if SEND_BIG_ENDIAN
	uECC_vli_bytesToNative((uECC_word_t*)&_x3, ((_dbuffer*)buffer)->round1.buffer + size, curve->num_bytes);
	size += curve->num_bytes;
	uECC_vli_bytesToNative((uECC_word_t*)&_x3 + curve->num_words, ((_dbuffer*)buffer)->round1.buffer + size, curve->num_bytes);
	size += curve->num_bytes;

	uECC_vli_bytesToNative(pack.ephmKey, ((_dbuffer*)buffer)->round1.buffer + size, curve->num_bytes);
	size += curve->num_bytes;
	uECC_vli_bytesToNative(pack.ephmKey + curve->num_words, ((_dbuffer*)buffer)->round1.buffer + size, curve->num_bytes);
	size += curve->num_bytes;

	uECC_vli_bytesToNative(pack.r, ((_dbuffer*)buffer)->round1.buffer + size, uECC_WORD_SIZE * BITS_TO_WORDS(curve->num_n_bits));
	size += uECC_WORD_SIZE * BITS_TO_WORDS(curve->num_n_bits);
	if (checkPack(&_x3, (eccPoint*)curve->G, &pack))
		return -2;

	uECC_vli_bytesToNative((uECC_word_t*)&_x4, ((_dbuffer*)buffer)->round1.buffer + size, curve->num_bytes);
	size += curve->num_bytes;
	uECC_vli_bytesToNative((uECC_word_t*)&_x4 + curve->num_words, ((_dbuffer*)buffer)->round1.buffer + size, curve->num_bytes);
	size += curve->num_bytes;

	uECC_vli_bytesToNative(pack.ephmKey, ((_dbuffer*)buffer)->round1.buffer + size, curve->num_bytes);
	size += curve->num_bytes;
	uECC_vli_bytesToNative(pack.ephmKey + curve->num_words, ((_dbuffer*)buffer)->round1.buffer + size, curve->num_bytes);
	size += curve->num_bytes;

	uECC_vli_bytesToNative(pack.r, ((_dbuffer*)buffer)->round1.buffer + size, uECC_WORD_SIZE * BITS_TO_WORDS(curve->num_n_bits));
	if (checkPack(&_x4, (eccPoint*)curve->G, &pack))
		return -2;
#else
	memcpy(&_x3, ((_dbuffer*)buffer)->round1.buffer + size, 2 * curve->num_bytes);
	size += 2 * curve->num_bytes;

	memcpy(pack.ephmKey, ((_dbuffer*)buffer)->round1.buffer + size, 2 * curve->num_bytes);
	size += 2 * curve->num_bytes;
	memcpy(pack.r, ((_dbuffer*)buffer)->round1.buffer + size, uECC_WORD_SIZE * BITS_TO_WORDS(curve->num_n_bits));
	size += uECC_WORD_SIZE * BITS_TO_WORDS(curve->num_n_bits);
	if (checkPack(&_x3, (eccPoint*)curve->G, &pack))
		return -2;

	memcpy(&_x4, ((_dbuffer*)buffer)->round1.buffer + size, 2 * curve->num_bytes);
	size += 2 * curve->num_bytes;

	memcpy(pack.ephmKey, ((_dbuffer*)buffer)->round1.buffer + size, 2 * curve->num_bytes);
	size += 2 * curve->num_bytes;
	memcpy(pack.r, ((_dbuffer*)buffer)->round1.buffer + size, uECC_WORD_SIZE * BITS_TO_WORDS(curve->num_n_bits));
	if (checkPack(&_x4, (eccPoint*)curve->G, &pack))
		return -2;
#endif
	return 0;
}

int writeRoundTwo(void* buffer)
{
	int err = 0;
	eccPoint Xm;
	ZKPPack pack;

	RoundTwo(&_x1, &_x3, &_x4, _p2, &Xm, &pack);
	((_dbuffer*)buffer)->round2.size = 0;
#if SEND_BIG_ENDIAN
	uECC_vli_nativeToBytes(((_dbuffer*)buffer)->round2.buffer + ((_dbuffer*)buffer)->round2.size, curve->num_bytes, (uECC_word_t*)&Xm);
	((_dbuffer*)buffer)->round2.size += curve->num_bytes;
	uECC_vli_nativeToBytes(((_dbuffer*)buffer)->round2.buffer + ((_dbuffer*)buffer)->round2.size, curve->num_bytes, (uECC_word_t*)&Xm + curve->num_words);
	((_dbuffer*)buffer)->round2.size += curve->num_bytes;

	uECC_vli_nativeToBytes(((_dbuffer*)buffer)->round2.buffer + ((_dbuffer*)buffer)->round2.size, curve->num_bytes, pack.ephmKey);
	((_dbuffer*)buffer)->round2.size += curve->num_bytes;
	uECC_vli_nativeToBytes(((_dbuffer*)buffer)->round2.buffer + ((_dbuffer*)buffer)->round2.size, curve->num_bytes, pack.ephmKey + curve->num_words);
	((_dbuffer*)buffer)->round2.size += curve->num_bytes;

	uECC_vli_nativeToBytes(((_dbuffer*)buffer)->round2.buffer + ((_dbuffer*)buffer)->round2.size, uECC_WORD_SIZE * BITS_TO_WORDS(curve->num_n_bits), pack.r);
	((_dbuffer*)buffer)->round2.size += uECC_WORD_SIZE * BITS_TO_WORDS(curve->num_n_bits);
#else
	memcpy(((_dbuffer*)buffer)->round2.buffer + ((_dbuffer*)buffer)->round2.size, &Xm, 2 * curve->num_bytes); //Copy Xm
	((_dbuffer*)buffer)->round2.size += 2 * curve->num_bytes;
	memcpy(((_dbuffer*)buffer)->round2.buffer + ((_dbuffer*)buffer)->round2.size, pack.ephmKey, 2 * curve->num_bytes); //Copy pack.ephmKey
	((_dbuffer*)buffer)->round2.size += 2 * curve->num_bytes;
	memcpy(((_dbuffer*)buffer)->round2.buffer + ((_dbuffer*)buffer)->round2.size, pack.r, uECC_WORD_SIZE * BITS_TO_WORDS(curve->num_n_bits)); //Copy pack.r
	((_dbuffer*)buffer)->round2.size += uECC_WORD_SIZE * BITS_TO_WORDS(curve->num_n_bits);
#endif
	return err;
}

int readRoundTwo(void* buffer)
{
	eccPoint basePoint, Xm;
	Ecc_Point_add((uECC_word_t*)& basePoint, (uECC_word_t*)& _x1, (uECC_word_t*)& _x2, curve);
	Ecc_Point_add((uECC_word_t*)& basePoint, (uECC_word_t*)& basePoint, (uECC_word_t*)& _x3, curve);
	ZKPPack pack;
	size_t size = 0;
	if (((_dbuffer*)buffer)->round2.size != (4 * curve->num_bytes + uECC_WORD_SIZE * BITS_TO_WORDS(curve->num_n_bits)))
		return -1;

#if SEND_BIG_ENDIAN
	uECC_vli_bytesToNative((uECC_word_t*)&Xm, ((_dbuffer*)buffer)->round2.buffer + size, curve->num_bytes);
	size += curve->num_bytes;
	uECC_vli_bytesToNative((uECC_word_t*)&Xm + curve->num_words, ((_dbuffer*)buffer)->round2.buffer + size, curve->num_bytes);
	size += curve->num_bytes;

	uECC_vli_bytesToNative(pack.ephmKey, ((_dbuffer*)buffer)->round2.buffer + size, curve->num_bytes);
	size += curve->num_bytes;
	uECC_vli_bytesToNative(pack.ephmKey + curve->num_words, ((_dbuffer*)buffer)->round2.buffer + size, curve->num_bytes);
	size += curve->num_bytes;

	uECC_vli_bytesToNative(pack.r, ((_dbuffer*)buffer)->round2.buffer + size, uECC_WORD_SIZE * BITS_TO_WORDS(curve->num_n_bits));
#else
	memcpy(&Xm, ((_dbuffer*)buffer)->round2.buffer, 2 * curve->num_bytes);
	size = 2 * curve->num_bytes;
	memcpy(pack.ephmKey, ((_dbuffer*)buffer)->round2.buffer + size, 2 * curve->num_bytes);
	size += 2 * curve->num_bytes;
	memcpy(pack.r, ((_dbuffer*)buffer)->round2.buffer + size, uECC_WORD_SIZE * BITS_TO_WORDS(curve->num_n_bits));

#endif
	if (checkPack(&Xm, &basePoint, &pack))
		return -2;
#if SHARED_KEY_GEN
	materialKeyGen(&_x4, &Xm, _p2, &((_dbuffer*)buffer)->round2.key);
#endif
	return 0;
}
