/* ------ Point operations ------ */


#pragma once
#include <stdint.h>
#include <string.h>
#include "../micro-ecc/uECC_vli.h"

#ifndef __attribute__
	#define __attribute__(A) /* do nothing */
#endif // !__attribute__


#define BITS_TO_WORDS(num_bits) ((num_bits + ((uECC_WORD_SIZE * 8) - 1)) / (uECC_WORD_SIZE * 8))
#define BITS_TO_BYTES(num_bits) ((num_bits + 7) / 8)


#ifdef uECC_MAX_WORDS
	#undef uECC_MAX_WORDS
#endif // 

#if (uECC_WORD_SIZE == 1)
	#if uECC_SUPPORTS_secp160r1
		#define uECC_MAX_WORDS 21 /* Due to the size of curve_n. */
	#endif
	#if uECC_SUPPORTS_secp192r1
		#undef uECC_MAX_WORDS
		#define uECC_MAX_WORDS 24
	#endif
	#if uECC_SUPPORTS_secp224r1
		#undef uECC_MAX_WORDS
		#define uECC_MAX_WORDS 28
	#endif
	#if (uECC_SUPPORTS_secp256r1 || uECC_SUPPORTS_secp256k1)
		#undef uECC_MAX_WORDS
		#define uECC_MAX_WORDS 32
	#endif
#elif (uECC_WORD_SIZE == 4)
	#if uECC_SUPPORTS_secp160r1
		#define uECC_MAX_WORDS 6 /* Due to the size of curve_n. */
	#endif
	#if uECC_SUPPORTS_secp192r1
		#undef uECC_MAX_WORDS
		#define uECC_MAX_WORDS 6
	#endif
	#if uECC_SUPPORTS_secp224r1
		#undef uECC_MAX_WORDS
		#define uECC_MAX_WORDS 7
	#endif
	#if (uECC_SUPPORTS_secp256r1 || uECC_SUPPORTS_secp256k1)
		#undef uECC_MAX_WORDS
		#define uECC_MAX_WORDS 8
	#endif
#elif (uECC_WORD_SIZE == 8)
	#if uECC_SUPPORTS_secp160r1
		#define uECC_MAX_WORDS 3
	#endif
	#if uECC_SUPPORTS_secp192r1
		#undef uECC_MAX_WORDS
		#define uECC_MAX_WORDS 3
	#endif
	#if uECC_SUPPORTS_secp224r1
		#undef uECC_MAX_WORDS
		#define uECC_MAX_WORDS 4
	#endif
	#if (uECC_SUPPORTS_secp256r1 || uECC_SUPPORTS_secp256k1)
		#undef uECC_MAX_WORDS
		#define uECC_MAX_WORDS 4
	#endif
#endif /* uECC_WORD_SIZE */

#define MAX_KEY_SIZE uECC_MAX_WORDS

struct uECC_Curve_t {
	wordcount_t num_words;
	wordcount_t num_bytes;
	bitcount_t num_n_bits;
	uECC_word_t p[uECC_MAX_WORDS];
	uECC_word_t n[uECC_MAX_WORDS];
	uECC_word_t G[uECC_MAX_WORDS * 2];
	uECC_word_t b[uECC_MAX_WORDS];
	void (*double_jacobian)(uECC_word_t* X1,
		uECC_word_t* Y1,
		uECC_word_t* Z1,
		uECC_Curve curve);
#if uECC_SUPPORT_COMPRESSED_POINT
	void (*mod_sqrt)(uECC_word_t* a, uECC_Curve curve);
#endif
	void (*x_side)(uECC_word_t* result, const uECC_word_t* x, uECC_Curve curve);
#if (uECC_OPTIMIZATION_LEVEL > 0)
	void (*mmod_fast)(uECC_word_t* result, uECC_word_t* product);
#endif
};

/* Returns 1 if 'point' is the point at infinity, 0 otherwise. */
#define EccPoint_isZero(point, curve) uECC_vli_isZero((point), (curve)->num_words * 2)

/* Point multiplication algorithm using Montgomery's ladder with co-Z coordinates.
From http://eprint.iacr.org/2011/338.pdf
*/

/* Modify (x1, y1) => (x1 * z^2, y1 * z^3) */
void apply_z(uECC_word_t* X1,
	uECC_word_t* Y1,
	const uECC_word_t* const Z,
	uECC_Curve curve);

/* P = (x1, y1) => 2P, (x2, y2) => P' */
void XYcZ_initial_double(uECC_word_t* X1,
	uECC_word_t* Y1,
	uECC_word_t* X2,
	uECC_word_t* Y2,
	const uECC_word_t* const initial_Z,
	uECC_Curve curve);

/* Input P = (x1, y1, Z), Q = (x2, y2, Z)
   Output P' = (x1', y1', Z3), P + Q = (x3, y3, Z3)
   or P => P', Q => P + Q
*/
void XYcZ_add(uECC_word_t* X1,
	uECC_word_t* Y1,
	uECC_word_t* X2,
	uECC_word_t* Y2,
	uECC_Curve curve);

/* Input P = (x1, y1, Z), Q = (x2, y2, Z)
   Output P + Q = (x3, y3, Z3), P - Q = (x3', y3', Z3)
   or P => P - Q, Q => P + Q
*/
void XYcZ_addC(uECC_word_t* X1,
	uECC_word_t* Y1,
	uECC_word_t* X2,
	uECC_word_t* Y2,
	uECC_Curve curve);

/* result may overlap point. */
void EccPoint_mult(uECC_word_t* result,
	const uECC_word_t* point,
	const uECC_word_t* scalar,
	const uECC_word_t* initial_Z,
	bitcount_t num_bits,
	uECC_Curve curve);

uECC_word_t regularize_k(const uECC_word_t* const k,
	uECC_word_t* k0,
	uECC_word_t* k1,
	uECC_Curve curve);

//uECC_word_t EccPoint_compute_public_key(uECC_word_t* result,
//	uECC_word_t* private_key,
//	uECC_Curve curve);

uECC_word_t Ecc_Point_mult(uECC_word_t* result,
	const uECC_word_t* point,
	const uECC_word_t* scalar,
	uECC_Curve curve);

int Ecc_Point_add(uECC_word_t* result,
	uECC_word_t* X,
	uECC_word_t* Y,
	uECC_Curve curve);

int multoadd(uECC_word_t*R, 
	uECC_word_t*n, 
	uECC_word_t* P, 
	uECC_word_t*m, 
	uECC_word_t*Q, 
	uECC_Curve curve);

//int Ecc_Point_add3(uECC_word_t* result, uECC_word_t* P,
//	uECC_word_t* Q,
//	uECC_word_t* R,
//	uECC_Curve curve);

int check_valid_point(const uECC_word_t* point, const uECC_word_t* xSide, uECC_Curve curve);
