/* ------ Point operations ------ */

#include "pointCalc.h"

/* Returns 1 if 'point' is the point at infinity, 0 otherwise. */
#define EccPoint_isZero(point, curve) uECC_vli_isZero((point), (curve)->num_words * 2)

/* Point multiplication algorithm using Montgomery's ladder with co-Z coordinates.
From http://eprint.iacr.org/2011/338.pdf
*/

/* Modify (x1, y1) => (x1 * z^2, y1 * z^3) */
void apply_z(uECC_word_t* X1,
	uECC_word_t* Y1,
	const uECC_word_t* const Z,
	uECC_Curve curve) {
	uECC_word_t t1[uECC_MAX_WORDS];

	uECC_vli_modSquare_fast(t1, Z, curve);    /* z^2 */
	uECC_vli_modMult_fast(X1, X1, t1, curve); /* x1 * z^2 */
	uECC_vli_modMult_fast(t1, t1, Z, curve);  /* z^3 */
	uECC_vli_modMult_fast(Y1, Y1, t1, curve); /* y1 * z^3 */
}

/* P = (x1, y1) => 2P, (x2, y2) => P' */
void XYcZ_initial_double(uECC_word_t* X1,
	uECC_word_t* Y1,
	uECC_word_t* X2,
	uECC_word_t* Y2,
	const uECC_word_t* const initial_Z,
	uECC_Curve curve) {
	uECC_word_t z[uECC_MAX_WORDS];
	wordcount_t num_words = curve->num_words;
	if (initial_Z) {
		uECC_vli_set(z, initial_Z, num_words);
	}
	else {
		uECC_vli_clear(z, num_words);
		z[0] = 1;
	}

	uECC_vli_set(X2, X1, num_words);
	uECC_vli_set(Y2, Y1, num_words);

	apply_z(X1, Y1, z, curve);
	curve->double_jacobian(X1, Y1, z, curve);
	apply_z(X2, Y2, z, curve);
}

/* Input P = (x1, y1, Z), Q = (x2, y2, Z)
   Output P' = (x1', y1', Z3), P + Q = (x3, y3, Z3)
   or P => P', Q => P + Q
*/
void XYcZ_add(uECC_word_t* X1,
	uECC_word_t* Y1,
	uECC_word_t* X2,
	uECC_word_t* Y2,
	uECC_Curve curve) {
	/* t1 = X1, t2 = Y1, t3 = X2, t4 = Y2 */
	uECC_word_t t5[uECC_MAX_WORDS];
	wordcount_t num_words = curve->num_words;

	uECC_vli_modSub(t5, X2, X1, curve->p, num_words); /* t5 = x2 - x1 */
	uECC_vli_modSquare_fast(t5, t5, curve);                  /* t5 = (x2 - x1)^2 = A */
	uECC_vli_modMult_fast(X1, X1, t5, curve);                /* t1 = x1*A = B */
	uECC_vli_modMult_fast(X2, X2, t5, curve);                /* t3 = x2*A = C */
	uECC_vli_modSub(Y2, Y2, Y1, curve->p, num_words); /* t4 = y2 - y1 */
	uECC_vli_modSquare_fast(t5, Y2, curve);                  /* t5 = (y2 - y1)^2 = D */

	uECC_vli_modSub(t5, t5, X1, curve->p, num_words); /* t5 = D - B */
	uECC_vli_modSub(t5, t5, X2, curve->p, num_words); /* t5 = D - B - C = x3 */
	uECC_vli_modSub(X2, X2, X1, curve->p, num_words); /* t3 = C - B */
	uECC_vli_modMult_fast(Y1, Y1, X2, curve);                /* t2 = y1*(C - B) */
	uECC_vli_modSub(X2, X1, t5, curve->p, num_words); /* t3 = B - x3 */
	uECC_vli_modMult_fast(Y2, Y2, X2, curve);                /* t4 = (y2 - y1)*(B - x3) */
	uECC_vli_modSub(Y2, Y2, Y1, curve->p, num_words); /* t4 = y3 */

	uECC_vli_set(X2, t5, num_words);
}

/* Input P = (x1, y1, Z), Q = (x2, y2, Z)
   Output P + Q = (x3, y3, Z3), P - Q = (x3', y3', Z3)
   or P => P - Q, Q => P + Q
*/
void XYcZ_addC(uECC_word_t* X1,
	uECC_word_t* Y1,
	uECC_word_t* X2,
	uECC_word_t* Y2,
	uECC_Curve curve) {
	/* t1 = X1, t2 = Y1, t3 = X2, t4 = Y2 */
	uECC_word_t t5[uECC_MAX_WORDS];
	uECC_word_t t6[uECC_MAX_WORDS];
	uECC_word_t t7[uECC_MAX_WORDS];
	wordcount_t num_words = curve->num_words;

	uECC_vli_modSub(t5, X2, X1, curve->p, num_words); /* t5 = x2 - x1 */
	uECC_vli_modSquare_fast(t5, t5, curve);                  /* t5 = (x2 - x1)^2 = A */
	uECC_vli_modMult_fast(X1, X1, t5, curve);                /* t1 = x1*A = B */
	uECC_vli_modMult_fast(X2, X2, t5, curve);                /* t3 = x2*A = C */
	uECC_vli_modAdd(t5, Y2, Y1, curve->p, num_words); /* t5 = y2 + y1 */
	uECC_vli_modSub(Y2, Y2, Y1, curve->p, num_words); /* t4 = y2 - y1 */

	uECC_vli_modSub(t6, X2, X1, curve->p, num_words); /* t6 = C - B */
	uECC_vli_modMult_fast(Y1, Y1, t6, curve);                /* t2 = y1 * (C - B) = E */
	uECC_vli_modAdd(t6, X1, X2, curve->p, num_words); /* t6 = B + C */
	uECC_vli_modSquare_fast(X2, Y2, curve);                  /* t3 = (y2 - y1)^2 = D */
	uECC_vli_modSub(X2, X2, t6, curve->p, num_words); /* t3 = D - (B + C) = x3 */

	uECC_vli_modSub(t7, X1, X2, curve->p, num_words); /* t7 = B - x3 */
	uECC_vli_modMult_fast(Y2, Y2, t7, curve);                /* t4 = (y2 - y1)*(B - x3) */
	uECC_vli_modSub(Y2, Y2, Y1, curve->p, num_words); /* t4 = (y2 - y1)*(B - x3) - E = y3 */

	uECC_vli_modSquare_fast(t7, t5, curve);                  /* t7 = (y2 + y1)^2 = F */
	uECC_vli_modSub(t7, t7, t6, curve->p, num_words); /* t7 = F - (B + C) = x3' */
	uECC_vli_modSub(t6, t7, X1, curve->p, num_words); /* t6 = x3' - B */
	uECC_vli_modMult_fast(t6, t6, t5, curve);                /* t6 = (y2+y1)*(x3' - B) */
	uECC_vli_modSub(Y1, t6, Y1, curve->p, num_words); /* t2 = (y2+y1)*(x3' - B) - E = y3' */

	uECC_vli_set(X1, t7, num_words);
}

/* result may overlap point. */
void EccPoint_mult(uECC_word_t* result,
	const uECC_word_t* point,
	const uECC_word_t* scalar,
	const uECC_word_t* initial_Z,
	bitcount_t num_bits,
	uECC_Curve curve) {
	/* R0 and R1 */
	uECC_word_t Rx[2][uECC_MAX_WORDS];
	uECC_word_t Ry[2][uECC_MAX_WORDS];
	uECC_word_t z[uECC_MAX_WORDS];
	bitcount_t i;
	uECC_word_t nb;
	wordcount_t num_words = curve->num_words;

	uECC_vli_set(Rx[1], point, num_words);
	uECC_vli_set(Ry[1], point + num_words, num_words);

	XYcZ_initial_double(Rx[1], Ry[1], Rx[0], Ry[0], initial_Z, curve);

	for (i = num_bits - 2; i > 0; --i) {
		nb = !uECC_vli_testBit(scalar, i);
		XYcZ_addC(Rx[1 - nb], Ry[1 - nb], Rx[nb], Ry[nb], curve);
		XYcZ_add(Rx[nb], Ry[nb], Rx[1 - nb], Ry[1 - nb], curve);
	}

	nb = !uECC_vli_testBit(scalar, 0);
	XYcZ_addC(Rx[1 - nb], Ry[1 - nb], Rx[nb], Ry[nb], curve);

	/* Find final 1/Z value. */
	uECC_vli_modSub(z, Rx[1], Rx[0], curve->p, num_words); /* X1 - X0 */
	uECC_vli_modMult_fast(z, z, Ry[1 - nb], curve);               /* Yb * (X1 - X0) */
	uECC_vli_modMult_fast(z, z, point, curve);                    /* xP * Yb * (X1 - X0) */
	uECC_vli_modInv(z, z, curve->p, num_words);            /* 1 / (xP * Yb * (X1 - X0)) */
	/* yP / (xP * Yb * (X1 - X0)) */
	uECC_vli_modMult_fast(z, z, point + num_words, curve);
	uECC_vli_modMult_fast(z, z, Rx[1 - nb], curve); /* Xb * yP / (xP * Yb * (X1 - X0)) */
	/* End 1/Z calculation */

	XYcZ_add(Rx[nb], Ry[nb], Rx[1 - nb], Ry[1 - nb], curve);
	apply_z(Rx[0], Ry[0], z, curve);

	uECC_vli_set(result, Rx[0], num_words);
	uECC_vli_set(result + num_words, Ry[0], num_words);
}

uECC_word_t regularize_k(const uECC_word_t* const k,
	uECC_word_t* k0,
	uECC_word_t* k1,
	uECC_Curve curve) {
	wordcount_t num_n_words = BITS_TO_WORDS(curve->num_n_bits);
	bitcount_t num_n_bits = curve->num_n_bits;
	uECC_word_t carry = uECC_vli_add(k0, k, curve->n, num_n_words) ||
		(num_n_bits < ((bitcount_t)num_n_words * uECC_WORD_SIZE * 8) &&
			uECC_vli_testBit(k0, num_n_bits));
	uECC_vli_add(k1, k0, curve->n, num_n_words);
	return carry;
}

//uECC_word_t EccPoint_compute_public_key(uECC_word_t* result,
//	uECC_word_t* private_key,
//	uECC_Curve curve) {
//	uECC_word_t tmp1[uECC_MAX_WORDS];
//	uECC_word_t tmp2[uECC_MAX_WORDS];
//	uECC_word_t* p2[2] = { tmp1, tmp2 };
//	uECC_word_t carry;
//
//	/* Regularize the bitcount for the private key so that attackers cannot use a side channel
//	   attack to learn the number of leading zeros. */
//	carry = regularize_k(private_key, tmp1, tmp2, curve);
//
//	EccPoint_mult(result, curve->G, p2[!carry], 0, curve->num_n_bits + 1, curve);
//
//	if (EccPoint_isZero(result, curve)) {
//		return 0;
//	}
//	return 1;
//}

uECC_word_t Ecc_Point_mult(uECC_word_t* result,
	const uECC_word_t* point,
	const uECC_word_t* scalar,
	uECC_Curve curve) {
	uECC_word_t tmp1[uECC_MAX_WORDS];
	uECC_word_t tmp2[uECC_MAX_WORDS];
	uECC_word_t* p2[2] = { tmp1, tmp2 };
	uECC_word_t carry;

	/* Regularize the bitcount for the private key so that attackers cannot use a side channel
	   attack to learn the number of leading zeros. */
	carry = regularize_k(scalar, tmp1, tmp2, curve);

	if (!uECC_generate_random_int(p2[carry], curve->p, curve->num_words)) {
		return 0;
	}
	uECC_word_t* initial_Z = p2[carry];

	EccPoint_mult(result, point, p2[!carry], initial_Z, curve->num_n_bits + 1, curve);
	//EccPoint_mult(result, point, scalar, 0, curve->num_n_bits + 1, curve);

	if (EccPoint_isZero(result, curve)) {
		return 0;
	}
	return 1;
}

//int Ecc_Point_add(uECC_word_t* result, uECC_word_t* P,
//	uECC_word_t* Q,
//	uECC_Curve curve) {
//	uint32_t lambda[uECC_MAX_WORDS], deltaX[uECC_MAX_WORDS], x[uECC_MAX_WORDS], y[uECC_MAX_WORDS];
//	if (uECC_vli_equal(P, Q, curve->num_words)) {
//		if (uECC_vli_equal(P + curve->num_words, Q + curve->num_words, curve->num_words))
//		{
//			uECC_word_t scalar2[uECC_MAX_WORDS];
//			uECC_vli_clear(scalar2, curve->num_words);
//			scalar2[0] = 2;
//			Ecc_Point_mult(result, P, scalar2, curve);
//			return 0;
//		}
//		memcpy(result, curve->p, curve->num_bytes);
//		memcpy(result + curve->num_words, curve->p, curve->num_bytes);
//		return 1;
//	}
//
//	uECC_vli_modSub(lambda, Q + curve->num_words, P + curve->num_words, curve->p, curve->num_words);
//	uECC_vli_modSub(deltaX, Q, P, curve->p, curve->num_words);
//	uECC_vli_modInv(deltaX, deltaX, curve->p, curve->num_words);
//	uECC_vli_modMult_fast(lambda, lambda, deltaX, curve);
//
//
//	uECC_vli_modSquare_fast(x, lambda, curve);
//	uECC_vli_modSub(x, x, P, curve->p, curve->num_words);
//	uECC_vli_modSub(x, x, Q, curve->p, curve->num_words);
//
//	uECC_vli_modSub(y, P, x, curve->p, curve->num_words);
//	uECC_vli_modMult_fast(y, y, lambda, curve);
//	uECC_vli_modSub(y, y, P + curve->num_words, curve->p, curve->num_words);
//
//	memcpy(result, x, curve->num_bytes);
//	memcpy(result + curve->num_words, y, curve->num_bytes);
//	return 0;
//}

int Ecc_Point_add(uECC_word_t* result, uECC_word_t* P,
	uECC_word_t* Q,
	uECC_Curve curve) {
	if (uECC_vli_equal(P, Q, curve->num_words)) {
		if (uECC_vli_equal(P + curve->num_words, Q + curve->num_words, curve->num_words))
		{
			uECC_word_t scalar2[uECC_MAX_WORDS];
			uECC_vli_clear(scalar2, uECC_MAX_WORDS);
			scalar2[0] = 2;
			Ecc_Point_mult(result, P, scalar2, curve);
			return 0;
		}
		memcpy(result, curve->p, BITS_TO_BYTES(curve->num_n_bits));
		memcpy(result + curve->num_words, curve->p, BITS_TO_BYTES(curve->num_n_bits));
		return 1;
	}
	
	uECC_word_t tmp[2 * MAX_KEY_SIZE], z[MAX_KEY_SIZE];
	memcpy(tmp, P, 2 * BITS_TO_BYTES(curve->num_n_bits));
	memcpy(result, Q, 2 * BITS_TO_BYTES(curve->num_n_bits));
	
	uECC_vli_modSub(z, result, tmp, curve->p, curve->num_words); /* z = x2 - x1 */
	XYcZ_add(tmp, tmp + curve->num_words, result, result + curve->num_words, curve);
	uECC_vli_modInv(z, z, curve->p, curve->num_words); /* z = 1/z */
	apply_z(result, result + curve->num_words, z, curve);
	return 0;
}

static inline bitcount_t smax(bitcount_t a, bitcount_t b) {
	return (a > b ? a : b);
}

int multoadd(uECC_word_t *R, uECC_word_t *n, uECC_word_t *P, uECC_word_t *m, uECC_word_t *Q, uECC_Curve curve) {
	/* Use Shamir's trick to calculate u1*G + u2*Q */

	const uECC_word_t* points[4];
	const uECC_word_t* point;
	
	wordcount_t num_words = curve->num_words;
	wordcount_t num_n_words = BITS_TO_WORDS(curve->num_n_bits);
	bitcount_t num_bits = smax(uECC_vli_numBits(n, num_n_words), uECC_vli_numBits(m, num_n_words));

	uECC_word_t z[MAX_KEY_SIZE], T[2 * MAX_KEY_SIZE], tz[MAX_KEY_SIZE], sum[2 * MAX_KEY_SIZE];
	
	Ecc_Point_add(sum, P, Q, curve);

	points[0] = NULL;
	points[1] = P;
	points[2] = Q;
	points[3] = sum;

	point = points[(!!uECC_vli_testBit(n, num_bits - 1)) | ((!!uECC_vli_testBit(m, num_bits - 1)) << 1)];

	memcpy(R, point, 2 * curve->num_bytes);


	uECC_vli_clear(z, num_words);
	z[0] = 1;

	for (bitcount_t i = num_bits - 2; i >= 0; --i) {
		uECC_word_t index;
		curve->double_jacobian(R, R + curve->num_words, z, curve);

		index = (!!uECC_vli_testBit(n, i)) | ((!!uECC_vli_testBit(m, i)) << 1);
		point = points[index];
		if (point) {
			memcpy(T, point, curve->num_bytes);
			memcpy(T + num_words, point + num_words, curve->num_bytes);
			apply_z(T, T + num_words, z, curve);
			uECC_vli_modSub(tz, R, T, curve->p, num_words); /* Z = x2 - x1 */
			XYcZ_add(T, T + num_words, R, R + curve->num_words, curve);
			uECC_vli_modMult_fast(z, z, tz, curve);
		}
	}

	uECC_vli_modInv(z, z, curve->p, num_words); /* Z = 1/Z */
	apply_z(R, R + curve->num_words, z, curve);

	return 0;
}


//int Ecc_Point_add3(uECC_word_t* result, uECC_word_t* P,
//	uECC_word_t* Q,
//	uECC_word_t* R,
//	uECC_Curve curve) {
//	wordcount_t num_words = curve->num_words;
//	if (uECC_vli_equal(P, Q, curve->num_words)) {
//		if (uECC_vli_equal(P + curve->num_words, Q + curve->num_words, curve->num_words))
//		{
//			uECC_word_t scalar2[uECC_MAX_WORDS];
//			uECC_vli_clear(scalar2, uECC_MAX_WORDS);
//			scalar2[0] = 2;
//			Ecc_Point_mult(result, P, scalar2, curve);
//			return 0;
//		}
//		memcpy(result, curve->p, BITS_TO_BYTES(curve->num_n_bits));
//		memcpy(result + curve->num_words, curve->p, BITS_TO_BYTES(curve->num_n_bits));
//		return 1;
//	}
//
//	uECC_word_t tmp[2 * MAX_KEY_SIZE], z[MAX_KEY_SIZE], z3[MAX_KEY_SIZE];
//	memcpy(tmp, P, 2 * BITS_TO_BYTES(curve->num_n_bits));
//	memcpy(result, Q, 2 * BITS_TO_BYTES(curve->num_n_bits));
//
//	uECC_vli_modSub(z, result, tmp, curve->p, curve->num_words); /* z = xQ - xP */
//
//	XYcZ_add(tmp, tmp + curve->num_words, result, result + curve->num_words, curve);
//	memcpy(tmp, R, 2 * BITS_TO_BYTES(curve->num_n_bits));
//
//	apply_z(result, result + num_words, z, curve);
//
//	uECC_vli_modSub(z3, result, R, curve->p, curve->num_words); /* z = xR - xSUM */
//
//	XYcZ_add(tmp, tmp + num_words, result, result + num_words, curve);
//
//	uECC_vli_modMult_fast(z, z, z3, curve);
//	
//	uECC_vli_modInv(z, z, curve->p, curve->num_words); /* z = 1/z */
//	apply_z(result, result + curve->num_words, z, curve);
//	return 0;
//}

int check_valid_point(const uECC_word_t* point, const uECC_word_t* xSide, uECC_Curve curve) {
    uECC_word_t ySquare[uECC_MAX_WORDS];
    
    /* The point at infinity is invalid. */
    if (EccPoint_isZero(point, curve)) {
        return 0;
    }
    
    /* x and y must be smaller than p. */
    if (uECC_vli_equal(curve->p, point, curve->num_words) ||
        uECC_vli_equal(curve->p, point + curve->num_words, curve->num_words)) {
        return 0;
    }
    
    uECC_vli_modSquare_fast(ySquare, point + curve->num_words, curve);
    //curve->x_side(tmp2, point, curve); /* tmp2 = x^3 + ax + b */
    
    /* Make sure that y^2 == x^3 + ax + b */
    return (int)(uECC_vli_equal(ySquare, xSide, curve->num_words));
}
