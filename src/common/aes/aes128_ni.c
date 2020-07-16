// SPDX-License-Identifier: Public domain
// Based on public domain code by Romain Dolbeau
// http://dolbeau.name/dolbeau/crypto/crypto.html

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <oqs/common.h>

#include <wmmintrin.h>

// From crypto_core/aes128ncrypt/dolbeau/aesenc-int
static inline void aes128ni_setkey_encrypt(const unsigned char *key, __m128i rkeys[11]) {
	__m128i key0 = _mm_loadu_si128((const __m128i_u *)(key + 0));
	__m128i temp0, temp1, temp4;
	int idx = 0;

	temp0 = key0;

	/* blockshift-based block by Cedric Bourrasset */
#define BLOCK1(IMM)                                       \
    temp1 = _mm_aeskeygenassist_si128(temp0, IMM);        \
    rkeys[idx++] = temp0;                                 \
    temp4 = _mm_slli_si128(temp0,4);                      \
    temp0 = _mm_xor_si128(temp0,temp4);                   \
    temp4 = _mm_slli_si128(temp0,8);                      \
    temp0 = _mm_xor_si128(temp0,temp4);                   \
    temp1 = _mm_shuffle_epi32(temp1,0xff);                \
    temp0 = _mm_xor_si128(temp0,temp1)

	BLOCK1(0x01);
	BLOCK1(0x02);
	BLOCK1(0x04);
	BLOCK1(0x08);
	BLOCK1(0x10);
	BLOCK1(0x20);
	BLOCK1(0x40);
	BLOCK1(0x80);
	BLOCK1(0x1b);
	BLOCK1(0x36);
	rkeys[idx++] = temp0;
}

// From crypto_core/aes128decrypt/dolbeau/aesenc-int
static inline void aes128ni_setkey_decrypt(const unsigned char *key, __m128i rkeys[11]) {
	__m128i tkeys[11];
	aes128ni_setkey_encrypt(key, tkeys);
	rkeys[0] = tkeys[10];
	rkeys[1] = _mm_aesimc_si128(tkeys[9]);
	rkeys[2] = _mm_aesimc_si128(tkeys[8]);
	rkeys[3] = _mm_aesimc_si128(tkeys[7]);
	rkeys[4] = _mm_aesimc_si128(tkeys[6]);
	rkeys[5] = _mm_aesimc_si128(tkeys[5]);
	rkeys[6] = _mm_aesimc_si128(tkeys[4]);
	rkeys[7] = _mm_aesimc_si128(tkeys[3]);
	rkeys[8] = _mm_aesimc_si128(tkeys[2]);
	rkeys[9] = _mm_aesimc_si128(tkeys[1]);
	rkeys[10] = tkeys[0];
}

void oqs_aes128_load_schedule_ni(const uint8_t *key, void **_schedule, int for_encryption) {
	*_schedule = malloc(11 * sizeof(__m128i));
	assert(*_schedule != NULL);
	__m128i *schedule = (__m128i *) *_schedule;
	if (for_encryption) {
		aes128ni_setkey_encrypt(key, schedule);
	} else {
		aes128ni_setkey_decrypt(key, schedule);
	}
}

void oqs_aes128_free_schedule_ni(void *schedule) {
	if (schedule != NULL) {
		OQS_MEM_secure_free(schedule, 11 * sizeof(__m128i));
	}
}

// From crypto_core/aes128encrypt/dolbeau/aesenc-int
static inline void aes128ni_encrypt(const __m128i rkeys[11], const unsigned char *n, unsigned char *out) {
	__m128i nv = _mm_load_si128((const __m128i *)n);
	__m128i temp = _mm_xor_si128(nv, rkeys[0]);
	temp = _mm_aesenc_si128(temp, rkeys[1]);
	temp = _mm_aesenc_si128(temp, rkeys[2]);
	temp = _mm_aesenc_si128(temp, rkeys[3]);
	temp = _mm_aesenc_si128(temp, rkeys[4]);
	temp = _mm_aesenc_si128(temp, rkeys[5]);
	temp = _mm_aesenc_si128(temp, rkeys[6]);
	temp = _mm_aesenc_si128(temp, rkeys[7]);
	temp = _mm_aesenc_si128(temp, rkeys[8]);
	temp = _mm_aesenc_si128(temp, rkeys[9]);
	temp = _mm_aesenclast_si128(temp, rkeys[10]);
	_mm_store_si128((__m128i *)(out), temp);
}

void oqs_aes128_enc_sch_block_ni(const uint8_t *plaintext, const void *_schedule, uint8_t *ciphertext) {
	const __m128i *schedule = (const __m128i *) _schedule;
	aes128ni_encrypt(schedule, plaintext, ciphertext);
}

void oqs_aes128_enc_sch_block8x_ni(const uint8_t *plaintext, const void *_schedule, uint8_t *ciphertext) {

	const __m128i *rkeys = (const __m128i *) _schedule;

	const uint8_t *pt0 = plaintext + 0 * 16;
	const uint8_t *pt1 = plaintext + 1 * 16;
	const uint8_t *pt2 = plaintext + 2 * 16;
	const uint8_t *pt3 = plaintext + 3 * 16;
	const uint8_t *pt4 = plaintext + 4 * 16;
	const uint8_t *pt5 = plaintext + 5 * 16;
	const uint8_t *pt6 = plaintext + 6 * 16;
	const uint8_t *pt7 = plaintext + 7 * 16;

	uint8_t *ct0 = ciphertext + 0 * 16;
	uint8_t *ct1 = ciphertext + 1 * 16;
	uint8_t *ct2 = ciphertext + 2 * 16;
	uint8_t *ct3 = ciphertext + 3 * 16;
	uint8_t *ct4 = ciphertext + 4 * 16;
	uint8_t *ct5 = ciphertext + 5 * 16;
	uint8_t *ct6 = ciphertext + 6 * 16;
	uint8_t *ct7 = ciphertext + 7 * 16;

	__m128i nv0 = _mm_load_si128((const __m128i *) pt0);
	__m128i nv1 = _mm_load_si128((const __m128i *) pt1);
	__m128i nv2 = _mm_load_si128((const __m128i *) pt2);
	__m128i nv3 = _mm_load_si128((const __m128i *) pt3);
	__m128i nv4 = _mm_load_si128((const __m128i *) pt4);
	__m128i nv5 = _mm_load_si128((const __m128i *) pt5);
	__m128i nv6 = _mm_load_si128((const __m128i *) pt6);
	__m128i nv7 = _mm_load_si128((const __m128i *) pt7);

	__m128i temp0 = _mm_xor_si128(nv0, rkeys[0]);
	__m128i temp1 = _mm_xor_si128(nv1, rkeys[0]);
	__m128i temp2 = _mm_xor_si128(nv2, rkeys[0]);
	__m128i temp3 = _mm_xor_si128(nv3, rkeys[0]);
	__m128i temp4 = _mm_xor_si128(nv4, rkeys[0]);
	__m128i temp5 = _mm_xor_si128(nv5, rkeys[0]);
	__m128i temp6 = _mm_xor_si128(nv6, rkeys[0]);
	__m128i temp7 = _mm_xor_si128(nv7, rkeys[0]);

#pragma unroll(9)
	for (int i = 1 ; i < 10 ; i++) {
		temp0 = _mm_aesenc_si128(temp0, rkeys[i]);
		temp1 = _mm_aesenc_si128(temp1, rkeys[i]);
		temp2 = _mm_aesenc_si128(temp2, rkeys[i]);
		temp3 = _mm_aesenc_si128(temp3, rkeys[i]);
		temp4 = _mm_aesenc_si128(temp4, rkeys[i]);
		temp5 = _mm_aesenc_si128(temp5, rkeys[i]);
		temp6 = _mm_aesenc_si128(temp6, rkeys[i]);
		temp7 = _mm_aesenc_si128(temp7, rkeys[i]);
	}

	temp0 = _mm_aesenclast_si128(temp0, rkeys[10]);
	temp1 = _mm_aesenclast_si128(temp1, rkeys[10]);
	temp2 = _mm_aesenclast_si128(temp2, rkeys[10]);
	temp3 = _mm_aesenclast_si128(temp3, rkeys[10]);
	temp4 = _mm_aesenclast_si128(temp4, rkeys[10]);
	temp5 = _mm_aesenclast_si128(temp5, rkeys[10]);
	temp6 = _mm_aesenclast_si128(temp6, rkeys[10]);
	temp7 = _mm_aesenclast_si128(temp7, rkeys[10]);

	_mm_store_si128((__m128i *) ct0, temp0);
	_mm_store_si128((__m128i *) ct1, temp1);
	_mm_store_si128((__m128i *) ct2, temp2);
	_mm_store_si128((__m128i *) ct3, temp3);
	_mm_store_si128((__m128i *) ct4, temp4);
	_mm_store_si128((__m128i *) ct5, temp5);
	_mm_store_si128((__m128i *) ct6, temp6);
	_mm_store_si128((__m128i *) ct7, temp7);

}

// From crypto_core/aes128decrypt/dolbeau/aesenc-int
static inline void aes128ni_decrypt(const __m128i rkeys[11], const unsigned char *n, unsigned char *out) {
	__m128i nv = _mm_load_si128((const __m128i *)n);
	__m128i temp = _mm_xor_si128(nv, rkeys[0]);
	temp = _mm_aesdec_si128(temp, rkeys[1]);
	temp = _mm_aesdec_si128(temp, rkeys[2]);
	temp = _mm_aesdec_si128(temp, rkeys[3]);
	temp = _mm_aesdec_si128(temp, rkeys[4]);
	temp = _mm_aesdec_si128(temp, rkeys[5]);
	temp = _mm_aesdec_si128(temp, rkeys[6]);
	temp = _mm_aesdec_si128(temp, rkeys[7]);
	temp = _mm_aesdec_si128(temp, rkeys[8]);
	temp = _mm_aesdec_si128(temp, rkeys[9]);
	temp = _mm_aesdeclast_si128(temp, rkeys[10]);
	_mm_store_si128((__m128i *)(out), temp);
}

void oqs_aes128_dec_sch_block_ni(const uint8_t *ciphertext, const void *_schedule, uint8_t *plaintext) {
	const __m128i *schedule = (const __m128i *) _schedule;
	aes128ni_decrypt(schedule, ciphertext, plaintext);
}
