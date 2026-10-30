#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <wmmintrin.h>
#include <emmintrin.h>
#include <smmintrin.h>
#include <omp.h>

static const uint8_t SEG_CT[4][16] = {
    {0x23,0x67,0x3a,0x4d,0x75,0x3f,0x67,0x5a,0x02,0x2a,0x71,0x10,0x4d,0x66,0x54,0xbe},
    {0x45,0x66,0x81,0xa3,0x80,0xa1,0x10,0xe3,0x3f,0x8b,0xe3,0x0b,0xcb,0x63,0x54,0xa6},
    {0xd7,0xa1,0xa6,0xb5,0x42,0x0d,0x69,0x8b,0x8d,0xed,0xfd,0x51,0x94,0x13,0xb9,0xb1},
    {0xec,0x26,0x65,0x66,0x3c,0x02,0x30,0x65,0x1b,0xfd,0x36,0x66,0xd3,0xb6,0xfd,0x76}
};

static const uint8_t SEG_IV[4][16] = {
    "few_n_far_btween",
    "nocturnal_sugars",
    "colors_on_leaves",
    "seconds_of_dream"
};

static inline __m128i key_exp_1_assist(__m128i k1, __m128i k2gen) {
    k2gen = _mm_shuffle_epi32(k2gen, 0xff);
    __m128i t = _mm_slli_si128(k1, 4);
    k1 = _mm_xor_si128(k1, t);
    t = _mm_slli_si128(k1, 8);
    k1 = _mm_xor_si128(k1, t);
    return _mm_xor_si128(k1, k2gen);
}

static inline __m128i key_exp_2(__m128i k1, __m128i k2) {
    __m128i k4 = _mm_aeskeygenassist_si128(k1, 0x00);
    __m128i k3 = _mm_shuffle_epi32(k4, 0xaa);
    __m128i t = _mm_slli_si128(k2, 4);
    k2 = _mm_xor_si128(k2, t);
    t = _mm_slli_si128(k2, 8);
    k2 = _mm_xor_si128(k2, t);
    return _mm_xor_si128(k2, k3);
}

static inline __m128i aes256_cbc_dec_1block(__m128i k0, __m128i k1, __m128i ct, __m128i iv) {
    __m128i rk0 = k0;
    __m128i rk1 = k1;
    __m128i rk2 = key_exp_1_assist(rk0, _mm_aeskeygenassist_si128(rk1, 0x01));
    __m128i rk3 = key_exp_2(rk2, rk1);
    __m128i rk4 = key_exp_1_assist(rk2, _mm_aeskeygenassist_si128(rk3, 0x02));
    __m128i rk5 = key_exp_2(rk4, rk3);
    __m128i rk6 = key_exp_1_assist(rk4, _mm_aeskeygenassist_si128(rk5, 0x04));
    __m128i rk7 = key_exp_2(rk6, rk5);
    __m128i rk8 = key_exp_1_assist(rk6, _mm_aeskeygenassist_si128(rk7, 0x08));
    __m128i rk9 = key_exp_2(rk8, rk7);
    __m128i rk10 = key_exp_1_assist(rk8, _mm_aeskeygenassist_si128(rk9, 0x10));
    __m128i rk11 = key_exp_2(rk10, rk9);
    __m128i rk12 = key_exp_1_assist(rk10, _mm_aeskeygenassist_si128(rk11, 0x20));
    __m128i rk13 = key_exp_2(rk12, rk11);
    __m128i rk14 = key_exp_1_assist(rk12, _mm_aeskeygenassist_si128(rk13, 0x40));

    __m128i s = _mm_xor_si128(ct, rk14);
    s = _mm_aesdec_si128(s, _mm_aesimc_si128(rk13));
    s = _mm_aesdec_si128(s, _mm_aesimc_si128(rk12));
    s = _mm_aesdec_si128(s, _mm_aesimc_si128(rk11));
    s = _mm_aesdec_si128(s, _mm_aesimc_si128(rk10));
    s = _mm_aesdec_si128(s, _mm_aesimc_si128(rk9));
    s = _mm_aesdec_si128(s, _mm_aesimc_si128(rk8));
    s = _mm_aesdec_si128(s, _mm_aesimc_si128(rk7));
    s = _mm_aesdec_si128(s, _mm_aesimc_si128(rk6));
    s = _mm_aesdec_si128(s, _mm_aesimc_si128(rk5));
    s = _mm_aesdec_si128(s, _mm_aesimc_si128(rk4));
    s = _mm_aesdec_si128(s, _mm_aesimc_si128(rk3));
    s = _mm_aesdec_si128(s, _mm_aesimc_si128(rk2));
    s = _mm_aesdec_si128(s, _mm_aesimc_si128(rk1));
    s = _mm_aesdeclast_si128(s, rk0);
    return _mm_xor_si128(s, iv);
}

// 4-way ILP pipelined decrypt when k1 (bytes 16..31) is shared across 4 keys a,b,c,d!
static inline void aes256_cbc_dec_4x_shared_k1(
    __m128i k0a, __m128i k0b, __m128i k0c, __m128i k0d,
    __m128i rk1, __m128i rk1_imc, __m128i rk1_assist,
    __m128i ct, __m128i iv,
    __m128i *pta, __m128i *ptb, __m128i *ptc, __m128i *ptd
) {
    __m128i rk2a = key_exp_1_assist(k0a, rk1_assist);
    __m128i rk2b = key_exp_1_assist(k0b, rk1_assist);
    __m128i rk2c = key_exp_1_assist(k0c, rk1_assist);
    __m128i rk2d = key_exp_1_assist(k0d, rk1_assist);

    __m128i rk3a = key_exp_2(rk2a, rk1);
    __m128i rk3b = key_exp_2(rk2b, rk1);
    __m128i rk3c = key_exp_2(rk2c, rk1);
    __m128i rk3d = key_exp_2(rk2d, rk1);

    __m128i rk4a = key_exp_1_assist(rk2a, _mm_aeskeygenassist_si128(rk3a, 0x02));
    __m128i rk4b = key_exp_1_assist(rk2b, _mm_aeskeygenassist_si128(rk3b, 0x02));
    __m128i rk4c = key_exp_1_assist(rk2c, _mm_aeskeygenassist_si128(rk3c, 0x02));
    __m128i rk4d = key_exp_1_assist(rk2d, _mm_aeskeygenassist_si128(rk3d, 0x02));

    __m128i rk5a = key_exp_2(rk4a, rk3a);
    __m128i rk5b = key_exp_2(rk4b, rk3b);
    __m128i rk5c = key_exp_2(rk4c, rk3c);
    __m128i rk5d = key_exp_2(rk4d, rk3d);

    __m128i rk6a = key_exp_1_assist(rk4a, _mm_aeskeygenassist_si128(rk5a, 0x04));
    __m128i rk6b = key_exp_1_assist(rk4b, _mm_aeskeygenassist_si128(rk5b, 0x04));
    __m128i rk6c = key_exp_1_assist(rk4c, _mm_aeskeygenassist_si128(rk5c, 0x04));
    __m128i rk6d = key_exp_1_assist(rk4d, _mm_aeskeygenassist_si128(rk5d, 0x04));

    __m128i rk7a = key_exp_2(rk6a, rk5a);
    __m128i rk7b = key_exp_2(rk6b, rk5b);
    __m128i rk7c = key_exp_2(rk6c, rk5c);
    __m128i rk7d = key_exp_2(rk6d, rk5d);

    __m128i rk8a = key_exp_1_assist(rk6a, _mm_aeskeygenassist_si128(rk7a, 0x08));
    __m128i rk8b = key_exp_1_assist(rk6b, _mm_aeskeygenassist_si128(rk7b, 0x08));
    __m128i rk8c = key_exp_1_assist(rk6c, _mm_aeskeygenassist_si128(rk7c, 0x08));
    __m128i rk8d = key_exp_1_assist(rk6d, _mm_aeskeygenassist_si128(rk7d, 0x08));

    __m128i rk9a = key_exp_2(rk8a, rk7a);
    __m128i rk9b = key_exp_2(rk8b, rk7b);
    __m128i rk9c = key_exp_2(rk8c, rk7c);
    __m128i rk9d = key_exp_2(rk8d, rk7d);

    __m128i rk10a = key_exp_1_assist(rk8a, _mm_aeskeygenassist_si128(rk9a, 0x10));
    __m128i rk10b = key_exp_1_assist(rk8b, _mm_aeskeygenassist_si128(rk9b, 0x10));
    __m128i rk10c = key_exp_1_assist(rk8c, _mm_aeskeygenassist_si128(rk9c, 0x10));
    __m128i rk10d = key_exp_1_assist(rk8d, _mm_aeskeygenassist_si128(rk9d, 0x10));

    __m128i rk11a = key_exp_2(rk10a, rk9a);
    __m128i rk11b = key_exp_2(rk10b, rk9b);
    __m128i rk11c = key_exp_2(rk10c, rk9c);
    __m128i rk11d = key_exp_2(rk10d, rk9d);

    __m128i rk12a = key_exp_1_assist(rk10a, _mm_aeskeygenassist_si128(rk11a, 0x20));
    __m128i rk12b = key_exp_1_assist(rk10b, _mm_aeskeygenassist_si128(rk11b, 0x20));
    __m128i rk12c = key_exp_1_assist(rk10c, _mm_aeskeygenassist_si128(rk11c, 0x20));
    __m128i rk12d = key_exp_1_assist(rk10d, _mm_aeskeygenassist_si128(rk11d, 0x20));

    __m128i rk13a = key_exp_2(rk12a, rk11a);
    __m128i rk13b = key_exp_2(rk12b, rk11b);
    __m128i rk13c = key_exp_2(rk12c, rk11c);
    __m128i rk13d = key_exp_2(rk12d, rk11d);

    __m128i rk14a = key_exp_1_assist(rk12a, _mm_aeskeygenassist_si128(rk13a, 0x40));
    __m128i rk14b = key_exp_1_assist(rk12b, _mm_aeskeygenassist_si128(rk13b, 0x40));
    __m128i rk14c = key_exp_1_assist(rk12c, _mm_aeskeygenassist_si128(rk13c, 0x40));
    __m128i rk14d = key_exp_1_assist(rk12d, _mm_aeskeygenassist_si128(rk13d, 0x40));

    __m128i sa = _mm_xor_si128(ct, rk14a);
    __m128i sb = _mm_xor_si128(ct, rk14b);
    __m128i sc = _mm_xor_si128(ct, rk14c);
    __m128i sd = _mm_xor_si128(ct, rk14d);

    sa = _mm_aesdec_si128(sa, _mm_aesimc_si128(rk13a));
    sb = _mm_aesdec_si128(sb, _mm_aesimc_si128(rk13b));
    sc = _mm_aesdec_si128(sc, _mm_aesimc_si128(rk13c));
    sd = _mm_aesdec_si128(sd, _mm_aesimc_si128(rk13d));

    sa = _mm_aesdec_si128(sa, _mm_aesimc_si128(rk12a));
    sb = _mm_aesdec_si128(sb, _mm_aesimc_si128(rk12b));
    sc = _mm_aesdec_si128(sc, _mm_aesimc_si128(rk12c));
    sd = _mm_aesdec_si128(sd, _mm_aesimc_si128(rk12d));

    sa = _mm_aesdec_si128(sa, _mm_aesimc_si128(rk11a));
    sb = _mm_aesdec_si128(sb, _mm_aesimc_si128(rk11b));
    sc = _mm_aesdec_si128(sc, _mm_aesimc_si128(rk11c));
    sd = _mm_aesdec_si128(sd, _mm_aesimc_si128(rk11d));

    sa = _mm_aesdec_si128(sa, _mm_aesimc_si128(rk10a));
    sb = _mm_aesdec_si128(sb, _mm_aesimc_si128(rk10b));
    sc = _mm_aesdec_si128(sc, _mm_aesimc_si128(rk10c));
    sd = _mm_aesdec_si128(sd, _mm_aesimc_si128(rk10d));

    sa = _mm_aesdec_si128(sa, _mm_aesimc_si128(rk9a));
    sb = _mm_aesdec_si128(sb, _mm_aesimc_si128(rk9b));
    sc = _mm_aesdec_si128(sc, _mm_aesimc_si128(rk9c));
    sd = _mm_aesdec_si128(sd, _mm_aesimc_si128(rk9d));

    sa = _mm_aesdec_si128(sa, _mm_aesimc_si128(rk8a));
    sb = _mm_aesdec_si128(sb, _mm_aesimc_si128(rk8b));
    sc = _mm_aesdec_si128(sc, _mm_aesimc_si128(rk8c));
    sd = _mm_aesdec_si128(sd, _mm_aesimc_si128(rk8d));

    sa = _mm_aesdec_si128(sa, _mm_aesimc_si128(rk7a));
    sb = _mm_aesdec_si128(sb, _mm_aesimc_si128(rk7b));
    sc = _mm_aesdec_si128(sc, _mm_aesimc_si128(rk7c));
    sd = _mm_aesdec_si128(sd, _mm_aesimc_si128(rk7d));

    sa = _mm_aesdec_si128(sa, _mm_aesimc_si128(rk6a));
    sb = _mm_aesdec_si128(sb, _mm_aesimc_si128(rk6b));
    sc = _mm_aesdec_si128(sc, _mm_aesimc_si128(rk6c));
    sd = _mm_aesdec_si128(sd, _mm_aesimc_si128(rk6d));

    sa = _mm_aesdec_si128(sa, _mm_aesimc_si128(rk5a));
    sb = _mm_aesdec_si128(sb, _mm_aesimc_si128(rk5b));
    sc = _mm_aesdec_si128(sc, _mm_aesimc_si128(rk5c));
    sd = _mm_aesdec_si128(sd, _mm_aesimc_si128(rk5d));

    sa = _mm_aesdec_si128(sa, _mm_aesimc_si128(rk4a));
    sb = _mm_aesdec_si128(sb, _mm_aesimc_si128(rk4b));
    sc = _mm_aesdec_si128(sc, _mm_aesimc_si128(rk4c));
    sd = _mm_aesdec_si128(sd, _mm_aesimc_si128(rk4d));

    sa = _mm_aesdec_si128(sa, _mm_aesimc_si128(rk3a));
    sb = _mm_aesdec_si128(sb, _mm_aesimc_si128(rk3b));
    sc = _mm_aesdec_si128(sc, _mm_aesimc_si128(rk3c));
    sd = _mm_aesdec_si128(sd, _mm_aesimc_si128(rk3d));

    sa = _mm_aesdec_si128(sa, _mm_aesimc_si128(rk2a));
    sb = _mm_aesdec_si128(sb, _mm_aesimc_si128(rk2b));
    sc = _mm_aesdec_si128(sc, _mm_aesimc_si128(rk2c));
    sd = _mm_aesdec_si128(sd, _mm_aesimc_si128(rk2d));

    sa = _mm_aesdec_si128(sa, rk1_imc);
    sb = _mm_aesdec_si128(sb, rk1_imc);
    sc = _mm_aesdec_si128(sc, rk1_imc);
    sd = _mm_aesdec_si128(sd, rk1_imc);

    *pta = _mm_xor_si128(_mm_aesdeclast_si128(sa, k0a), iv);
    *ptb = _mm_xor_si128(_mm_aesdeclast_si128(sb, k0b), iv);
    *ptc = _mm_xor_si128(_mm_aesdeclast_si128(sc, k0c), iv);
    *ptd = _mm_xor_si128(_mm_aesdeclast_si128(sd, k0d), iv);
}

void test_decrypt_block(int seg, const char *key32, uint8_t *out16) {
    __m128i k0 = _mm_loadu_si128((const __m128i *)key32);
    __m128i k1 = _mm_loadu_si128((const __m128i *)(key32 + 16));
    __m128i ct = _mm_loadu_si128((const __m128i *)SEG_CT[seg]);
    __m128i iv = _mm_loadu_si128((const __m128i *)SEG_IV[seg]);
    __m128i pt = aes256_cbc_dec_1block(k0, k1, ct, iv);
    _mm_storeu_si128((__m128i *)out16, pt);
}

int sweep_pairs(
    int seg,
    const char *lefts, int n_left, int len_left,
    const char *rights, int n_right, int len_right,
    char *hit_out
) {
    if (seg < 0 || seg > 3 || len_left + len_right != 32) return -1;
    __m128i ct = _mm_loadu_si128((const __m128i *)SEG_CT[seg]);
    __m128i iv = _mm_loadu_si128((const __m128i *)SEG_IV[seg]);
    int found = 0;

    if (len_right >= 16 && n_left >= 4) {
        // Outer loop over right (so rk1 is constant across all i!), inner loop 4x unrolled over left!
        int rem_pref = 16 - len_left;
        #pragma omp parallel for schedule(static) shared(found)
        for (int j = 0; j < n_right; j++) {
            if (found) continue;
            const char *r_ptr = rights + (size_t)j * len_right;
            __m128i rk1 = _mm_loadu_si128((const __m128i *)(r_ptr + rem_pref));
            __m128i rk1_imc = _mm_aesimc_si128(rk1);
            __m128i rk1_assist = _mm_aeskeygenassist_si128(rk1, 0x01);

            uint8_t ka[16], kb[16], kc[16], kd[16];
            if (rem_pref > 0) {
                memcpy(ka + len_left, r_ptr, rem_pref);
                memcpy(kb + len_left, r_ptr, rem_pref);
                memcpy(kc + len_left, r_ptr, rem_pref);
                memcpy(kd + len_left, r_ptr, rem_pref);
            }
            int i = 0;
            for (; i + 3 < n_left; i += 4) {
                memcpy(ka, lefts + (size_t)i * len_left, len_left);
                memcpy(kb, lefts + (size_t)(i + 1) * len_left, len_left);
                memcpy(kc, lefts + (size_t)(i + 2) * len_left, len_left);
                memcpy(kd, lefts + (size_t)(i + 3) * len_left, len_left);
                __m128i pta, ptb, ptc, ptd;
                aes256_cbc_dec_4x_shared_k1(
                    _mm_loadu_si128((const __m128i *)ka),
                    _mm_loadu_si128((const __m128i *)kb),
                    _mm_loadu_si128((const __m128i *)kc),
                    _mm_loadu_si128((const __m128i *)kd),
                    rk1, rk1_imc, rk1_assist, ct, iv,
                    &pta, &ptb, &ptc, &ptd
                );
                uint64_t ha = (uint64_t)_mm_extract_epi64(pta, 1);
                uint64_t hb = (uint64_t)_mm_extract_epi64(ptb, 1);
                uint64_t hc = (uint64_t)_mm_extract_epi64(ptc, 1);
                uint64_t hd = (uint64_t)_mm_extract_epi64(ptd, 1);
                if (__builtin_expect((ha == 0x0808080808080808ULL) | (hb == 0x0808080808080808ULL) |
                                     (hc == 0x0808080808080808ULL) | (hd == 0x0808080808080808ULL), 0)) {
                    int hit_idx = (ha == 0x0808080808080808ULL) ? i :
                                  (hb == 0x0808080808080808ULL) ? (i + 1) :
                                  (hc == 0x0808080808080808ULL) ? (i + 2) : (i + 3);
                    #pragma omp critical
                    {
                        if (!found) {
                            found = 1;
                            memcpy(hit_out, lefts + (size_t)hit_idx * len_left, len_left);
                            memcpy(hit_out + len_left, r_ptr, len_right);
                            hit_out[32] = '\0';
                            FILE *f = fopen("/home/user/p2g_work/hits.log", "a");
                            if (f) { fprintf(f, "SEG %d HIT: %s\n", seg + 1, hit_out); fclose(f); }
                        }
                    }
                }
            }
            for (; i < n_left; i++) {
                memcpy(ka, lefts + (size_t)i * len_left, len_left);
                __m128i pt = aes256_cbc_dec_1block(_mm_loadu_si128((const __m128i *)ka), rk1, ct, iv);
                if (__builtin_expect((uint64_t)_mm_extract_epi64(pt, 1) == 0x0808080808080808ULL, 0)) {
                    #pragma omp critical
                    {
                        if (!found) {
                            found = 1;
                            memcpy(hit_out, lefts + (size_t)i * len_left, len_left);
                            memcpy(hit_out + len_left, r_ptr, len_right);
                            hit_out[32] = '\0';
                            FILE *f = fopen("/home/user/p2g_work/hits.log", "a");
                            if (f) { fprintf(f, "SEG %d HIT: %s\n", seg + 1, hit_out); fclose(f); }
                        }
                    }
                }
            }
        }
    } else {
        #pragma omp parallel for schedule(static) shared(found)
        for (int i = 0; i < n_left; i++) {
            if (found) continue;
            uint8_t key[32];
            memcpy(key, lefts + (size_t)i * len_left, len_left);
            for (int j = 0; j < n_right; j++) {
                memcpy(key + len_left, rights + (size_t)j * len_right, len_right);
                __m128i k0 = _mm_loadu_si128((const __m128i *)key);
                __m128i k1 = _mm_loadu_si128((const __m128i *)(key + 16));
                __m128i pt = aes256_cbc_dec_1block(k0, k1, ct, iv);
                if (__builtin_expect((uint64_t)_mm_extract_epi64(pt, 1) == 0x0808080808080808ULL, 0)) {
                    #pragma omp critical
                    {
                        if (!found) {
                            found = 1;
                            memcpy(hit_out, key, 32);
                            hit_out[32] = '\0';
                            FILE *f = fopen("/home/user/p2g_work/hits.log", "a");
                            if (f) { fprintf(f, "SEG %d HIT: %s\n", seg + 1, hit_out); fclose(f); }
                        }
                    }
                }
            }
        }
    }
    return found;
}
