#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <wmmintrin.h>
#include <emmintrin.h>
#include <smmintrin.h>
#include <omp.h>

static const uint8_t C1[16] = {0x23,0x67,0x3a,0x4d,0x75,0x3f,0x67,0x5a,0x02,0x2a,0x71,0x10,0x4d,0x66,0x54,0xbe};
static const uint8_t C2[16] = {0x45,0x66,0x81,0xa3,0x80,0xa1,0x10,0xe3,0x3f,0x8b,0xe3,0x0b,0xcb,0x63,0x54,0xa6};
static const uint8_t C3[16] = {0xd7,0xa1,0xa6,0xb5,0x42,0x0d,0x69,0x8b,0x8d,0xed,0xfd,0x51,0x94,0x13,0xb9,0xb1};
static const uint8_t C4[16] = {0xec,0x26,0x65,0x66,0x3c,0x02,0x30,0x65,0x1b,0xfd,0x36,0x66,0xd3,0xb6,0xfd,0x76};

static const uint8_t IV1[16] = "few_n_far_btween";
static const uint8_t IV2[16] = "nocturnal_sugars";
static const uint8_t IV3[16] = "colors_on_leaves";
static const uint8_t IV4[16] = "seconds_of_dream";

static inline __m128i key_exp_1(__m128i k1, __m128i k2) {
    k2 = _mm_shuffle_epi32(k2, 0xff);
    __m128i t = _mm_slli_si128(k1, 4);
    k1 = _mm_xor_si128(k1, t);
    t = _mm_slli_si128(t, 4);
    k1 = _mm_xor_si128(k1, t);
    t = _mm_slli_si128(t, 4);
    k1 = _mm_xor_si128(k1, t);
    return _mm_xor_si128(k1, k2);
}

static inline __m128i key_exp_2(__m128i k1, __m128i k2) {
    __m128i t1 = _mm_aeskeygenassist_si128(k1, 0x00);
    t1 = _mm_shuffle_epi32(t1, 0xaa);
    __m128i t2 = _mm_slli_si128(k2, 4);
    k2 = _mm_xor_si128(k2, t2);
    t2 = _mm_slli_si128(t2, 4);
    k2 = _mm_xor_si128(k2, t2);
    t2 = _mm_slli_si128(t2, 4);
    k2 = _mm_xor_si128(k2, t2);
    return _mm_xor_si128(k2, t1);
}

static inline uint64_t aes256_cbc_tail64(const uint8_t *key, __m128i ct, __m128i iv) {
    __m128i k0  = _mm_loadu_si128((const __m128i *)(key));
    __m128i k1  = _mm_loadu_si128((const __m128i *)(key + 16));
    __m128i k2  = key_exp_1(k0, _mm_aeskeygenassist_si128(k1, 0x01));
    __m128i k3  = key_exp_2(k2, k1);
    __m128i k4  = key_exp_1(k2, _mm_aeskeygenassist_si128(k3, 0x02));
    __m128i k5  = key_exp_2(k4, k3);
    __m128i k6  = key_exp_1(k4, _mm_aeskeygenassist_si128(k5, 0x04));
    __m128i k7  = key_exp_2(k6, k5);
    __m128i k8  = key_exp_1(k6, _mm_aeskeygenassist_si128(k7, 0x08));
    __m128i k9  = key_exp_2(k8, k7);
    __m128i k10 = key_exp_1(k8, _mm_aeskeygenassist_si128(k9, 0x10));
    __m128i k11 = key_exp_2(k10, k9);
    __m128i k12 = key_exp_1(k10, _mm_aeskeygenassist_si128(k11, 0x20));
    __m128i k13 = key_exp_2(k12, k11);
    __m128i k14 = key_exp_1(k12, _mm_aeskeygenassist_si128(k13, 0x40));

    __m128i b = _mm_xor_si128(ct, k14);
    b = _mm_aesdec_si128(b, _mm_aesimc_si128(k13));
    b = _mm_aesdec_si128(b, _mm_aesimc_si128(k12));
    b = _mm_aesdec_si128(b, _mm_aesimc_si128(k11));
    b = _mm_aesdec_si128(b, _mm_aesimc_si128(k10));
    b = _mm_aesdec_si128(b, _mm_aesimc_si128(k9));
    b = _mm_aesdec_si128(b, _mm_aesimc_si128(k8));
    b = _mm_aesdec_si128(b, _mm_aesimc_si128(k7));
    b = _mm_aesdec_si128(b, _mm_aesimc_si128(k6));
    b = _mm_aesdec_si128(b, _mm_aesimc_si128(k5));
    b = _mm_aesdec_si128(b, _mm_aesimc_si128(k4));
    b = _mm_aesdec_si128(b, _mm_aesimc_si128(k3));
    b = _mm_aesdec_si128(b, _mm_aesimc_si128(k2));
    b = _mm_aesdec_si128(b, _mm_aesimc_si128(k1));
    b = _mm_aesdeclast_si128(b, k0);
    b = _mm_xor_si128(b, iv);
    return (uint64_t)_mm_extract_epi64(b, 1);
}

void test_aes256_decrypt(int seg_id, const uint8_t *key, uint8_t *out16) {
    const uint8_t *C = (seg_id==1)?C1:(seg_id==2)?C2:(seg_id==3)?C3:C4;
    const uint8_t *IV = (seg_id==1)?IV1:(seg_id==2)?IV2:(seg_id==3)?IV3:IV4;
    __m128i ct = _mm_loadu_si128((const __m128i *)C);
    __m128i iv = _mm_loadu_si128((const __m128i *)IV);
    __m128i k0  = _mm_loadu_si128((const __m128i *)(key));
    __m128i k1  = _mm_loadu_si128((const __m128i *)(key + 16));
    __m128i k2  = key_exp_1(k0, _mm_aeskeygenassist_si128(k1, 0x01));
    __m128i k3  = key_exp_2(k2, k1);
    __m128i k4  = key_exp_1(k2, _mm_aeskeygenassist_si128(k3, 0x02));
    __m128i k5  = key_exp_2(k4, k3);
    __m128i k6  = key_exp_1(k4, _mm_aeskeygenassist_si128(k5, 0x04));
    __m128i k7  = key_exp_2(k6, k5);
    __m128i k8  = key_exp_1(k6, _mm_aeskeygenassist_si128(k7, 0x08));
    __m128i k9  = key_exp_2(k8, k7);
    __m128i k10 = key_exp_1(k8, _mm_aeskeygenassist_si128(k9, 0x10));
    __m128i k11 = key_exp_2(k10, k9);
    __m128i k12 = key_exp_1(k10, _mm_aeskeygenassist_si128(k11, 0x20));
    __m128i k13 = key_exp_2(k12, k11);
    __m128i k14 = key_exp_1(k12, _mm_aeskeygenassist_si128(k13, 0x40));

    __m128i b = _mm_xor_si128(ct, k14);
    b = _mm_aesdec_si128(b, _mm_aesimc_si128(k13));
    b = _mm_aesdec_si128(b, _mm_aesimc_si128(k12));
    b = _mm_aesdec_si128(b, _mm_aesimc_si128(k11));
    b = _mm_aesdec_si128(b, _mm_aesimc_si128(k10));
    b = _mm_aesdec_si128(b, _mm_aesimc_si128(k9));
    b = _mm_aesdec_si128(b, _mm_aesimc_si128(k8));
    b = _mm_aesdec_si128(b, _mm_aesimc_si128(k7));
    b = _mm_aesdec_si128(b, _mm_aesimc_si128(k6));
    b = _mm_aesdec_si128(b, _mm_aesimc_si128(k5));
    b = _mm_aesdec_si128(b, _mm_aesimc_si128(k4));
    b = _mm_aesdec_si128(b, _mm_aesimc_si128(k3));
    b = _mm_aesdec_si128(b, _mm_aesimc_si128(k2));
    b = _mm_aesdec_si128(b, _mm_aesimc_si128(k1));
    b = _mm_aesdeclast_si128(b, k0);
    b = _mm_xor_si128(b, iv);
    _mm_storeu_si128((__m128i *)out16, b);
}

static inline int is_valid_pad(uint64_t t) {
    return (t == 0x0808080808080808ULL) ||
           (t == 0x0000000000000000ULL) ||
           (t == 0x070707070707070aULL) ||
           (t == 0x0606060606060a0dULL) ||
           (t == 0x0800000000000000ULL);
}

int sweep_pairs(int seg_id, const char *left_list, long n_left, int len_left,
                const char *right_list, long n_right, int len_right,
                char *out_hit) {
    const uint8_t *C = (seg_id==1)?C1:(seg_id==2)?C2:(seg_id==3)?C3:C4;
    const uint8_t *IV = (seg_id==1)?IV1:(seg_id==2)?IV2:(seg_id==3)?IV3:IV4;
    __m128i ct_v = _mm_loadu_si128((const __m128i *)C);
    __m128i iv_v = _mm_loadu_si128((const __m128i *)IV);
    volatile int found = 0;

    #pragma omp parallel
    {
        uint8_t key[32] __attribute__((aligned(16)));

        #pragma omp for schedule(dynamic, 16)
        for (long i = 0; i < n_left; i++) {
            if (found) continue;
            memcpy(key, left_list + (size_t)i * len_left, len_left);
            for (long j = 0; j < n_right; j++) {
                memcpy(key + len_left, right_list + (size_t)j * len_right, len_right);
                uint64_t t = aes256_cbc_tail64(key, ct_v, iv_v);
                if (__builtin_expect(is_valid_pad(t), 0)) {
                    #pragma omp critical
                    {
                        if (!found) {
                            found = 1;
                            memcpy(out_hit, key, 32);
                            out_hit[32] = 0;
                            FILE *fp = fopen("/home/user/p2g_work/hits.log", "a");
                            if (fp) {
                                fprintf(fp, "SEG %d HIT (pad=0x%016llx): %s\n", seg_id, (unsigned long long)t, out_hit);
                                fclose(fp);
                            }
                        }
                    }
                    break;
                }
            }
        }
    }
    return found;
}
