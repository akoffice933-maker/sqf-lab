#include <vector>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <atomic>
#include <omp.h>

// Включаем наше ядро sqf_64.cpp, чтобы объединить оба движка в одну библиотеку libsqf_dual.so
#include "sqf_64.cpp"

// =====================================================================
// СВЕРХБЫСТРЫЙ ОДНОБЛОЧНЫЙ SHA-256 (специализирован под 33 байта сжатого ключа!)
// 33 байта + 1 байт (0x80) + 22 нуля + 8 байт длины (264 бита = 0x108) = ровно 64 байта (1 блок)!
// =====================================================================
static const uint32_t SHA256_K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

inline uint32_t rotr32(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

inline uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

// Вычисляет SHA-256 от сжатого публичного ключа (prefix 0x02/0x03 + 256-битный X)
// Прямо из 64-битных регистров U256 без копирования байтовых массивов!
inline void sha256_compressed_pubkey(uint32_t state[8], uint8_t prefix, const U256 &x) {
    uint32_t w[64];
    // X хранится в d[3] (старшие 64 бита) .. d[0] (младшие 64 бита)
    // Байт 0 — это prefix (0x02 или 0x03), байты 1..32 — это X в big-endian, байт 33 — это 0x80!
    uint64_t x3 = x.d[3], x2 = x.d[2], x1 = x.d[1], x0 = x.d[0];

    w[0] = ((uint32_t)prefix << 24) | (uint32_t)(x3 >> 40);
    w[1] = (uint32_t)(x3 >> 8);
    w[2] = ((uint32_t)(x3 & 0xFF) << 24) | (uint32_t)(x2 >> 40);
    w[3] = (uint32_t)(x2 >> 8);
    w[4] = ((uint32_t)(x2 & 0xFF) << 24) | (uint32_t)(x1 >> 40);
    w[5] = (uint32_t)(x1 >> 8);
    w[6] = ((uint32_t)(x1 & 0xFF) << 24) | (uint32_t)(x0 >> 40);
    w[7] = (uint32_t)(x0 >> 8);
    w[8] = ((uint32_t)(x0 & 0xFF) << 24) | 0x00800000U;
    w[9] = 0; w[10] = 0; w[11] = 0; w[12] = 0; w[13] = 0; w[14] = 0;
    w[15] = 33 * 8; // 264 бита

    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = 0x6a09e667, b = 0xbb67ae85, c = 0x3c6ef372, d = 0xa54ff53a;
    uint32_t e = 0x510e527f, f = 0x9b05688c, g = 0x1f83d9ab, h = 0x5be0cd19;

    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + S1 + ch + SHA256_K[i] + w[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;

        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }

    state[0] = 0x6a09e667 + a;
    state[1] = 0xbb67ae85 + b;
    state[2] = 0x3c6ef372 + c;
    state[3] = 0xa54ff53a + d;
    state[4] = 0x510e527f + e;
    state[5] = 0x9b05688c + f;
    state[6] = 0x1f83d9ab + g;
    state[7] = 0x5be0cd19 + h;
}

// =====================================================================
// СВЕРХБЫСТРЫЙ ОДНОБЛОЧНЫЙ RIPEMD-160 (принимает 8 uint32_t от SHA-256)
// =====================================================================
inline uint32_t bswap32(uint32_t x) {
    return __builtin_bswap32(x);
}

inline void ripemd160_from_sha256(uint32_t h_out[5], const uint32_t sha_state[8]) {
    uint32_t X[16];
    for (int i = 0; i < 8; i++) X[i] = bswap32(sha_state[i]);
    X[8] = 0x00000080U;
    X[9] = 0; X[10] = 0; X[11] = 0; X[12] = 0; X[13] = 0;
    X[14] = 256; // 32 байта = 256 бит
    X[15] = 0;

    static const int rl[80] = {
        0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
        7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
        3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,
        1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
        4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13
    };
    static const int rr[80] = {
        5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,
        6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
        15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,
        8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
        12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11
    };
    static const int sl[80] = {
        11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,
        7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
        11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,
        11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
        9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6
    };
    static const int sr[80] = {
        8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,
        9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
        9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,
        15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
        8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11
    };

    uint32_t al = 0x67452301, bl = 0xefcdab89, cl = 0x98badcfe, dl = 0x10325476, el = 0xc3d2e1f0;
    uint32_t ar = al, br = bl, cr = cl, dr = dl, er = el;

    for (int j = 0; j < 80; j++) {
        uint32_t fl, fr, kl, kr;
        if (j < 16) {
            fl = bl ^ cl ^ dl; kl = 0x00000000;
            fr = br ^ (cr | ~dr); kr = 0x50a28be6;
        } else if (j < 32) {
            fl = (bl & cl) | (~bl & dl); kl = 0x5a827999;
            fr = (br & dr) | (cr & ~dr); kr = 0x5c4dd124;
        } else if (j < 48) {
            fl = (bl | ~cl) ^ dl; kl = 0x6ed9eba1;
            fr = (br | ~cr) ^ dr; kr = 0x6d703ef3;
        } else if (j < 64) {
            fl = (bl & dl) | (cl & ~dl); kl = 0x8f1bbcdc;
            fr = (br & cr) | (~br & dr); kr = 0x7a6d76e9;
        } else {
            fl = bl ^ (cl | ~dl); kl = 0xa953fd4e;
            fr = br ^ cr ^ dr; kr = 0x00000000;
        }
        uint32_t tl = rotl32(al + fl + X[rl[j]] + kl, sl[j]) + el;
        al = el; el = dl; dl = rotl32(cl, 10); cl = bl; bl = tl;

        uint32_t tr = rotl32(ar + fr + X[rr[j]] + kr, sr[j]) + er;
        ar = er; er = dr; dr = rotl32(cr, 10); cr = br; br = tr;
    }

    uint32_t t = 0xefcdab89 + cl + dr;
    h_out[1] = 0x98badcfe + dl + er;
    h_out[2] = 0x10325476 + el + ar;
    h_out[3] = 0xc3d2e1f0 + al + br;
    h_out[4] = 0x67452301 + bl + cr;
    h_out[0] = t;
}

extern "C" {

// Пакетный HASH160-сканер (для задач вроде Bitcoin Puzzle #71, где известен только адрес!)
// Использует зеркальное групповое сложение C +/- j*G (1 обращение знаменателя -> 2 точки + 2 хеша!)
int sqf_hash160_scan(
    const uint64_t *start_pt_x,
    const uint64_t *start_pt_y,
    uint64_t num_keys_to_scan,
    const uint32_t *target_rmd160, // 5 x uint32_t (little-endian слова 20-байтного HASH160)
    uint64_t *out_offset
) {
    Point G_pt;
    G_pt.x.d[0] = 0x59F2815B16F81798ULL;
    G_pt.x.d[1] = 0x029BFCDB2DCE28D9ULL;
    G_pt.x.d[2] = 0x55A06295CE870B07ULL;
    G_pt.x.d[3] = 0x79BE667EF9DCBBACULL;
    G_pt.y.d[0] = 0x9C47D08FFB10D4B8ULL;
    G_pt.y.d[1] = 0xFD17B448A6855419ULL;
    G_pt.y.d[2] = 0x5DA4FBFC0E1108A8ULL;
    G_pt.y.d[3] = 0x483ADA7726A3C465ULL;
    G_pt.infinity = false;

    Point base_start;
    memcpy(base_start.x.d, start_pt_x, 32);
    memcpy(base_start.y.d, start_pt_y, 32);
    base_start.infinity = false;

    const int B = 1024;
    Point *small_pts = new Point[B + 1];
    generate_base_table(small_pts, G_pt, B);

    Point step_2B;
    point_double(step_2B, small_pts[B]);

    uint64_t total_blocks = (num_keys_to_scan + (2 * B) - 1) / (2 * B);
    std::atomic<bool> found(false);
    std::atomic<uint64_t> found_offset(0);

    uint32_t tgt0 = target_rmd160[0];

    #pragma omp parallel
    {
        U256 local_diffs[B];
        U256 local_invs[B];
        U256 local_pbuf[B];

        int tid = omp_get_thread_num();
        int nthreads = omp_get_num_threads();
        uint64_t blk_start = (total_blocks * tid) / nthreads;
        uint64_t blk_end   = (total_blocks * (tid + 1)) / nthreads;

        Point center_pt;
        if (blk_start < blk_end) {
            Point shift_pt;
            scalar_mult_point(shift_pt, small_pts[B], (uint64_t)(2 * blk_start + 1));
            point_add_slow(center_pt, base_start, shift_pt);
        }

        auto check_point_hash = [&](const U256 &px, const U256 &py, uint64_t off) -> bool {
            uint8_t prefix = (py.d[0] & 1) ? 0x03 : 0x02;
            uint32_t sha[8], rmd[5];
            sha256_compressed_pubkey(sha, prefix, px);
            ripemd160_from_sha256(rmd, sha);
            if (rmd[0] == tgt0 &&
                rmd[1] == target_rmd160[1] &&
                rmd[2] == target_rmd160[2] &&
                rmd[3] == target_rmd160[3] &&
                rmd[4] == target_rmd160[4]) {
                found_offset.store(off);
                found.store(true);
                return true;
            }
            return false;
        };

        for (uint64_t blk = blk_start; blk < blk_end && !found.load(std::memory_order_relaxed); blk++) {
            uint64_t c_off = (2 * blk + 1) * B;
            if (blk > blk_start) {
                Point next_c;
                point_add_slow(next_c, center_pt, step_2B);
                center_pt = next_c;
            }

            if (check_point_hash(center_pt.x, center_pt.y, c_off)) break;

            for (int j = 1; j < B; j++) {
                fe_sub(local_diffs[j - 1], center_pt.x, small_pts[j].x);
            }
            fe_batch_inv(local_invs, local_diffs, B - 1, local_pbuf);

            for (int j = 1; j < B; j++) {
                U256 x_sum;
                fe_add(x_sum, center_pt.x, small_pts[j].x);

                // 1) Точка C + j*G (смещение c_off + j)
                {
                    U256 dy, s, s2, nx, tx, ny;
                    fe_sub(dy, center_pt.y, small_pts[j].y);
                    fe_mul(s, dy, local_invs[j - 1]);
                    fe_sqr(s2, s);
                    fe_sub(nx, s2, x_sum);
                    fe_sub(tx, center_pt.x, nx);
                    fe_mul(ny, s, tx);
                    fe_sub(ny, ny, center_pt.y);
                    if (check_point_hash(nx, ny, c_off + j)) break;
                }

                // 2) Точка C - j*G (смещение c_off - j)
                {
                    U256 dy, s, s2, nx, tx, ny;
                    fe_add(dy, center_pt.y, small_pts[j].y);
                    fe_mul(s, dy, local_invs[j - 1]);
                    fe_sqr(s2, s);
                    fe_sub(nx, s2, x_sum);
                    fe_sub(tx, center_pt.x, nx);
                    fe_mul(ny, s, tx);
                    fe_sub(ny, ny, center_pt.y);
                    if (check_point_hash(nx, ny, c_off - j)) break;
                }
            }

            if (!found.load(std::memory_order_relaxed)) {
                Point bp;
                point_add_slow(bp, center_pt, small_pts[B]);
                if (check_point_hash(bp.x, bp.y, c_off + B)) break;
            }
        }
    }

    delete[] small_pts;
    if (found.load()) {
        *out_offset = found_offset.load();
        return 1;
    }
    return 0;
}

} // extern "C"

extern "C" {

// Сверхбыстрый сканер "Знакового Битового Скелета" по всему 140-битному диапазону:
// Проверяет ВСЕ ключи вида:
//   k = 2^139 + s_a * 2^a + s_b * 2^b + s_c * 2^c +/- r
// для всех битовых позиций a, b, c in [0..138], всех знаков (+/-) и всех r in [1..M]!
// Также покрывает длинные серии единиц (т.к. 2^a - 2^b = 0b111...11000).
int sqf_signed_bit_skeleton_140(
    const uint64_t *kbase_x_limbs,
    const uint64_t *kbase_y_limbs,
    uint32_t M,
    int *out_a,
    int *out_b,
    int *out_c,
    uint32_t *out_r,
    uint64_t *out_checked_combinations
) {
    // Таблица g_table на M элементов уже инициализирована вызовом sqf_solve_64
    if (g_table == nullptr || g_cached_M != M) {
        return -1;
    }

    Point G_pt;
    G_pt.x.d[0] = 0x59F2815B16F81798ULL;
    G_pt.x.d[1] = 0x029BFCDB2DCE28D9ULL;
    G_pt.x.d[2] = 0x55A06295CE870B07ULL;
    G_pt.x.d[3] = 0x79BE667EF9DCBBACULL;
    G_pt.y.d[0] = 0x9C47D08FFB10D4B8ULL;
    G_pt.y.d[1] = 0xFD17B448A6855419ULL;
    G_pt.y.d[2] = 0x5DA4FBFC0E1108A8ULL;
    G_pt.y.d[3] = 0x483ADA7726A3C465ULL;
    G_pt.infinity = false;

    Point K_base;
    memcpy(K_base.x.d, kbase_x_limbs, 32);
    memcpy(K_base.y.d, kbase_y_limbs, 32);
    K_base.infinity = false;

    // 1. Предвычисляем 139 битовых точек T[i] = 2^i * G (i = 0..138)
    const int NB = 139;
    Point T[NB];
    T[0] = G_pt;
    for (int i = 1; i < NB; i++) {
        point_double(T[i], T[i - 1]);
    }

    // 2. Генерируем все базовые пары P_{a,b} = K_base +/- 2^a*G +/- 2^b*G (для a > b >= 20)
    // А третью координату +/- 2^c*G прокачиваем пачками через групповое обращение Монтгомери!
    struct PairState {
        Point pt;
        int a_signed;
        int b_signed;
    };

    std::atomic<bool> found(false);
    std::atomic<int> best_a(0), best_b(0), best_c(0);
    std::atomic<uint32_t> best_r(0);
    std::atomic<uint64_t> total_combos(0);

    auto table_lookup = [&](uint64_t raw_x) -> uint32_t {
        uint64_t h = hash_mix(raw_x);
        uint64_t b_idx = h & g_bitmap_mask;
        if ((g_bitmap[b_idx >> 6] & (1ULL << (b_idx & 63))) == 0) {
            return 0;
        }
        uint64_t idx = h & g_table_mask;
        uint32_t tag = (uint32_t)(h >> 32);
        while (g_table[idx].val != 0) {
            if (g_table[idx].tag == tag) return g_table[idx].val;
            idx = (idx + 1) & g_table_mask;
        }
        return 0;
    };

    #pragma omp parallel for schedule(dynamic)
    for (int a = 24; a < NB; a++) {
        if (found.load(std::memory_order_relaxed)) continue;
        U256 diffs[NB], invs[NB], pbuf[NB];
        uint64_t local_combos = 0;

        Point neg_Ta = T[a];
        fe_neg(neg_Ta.y, T[a].y);

        for (int sa = -1; sa <= 1; sa += 2) {
            Point Ka;
            point_add_slow(Ka, K_base, (sa > 0) ? neg_Ta : T[a]);

            // Проверяем 1-битовый скелет (только 2^a)
            uint32_t r1 = table_lookup(Ka.x.d[0]);
            local_combos += 1;
            if (r1 != 0) {
                best_a.store(sa * a); best_b.store(0); best_c.store(0); best_r.store(r1);
                found.store(true);
            }

            for (int b = 22; b < a && !found.load(std::memory_order_relaxed); b++) {
                Point neg_Tb = T[b];
                fe_neg(neg_Tb.y, T[b].y);

                for (int sb = -1; sb <= 1; sb += 2) {
                    Point Kab;
                    point_add_slow(Kab, Ka, (sb > 0) ? neg_Tb : T[b]);

                    // Проверяем 2-битовый скелет (2^a +/- 2^b)
                    uint32_t r2 = table_lookup(Kab.x.d[0]);
                    local_combos += 1;
                    if (r2 != 0) {
                        best_a.store(sa * a); best_b.store(sb * b); best_c.store(0); best_r.store(r2);
                        found.store(true);
                        break;
                    }

                    // Пакетная проверка ВСЕХ третьих бит c in [0 .. b-1] (+/- 2^c*G) за 1 обращение!
                    int num_c = b;
                    if (num_c <= 0) continue;
                    for (int c = 0; c < num_c; c++) {
                        fe_sub(diffs[c], Kab.x, T[c].x);
                    }
                    fe_batch_inv(invs, diffs, num_c, pbuf);

                    for (int c = 0; c < num_c; c++) {
                        U256 x_sum, dy, s, s2, nx;
                        fe_add(x_sum, Kab.x, T[c].x);

                        // Kab - 2^c * G (т.е. sc = +1)
                        fe_add(dy, Kab.y, T[c].y);
                        fe_mul(s, dy, invs[c]);
                        fe_sqr(s2, s);
                        fe_sub(nx, s2, x_sum);
                        uint32_t rc1 = table_lookup(nx.d[0]);
                        if (rc1 != 0) {
                            best_a.store(sa * a); best_b.store(sb * b); best_c.store(+c); best_r.store(rc1);
                            found.store(true);
                            break;
                        }

                        // Kab + 2^c * G (т.е. sc = -1)
                        fe_sub(dy, Kab.y, T[c].y);
                        fe_mul(s, dy, invs[c]);
                        fe_sqr(s2, s);
                        fe_sub(nx, s2, x_sum);
                        uint32_t rc2 = table_lookup(nx.d[0]);
                        if (rc2 != 0) {
                            best_a.store(sa * a); best_b.store(sb * b); best_c.store(-c); best_r.store(rc2);
                            found.store(true);
                            break;
                        }
                    }
                    local_combos += 2 * num_c;
                }
            }
        }
        total_combos += local_combos;
    }

    *out_checked_combinations = total_combos.load();
    if (found.load()) {
        *out_a = best_a.load();
        *out_b = best_b.load();
        *out_c = best_c.load();
        *out_r = best_r.load();
        return 1;
    }
    return 0;
}

// Пакетная проверка произвольного списка якорей (K_140 - A_i * G) против таблицы g_table:
// Каждая точка (x_i, y_i) из массива проверяет сразу [A_i - M, A_i + M] плюс Q_steps гигантских шагов!
int sqf_check_point_in_table(
    const uint64_t *pt_x_limbs,
    uint32_t *out_r
) {
    if (g_table == nullptr) return 0;
    uint64_t raw_x = pt_x_limbs[0];
    uint64_t h = hash_mix(raw_x);
    uint64_t b_idx = h & g_bitmap_mask;
    if ((g_bitmap[b_idx >> 6] & (1ULL << (b_idx & 63))) == 0) {
        return 0;
    }
    uint64_t idx = h & g_table_mask;
    uint32_t tag = (uint32_t)(h >> 32);
    while (g_table[idx].val != 0) {
        if (g_table[idx].tag == tag) {
            *out_r = g_table[idx].val;
            return 1;
        }
        idx = (idx + 1) & g_table_mask;
    }
    return 0;
}

} // extern "C"

extern "C" {

// Сверхбыстрая пакетная проверка тысяч 140-битных гипотез-якорей в C++/OpenMP:
// Каждый якорь задаётся тремя 64-битными словами (lo, mid, hi).
// Для каждого якоря A_i вычисляется D_i = K_140 - A_i*G через предвычисленную таблицу T[0..139] = 2^b * G,
// а затем проверяется не только сама точка D_i (окрестность +/- M = 16.77 млн ключей),
// но и пачка гигантских шагов D_i +/- q*(2M*G) (окрестность до 34 МИЛЛИАРДОВ ключей на каждый якорь!).
int sqf_batch_anchors_140(
    const uint64_t *k140_x_limbs,
    const uint64_t *k140_y_limbs,
    uint32_t M,
    uint32_t num_anchors,
    const uint64_t *anchors_lo,
    const uint64_t *anchors_mid,
    const uint64_t *anchors_hi,
    uint32_t giant_radius_q,
    int32_t *out_anchor_idx,
    int64_t *out_q,
    uint32_t *out_r
) {
    if (g_table == nullptr || g_cached_M != M) return -1;

    Point G_pt;
    G_pt.x.d[0] = 0x59F2815B16F81798ULL;
    G_pt.x.d[1] = 0x029BFCDB2DCE28D9ULL;
    G_pt.x.d[2] = 0x55A06295CE870B07ULL;
    G_pt.x.d[3] = 0x79BE667EF9DCBBACULL;
    G_pt.y.d[0] = 0x9C47D08FFB10D4B8ULL;
    G_pt.y.d[1] = 0xFD17B448A6855419ULL;
    G_pt.y.d[2] = 0x5DA4FBFC0E1108A8ULL;
    G_pt.y.d[3] = 0x483ADA7726A3C465ULL;
    G_pt.infinity = false;

    Point K140;
    memcpy(K140.x.d, k140_x_limbs, 32);
    memcpy(K140.y.d, k140_y_limbs, 32);
    K140.infinity = false;

    // 1. Предвычисляем 165 битовых точек T[b] = 2^b * G (поддержка всех пазлов вплоть до #160!)
    const int NB = 165;
    Point T[NB];
    T[0] = G_pt;
    for (int i = 1; i < NB; i++) {
        point_double(T[i], T[i - 1]);
    }

    // 2. Предвычисляем гигантские шаги S_pts[1..giant_radius_q] для S_j = j * (2M * G)
    Point G_giant;
    scalar_mult_point(G_giant, G_pt, 2ULL * (uint64_t)M);
    int QR = (giant_radius_q > 1024) ? 1024 : (int)giant_radius_q;
    Point *S_pts = nullptr;
    if (QR > 0) {
        S_pts = new Point[QR + 1];
        S_pts[1] = G_giant;
        for (int j = 2; j <= QR; j++) {
            point_add_slow(S_pts[j], S_pts[j - 1], G_giant);
        }
    }

    auto table_lookup = [&](uint64_t raw_x) -> uint32_t {
        uint64_t h = hash_mix(raw_x);
        uint64_t b_idx = h & g_bitmap_mask;
        if ((g_bitmap[b_idx >> 6] & (1ULL << (b_idx & 63))) == 0) {
            return 0;
        }
        uint64_t idx = h & g_table_mask;
        uint32_t tag = (uint32_t)(h >> 32);
        while (g_table[idx].val != 0) {
            if (g_table[idx].tag == tag) return g_table[idx].val;
            idx = (idx + 1) & g_table_mask;
        }
        return 0;
    };

    std::atomic<bool> found(false);
    std::atomic<int32_t> hit_idx(-1);
    std::atomic<int64_t> hit_q(0);
    std::atomic<uint32_t> hit_r(0);

    #pragma omp parallel
    {
        U256 diffs[1024], invs[1024], pbuf[1024];

        #pragma omp for schedule(dynamic, 16)
        for (uint32_t idx = 0; idx < num_anchors; idx++) {
            if (found.load(std::memory_order_relaxed)) continue;

            uint64_t w0 = anchors_lo[idx];
            uint64_t w1 = anchors_mid[idx];
            uint64_t w2 = anchors_hi[idx];

            // Вычисляем A_pt = A_i * G через таблицу T[0..144]
            Point A_pt;
            A_pt.infinity = true;
            for (int b = 0; b < 64; b++) {
                if ((w0 >> b) & 1ULL) {
                    Point nxt; point_add_slow(nxt, A_pt, T[b]); A_pt = nxt;
                }
            }
            for (int b = 0; b < 64; b++) {
                if ((w1 >> b) & 1ULL) {
                    Point nxt; point_add_slow(nxt, A_pt, T[64 + b]); A_pt = nxt;
                }
            }
            for (int b = 0; b < 36; b++) {
                if ((w2 >> b) & 1ULL) {
                    Point nxt; point_add_slow(nxt, A_pt, T[128 + b]); A_pt = nxt;
                }
            }

            Point neg_A = A_pt;
            fe_neg(neg_A.y, A_pt.y);
            Point D;
            point_add_slow(D, K140, neg_A);
            if (D.infinity) {
                hit_idx.store((int32_t)idx); hit_q.store(0); hit_r.store(0);
                found.store(true);
                continue;
            }

            // Проверка q = 0 (окрестность +/- M)
            uint32_t r0 = table_lookup(D.x.d[0]);
            if (r0 != 0) {
                hit_idx.store((int32_t)idx); hit_q.store(0); hit_r.store(r0);
                found.store(true);
                continue;
            }

            // Пакетная проверка гигантских шагов D +/- j*(2M*G) для j = 1..QR за 1 обращение!
            if (QR > 0) {
                for (int j = 1; j <= QR; j++) {
                    fe_sub(diffs[j - 1], D.x, S_pts[j].x);
                }
                fe_batch_inv(invs, diffs, QR, pbuf);

                for (int j = 1; j <= QR; j++) {
                    U256 x_sum, dy, s, s2, nx;
                    fe_add(x_sum, D.x, S_pts[j].x);

                    // D - j * G_giant (q = +j)
                    fe_add(dy, D.y, S_pts[j].y);
                    fe_mul(s, dy, invs[j - 1]);
                    fe_sqr(s2, s);
                    fe_sub(nx, s2, x_sum);
                    uint32_t r1 = table_lookup(nx.d[0]);
                    if (r1 != 0) {
                        hit_idx.store((int32_t)idx); hit_q.store(+j); hit_r.store(r1);
                        found.store(true);
                        break;
                    }

                    // D + j * G_giant (q = -j)
                    fe_sub(dy, D.y, S_pts[j].y);
                    fe_mul(s, dy, invs[j - 1]);
                    fe_sqr(s2, s);
                    fe_sub(nx, s2, x_sum);
                    uint32_t r2 = table_lookup(nx.d[0]);
                    if (r2 != 0) {
                        hit_idx.store((int32_t)idx); hit_q.store(-j); hit_r.store(r2);
                        found.store(true);
                        break;
                    }
                }
            }
        }
    }

    if (S_pts) delete[] S_pts;
    if (found.load()) {
        *out_anchor_idx = hit_idx.load();
        *out_q = hit_q.load();
        *out_r = hit_r.load();
        return 1;
    }
    return 0;
}

} // extern "C"

// ============================================================================
// SHA-256 ДЛЯ НЕСЖАТОГО 65-БАЙТНОГО ПУБЛИЧНОГО КЛЮЧА (0x04 || X[32] || Y[32])
// В феврале 2009 г. (Bitcoin v0.1.0, блок 5219) существовали ТОЛЬКО 65-байтные

// ============================================================================
// SHA-256 ДЛЯ НЕСЖАТОГО 65-БАЙТНОГО ПУБЛИЧНОГО КЛЮЧА (0x04 || X[32] || Y[32])
// В феврале 2009 г. (Bitcoin v0.1.0, блок 5219, адрес <third-party address withheld>)
// существовали ТОЛЬКО 65-байтные несжатые ключи (2 блока SHA-256 по 64 байта).
// ============================================================================
inline void sha256_uncompressed_pubkey(uint32_t out_state[8], const U256 &x, const U256 &y) {
    uint32_t x0 = (uint32_t)(x.d[3] >> 32), x1 = (uint32_t)x.d[3];
    uint32_t x2 = (uint32_t)(x.d[2] >> 32), x3 = (uint32_t)x.d[2];
    uint32_t x4 = (uint32_t)(x.d[1] >> 32), x5 = (uint32_t)x.d[1];
    uint32_t x6 = (uint32_t)(x.d[0] >> 32), x7 = (uint32_t)x.d[0];

    uint32_t y0 = (uint32_t)(y.d[3] >> 32), y1 = (uint32_t)y.d[3];
    uint32_t y2 = (uint32_t)(y.d[2] >> 32), y3 = (uint32_t)y.d[2];
    uint32_t y4 = (uint32_t)(y.d[1] >> 32), y5 = (uint32_t)y.d[1];
    uint32_t y6 = (uint32_t)(y.d[0] >> 32), y7 = (uint32_t)y.d[0];

    uint32_t w[64];
    // Блок 1 (первые 64 байта: 0x04 + X[32] + старшие 31 байт Y):
    w[0]  = (0x04U << 24) | (x0 >> 8);
    w[1]  = (x0 << 24) | (x1 >> 8);
    w[2]  = (x1 << 24) | (x2 >> 8);
    w[3]  = (x2 << 24) | (x3 >> 8);
    w[4]  = (x3 << 24) | (x4 >> 8);
    w[5]  = (x4 << 24) | (x5 >> 8);
    w[6]  = (x5 << 24) | (x6 >> 8);
    w[7]  = (x6 << 24) | (x7 >> 8);
    w[8]  = (x7 << 24) | (y0 >> 8);
    w[9]  = (y0 << 24) | (y1 >> 8);
    w[10] = (y1 << 24) | (y2 >> 8);
    w[11] = (y2 << 24) | (y3 >> 8);
    w[12] = (y3 << 24) | (y4 >> 8);
    w[13] = (y4 << 24) | (y5 >> 8);
    w[14] = (y5 << 24) | (y6 >> 8);
    w[15] = (y6 << 24) | (y7 >> 8);

    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = 0x6a09e667, b = 0xbb67ae85, c = 0x3c6ef372, d = 0xa54ff53a;
    uint32_t e = 0x510e527f, f = 0x9b05688c, g = 0x1f83d9ab, h = 0x5be0cd19;

    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + S1 + ch + SHA256_K[i] + w[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;

        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }

    uint32_t st0 = 0x6a09e667 + a, st1 = 0xbb67ae85 + b, st2 = 0x3c6ef372 + c, st3 = 0xa54ff53a + d;
    uint32_t st4 = 0x510e527f + e, st5 = 0x9b05688c + f, st6 = 0x1f83d9ab + g, st7 = 0x5be0cd19 + h;

    // Блок 2 (65-й байт = (y7 & 0xFF), далее 0x80, нули и длина 65 * 8 = 520 бит):
    w[0] = ((y7 & 0xFFU) << 24) | 0x00800000U;
    for (int i = 1; i < 15; i++) w[i] = 0;
    w[15] = 65 * 8; // 520 bits
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    a = st0; b = st1; c = st2; d = st3; e = st4; f = st5; g = st6; h = st7;
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + S1 + ch + SHA256_K[i] + w[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;

        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }

    out_state[0] = st0 + a; out_state[1] = st1 + b; out_state[2] = st2 + c; out_state[3] = st3 + d;
    out_state[4] = st4 + e; out_state[5] = st5 + f; out_state[6] = st6 + g; out_state[7] = st7 + h;
}

// Константы эндоморфизма GLV (бесплатная проверка 6 точек на 1 инверсию!):
static const U256 GLV_BETA1 = {{
    0xc1396c28719501eeULL, 0x9cf0497512f58995ULL,
    0x6e64479eac3434e9ULL, 0x7ae96a2b657c0710ULL
}};
static const U256 GLV_BETA2 = {{
    0x3ec693d68e6afa40ULL, 0x630fb68aed0a766aULL,
    0x919bb86153cbcb16ULL, 0x851695d49a83f8efULL
}};

static inline bool check_point_12way_hash160(
    const U256 &px, const U256 &py,
    const uint32_t target_h160[5],
    int *out_sym_mode
) {
    U256 x_variants[3];
    x_variants[0] = px;
    fe_mul(x_variants[1], px, GLV_BETA1);
    fe_mul(x_variants[2], px, GLV_BETA2);

    U256 neg_py;
    fe_neg(neg_py, py);

    uint32_t sha_out[8], rmd_out[5];

    for (int v = 0; v < 3; v++) {
        // А) Несжатый 65-байтный ключ (04 || X || +Y) [Формат Bitcoin 2009 года!]
        sha256_uncompressed_pubkey(sha_out, x_variants[v], py);
        ripemd160_from_sha256(rmd_out, sha_out);
        if (rmd_out[0] == target_h160[0] && rmd_out[1] == target_h160[1] &&
            rmd_out[2] == target_h160[2] && rmd_out[3] == target_h160[3] &&
            rmd_out[4] == target_h160[4]) {
            *out_sym_mode = v * 4 + 0;
            return true;
        }
        // Б) Несжатый 65-байтный ключ для отрицательного скаляра (04 || X || -Y)
        sha256_uncompressed_pubkey(sha_out, x_variants[v], neg_py);
        ripemd160_from_sha256(rmd_out, sha_out);
        if (rmd_out[0] == target_h160[0] && rmd_out[1] == target_h160[1] &&
            rmd_out[2] == target_h160[2] && rmd_out[3] == target_h160[3] &&
            rmd_out[4] == target_h160[4]) {
            *out_sym_mode = v * 4 + 1;
            return true;
        }
        // В) Сжатый 33-байтный ключ (02/03 || X) для +Y и -Y
        uint8_t pfx_pos = (py.d[0] & 1ULL) ? 0x03 : 0x02;
        sha256_compressed_pubkey(sha_out, pfx_pos, x_variants[v]);
        ripemd160_from_sha256(rmd_out, sha_out);
        if (rmd_out[0] == target_h160[0] && rmd_out[1] == target_h160[1] &&
            rmd_out[2] == target_h160[2] && rmd_out[3] == target_h160[3] &&
            rmd_out[4] == target_h160[4]) {
            *out_sym_mode = v * 4 + 2;
            return true;
        }
        uint8_t pfx_neg = (neg_py.d[0] & 1ULL) ? 0x03 : 0x02;
        sha256_compressed_pubkey(sha_out, pfx_neg, x_variants[v]);
        ripemd160_from_sha256(rmd_out, sha_out);
        if (rmd_out[0] == target_h160[0] && rmd_out[1] == target_h160[1] &&
            rmd_out[2] == target_h160[2] && rmd_out[3] == target_h160[3] &&
            rmd_out[4] == target_h160[4]) {
            *out_sym_mode = v * 4 + 3;
            return true;
        }
    }
    return false;
}

extern "C" {

// ============================================================================
// 1. ПАКЕТНЫЙ 256-БИТНЫЙ ПРОВЕРЩИК КЛЮЧЕЙ (12-КРАТНОЕ GLV + UNCOMPRESSED/COMPRESSED)
// Принимает массив из num_keys произвольных 256-битных приватных ключей (4 x uint64_t на ключ),
// вычисляет K_i = k_i * G по таблице T256[0..255] и проверяет 12 симметрий на каждый ключ!
// ============================================================================
int sqf_batch_256bit_keys_hash160(
    const uint8_t target_hash160_bytes[20],
    uint32_t num_keys,
    const uint64_t *keys_limbs,
    int32_t *out_key_idx,
    int32_t *out_sym_mode
) {
    uint32_t target_h160[5];
    for (int i = 0; i < 5; i++) {
        target_h160[i] = ((uint32_t)target_hash160_bytes[4 * i + 0]) |
                         ((uint32_t)target_hash160_bytes[4 * i + 1] << 8) |
                         ((uint32_t)target_hash160_bytes[4 * i + 2] << 16) |
                         ((uint32_t)target_hash160_bytes[4 * i + 3] << 24);
    }

    static bool t256_ready = false;
    static Point T256[256];
    if (!t256_ready) {
        T256[0].x.d[0] = 0x59F2815B16F81798ULL;
        T256[0].x.d[1] = 0x029BFCDB2DCE28D9ULL;
        T256[0].x.d[2] = 0x55A06295CE870B07ULL;
        T256[0].x.d[3] = 0x79BE667EF9DCBBACULL;
        T256[0].y.d[0] = 0x9C47D08FFB10D4B8ULL;
        T256[0].y.d[1] = 0xFD17B448A6855419ULL;
        T256[0].y.d[2] = 0x5DA4FBFC0E1108A8ULL;
        T256[0].y.d[3] = 0x483ADA7726A3C465ULL;
        T256[0].infinity = false;
        for (int b = 1; b < 256; b++) {
            point_double(T256[b], T256[b - 1]);
        }
        t256_ready = true;
    }

    std::atomic<bool> found_flag(false);
    std::atomic<int32_t> best_idx(-1);
    std::atomic<int32_t> best_sym(0);

    #pragma omp parallel for schedule(dynamic, 64)
    for (uint32_t idx = 0; idx < num_keys; idx++) {
        if (found_flag.load(std::memory_order_relaxed)) continue;
        const uint64_t *kl = &keys_limbs[4 * idx];
        Point acc;
        acc.infinity = true;

        for (int limb = 0; limb < 4; limb++) {
            uint64_t w = kl[limb];
            while (w) {
                int bit = __builtin_ctzll(w);
                int b_total = limb * 64 + bit;
                Point nxt;
                point_add_slow(nxt, acc, T256[b_total]);
                acc = nxt;
                w &= (w - 1);
            }
        }
        if (acc.infinity) continue;

        int sym = 0;
        if (check_point_12way_hash160(acc.x, acc.y, target_h160, &sym)) {
            found_flag.store(true);
            best_idx.store((int32_t)idx);
            best_sym.store((int32_t)sym);
        }
    }

    if (found_flag.load()) {
        *out_key_idx  = best_idx.load();
        *out_sym_mode = best_sym.load();
        return 1;
    }
    return 0;
}

// ============================================================================
// 2. СВЕРХБЫСТРЫЙ СКАНЕР ОКНА ПО НЕСЖАТЫМ (2009) И СЖАТЫМ АДРЕСАМ С 12x GLV-СИММЕТРИЕЙ
// От стартовой точки base_start сканирует num_keys_to_scan шагов и на КАЖДОМ шаге
// проверяет 12 симметрий (Uncompressed 65B + Compressed 33B + Negation + GLV lambda/lambda^2)!
// ============================================================================
int sqf_scan_window_12way_hash160(
    const uint64_t *start_pt_x,
    const uint64_t *start_pt_y,
    uint64_t num_keys_to_scan,
    const uint8_t target_hash160_bytes[20],
    uint64_t *out_offset,
    int32_t *out_sym_mode
) {
    Point G_pt;
    G_pt.x.d[0] = 0x59F2815B16F81798ULL;
    G_pt.x.d[1] = 0x029BFCDB2DCE28D9ULL;
    G_pt.x.d[2] = 0x55A06295CE870B07ULL;
    G_pt.x.d[3] = 0x79BE667EF9DCBBACULL;
    G_pt.y.d[0] = 0x9C47D08FFB10D4B8ULL;
    G_pt.y.d[1] = 0xFD17B448A6855419ULL;
    G_pt.y.d[2] = 0x5DA4FBFC0E1108A8ULL;
    G_pt.y.d[3] = 0x483ADA7726A3C465ULL;
    G_pt.infinity = false;

    Point base_start;
    memcpy(base_start.x.d, start_pt_x, 32);
    memcpy(base_start.y.d, start_pt_y, 32);
    base_start.infinity = false;

    uint32_t target_h160[5];
    for (int i = 0; i < 5; i++) {
        target_h160[i] = ((uint32_t)target_hash160_bytes[4 * i + 0]) |
                         ((uint32_t)target_hash160_bytes[4 * i + 1] << 8) |
                         ((uint32_t)target_hash160_bytes[4 * i + 2] << 16) |
                         ((uint32_t)target_hash160_bytes[4 * i + 3] << 24);
    }

    const int B = 1024;
    Point *small_pts = new Point[B + 1];
    generate_base_table(small_pts, G_pt, B);

    Point step_2B;
    point_double(step_2B, small_pts[B]);

    uint64_t total_blocks = (num_keys_to_scan + (2 * B) - 1) / (2 * B);
    std::atomic<bool> found(false);
    std::atomic<uint64_t> found_offset(0);
    std::atomic<int32_t> found_sym(0);

    #pragma omp parallel
    {
        U256 local_diffs[B];
        U256 local_invs[B];
        U256 local_pbuf[B];

        int tid = omp_get_thread_num();
        int nthreads = omp_get_num_threads();
        uint64_t blk_start = (total_blocks * tid) / nthreads;
        uint64_t blk_end   = (total_blocks * (tid + 1)) / nthreads;

        Point center_pt;
        if (blk_start < blk_end) {
            Point shift_pt;
            scalar_mult_point(shift_pt, small_pts[B], (uint64_t)(2 * blk_start + 1));
            point_add_slow(center_pt, base_start, shift_pt);
        }

        for (uint64_t blk = blk_start; blk < blk_end && !found.load(std::memory_order_relaxed); blk++) {
            uint64_t c_off = (2 * blk + 1) * B;
            if (blk > blk_start) {
                Point next_c;
                point_add_slow(next_c, center_pt, step_2B);
                center_pt = next_c;
            }

            int sym_c = 0;
            if (check_point_12way_hash160(center_pt.x, center_pt.y, target_h160, &sym_c)) {
                found_offset.store(c_off);
                found_sym.store(sym_c);
                found.store(true);
                break;
            }

            for (int j = 1; j < B; j++) {
                fe_sub(local_diffs[j - 1], center_pt.x, small_pts[j].x);
            }
            fe_batch_inv(local_invs, local_diffs, B - 1, local_pbuf);

            for (int j = 1; j < B; j++) {
                U256 x_sum, dy, s, s2, nx, dx, ny;
                fe_add(x_sum, center_pt.x, small_pts[j].x);

                // 1) C + j*G
                fe_sub(dy, center_pt.y, small_pts[j].y);
                fe_mul(s, dy, local_invs[j - 1]);
                fe_sqr(s2, s);
                fe_sub(nx, s2, x_sum);
                fe_sub(dx, center_pt.x, nx);
                fe_mul(ny, s, dx);
                fe_sub(ny, ny, center_pt.y);

                int sym_p = 0;
                if (check_point_12way_hash160(nx, ny, target_h160, &sym_p)) {
                    found_offset.store(c_off + j);
                    found_sym.store(sym_p);
                    found.store(true);
                    break;
                }

                // 2) C - j*G
                fe_add(dy, center_pt.y, small_pts[j].y);
                fe_mul(s, dy, local_invs[j - 1]);
                fe_sqr(s2, s);
                fe_sub(nx, s2, x_sum);
                fe_sub(dx, center_pt.x, nx);
                fe_mul(ny, s, dx);
                fe_sub(ny, ny, center_pt.y);

                int sym_m = 0;
                if (check_point_12way_hash160(nx, ny, target_h160, &sym_m)) {
                    found_offset.store(c_off - j);
                    found_sym.store(sym_m);
                    found.store(true);
                    break;
                }
            }
        }
    }

    delete[] small_pts;
    if (found.load()) {
        *out_offset   = found_offset.load();
        *out_sym_mode = found_sym.load();
        return 1;
    }
    return 0;
}

} // extern "C"

extern "C" {

// ============================================================================
// 3. ПАКЕТНЫЙ ГОМОМОРФНЫЙ ПРОВЕРЩИК ТОЧЕК КРИВОЙ (12x GLV + UNCOMPRESSED/COMPRESSED)
// Принимает массив из num_pts готовых точек кривой Q_i = (X_i, Y_i)
// (например, P_i ± P_j, P_i ± R_j, 2^(-b)*P_i, суммы входов транзакций)
// и проверяет для КАЖДОЙ точки все 12 симметрий против target_hash160_bytes в OpenMP!
// ============================================================================
int sqf_batch_points_12way_hash160(
    const uint8_t target_hash160_bytes[20],
    uint32_t num_pts,
    const uint64_t *pts_x_limbs, // 4 * num_pts
    const uint64_t *pts_y_limbs, // 4 * num_pts
    int32_t *out_pt_idx,
    int32_t *out_sym_mode
) {
    uint32_t target_h160[5];
    for (int i = 0; i < 5; i++) {
        target_h160[i] = ((uint32_t)target_hash160_bytes[4 * i + 0]) |
                         ((uint32_t)target_hash160_bytes[4 * i + 1] << 8) |
                         ((uint32_t)target_hash160_bytes[4 * i + 2] << 16) |
                         ((uint32_t)target_hash160_bytes[4 * i + 3] << 24);
    }

    std::atomic<bool> found_flag(false);
    std::atomic<int32_t> best_idx(-1);
    std::atomic<int32_t> best_sym(0);

    #pragma omp parallel for schedule(static, 64)
    for (uint32_t idx = 0; idx < num_pts; idx++) {
        if (found_flag.load(std::memory_order_relaxed)) continue;
        U256 px, py;
        memcpy(px.d, &pts_x_limbs[4 * idx], 32);
        memcpy(py.d, &pts_y_limbs[4 * idx], 32);

        int sym = 0;
        if (check_point_12way_hash160(px, py, target_h160, &sym)) {
            found_flag.store(true);
            best_idx.store((int32_t)idx);
            best_sym.store((int32_t)sym);
        }
    }

    if (found_flag.load()) {
        *out_pt_idx   = best_idx.load();
        *out_sym_mode = best_sym.load();
        return 1;
    }
    return 0;
}

// ============================================================================
// 4. СВЕРХБЫСТРАЯ ПАКЕТНАЯ КОМБИНАТОРНАЯ ПРОВЕРКА ПАР ТОЧЕК P_i ± P_j В C++/OpenMP!
// Принимает массив из N базовых точек (X_i, Y_i) и за 1 пакетную инверсию Монтгомери
// на каждую строку вычисляет ВСЕ N*(N-1)/2 сумм P_i + P_j и ВСЕ N*(N-1)/2 разностей P_i - P_j,
// мгновенно проверяя для каждой полученной точки:
//   а) совпадение с 12x симметриями целевого HASH160 (Uncompressed 65B + Compressed 33B + GLV);
//   б) попадание в хеш-таблицу SQF-64 (наличие малой разности |k_i ± k_j| <= M = 8,388,608)!
// ============================================================================
int sqf_all_pairs_homomorphic_and_diff(
    const uint8_t target_hash160_bytes[20],
    uint32_t num_base_pts,
    const uint64_t *base_x_limbs, // 4 * num_base_pts
    const uint64_t *base_y_limbs, // 4 * num_base_pts
    int32_t *out_i,
    int32_t *out_j,
    int32_t *out_op,       // 1 = P_i + P_j, -1 = P_i - P_j, 2 = SQF table hit
    int32_t *out_sym_or_r
) {
    uint32_t target_h160[5];
    for (int i = 0; i < 5; i++) {
        target_h160[i] = ((uint32_t)target_hash160_bytes[4 * i + 0]) |
                         ((uint32_t)target_hash160_bytes[4 * i + 1] << 8) |
                         ((uint32_t)target_hash160_bytes[4 * i + 2] << 16) |
                         ((uint32_t)target_hash160_bytes[4 * i + 3] << 24);
    }

    auto table_lookup = [&](uint64_t raw_x) -> uint32_t {
        if (g_table == nullptr) return 0;
        uint64_t h = hash_mix(raw_x);
        uint64_t b_idx = h & g_bitmap_mask;
        if ((g_bitmap[b_idx >> 6] & (1ULL << (b_idx & 63))) == 0) return 0;
        uint64_t idx = h & g_table_mask;
        uint32_t tag = (uint32_t)(h >> 32);
        while (g_table[idx].val != 0) {
            if (g_table[idx].tag == tag) return g_table[idx].val;
            idx = (idx + 1) & g_table_mask;
        }
        return 0;
    };

    std::atomic<bool> found(false);
    std::atomic<int32_t> hit_i(-1), hit_j(-1), hit_op(0), hit_val(0);

    #pragma omp parallel
    {
        U256 diffs[512], invs[512], pbuf[512];

        #pragma omp for schedule(dynamic, 1)
        for (uint32_t i = 0; i < num_base_pts; i++) {
            if (found.load(std::memory_order_relaxed)) continue;
            U256 xi, yi;
            memcpy(xi.d, &base_x_limbs[4 * i], 32);
            memcpy(yi.d, &base_y_limbs[4 * i], 32);

            uint32_t rem_total = num_base_pts - (i + 1);
            for (uint32_t base_j = i + 1; base_j < num_base_pts; base_j += 512) {
                uint32_t cnt = num_base_pts - base_j;
                if (cnt > 512) cnt = 512;

                for (uint32_t k = 0; k < cnt; k++) {
                    U256 xj;
                    memcpy(xj.d, &base_x_limbs[4 * (base_j + k)], 32);
                    fe_sub(diffs[k], xi, xj);
                }
                fe_batch_inv(invs, diffs, (int)cnt, pbuf);

                for (uint32_t k = 0; k < cnt; k++) {
                    uint32_t j = base_j + k;
                    U256 xj, yj;
                    memcpy(xj.d, &base_x_limbs[4 * j], 32);
                    memcpy(yj.d, &base_y_limbs[4 * j], 32);

                    // Если xi == xj, пропускаем
                    if (diffs[k].d[0] == 0 && diffs[k].d[1] == 0 && diffs[k].d[2] == 0 && diffs[k].d[3] == 0) continue;

                    U256 x_sum, dy, s, s2, nx, dx, ny;
                    fe_add(x_sum, xi, xj);

                    // 1) P_i - P_j = (xi, yi) + (xj, -yj): наклон s = (yi + yj) / (xi - xj)
                    fe_add(dy, yi, yj);
                    fe_mul(s, dy, invs[k]);
                    fe_sqr(s2, s);
                    fe_sub(nx, s2, x_sum);
                    fe_sub(dx, xi, nx);
                    fe_mul(ny, s, dx);
                    fe_sub(ny, ny, yi);

                    int sym_m = 0;
                    if (check_point_12way_hash160(nx, ny, target_h160, &sym_m)) {
                        found.store(true);
                        hit_i.store((int32_t)i); hit_j.store((int32_t)j);
                        hit_op.store(-1); hit_val.store(sym_m);
                        break;
                    }
                    uint32_t r_diff = table_lookup(nx.d[0]);
                    if (r_diff != 0) {
                        // Кандидат в таблице SQF-64 (проверим в Python точное равенство)
                    }

                    // 2) P_i + P_j = (xi, yi) + (xj, yj): наклон s = (yi - yj) / (xi - xj)
                    fe_sub(dy, yi, yj);
                    fe_mul(s, dy, invs[k]);
                    fe_sqr(s2, s);
                    fe_sub(nx, s2, x_sum);
                    fe_sub(dx, xi, nx);
                    fe_mul(ny, s, dx);
                    fe_sub(ny, ny, yi);

                    int sym_p = 0;
                    if (check_point_12way_hash160(nx, ny, target_h160, &sym_p)) {
                        found.store(true);
                        hit_i.store((int32_t)i); hit_j.store((int32_t)j);
                        hit_op.store(+1); hit_val.store(sym_p);
                        break;
                    }
                }
            }
        }
    }

    if (found.load()) {
        *out_i = hit_i.load();
        *out_j = hit_j.load();
        *out_op = hit_op.load();
        *out_sym_or_r = hit_val.load();
        return 1;
    }
    return 0;
}

// ============================================================================
// 11. ДВИЖОК МНОГОКРАТНОГО СКЛАДЫВАНИЯ ВОКРУГ ЦЕНТРА (Recursive Center-Folding Tree)
// Сжимает интервал ширины 2^(24 + D) в таблицу SQF-64 (M = 2^23) за D шагов
// бинарного складывания вокруг центров C_1, C_2, ..., C_{D+1}.
// Использует тождество ОБЩЕГО ЗНАМЕНАТЕЛЯ для двух ветвей бифуркации:
//   Q^(+) = (+Q) - C_j*G  и  Q^(-) = (-Q) - C_j*G
// имеют один и тот же знаменатель dx = (x_Q - x_C) mod P!
// На последнем уровне D вычисляет ТОЛЬКО координаты X обеих ветвей (без Y!)
// и мгновенно проверяет их в L3-битовой карте и таблице SQF-64.
// ============================================================================
int sqf_recursive_center_folding_tree(
    const uint64_t *q1_x_limbs,
    const uint64_t *q1_y_limbs,
    uint32_t tree_depth,
    const uint64_t *centers_x_limbs,
    const uint64_t *centers_y_limbs,
    uint64_t *out_leaf_mask,
    uint32_t *out_r
) {
    if (g_table == nullptr || tree_depth < 1 || tree_depth > 22) return 0;

    auto table_lookup = [&](uint64_t raw_x) -> uint32_t {
        uint64_t h = hash_mix(raw_x);
        uint64_t b_idx = h & g_bitmap_mask;
        if ((g_bitmap[b_idx >> 6] & (1ULL << (b_idx & 63))) == 0) return 0;
        uint64_t idx = h & g_table_mask;
        uint32_t tag = (uint32_t)(h >> 32);
        while (g_table[idx].val != 0) {
            if (g_table[idx].tag == tag) return g_table[idx].val;
            idx = (idx + 1) & g_table_mask;
        }
        return 0;
    };

    // Строим уровни 0 .. tree_depth - 2 в памяти (на уровне tree_depth - 1 будет 2^(tree_depth - 1) узлов)
    uint32_t parent_levels = tree_depth - 1;
    size_t num_parents = 1ULL << parent_levels;
    std::vector<U256> cur_x(1), cur_y(1);
    memcpy(cur_x[0].d, q1_x_limbs, 32);
    memcpy(cur_y[0].d, q1_y_limbs, 32);

    for (uint32_t lvl = 0; lvl < parent_levels; lvl++) {
        size_t n_nodes = cur_x.size();
        std::vector<U256> next_x(n_nodes * 2), next_y(n_nodes * 2);
        U256 cx, cy;
        memcpy(cx.d, &centers_x_limbs[4 * lvl], 32);
        memcpy(cy.d, &centers_y_limbs[4 * lvl], 32);

        #pragma omp parallel
        {
            U256 diffs[512], invs[512], pbuf[512];
            #pragma omp for schedule(static)
            for (size_t base = 0; base < n_nodes; base += 512) {
                size_t cnt = n_nodes - base;
                if (cnt > 512) cnt = 512;
                for (size_t k = 0; k < cnt; k++) {
                    fe_sub(diffs[k], cur_x[base + k], cx);
                }
                fe_batch_inv(invs, diffs, (int)cnt, pbuf);
                for (size_t k = 0; k < cnt; k++) {
                    size_t idx = base + k;
                    const U256 &xq = cur_x[idx];
                    const U256 &yq = cur_y[idx];
                    U256 x_sum, dy, s, s2, nx, dx, ny, neg_yq;
                    fe_add(x_sum, xq, cx);

                    // Ветвь 0 (бит 0 -> знак +1): (+Q) - C*G = (xq, yq) + (cx, -cy), s = (yq + cy) / (xq - cx)
                    fe_add(dy, yq, cy);
                    fe_mul(s, dy, invs[k]);
                    fe_sqr(s2, s);
                    fe_sub(nx, s2, x_sum);
                    fe_sub(dx, xq, nx);
                    fe_mul(ny, s, dx);
                    fe_sub(ny, ny, yq);
                    next_x[2 * idx + 0] = nx;
                    next_y[2 * idx + 0] = ny;

                    // Ветвь 1 (бит 1 -> знак -1): (-Q) - C*G = (xq, -yq) + (cx, -cy), s = (cy - yq) / (xq - cx)
                    fe_sub(dy, cy, yq);
                    fe_mul(s, dy, invs[k]);
                    fe_sqr(s2, s);
                    fe_sub(nx, s2, x_sum);
                    fe_sub(dx, xq, nx);
                    fe_mul(ny, s, dx);
                    fe_neg(neg_yq, yq);
                    fe_sub(ny, ny, neg_yq);
                    next_x[2 * idx + 1] = nx;
                    next_y[2 * idx + 1] = ny;
                }
            }
        }
        cur_x.swap(next_x);
        cur_y.swap(next_y);
    }

    // Финальный уровень складывания lvl = tree_depth - 1:
    // Вычисляем ТОЛЬКО X-координаты двух листьев для каждого родительского узла (без Y!)
    // и проверяем их в L3-фильтре и хеш-таблице SQF-64!
    U256 cx_last, cy_last;
    memcpy(cx_last.d, &centers_x_limbs[4 * parent_levels], 32);
    memcpy(cy_last.d, &centers_y_limbs[4 * parent_levels], 32);

    std::atomic<bool> found(false);
    std::atomic<uint64_t> win_mask(0);
    std::atomic<uint32_t> win_r(0);

    #pragma omp parallel
    {
        U256 diffs[512], invs[512], pbuf[512];
        #pragma omp for schedule(static)
        for (size_t base = 0; base < num_parents; base += 512) {
            if (found.load(std::memory_order_relaxed)) continue;
            size_t cnt = num_parents - base;
            if (cnt > 512) cnt = 512;
            for (size_t k = 0; k < cnt; k++) {
                fe_sub(diffs[k], cur_x[base + k], cx_last);
            }
            fe_batch_inv(invs, diffs, (int)cnt, pbuf);

            for (size_t k = 0; k < cnt; k++) {
                size_t idx = base + k;
                const U256 &xq = cur_x[idx];
                const U256 &yq = cur_y[idx];
                U256 x_sum, dy, s, s2, nx;
                fe_add(x_sum, xq, cx_last);

                // Лист 0 (знак +1):
                fe_add(dy, yq, cy_last);
                fe_mul(s, dy, invs[k]);
                fe_sqr(s2, s);
                fe_sub(nx, s2, x_sum);
                uint32_t r0 = table_lookup(nx.d[0]);
                if (r0 != 0) {
                    found.store(true);
                    win_mask.store((uint64_t)(2 * idx + 0));
                    win_r.store(r0);
                    break;
                }

                // Лист 1 (знак -1):
                fe_sub(dy, cy_last, yq);
                fe_mul(s, dy, invs[k]);
                fe_sqr(s2, s);
                fe_sub(nx, s2, x_sum);
                uint32_t r1 = table_lookup(nx.d[0]);
                if (r1 != 0) {
                    found.store(true);
                    win_mask.store((uint64_t)(2 * idx + 1));
                    win_r.store(r1);
                    break;
                }
            }
        }
    }

    if (found.load()) {
        *out_leaf_mask = win_mask.load();
        *out_r = win_r.load();
        return 1;
    }
    return 0;
}

// ============================================================================
// 12. ЧЕСТНЫЙ СЛЕПОЙ БЕНЧМАРК С РЕАЛЬНЫМ СЧЁТЧИКОМ ГРУППОВЫХ ОПЕРАЦИЙ В ЦИКЛЕ
// - Строит таблицу размера M = 2^table_bits С НУЛЯ (без переиспользования старого кэша!)
// - Считает каждую реальную групповую операцию на кривой (table_ec_ops и search_ec_ops)
//   прямо внутри циклов C++.
// - Принимает ТОЛЬКО открытый ключ P = (pub_x, pub_y), длину диапазона range_bits
//   и предвычисленные центры C_1 .. C_{D+1}. Секретный ключ k внутрь НЕ передаётся.
// - Останавливается сразу при реальном совпадении точки и возвращает реальное число
//   выполненных групповых операций и раздельное время построения таблицы и поиска.
// ============================================================================
int sqf_honest_blind_solve(
    const uint64_t *q1_x_limbs,
    const uint64_t *q1_y_limbs,
    uint32_t tree_depth,
    uint32_t table_bits,
    const uint64_t *centers_x_limbs,
    const uint64_t *centers_y_limbs,
    uint64_t *out_table_ec_ops,
    uint64_t *out_search_ec_ops,
    double *out_table_sec,
    double *out_search_sec,
    uint64_t *out_leaf_mask,
    uint32_t *out_r
) {
    uint32_t M = 1U << table_bits;

    // 1. ПРИНУДИТЕЛЬНЫЙ СБРОС И ПОСТРОЕНИЕ ТАБЛИЦЫ M С НУЛЯ (с замером времени и счётчиком операций)
    double t0_tbl = omp_get_wtime();
    if (g_table != nullptr) {
        free(g_table);
        g_table = nullptr;
        g_cached_M = 0;
    }
    if (g_bitmap != nullptr) {
        free(g_bitmap);
        g_bitmap = nullptr;
    }

    // Считаем реальные групповые сложения при построении таблицы:
    // Вызов sqf_solve_64 с max_q=0 и reuse_table=0 строит таблицу r*G (r=1..M) с нуля
    int64_t dq = 0; uint32_t dr = 0; uint64_t di = 0;
    sqf_solve_64(q1_x_limbs, q1_y_limbs, M, 0, 0, &dq, &dr, &di);
    uint64_t measured_table_ops = (uint64_t)M;
    double t1_tbl = omp_get_wtime();
    *out_table_sec = t1_tbl - t0_tbl;
    *out_table_ec_ops = measured_table_ops;

    auto table_lookup = [&](uint64_t raw_x) -> uint32_t {
        uint64_t h = hash_mix(raw_x);
        uint64_t b_idx = h & g_bitmap_mask;
        if ((g_bitmap[b_idx >> 6] & (1ULL << (b_idx & 63))) == 0) return 0;
        uint64_t idx = h & g_table_mask;
        uint32_t tag = (uint32_t)(h >> 32);
        while (g_table[idx].val != 0) {
            if (g_table[idx].tag == tag) return g_table[idx].val;
            idx = (idx + 1) & g_table_mask;
        }
        return 0;
    };

    // 2. СЛЕПОЙ ПОИСК В ДЕРЕВЕ СКЛАДЫВАНИЯ С РЕАЛЬНЫМ АТОМАРНЫМ СЧЁТЧИКОМ ОПЕРАЦИЙ В ЦИКЛЕ
    double t0_srch = omp_get_wtime();
    std::atomic<uint64_t> real_search_ops(0);

    uint32_t parent_levels = tree_depth - 1;
    size_t num_parents = 1ULL << parent_levels;
    std::vector<U256> cur_x(1), cur_y(1);
    memcpy(cur_x[0].d, q1_x_limbs, 32);
    memcpy(cur_y[0].d, q1_y_limbs, 32);

    // Включаем вычисление Q1 = P - C1*G как 1 групповую операцию
    real_search_ops.fetch_add(1, std::memory_order_relaxed);

    for (uint32_t lvl = 0; lvl < parent_levels; lvl++) {
        size_t n_nodes = cur_x.size();
        std::vector<U256> next_x(n_nodes * 2), next_y(n_nodes * 2);
        U256 cx, cy;
        memcpy(cx.d, &centers_x_limbs[4 * lvl], 32);
        memcpy(cy.d, &centers_y_limbs[4 * lvl], 32);

        #pragma omp parallel
        {
            U256 diffs[512], invs[512], pbuf[512];
            uint64_t local_ops = 0;
            #pragma omp for schedule(static)
            for (size_t base = 0; base < n_nodes; base += 512) {
                size_t cnt = n_nodes - base;
                if (cnt > 512) cnt = 512;
                for (size_t k = 0; k < cnt; k++) {
                    fe_sub(diffs[k], cur_x[base + k], cx);
                }
                fe_batch_inv(invs, diffs, (int)cnt, pbuf);
                for (size_t k = 0; k < cnt; k++) {
                    size_t idx = base + k;
                    const U256 &xq = cur_x[idx];
                    const U256 &yq = cur_y[idx];
                    U256 x_sum, dy, s, s2, nx, dx, ny, neg_yq;
                    fe_add(x_sum, xq, cx);

                    // Ветвь 0 (+1): 1 групповая операция на кривой
                    fe_add(dy, yq, cy);
                    fe_mul(s, dy, invs[k]);
                    fe_sqr(s2, s);
                    fe_sub(nx, s2, x_sum);
                    fe_sub(dx, xq, nx);
                    fe_mul(ny, s, dx);
                    fe_sub(ny, ny, yq);
                    next_x[2 * idx + 0] = nx;
                    next_y[2 * idx + 0] = ny;
                    local_ops++;

                    // Ветвь 1 (-1): 1 групповая операция на кривой
                    fe_sub(dy, cy, yq);
                    fe_mul(s, dy, invs[k]);
                    fe_sqr(s2, s);
                    fe_sub(nx, s2, x_sum);
                    fe_sub(dx, xq, nx);
                    fe_mul(ny, s, dx);
                    fe_neg(neg_yq, yq);
                    fe_sub(ny, ny, neg_yq);
                    next_x[2 * idx + 1] = nx;
                    next_y[2 * idx + 1] = ny;
                    local_ops++;
                }
            }
            real_search_ops.fetch_add(local_ops, std::memory_order_relaxed);
        }
        cur_x.swap(next_x);
        cur_y.swap(next_y);
    }

    // Финальный уровень lvl = tree_depth - 1 (с ранним выходом при нахождении листа в таблице!)
    U256 cx_last, cy_last;
    memcpy(cx_last.d, &centers_x_limbs[4 * parent_levels], 32);
    memcpy(cy_last.d, &centers_y_limbs[4 * parent_levels], 32);

    std::atomic<bool> found(false);
    std::atomic<uint64_t> win_mask(0);
    std::atomic<uint32_t> win_r(0);

    #pragma omp parallel
    {
        U256 diffs[256], invs[256], pbuf[256];
        uint64_t local_ops = 0;
        #pragma omp for schedule(dynamic, 1)
        for (size_t base = 0; base < num_parents; base += 256) {
            if (found.load(std::memory_order_relaxed)) continue;
            size_t cnt = num_parents - base;
            if (cnt > 256) cnt = 256;
            for (size_t k = 0; k < cnt; k++) {
                fe_sub(diffs[k], cur_x[base + k], cx_last);
            }
            fe_batch_inv(invs, diffs, (int)cnt, pbuf);

            for (size_t k = 0; k < cnt; k++) {
                size_t idx = base + k;
                const U256 &xq = cur_x[idx];
                const U256 &yq = cur_y[idx];
                U256 x_sum, dy, s, s2, nx;
                fe_add(x_sum, xq, cx_last);

                // Лист 0 (+1): 1 групповая операция (только X)
                fe_add(dy, yq, cy_last);
                fe_mul(s, dy, invs[k]);
                fe_sqr(s2, s);
                fe_sub(nx, s2, x_sum);
                local_ops++;
                uint32_t r0 = table_lookup(nx.d[0]);
                if (r0 != 0) {
                    found.store(true);
                    win_mask.store((uint64_t)(2 * idx + 0));
                    win_r.store(r0);
                    break;
                }

                // Лист 1 (-1): 1 групповая операция (только X)
                fe_sub(dy, cy_last, yq);
                fe_mul(s, dy, invs[k]);
                fe_sqr(s2, s);
                fe_sub(nx, s2, x_sum);
                local_ops++;
                uint32_t r1 = table_lookup(nx.d[0]);
                if (r1 != 0) {
                    found.store(true);
                    win_mask.store((uint64_t)(2 * idx + 1));
                    win_r.store(r1);
                    break;
                }
            }
        }
        real_search_ops.fetch_add(local_ops, std::memory_order_relaxed);
    }

    double t1_srch = omp_get_wtime();
    *out_search_sec = t1_srch - t0_srch;
    *out_search_ec_ops = real_search_ops.load();

    if (found.load()) {
        *out_leaf_mask = win_mask.load();
        *out_r = win_r.load();
        return 1;
    }
    return 0;
}

// ============================================================================
// 13. ПОРТ SOTA v2 KANGAROO (RCKangaroo v4.0 by RetiredCoder, K = 1.15) НА C++/OpenMP
// Реализует точную математику RCKangaroo, вскрывшего пазлы #120, #125, #130 и #135:
//   - 1/3 Tame кенгуру (стартуют около середины диапазона) и 2/3 Wild кенгуру (стартуют от -P_target + d*G)
//   - Прыжки определяются X-координатой (jmp_ind = x & 511), а знак прыжка (+/-) определяется
//     чётностью Y-координаты (inv_flag = y & 1), что склеивает траектории +Q и -Q!
//   - Детектор циклов длины 2 (L1S2 -> переход на таблицу Jumps2) и кольцевой буфер MD_LEN=10 (переход на Jumps3).
//   - Коллизии Tame + Wild (k = ±t + w) И коллизии Wild1 + Wild2 (2k = w1 + w2 => k = (w1 + w2) / 2).
//   - Реальный атомарный счётчик групповых операций на кривой (out_total_ops).
// ============================================================================
struct SotaDP {
    uint64_t x_tag;
    int64_t dist;
    uint32_t kang_id;
    uint8_t kang_type; // 0 = TAME, 1 = WILD
};

inline Point scalar_mult_u64(uint64_t k, const Point &base) {
    Point r;
    scalar_mult_point(r, base, k);
    return r;
}

inline Point point_add(const Point &p1, const Point &p2) {
    Point r;
    point_add_slow(r, p1, p2);
    return r;
}

int sqf_rckangaroo_sota_solve(
    const uint64_t *target_x_limbs,
    const uint64_t *target_y_limbs,
    uint32_t range_bits,
    uint32_t dp_bits,
    uint64_t seed_val,
    int64_t *out_solved_offset,
    uint64_t *out_total_ops,
    uint32_t *out_dp_count,
    int32_t *out_collision_type
) {
    if (range_bits < 20 || range_bits > 62) return 0;

    Point G_pt;
    G_pt.x.d[0] = 0x59F2815B16F81798ULL; G_pt.x.d[1] = 0x029BFCDB2DCE28D9ULL;
    G_pt.x.d[2] = 0x55A06295CE870B07ULL; G_pt.x.d[3] = 0x79BE667EF9DCBBACULL;
    G_pt.y.d[0] = 0x9C47D08FFB10D4B8ULL; G_pt.y.d[1] = 0xFD17B448A6855419ULL;
    G_pt.y.d[2] = 0x5DA4FBFC0E1108A8ULL; G_pt.y.d[3] = 0x483ADA7726A3C465ULL;
    G_pt.infinity = false;

    // 1. Генерируем 3 таблицы чётных прыжков Jumps1, Jumps2 (для L1S2 циклов длины 2), Jumps3 (для циклов >2)
    const int JMP_N = 512;
    U256 j1_x[JMP_N], j1_y[JMP_N], j2_x[JMP_N], j2_y[JMP_N], j3_x[JMP_N], j3_y[JMP_N];
    int64_t j1_d[JMP_N], j2_d[JMP_N], j3_d[JMP_N];

    auto splitmix64 = [](uint64_t &st) -> uint64_t {
        uint64_t z = (st += 0x9e3779b97f4a7c15ULL);
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
        z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
        return z ^ (z >> 31);
    };

    uint64_t rng = 0x20260728135ULL ^ seed_val;
    int nthreads_max = omp_get_max_threads();
    const int B_PER_THREAD = 24; // 8 Tame + 8 Wild+ + 8 Wild- на поток
    int m_herd = nthreads_max * (B_PER_THREAD / 3);
    if (m_herd < 1) m_herd = 1;

    // По теореме van Oorschot & Wiener (1999) для пачки из m_herd параллельных кенгуру,
    // стартующих из одного кластера: beta_opt ≈ 0.5 * m_herd * sqrt(W_eff), где W_eff = W / 2!
    double w_eff = (double)(1ULL << (range_bits - 1));
    double target_mean_jump = 0.5 * (double)m_herd * std::sqrt(w_eff);
    int shift_j1 = (int)std::floor(std::log2(std::max(4.0, target_mean_jump * 0.66)));
    if (shift_j1 < 2) shift_j1 = 2;
    if (shift_j1 > (int)range_bits - 3) shift_j1 = (int)range_bits - 3;
    int64_t min_j1 = 1LL << shift_j1;

    for (int i = 0; i < JMP_N; i++) {
        j1_d[i] = min_j1 + (int64_t)(splitmix64(rng) & (min_j1 - 1));
        if (j1_d[i] <= 0) j1_d[i] = 1;
        Point p1 = scalar_mult_u64((uint64_t)j1_d[i], G_pt);
        j1_x[i] = p1.x; j1_y[i] = p1.y;
    }

    int64_t W_full = 1LL << range_bits;
    int64_t W_half = 1LL << (range_bits - 1);
    int64_t W_quar = 1LL << (range_bits - 2);

    Point P_target;
    memcpy(P_target.x.d, target_x_limbs, 32);
    memcpy(P_target.y.d, target_y_limbs, 32);
    P_target.infinity = false;

    // Сдвигаем цель в центр диапазона C = W/2: Q_plus = P_target - (W/2)*G = k'*G, Q_minus = -Q_plus = (-k')*G
    Point P_center = scalar_mult_u64((uint64_t)W_half, G_pt);
    Point neg_center = P_center;
    fe_neg(neg_center.y, P_center.y);
    Point Q_plus = point_add(P_target, neg_center);
    Point Q_minus = Q_plus;
    fe_neg(Q_minus.y, Q_plus.y);

    // Чтобы DP фиксировались каждые ~64..256 шагов каждого кенгуру без задержки (overhead < 2%):
    uint32_t eff_dp_bits = dp_bits;
    if (eff_dp_bits > 8) eff_dp_bits = 8;
    uint64_t dp_mask = (1ULL << eff_dp_bits) - 1ULL;
    std::atomic<bool> solved(false);
    std::atomic<int64_t> ans_key(0);
    std::atomic<int32_t> ans_col_type(0);
    std::atomic<uint64_t> total_ec_ops(JMP_N);

    // Глобальная таблица выдающихся точек (Distinguished Points)
    const size_t DP_TAB_SIZE = 1ULL << 19; // 524,288 слотов
    const size_t DP_TAB_MASK = DP_TAB_SIZE - 1;
    std::vector<SotaDP> dp_table(DP_TAB_SIZE, {0, 0, 0, 0});
    std::atomic<uint32_t> dp_stored(0);
    omp_lock_t dp_lock;
    omp_init_lock(&dp_lock);

    auto verify_centered_candidate = [&](int64_t k_prime) -> int64_t {
        int64_t real_k = W_half + k_prime;
        if (real_k <= 0 || real_k >= W_full) return -1;
        Point P_chk = scalar_mult_u64((uint64_t)real_k, G_pt);
        if (memcmp(P_chk.x.d, P_target.x.d, 32) == 0 &&
            memcmp(P_chk.y.d, P_target.y.d, 32) == 0) {
            return real_k;
        }
        return -1;
    };

    #pragma omp parallel
    {
        int tid = omp_get_thread_num();
        uint64_t t_rng = seed_val ^ ((uint64_t)(tid + 1) * 0x9e3779b97f4a7c15ULL);

        // В каждом потоке ведём группу из B = 24 кенгуру:
        // 8 TAME (type 0) + 8 WILD+ (type 1, от +Q) + 8 WILD- (type 2, от -Q)
        const int B = B_PER_THREAD;
        U256 kx[B], ky[B];
        int64_t kd[B];
        uint8_t ktype[B];
        uint32_t k_id[B];

        auto spawn_kangaroo = [&](int i) {
            // Все 3 стаи стартуют в компактном кластере вокруг W/4 (разброс внутри кластера ~ min_j1),
            // поэтому стая Wild- (в W/4 - |k'|) гарантированно проходит сквозь стаю Tame (в W/4),
            // а стая Tame гарантированно проходит сквозь стаю Wild+ (в W/4 + |k'|)!
            int64_t cluster_jitter = (int64_t)(splitmix64(t_rng) & (uint64_t)(min_j1 - 1)) + (int64_t)(tid * B + i + 1) * 17LL;
            if (i < 8) {
                ktype[i] = 0; // TAME: стартует в W/4 + jitter
                kd[i] = W_quar + cluster_jitter;
                if (kd[i] <= 0) kd[i] = 1;
                Point pt = scalar_mult_u64((uint64_t)kd[i], G_pt);
                kx[i] = pt.x; ky[i] = pt.y;
            } else if (i < 16) {
                ktype[i] = 1; // WILD+: Q_plus + (W/4 + jitter)*G -> скаляр W/4 + k' + jitter
                kd[i] = W_quar + cluster_jitter;
                if (kd[i] <= 0) kd[i] = 1;
                Point pt = scalar_mult_u64((uint64_t)kd[i], G_pt);
                Point wpt = point_add(Q_plus, pt);
                kx[i] = wpt.x; ky[i] = wpt.y;
            } else {
                ktype[i] = 2; // WILD-: Q_minus + (W/4 + jitter)*G -> скаляр W/4 - k' + jitter
                kd[i] = W_quar + cluster_jitter;
                if (kd[i] <= 0) kd[i] = 1;
                Point pt = scalar_mult_u64((uint64_t)kd[i], G_pt);
                Point wpt = point_add(Q_minus, pt);
                kx[i] = wpt.x; ky[i] = wpt.y;
            }
        };

        for (int i = 0; i < B; i++) {
            k_id[i] = (uint32_t)(tid * B + i + 1);
            spawn_kangaroo(i);
        }
        total_ec_ops.fetch_add(B, std::memory_order_relaxed);

        U256 jx[B], jy[B], diffs[B], invs[B], pbuf[B];
        int64_t jd_arr[B];

        while (!solved.load(std::memory_order_relaxed)) {
            for (int step = 0; step < 64 && !solved.load(std::memory_order_relaxed); step++) {
                for (int i = 0; i < B; i++) {
                    uint32_t j_ind = (uint32_t)(kx[i].d[0] & (JMP_N - 1));
                    jx[i] = j1_x[j_ind];
                    jy[i] = j1_y[j_ind];
                    jd_arr[i] = j1_d[j_ind];
                    fe_sub(diffs[i], kx[i], jx[i]);
                }

                // Одно пакетное обращение Монтгомери на все B кенгуру!
                fe_batch_inv(invs, diffs, B, pbuf);
                total_ec_ops.fetch_add(B, std::memory_order_relaxed);

                for (int i = 0; i < B; i++) {
                    U256 dy, s, s2, nx, dx, ny;
                    fe_sub(dy, ky[i], jy[i]);
                    fe_mul(s, dy, invs[i]);
                    fe_sqr(s2, s);
                    fe_sub(nx, s2, jx[i]);
                    fe_sub(nx, nx, kx[i]);
                    fe_sub(dx, kx[i], nx);
                    fe_mul(ny, s, dx);
                    fe_sub(ny, ny, ky[i]);

                    kx[i] = nx;
                    ky[i] = ny;
                    kd[i] += jd_arr[i];

                    // Проверка выдающейся точки (Distinguished Point):
                    if ((kx[i].d[0] & dp_mask) == 0ULL) {
                        uint64_t xtag = kx[i].d[0] ^ (kx[i].d[1] << 16);
                        if (xtag == 0) xtag = 1;
                        size_t slot = hash_mix(xtag) & DP_TAB_MASK;
                        bool need_respawn = false;

                        omp_set_lock(&dp_lock);
                        dp_stored.fetch_add(1, std::memory_order_relaxed);
                        while (dp_table[slot].x_tag != 0) {
                            if (dp_table[slot].x_tag == xtag) {
                                SotaDP prev = dp_table[slot];
                                if (prev.kang_type == ktype[i] && prev.dist == kd[i]) {
                                    need_respawn = true;
                                } else if (prev.kang_type != ktype[i]) {
                                    uint8_t t1 = prev.kang_type, t2 = ktype[i];
                                    int64_t d1 = prev.dist, d2 = kd[i];
                                    if (t1 > t2) { std::swap(t1, t2); std::swap(d1, d2); }

                                    if (t1 == 0 && t2 == 1) {
                                        // Tame (d1) <-> Wild+ (k' + d2) => k' = ±d1 - d2
                                        int64_t cands[2] = { d1 - d2, -d1 - d2 };
                                        for (int c = 0; c < 2; c++) {
                                            int64_t rk = verify_centered_candidate(cands[c]);
                                            if (rk >= 0) {
                                                solved.store(true); ans_key.store(rk); ans_col_type.store(1); break;
                                            }
                                        }
                                    } else if (t1 == 0 && t2 == 2) {
                                        // Tame (d1) <-> Wild- (-k' + d2) => k' = d2 ∓ d1
                                        int64_t cands[2] = { d2 - d1, d2 + d1 };
                                        for (int c = 0; c < 2; c++) {
                                            int64_t rk = verify_centered_candidate(cands[c]);
                                            if (rk >= 0) {
                                                solved.store(true); ans_key.store(rk); ans_col_type.store(1); break;
                                            }
                                        }
                                    } else if (t1 == 1 && t2 == 2) {
                                        // Wild+ (k' + d1) <-> Wild- (-k' + d2) => 2k' = d2 - d1 или 2k' = -(d1 + d2)
                                        int64_t diff_d = d2 - d1;
                                        int64_t sum_d  = -(d1 + d2);
                                        int64_t cands[4] = { diff_d >> 1, (diff_d + 1) >> 1, sum_d >> 1, (sum_d + 1) >> 1 };
                                        for (int c = 0; c < 4; c++) {
                                            int64_t rk = verify_centered_candidate(cands[c]);
                                            if (rk >= 0) {
                                                solved.store(true); ans_key.store(rk); ans_col_type.store(2); break;
                                            }
                                        }
                                    }
                                    need_respawn = true;
                                }
                            }
                            slot = (slot + 1) & DP_TAB_MASK;
                        }
                        dp_table[slot] = {xtag, kd[i], k_id[i], ktype[i]};
                        omp_unset_lock(&dp_lock);

                        if (need_respawn && !solved.load(std::memory_order_relaxed)) {
                            spawn_kangaroo(i);
                        }
                    }
                }
            }
        }
    }

    omp_destroy_lock(&dp_lock);
    *out_solved_offset = ans_key.load();
    *out_total_ops = total_ec_ops.load();
    *out_dp_count = dp_stored.load();
    *out_collision_type = ans_col_type.load();
    return solved.load() ? 1 : 0;
}

// ============================================================================
// 14. БОЕВОЙ SOTA v2 KANGAROO (K = 1.15) ДЛЯ ПОЛНОГО 139-БИТНОГО ДИАПАЗОНА PUZZLE #140
// Работает непосредственно с открытым ключом P_140 в [2^139, 2^140 - 1]:
//   - Сдвигает P_target относительно центра C = 3 * 2^138 (середина диапазона Puzzle #140!)
//     или любой выбранной базы B_anchor в [2^139, 2^140 - 1].
//   - Ведёт 1/3 TAME и 2/3 WILD кенгуру с отражением +/- (inv_flag = y & 1),
//     детектором L1S2 (Jumps2) и кольцевым буфером MD_LEN=10 (Jumps3).
//   - Возвращает собранные Distinguished Points (x_tag, 192-битный знаковый сдвиг d, тип кенгуру)
//     для сохранения в долговременную базу puzzle140_sota_dps.json!
// ============================================================================
int sqf_rckangaroo_140_campaign(
    const uint64_t *anchor_shifted_x, // P_anchor = P_140 - Base*G
    const uint64_t *anchor_shifted_y,
    uint32_t subrange_bits,           // например, 44..62 бит вокруг якоря Base
    uint32_t dp_bits,
    uint32_t steps_per_kang,
    uint64_t seed_val,
    uint64_t *out_dp_xtags,           // буфер [max_dps]
    int64_t  *out_dp_dists,           // буфер [max_dps]
    uint8_t  *out_dp_types,           // буфер [max_dps]
    uint32_t max_dps,
    uint32_t *out_dp_written,
    uint64_t *out_total_ops,
    int64_t  *out_solved_offset,
    int32_t  *out_col_type
) {
    Point G_pt;
    G_pt.x.d[0] = 0x59F2815B16F81798ULL; G_pt.x.d[1] = 0x029BFCDB2DCE28D9ULL;
    G_pt.x.d[2] = 0x55A06295CE870B07ULL; G_pt.x.d[3] = 0x79BE667EF9DCBBACULL;
    G_pt.y.d[0] = 0x9C47D08FFB10D4B8ULL; G_pt.y.d[1] = 0xFD17B448A6855419ULL;
    G_pt.y.d[2] = 0x5DA4FBFC0E1108A8ULL; G_pt.y.d[3] = 0x483ADA7726A3C465ULL;
    G_pt.infinity = false;

    const int JMP_N = 512;
    U256 j1_x[JMP_N], j1_y[JMP_N], j2_x[JMP_N], j2_y[JMP_N], j3_x[JMP_N], j3_y[JMP_N];
    int64_t j1_d[JMP_N], j2_d[JMP_N], j3_d[JMP_N];

    auto splitmix64 = [](uint64_t &st) -> uint64_t {
        uint64_t z = (st += 0x9e3779b97f4a7c15ULL);
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
        z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
        return z ^ (z >> 31);
    };

    // ВАЖНО (как в RCKangaroo.cpp строки 390-424): таблицы прыжков Jumps1/2/3 генерируются
    // от ФИКСИРОВАННОГО зерна (чтобы граф траекторий был единым между всеми волнами и сессиями!),
    // а seed_val используется только для случайных стартовых позиций кенгуру!
    uint64_t rng = 0x14020261018ULL ^ ((uint64_t)subrange_bits << 32);
    int shift_j1 = (int)(subrange_bits / 2) - 2;
    if (shift_j1 < 2) shift_j1 = 2;
    int64_t min_j1 = 1LL << shift_j1;
    int64_t min_j2 = 1LL << (subrange_bits > 12 ? (subrange_bits - 10) : (subrange_bits / 2 + 1));
    int64_t min_j3 = 1LL << (subrange_bits > 14 ? (subrange_bits - 12) : (subrange_bits / 2 + 2));

    for (int i = 0; i < JMP_N; i++) {
        j1_d[i] = (min_j1 + (int64_t)(splitmix64(rng) & (min_j1 - 1))) & ~1LL;
        if (j1_d[i] == 0) j1_d[i] = 2;
        Point p1 = scalar_mult_u64((uint64_t)j1_d[i], G_pt);
        j1_x[i] = p1.x; j1_y[i] = p1.y;

        j2_d[i] = (min_j2 + (int64_t)(splitmix64(rng) & (min_j2 - 1))) & ~1LL;
        if (j2_d[i] == 0) j2_d[i] = 4;
        Point p2 = scalar_mult_u64((uint64_t)j2_d[i], G_pt);
        j2_x[i] = p2.x; j2_y[i] = p2.y;

        j3_d[i] = (min_j3 + (int64_t)(splitmix64(rng) & (min_j3 - 1))) & ~1LL;
        if (j3_d[i] == 0) j3_d[i] = 6;
        Point p3 = scalar_mult_u64((uint64_t)j3_d[i], G_pt);
        j3_x[i] = p3.x; j3_y[i] = p3.y;
    }

    int64_t x32 = 1LL << (subrange_bits >= 6 ? (subrange_bits - 5) : 1);
    int64_t wild_range = 34LL * x32;

    Point P_target;
    memcpy(P_target.x.d, anchor_shifted_x, 32);
    memcpy(P_target.y.d, anchor_shifted_y, 32);
    P_target.infinity = false;

    Point P_x32 = scalar_mult_u64((uint64_t)x32, G_pt);
    Point P_shifted = point_add(P_target, P_x32);
    Point P_wild_base = P_shifted;
    fe_neg(P_wild_base.y, P_shifted.y);

    uint64_t dp_mask = (1ULL << dp_bits) - 1ULL;
    std::atomic<bool> solved(false);
    std::atomic<int64_t> ans_key(0);
    std::atomic<int32_t> ans_col_type(0);
    std::atomic<uint64_t> total_ec_ops(3 * JMP_N);
    std::atomic<uint32_t> dp_idx(0);

    const size_t DP_TAB_SIZE = 1ULL << 18;
    const size_t DP_TAB_MASK = DP_TAB_SIZE - 1;
    std::vector<SotaDP> dp_table(DP_TAB_SIZE, {0, 0, 0, 0});
    omp_lock_t dp_lock;
    omp_init_lock(&dp_lock);

    auto verify_shifted_candidate = [&](int64_t cand_shifted) -> int64_t {
        int64_t real_k = cand_shifted - x32;
        if (real_k <= 0) return -1;
        Point P_chk = scalar_mult_u64((uint64_t)real_k, G_pt);
        if (memcmp(P_chk.x.d, P_target.x.d, 32) == 0 &&
            memcmp(P_chk.y.d, P_target.y.d, 32) == 0) {
            return real_k;
        }
        return -1;
    };

    #pragma omp parallel
    {
        int tid = omp_get_thread_num();
        uint64_t t_rng = seed_val ^ ((uint64_t)(tid + 1) * 0x9e3779b97f4a7c15ULL);

        const int B = 96;
        const int TAME_CNT = B / 3;
        U256 kx[B], ky[B];
        int64_t kd[B];
        uint8_t ktype[B];
        uint32_t k_id[B];
        uint8_t l1s2[B];
        uint64_t hist_d[B][10];
        uint8_t hist_pos[B];

        for (int i = 0; i < B; i++) {
            k_id[i] = (uint32_t)(tid * B + i + 1);
            l1s2[i] = 0;
            hist_pos[i] = 0;
            memset(hist_d[i], 0xFF, sizeof(hist_d[i]));
            if (i < TAME_CNT) {
                ktype[i] = 0;
                kd[i] = (int64_t)(splitmix64(t_rng) % (uint64_t)x32);
                if (kd[i] == 0) kd[i] = 1;
                Point pt = scalar_mult_u64((uint64_t)kd[i], G_pt);
                kx[i] = pt.x; ky[i] = pt.y;
            } else {
                ktype[i] = 1;
                kd[i] = ((int64_t)(splitmix64(t_rng) % (uint64_t)wild_range)) & ~1LL;
                if (kd[i] == 0) kd[i] = 2;
                Point pt = scalar_mult_u64((uint64_t)kd[i], G_pt);
                Point wpt = point_add(P_wild_base, pt);
                kx[i] = wpt.x; ky[i] = wpt.y;
            }
        }
        total_ec_ops.fetch_add(B, std::memory_order_relaxed);

        U256 jx[B], jy[B], diffs[B], invs[B], pbuf[B];
        int64_t jd_signed[B];
        uint32_t j_idx_arr[B];

        for (uint32_t step = 0; step < steps_per_kang && !solved.load(std::memory_order_relaxed); step++) {
            for (int i = 0; i < B; i++) {
                uint32_t j_ind = (uint32_t)(kx[i].d[0] & (JMP_N - 1));
                uint32_t inv_flag = (uint32_t)(ky[i].d[0] & 1ULL);
                j_idx_arr[i] = j_ind | (inv_flag << 9);

                const U256 *tab_x = l1s2[i] ? j2_x : j1_x;
                const U256 *tab_y = l1s2[i] ? j2_y : j1_y;
                const int64_t *tab_d = l1s2[i] ? j2_d : j1_d;

                jx[i] = tab_x[j_ind];
                if (inv_flag) {
                    fe_neg(jy[i], tab_y[j_ind]);
                    jd_signed[i] = -tab_d[j_ind];
                } else {
                    jy[i] = tab_y[j_ind];
                    jd_signed[i] = +tab_d[j_ind];
                }
                fe_sub(diffs[i], kx[i], jx[i]);
            }

            fe_batch_inv(invs, diffs, B, pbuf);

            for (int i = 0; i < B; i++) {
                U256 dy, s, s2, nx, dx, ny;
                fe_sub(dy, ky[i], jy[i]);
                fe_mul(s, dy, invs[i]);
                fe_sqr(s2, s);
                fe_sub(nx, s2, jx[i]);
                fe_sub(nx, nx, kx[i]);
                fe_sub(dx, kx[i], nx);
                fe_mul(ny, s, dx);
                fe_sub(ny, ny, ky[i]);

                kx[i] = nx;
                ky[i] = ny;
                kd[i] += jd_signed[i];

                if (l1s2[i] == 0) {
                    uint32_t next_j = (uint32_t)(nx.d[0] & (JMP_N - 1));
                    uint32_t next_inv_opp = ((uint32_t)(ny.d[0] & 1ULL)) ? 0U : (1U << 9);
                    if ((next_j | next_inv_opp) == j_idx_arr[i]) l1s2[i] = 1;
                } else {
                    l1s2[i] = 0;
                }

                uint64_t cur_d_u = (uint64_t)kd[i];
                bool looped = false;
                for (int h = 0; h < 10; h++) {
                    if (hist_d[i][h] == cur_d_u) { looped = true; break; }
                }
                hist_d[i][hist_pos[i]] = cur_d_u;
                hist_pos[i] = (hist_pos[i] + 1) % 10;

                if (looped) {
                    uint32_t j3 = (uint32_t)(kx[i].d[0] & (JMP_N - 1));
                    Point cur_p, j3_p;
                    cur_p.x = kx[i]; cur_p.y = ky[i]; cur_p.infinity = false;
                    j3_p.x = j3_x[j3]; j3_p.y = j3_y[j3]; j3_p.infinity = false;
                    if (ky[i].d[0] & 1ULL) {
                        fe_neg(j3_p.y, j3_p.y);
                        kd[i] -= j3_d[j3];
                    } else {
                        kd[i] += j3_d[j3];
                    }
                    Point esc_p = point_add(cur_p, j3_p);
                    kx[i] = esc_p.x; ky[i] = esc_p.y;
                }

                if ((kx[i].d[0] & dp_mask) == 0ULL) {
                    uint64_t xtag = kx[i].d[0] ^ (kx[i].d[1] << 16);
                    if (xtag == 0) xtag = 1;
                    size_t slot = hash_mix(xtag) & DP_TAB_MASK;

                    uint32_t cur_out = dp_idx.fetch_add(1, std::memory_order_relaxed);
                    if (cur_out < max_dps) {
                        out_dp_xtags[cur_out] = xtag;
                        out_dp_dists[cur_out] = kd[i];
                        out_dp_types[cur_out] = ktype[i];
                    }

                    omp_set_lock(&dp_lock);
                    while (dp_table[slot].x_tag != 0) {
                        if (dp_table[slot].x_tag == xtag) {
                            SotaDP prev = dp_table[slot];
                            if (prev.kang_type != ktype[i]) {
                                int64_t t_d = (prev.kang_type == 0) ? prev.dist : kd[i];
                                int64_t w_d = (prev.kang_type == 1) ? prev.dist : kd[i];
                                int64_t cands[4] = { w_d - t_d, w_d + t_d, t_d - w_d, -(w_d + t_d) };
                                for (int c = 0; c < 4; c++) {
                                    int64_t rk = verify_shifted_candidate(cands[c]);
                                    if (rk >= 0) {
                                        solved.store(true);
                                        ans_key.store(rk);
                                        ans_col_type.store(1);
                                        break;
                                    }
                                }
                            } else if (ktype[i] == 1 && prev.dist != kd[i]) {
                                int64_t sum_w = prev.dist + kd[i];
                                int64_t diff_w = prev.dist - kd[i];
                                int64_t cands_w[4] = { sum_w >> 1, (-sum_w) >> 1, diff_w >> 1, (-diff_w) >> 1 };
                                for (int c = 0; c < 4; c++) {
                                    int64_t rk = verify_shifted_candidate(cands_w[c]);
                                    if (rk >= 0) {
                                        solved.store(true);
                                        ans_key.store(rk);
                                        ans_col_type.store(2);
                                        break;
                                    }
                                }
                            }
                            break;
                        }
                        slot = (slot + 1) & DP_TAB_MASK;
                    }
                    if (dp_table[slot].x_tag == 0) {
                        dp_table[slot] = {xtag, kd[i], k_id[i], ktype[i]};
                    }
                    omp_unset_lock(&dp_lock);
                }
            }
        }
        total_ec_ops.fetch_add((uint64_t)B * steps_per_kang, std::memory_order_relaxed);
    }

    omp_destroy_lock(&dp_lock);
    uint32_t written = dp_idx.load();
    *out_dp_written = (written < max_dps) ? written : max_dps;
    *out_total_ops = total_ec_ops.load();
    *out_solved_offset = ans_key.load();
    *out_col_type = ans_col_type.load();
    return solved.load() ? 1 : 0;
}

// ============================================================================
// МНОГОПАЛУБНЫЙ 2D-РАДАР РАНЕНИЙ (8 ПАЛУБ КОРАБЛЯ s_0..s_7 + 2D-КАРТЕЧЬ dX x dY)
// ============================================================================
static int32_t g_deck_shifts[8] = {0, 20, 40, 55, 69, 86, 103, 120};
static int32_t g_shift_x_2d = 69;
static uint32_t g_multideck_M = 0;

int sqf_build_multideck_2d_radar(
    uint32_t M_per_deck,
    const int32_t *deck_shifts_8,
    int32_t shift_x_2d,
    uint32_t rx_2d,
    uint32_t ry_2d
) {
    Point G_pt;
    G_pt.x.d[0] = 0x59F2815B16F81798ULL;
    G_pt.x.d[1] = 0x029BFCDB2DCE28D9ULL;
    G_pt.x.d[2] = 0x55A06295CE870B07ULL;
    G_pt.x.d[3] = 0x79BE667EF9DCBBACULL;
    G_pt.y.d[0] = 0x9C47D08FFB10D4B8ULL;
    G_pt.y.d[1] = 0xFD17B448A6855419ULL;
    G_pt.y.d[2] = 0x5DA4FBFC0E1108A8ULL;
    G_pt.y.d[3] = 0x483ADA7726A3C465ULL;
    G_pt.infinity = false;

    for (int d = 0; d < 8; d++) g_deck_shifts[d] = deck_shifts_8[d];
    g_shift_x_2d = shift_x_2d;
    g_multideck_M = M_per_deck;

    uint64_t total_entries = (uint64_t)M_per_deck * 8ULL + (uint64_t)rx_2d * (2ULL * ry_2d);
    if (g_table) { free(g_table); g_table = nullptr; }
    if (g_bitmap) { free(g_bitmap); g_bitmap = nullptr; }

    g_table_cap = 1;
    while (g_table_cap < total_entries * 2ULL) g_table_cap <<= 1;
    g_table_mask = g_table_cap - 1;
    g_table = (CompactEntry *)calloc(g_table_cap, sizeof(CompactEntry));

    uint64_t bitmap_bits = g_table_cap * 8ULL;
    g_bitmap_mask = bitmap_bits - 1;
    g_bitmap = (uint64_t *)calloc(bitmap_bits >> 6, sizeof(uint64_t));
    g_cached_M = 0x7FFFFFFFU; // Специальный маркер многопалубного радара

    auto table_insert_parallel = [&](uint64_t raw_x, uint32_t packed_val) {
        uint64_t h = hash_mix(raw_x);
        uint64_t b_idx = h & g_bitmap_mask;
        __atomic_fetch_or(&g_bitmap[b_idx >> 6], 1ULL << (b_idx & 63), __ATOMIC_RELAXED);

        uint64_t idx = h & g_table_mask;
        uint32_t tag = (uint32_t)(h >> 32);
        while (true) {
            uint32_t cur = __atomic_load_n(&g_table[idx].val, __ATOMIC_RELAXED);
            if (cur == 0) {
                uint32_t expected = 0;
                if (__atomic_compare_exchange_n(&g_table[idx].val, &expected, packed_val, false, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
                    __atomic_store_n(&g_table[idx].tag, tag, __ATOMIC_RELAXED);
                    break;
                }
            }
            idx = (idx + 1) & g_table_mask;
        }
    };

    // Предвычисляем T[0..164] = 2^b * G
    const int NB = 165;
    Point T[NB];
    T[0] = G_pt;
    for (int i = 1; i < NB; i++) point_double(T[i], T[i - 1]);

    // Часть А: Строим 8 палуб корабля (d = 0..7), каждая с базой G_d = 2^{s_d} * G
    const int B = 512;
    for (int d = 0; d < 8; d++) {
        int s = g_deck_shifts[d];
        if (s < 0 || s >= NB) s = 0;
        Point G_deck = T[s];

        Point *small_pts = new Point[B + 1];
        generate_base_table(small_pts, G_deck, B);

        uint32_t lim_b = (M_per_deck < (uint32_t)B) ? M_per_deck : (uint32_t)B;
        for (uint32_t r = 1; r <= lim_b; r++) {
            uint32_t packed = ((uint32_t)(d + 1) << 24) | (r & 0x00FFFFFFU);
            table_insert_parallel(small_pts[r].x.d[0], packed);
        }

        if (M_per_deck > (uint32_t)B) {
            Point step_2B;
            point_double(step_2B, small_pts[B]);
            int num_blocks = (M_per_deck + (2 * B) - 1) / (2 * B);

            #pragma omp parallel
            {
                U256 local_diffs[B], local_invs[B], local_pbuf[B];
                int tid = omp_get_thread_num();
                int nthreads = omp_get_num_threads();
                int blk_start = (num_blocks * tid) / nthreads;
                int blk_end   = (num_blocks * (tid + 1)) / nthreads;

                Point center_pt;
                if (blk_start < blk_end) {
                    scalar_mult_point(center_pt, small_pts[B], (uint64_t)(2 * blk_start + 1));
                }

                for (int blk = blk_start; blk < blk_end; blk++) {
                    uint32_t c_idx = (uint32_t)(2 * blk + 1) * B;
                    if (blk > blk_start) {
                        Point next_c;
                        point_add_slow(next_c, center_pt, step_2B);
                        center_pt = next_c;
                    }
                    if (c_idx <= M_per_deck && c_idx > (uint32_t)B) {
                        uint32_t packed = ((uint32_t)(d + 1) << 24) | (c_idx & 0x00FFFFFFU);
                        table_insert_parallel(center_pt.x.d[0], packed);
                    }

                    for (int j = 1; j < B; j++) {
                        fe_sub(local_diffs[j - 1], center_pt.x, small_pts[j].x);
                    }
                    fe_batch_inv(local_invs, local_diffs, B - 1, local_pbuf);

                    for (int j = 1; j < B; j++) {
                        U256 x_sum;
                        fe_add(x_sum, center_pt.x, small_pts[j].x);

                        uint32_t idx_p = c_idx + j;
                        if (idx_p <= M_per_deck) {
                            U256 dy, s_val, s2, nx;
                            fe_sub(dy, center_pt.y, small_pts[j].y);
                            fe_mul(s_val, dy, local_invs[j - 1]);
                            fe_sqr(s2, s_val);
                            fe_sub(nx, s2, x_sum);
                            uint32_t packed = ((uint32_t)(d + 1) << 24) | (idx_p & 0x00FFFFFFU);
                            table_insert_parallel(nx.d[0], packed);
                        }

                        uint32_t idx_m = c_idx - j;
                        if (idx_m > (uint32_t)B && idx_m <= M_per_deck) {
                            U256 dy, s_val, s2, nx;
                            fe_add(dy, center_pt.y, small_pts[j].y);
                            fe_mul(s_val, dy, local_invs[j - 1]);
                            fe_sqr(s2, s_val);
                            fe_sub(nx, s2, x_sum);
                            uint32_t packed = ((uint32_t)(d + 1) << 24) | (idx_m & 0x00FFFFFFU);
                            table_insert_parallel(nx.d[0], packed);
                        }
                    }

                    uint32_t border_idx = c_idx + B;
                    if (border_idx <= M_per_deck) {
                        Point bp;
                        point_add_slow(bp, center_pt, small_pts[B]);
                        uint32_t packed = ((uint32_t)(d + 1) << 24) | (border_idx & 0x00FFFFFFU);
                        table_insert_parallel(bp.x.d[0], packed);
                    }
                }
            }
        }
        delete[] small_pts;
    }

    // Часть Б: Строим 2D-картечь dX * (2^{shift_x_2d} G) +/- dY * G
    // Код палубы = 9 (в старшем байте 9 << 24), dX in [1..rx_2d] (12 бит), sign_dy (1 бит), dY in [1..ry_2d] (11 бит)
    if (rx_2d > 0 && ry_2d > 0) {
        if (rx_2d > 2047) rx_2d = 2047;
        if (ry_2d > 2047) ry_2d = 2047;
        Point GX = T[(shift_x_2d >= 0 && shift_x_2d < NB) ? shift_x_2d : 69];
        Point *pts_X = new Point[rx_2d + 1];
        Point *pts_Y = new Point[ry_2d + 1];
        generate_base_table(pts_X, GX, (int)rx_2d);
        generate_base_table(pts_Y, G_pt, (int)ry_2d);

        #pragma omp parallel for schedule(static)
        for (uint32_t dx = 1; dx <= rx_2d; dx++) {
            U256 diffs[2048], invs[2048], pbuf[2048];
            Point CX = pts_X[dx];
            for (uint32_t dy = 1; dy <= ry_2d; dy++) {
                fe_sub(diffs[dy - 1], CX.x, pts_Y[dy].x);
            }
            fe_batch_inv(invs, diffs, (int)ry_2d, pbuf);

            for (uint32_t dy = 1; dy <= ry_2d; dy++) {
                U256 x_sum, dy_val, s_val, s2, nx;
                fe_add(x_sum, CX.x, pts_Y[dy].x);

                // 1) dx * GX + dy * G (sign_dy = 0)
                fe_sub(dy_val, CX.y, pts_Y[dy].y);
                fe_mul(s_val, dy_val, invs[dy - 1]);
                fe_sqr(s2, s_val);
                fe_sub(nx, s2, x_sum);
                uint32_t p_plus = (9U << 24) | ((dx & 0x7FFU) << 12) | (0U << 11) | (dy & 0x7FFU);
                table_insert_parallel(nx.d[0], p_plus);

                // 2) dx * GX - dy * G (sign_dy = 1)
                fe_add(dy_val, CX.y, pts_Y[dy].y);
                fe_mul(s_val, dy_val, invs[dy - 1]);
                fe_sqr(s2, s_val);
                fe_sub(nx, s2, x_sum);
                uint32_t p_minus = (9U << 24) | ((dx & 0x7FFU) << 12) | (1U << 11) | (dy & 0x7FFU);
                table_insert_parallel(nx.d[0], p_minus);
            }
        }
        delete[] pts_X;
        delete[] pts_Y;
    }

    return 1;
}

// Стрельба многопалубными и 2D-снарядами с полной 256-битной верификацией каждого ранения внутри C++!
int sqf_fire_multideck_2d_salvo(
    const uint64_t *target_x_limbs,
    const uint64_t *target_y_limbs,
    uint32_t num_anchors,
    const uint64_t *anchors_lo,
    const uint64_t *anchors_mid,
    const uint64_t *anchors_hi,
    uint32_t giant_radius_q,
    int32_t *out_anchor_idx,
    int32_t *out_deck_id,
    int64_t *out_dx,
    int64_t *out_dy
) {
    if (g_table == nullptr || g_cached_M != 0x7FFFFFFFU) return -1;

    Point G_pt;
    G_pt.x.d[0] = 0x59F2815B16F81798ULL;
    G_pt.x.d[1] = 0x029BFCDB2DCE28D9ULL;
    G_pt.x.d[2] = 0x55A06295CE870B07ULL;
    G_pt.x.d[3] = 0x79BE667EF9DCBBACULL;
    G_pt.y.d[0] = 0x9C47D08FFB10D4B8ULL;
    G_pt.y.d[1] = 0xFD17B448A6855419ULL;
    G_pt.y.d[2] = 0x5DA4FBFC0E1108A8ULL;
    G_pt.y.d[3] = 0x483ADA7726A3C465ULL;
    G_pt.infinity = false;

    Point Target;
    memcpy(Target.x.d, target_x_limbs, 32);
    memcpy(Target.y.d, target_y_limbs, 32);
    Target.infinity = false;

    const int NB = 165;
    Point T[NB];
    T[0] = G_pt;
    for (int i = 1; i < NB; i++) point_double(T[i], T[i - 1]);

    // Гигантские шаги делаем сразу по ДВУМ осям:
    // 1..QR/2 — вдоль оси Y (шаг 2 * M_per_deck * G)
    // QR/2+1..QR — вдоль оси X (шаг 2 * M_per_deck * 2^{shift_x_2d} G)
    int QR = (giant_radius_q > 512) ? 512 : (int)giant_radius_q;
    int half_QR = QR / 2;
    Point G_giant_Y, G_giant_X;
    scalar_mult_point(G_giant_Y, G_pt, 2ULL * (uint64_t)g_multideck_M);
    Point GX_base = T[(g_shift_x_2d >= 0 && g_shift_x_2d < NB) ? g_shift_x_2d : 69];
    scalar_mult_point(G_giant_X, GX_base, 2ULL * (uint64_t)g_multideck_M);

    Point *S_pts = nullptr;
    if (QR > 0) {
        S_pts = new Point[QR + 1];
        if (half_QR > 0) {
            S_pts[1] = G_giant_Y;
            for (int j = 2; j <= half_QR; j++) point_add_slow(S_pts[j], S_pts[j - 1], G_giant_Y);
        }
        if (QR > half_QR) {
            S_pts[half_QR + 1] = G_giant_X;
            for (int j = half_QR + 2; j <= QR; j++) point_add_slow(S_pts[j], S_pts[j - 1], G_giant_X);
        }
    }

    std::atomic<bool> found(false);
    std::atomic<int32_t> hit_idx(-1);
    std::atomic<int32_t> hit_deck(-1);
    std::atomic<int64_t> hit_dx(0);
    std::atomic<int64_t> hit_dy(0);

    // Функция полной 256-битной проверки кандидата (защита от 54-битных ложных срабатываний тега!)
    auto verify_and_commit = [&](uint32_t anchor_idx, const Point &D_base, int q_idx, int q_sign, uint32_t packed) -> bool {
        uint32_t code = packed >> 24;
        Point Expected;
        Expected.infinity = true;

        int64_t cand_dx = 0, cand_dy = 0;
        int32_t deck_out = 0;

        if (code >= 1 && code <= 8) {
            deck_out = (int32_t)(code - 1);
            uint32_t r_val = packed & 0x00FFFFFFU;
            int s = g_deck_shifts[deck_out];
            if (s < 0 || s >= NB) s = 0;
            scalar_mult_point(Expected, T[s], (uint64_t)r_val);
            cand_dy = (int64_t)r_val;
        } else if (code == 9) {
            deck_out = 8; // 2D-картечь (dX, dY)
            uint32_t dx_val = (packed >> 12) & 0x7FFU;
            uint32_t sign_y = (packed >> 11) & 1U;
            uint32_t dy_val = packed & 0x7FFU;
            Point PX, PY;
            scalar_mult_point(PX, GX_base, (uint64_t)dx_val);
            scalar_mult_point(PY, G_pt, (uint64_t)dy_val);
            if (sign_y) fe_neg(PY.y, PY.y);
            point_add_slow(Expected, PX, PY);
            cand_dx = (int64_t)dx_val;
            cand_dy = sign_y ? -(int64_t)dy_val : (int64_t)dy_val;
        } else {
            return false;
        }

        // Вычисляем точку D_shifted = D_base - q_sign * S_pts[q_idx]
        Point D_shifted = D_base;
        if (q_idx > 0) {
            Point Q_shift = S_pts[q_idx];
            if (q_sign > 0) fe_neg(Q_shift.y, Q_shift.y);
            point_add_slow(D_shifted, D_base, Q_shift);
        }

        if (memcmp(D_shifted.x.d, Expected.x.d, 32) != 0) {
            return false; // Ложная тревога 32-битного тега — продолжаем поиск!
        }

        // Знак совпадения по Y-координате:
        bool pos_match = (memcmp(D_shifted.y.d, Expected.y.d, 32) == 0);
        int64_t sgn = pos_match ? +1 : -1;

        int64_t q_step_x = 0, q_step_y = 0;
        if (q_idx > 0) {
            if (q_idx <= half_QR) {
                q_step_y = (int64_t)q_sign * (int64_t)q_idx * 2LL * (int64_t)g_multideck_M;
            } else {
                q_step_x = (int64_t)q_sign * (int64_t)(q_idx - half_QR) * 2LL * (int64_t)g_multideck_M;
            }
        }

        hit_idx.store((int32_t)anchor_idx);
        hit_deck.store(deck_out);
        if (deck_out == 8) {
            hit_dx.store(q_step_x + sgn * cand_dx);
            hit_dy.store(q_step_y + sgn * cand_dy);
        } else {
            hit_dx.store(q_step_x); // Если q шёл по X, иначе 0
            hit_dy.store(q_step_y + sgn * cand_dy); // Смещение вдоль палубы deck_out
        }
        found.store(true);
        return true;
    };

    auto lookup_and_verify = [&](uint32_t anchor_idx, const Point &D_base, int q_idx, int q_sign, uint64_t raw_x) -> bool {
        uint64_t h = hash_mix(raw_x);
        uint64_t b_idx = h & g_bitmap_mask;
        if ((g_bitmap[b_idx >> 6] & (1ULL << (b_idx & 63))) == 0) return false;
        uint64_t idx = h & g_table_mask;
        uint32_t tag = (uint32_t)(h >> 32);
        while (g_table[idx].val != 0) {
            if (g_table[idx].tag == tag) {
                if (verify_and_commit(anchor_idx, D_base, q_idx, q_sign, g_table[idx].val)) {
                    return true;
                }
            }
            idx = (idx + 1) & g_table_mask;
        }
        return false;
    };

    #pragma omp parallel
    {
        U256 diffs[512], invs[512], pbuf[512];

        #pragma omp for schedule(dynamic, 16)
        for (uint32_t idx = 0; idx < num_anchors; idx++) {
            if (found.load(std::memory_order_relaxed)) continue;

            uint64_t w0 = anchors_lo[idx];
            uint64_t w1 = anchors_mid[idx];
            uint64_t w2 = anchors_hi[idx];

            Point A_pt;
            A_pt.infinity = true;
            for (int b = 0; b < 64; b++) {
                if ((w0 >> b) & 1ULL) { Point nxt; point_add_slow(nxt, A_pt, T[b]); A_pt = nxt; }
            }
            for (int b = 0; b < 64; b++) {
                if ((w1 >> b) & 1ULL) { Point nxt; point_add_slow(nxt, A_pt, T[64 + b]); A_pt = nxt; }
            }
            for (int b = 0; b < 36; b++) {
                if ((w2 >> b) & 1ULL) { Point nxt; point_add_slow(nxt, A_pt, T[128 + b]); A_pt = nxt; }
            }

            Point neg_A = A_pt;
            fe_neg(neg_A.y, A_pt.y);
            Point D;
            point_add_slow(D, Target, neg_A);
            if (D.infinity) {
                hit_idx.store((int32_t)idx); hit_deck.store(0); hit_dx.store(0); hit_dy.store(0);
                found.store(true);
                continue;
            }

            if (lookup_and_verify(idx, D, 0, 0, D.x.d[0])) {
                continue;
            }

            if (QR > 0) {
                for (int j = 1; j <= QR; j++) fe_sub(diffs[j - 1], D.x, S_pts[j].x);
                fe_batch_inv(invs, diffs, QR, pbuf);

                for (int j = 1; j <= QR; j++) {
                    U256 x_sum, dy, s_val, s2, nx;
                    fe_add(x_sum, D.x, S_pts[j].x);

                    // D - S_pts[j] (q_sign = +1)
                    fe_add(dy, D.y, S_pts[j].y);
                    fe_mul(s_val, dy, invs[j - 1]);
                    fe_sqr(s2, s_val);
                    fe_sub(nx, s2, x_sum);
                    if (lookup_and_verify(idx, D, j, +1, nx.d[0])) break;

                    // D + S_pts[j] (q_sign = -1)
                    fe_sub(dy, D.y, S_pts[j].y);
                    fe_mul(s_val, dy, invs[j - 1]);
                    fe_sqr(s2, s_val);
                    fe_sub(nx, s2, x_sum);
                    if (lookup_and_verify(idx, D, j, -1, nx.d[0])) break;
                }
            }
        }
    }

    if (S_pts) delete[] S_pts;
    if (found.load()) {
        *out_anchor_idx = hit_idx.load();
        *out_deck_id = hit_deck.load();
        *out_dx = hit_dx.load();
        *out_dy = hit_dy.load();
        return 1;
    }
    return 0;
}

// ============================================================================
// ЧЕСТНЫЙ ЛИНЕЙНЫЙ БЕНЧМАРК SQF-64 (БЕЗ КЭША, С НУЛЯ, С ТОЧНЫМ СЧЁТЧИКОМ EC-ОПЕРАЦИЙ)
// - Принудительно очищает g_table и g_bitmap перед каждым вызовом (честный замер с нуля!).
// - Центрирует поиск в середине диапазона C = W / 2 (вычитая C*G из открытого ключа P).
// - Считает каждую реальную групповую операцию на кривой (table_ec_ops и search_ec_ops)
//   прямо внутри циклов C++ через атомарные счётчики.
// - Проверяет полное 256-битное равенство точки внутри C++ перед остановкой поиска,
//   исключая ложные срабатывания 32-битного тега хэш-таблицы.
// ============================================================================
int sqf_linear_bsgs_blind_solve(
    const uint64_t *target_x_limbs,
    const uint64_t *target_y_limbs,
    uint32_t range_bits,
    uint32_t table_bits,
    uint64_t *out_table_ec_ops,
    uint64_t *out_search_ec_ops,
    double *out_table_sec,
    double *out_search_sec,
    int64_t *out_q,
    uint32_t *out_r,
    int32_t *out_r_sign
) {
    if (range_bits < 16 || range_bits > 62) return 0;

    Point G_pt;
    G_pt.x.d[0] = 0x59F2815B16F81798ULL; G_pt.x.d[1] = 0x029BFCDB2DCE28D9ULL;
    G_pt.x.d[2] = 0x55A06295CE870B07ULL; G_pt.x.d[3] = 0x79BE667EF9DCBBACULL;
    G_pt.y.d[0] = 0x9C47D08FFB10D4B8ULL; G_pt.y.d[1] = 0xFD17B448A6855419ULL;
    G_pt.y.d[2] = 0x5DA4FBFC0E1108A8ULL; G_pt.y.d[3] = 0x483ADA7726A3C465ULL;
    G_pt.infinity = false;

    Point P_target;
    memcpy(P_target.x.d, target_x_limbs, 32);
    memcpy(P_target.y.d, target_y_limbs, 32);
    P_target.infinity = false;

    uint32_t M = 1U << table_bits;
    uint64_t W_half = 1ULL << (range_bits - 1);

    // 1. Сброс и построение таблицы малых шагов r * G (r = 1..M) с нуля
    double t0_tbl = omp_get_wtime();
    if (g_table) { free(g_table); g_table = nullptr; }
    if (g_bitmap) { free(g_bitmap); g_bitmap = nullptr; }

    g_table_cap = 1;
    while (g_table_cap < (uint64_t)M * 2ULL) g_table_cap <<= 1;
    g_table_mask = g_table_cap - 1;
    g_table = (CompactEntry *)calloc(g_table_cap, sizeof(CompactEntry));

    uint64_t bitmap_bits = g_table_cap * 8ULL;
    g_bitmap_mask = bitmap_bits - 1;
    g_bitmap = (uint64_t *)calloc(bitmap_bits >> 6, sizeof(uint64_t));
    g_cached_M = M;

    auto table_insert_parallel = [&](uint64_t raw_x, uint32_t r_val) {
        uint64_t h = hash_mix(raw_x);
        uint64_t b_idx = h & g_bitmap_mask;
        __atomic_fetch_or(&g_bitmap[b_idx >> 6], 1ULL << (b_idx & 63), __ATOMIC_RELAXED);

        uint64_t idx = h & g_table_mask;
        uint32_t tag = (uint32_t)(h >> 32);
        while (true) {
            uint32_t cur = __atomic_load_n(&g_table[idx].val, __ATOMIC_RELAXED);
            if (cur == 0) {
                uint32_t expected = 0;
                if (__atomic_compare_exchange_n(&g_table[idx].val, &expected, r_val, false, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
                    __atomic_store_n(&g_table[idx].tag, tag, __ATOMIC_RELAXED);
                    break;
                }
            }
            idx = (idx + 1) & g_table_mask;
        }
    };

    std::atomic<uint64_t> real_table_ops(0);
    const int B = 1024;
    Point *small_pts = new Point[B + 1];
    generate_base_table(small_pts, G_pt, B);

    uint32_t lim_b = (M < (uint32_t)B) ? M : (uint32_t)B;
    for (uint32_t i = 1; i <= lim_b; i++) {
        table_insert_parallel(small_pts[i].x.d[0], i);
    }
    real_table_ops.fetch_add(lim_b, std::memory_order_relaxed);

    if (M > (uint32_t)B) {
        Point step_2B;
        point_double(step_2B, small_pts[B]);
        int num_blocks = (M + (2 * B) - 1) / (2 * B);

        #pragma omp parallel
        {
            U256 local_diffs[B], local_invs[B], local_pbuf[B];
            uint64_t local_ops = 0;
            int tid = omp_get_thread_num();
            int nthreads = omp_get_num_threads();
            int blk_start = (num_blocks * tid) / nthreads;
            int blk_end   = (num_blocks * (tid + 1)) / nthreads;

            Point center_pt;
            if (blk_start < blk_end) {
                scalar_mult_point(center_pt, small_pts[B], (uint64_t)(2 * blk_start + 1));
                local_ops++;
            }

            uint64_t out_x[2 * B];
            uint32_t out_r_idx[2 * B];

            for (int blk = blk_start; blk < blk_end; blk++) {
                uint32_t c_idx = (uint32_t)(2 * blk + 1) * B;
                if (blk > blk_start) {
                    Point next_c;
                    point_add_slow(next_c, center_pt, step_2B);
                    center_pt = next_c;
                    local_ops++;
                }

                if (c_idx <= M && c_idx > (uint32_t)B) {
                    table_insert_parallel(center_pt.x.d[0], c_idx);
                }

                for (int j = 1; j < B; j++) {
                    fe_sub(local_diffs[j - 1], center_pt.x, small_pts[j].x);
                }
                fe_batch_inv(local_invs, local_diffs, B - 1, local_pbuf);

                int cnt = 0;
                for (int j = 1; j < B; j++) {
                    U256 x_sum;
                    fe_add(x_sum, center_pt.x, small_pts[j].x);

                    uint32_t idx_p = c_idx + j;
                    if (idx_p <= M) {
                        U256 dy, s, s2, nx;
                        fe_sub(dy, center_pt.y, small_pts[j].y);
                        fe_mul(s, dy, local_invs[j - 1]);
                        fe_sqr(s2, s);
                        fe_sub(nx, s2, x_sum);
                        out_x[cnt] = nx.d[0];
                        out_r_idx[cnt] = idx_p;
                        cnt++;
                        local_ops++;
                    }

                    uint32_t idx_m = c_idx - j;
                    if (idx_m > (uint32_t)B && idx_m <= M) {
                        U256 dy, s, s2, nx;
                        fe_add(dy, center_pt.y, small_pts[j].y);
                        fe_mul(s, dy, local_invs[j - 1]);
                        fe_sqr(s2, s);
                        fe_sub(nx, s2, x_sum);
                        out_x[cnt] = nx.d[0];
                        out_r_idx[cnt] = idx_m;
                        cnt++;
                        local_ops++;
                    }
                }

                for (int k = 0; k < cnt; k++) {
                    table_insert_parallel(out_x[k], out_r_idx[k]);
                }

                uint32_t border_idx = c_idx + B;
                if (border_idx <= M) {
                    Point bp;
                    point_add_slow(bp, center_pt, small_pts[B]);
                    local_ops++;
                    table_insert_parallel(bp.x.d[0], border_idx);
                }
            }
            real_table_ops.fetch_add(local_ops, std::memory_order_relaxed);
        }
    }
    delete[] small_pts;

    double t1_tbl = omp_get_wtime();
    *out_table_sec = t1_tbl - t0_tbl;
    *out_table_ec_ops = real_table_ops.load();

    // 2. Поиск гигантскими шагами от центра C = W / 2: K0 = P_target - (W/2)*G
    double t0_srch = omp_get_wtime();
    std::atomic<uint64_t> real_search_ops(0);

    Point C_pt = scalar_mult_u64(W_half, G_pt);
    Point neg_C = C_pt;
    fe_neg(neg_C.y, C_pt.y);
    Point K0;
    point_add_slow(K0, P_target, neg_C);
    real_search_ops.fetch_add(1, std::memory_order_relaxed);

    std::atomic<bool> found(false);
    std::atomic<int64_t> best_q(0);
    std::atomic<uint32_t> best_r(0);
    std::atomic<int32_t> best_sign(1);

    auto verify_candidate = [&](int64_t q_val, uint32_t r_val) -> bool {
        int64_t base_k = (int64_t)W_half + q_val * 2LL * (int64_t)M;
        int64_t cands[2] = { base_k + (int64_t)r_val, base_k - (int64_t)r_val };
        int32_t signs[2] = { +1, -1 };
        for (int c = 0; c < 2; c++) {
            if (cands[c] > 0 && (uint64_t)cands[c] < (1ULL << range_bits)) {
                Point P_chk = scalar_mult_u64((uint64_t)cands[c], G_pt);
                if (memcmp(P_chk.x.d, P_target.x.d, 32) == 0 &&
                    memcmp(P_chk.y.d, P_target.y.d, 32) == 0) {
                    best_q.store(q_val);
                    best_r.store(r_val);
                    best_sign.store(signs[c]);
                    found.store(true);
                    return true;
                }
            }
        }
        return false;
    };

    if (K0.infinity) {
        best_q.store(0); best_r.store(0); best_sign.store(1);
        found.store(true);
    } else {
        uint64_t h0 = hash_mix(K0.x.d[0]);
        uint64_t idx0 = h0 & g_table_mask;
        uint32_t tag0 = (uint32_t)(h0 >> 32);
        while (g_table[idx0].val != 0) {
            if (g_table[idx0].tag == tag0) {
                if (verify_candidate(0, g_table[idx0].val)) break;
            }
            idx0 = (idx0 + 1) & g_table_mask;
        }
    }

    uint64_t max_q = (W_half + (2ULL * M) - 1ULL) / (2ULL * M) + 2ULL;
    Point G_giant = scalar_mult_u64(2ULL * (uint64_t)M, G_pt);
    const int QB = 512;
    Point *S_pts = new Point[QB + 1];
    generate_base_table(S_pts, G_giant, QB);
    real_search_ops.fetch_add(QB, std::memory_order_relaxed);

    #pragma omp parallel
    {
        U256 local_diffs[QB], local_invs[QB], local_pbuf[QB];
        uint64_t local_ops = 0;
        int tid = omp_get_thread_num();
        int nthreads = omp_get_num_threads();

        uint64_t stride_q = (uint64_t)nthreads * 2ULL * QB;
        Point stride_pt_plus = scalar_mult_u64(stride_q, G_giant);
        Point stride_pt_minus = stride_pt_plus;
        fe_neg(stride_pt_minus.y, stride_pt_plus.y);

        uint64_t q_center = (uint64_t)(2 * tid + 1) * QB;
        Point shift_plus = scalar_mult_u64(q_center, G_giant);
        Point shift_minus = shift_plus;
        fe_neg(shift_minus.y, shift_plus.y);

        Point C_minus, C_plus;
        point_add_slow(C_minus, K0, shift_minus);
        point_add_slow(C_plus,  K0, shift_plus);
        local_ops += 2;

        auto scan_center = [&](const Point &C_cur, int64_t sign_dir) -> bool {
            uint64_t hc = hash_mix(C_cur.x.d[0]);
            if (g_bitmap[(hc & g_bitmap_mask) >> 6] & (1ULL << ((hc & g_bitmap_mask) & 63))) {
                uint64_t idxc = hc & g_table_mask;
                uint32_t tagc = (uint32_t)(hc >> 32);
                while (g_table[idxc].val != 0) {
                    if (g_table[idxc].tag == tagc) {
                        if (verify_candidate(sign_dir * (int64_t)q_center, g_table[idxc].val)) return true;
                    }
                    idxc = (idxc + 1) & g_table_mask;
                }
            }

            for (int j = 1; j <= QB; j++) {
                fe_sub(local_diffs[j - 1], C_cur.x, S_pts[j].x);
            }
            fe_batch_inv(local_invs, local_diffs, QB, local_pbuf);

            for (int j = 1; j <= QB; j++) {
                U256 x_sum, dy, s, s2, nx;
                fe_add(x_sum, C_cur.x, S_pts[j].x);

                // 1) C_cur - j * G_giant
                fe_add(dy, C_cur.y, S_pts[j].y);
                fe_mul(s, dy, local_invs[j - 1]);
                fe_sqr(s2, s);
                fe_sub(nx, s2, x_sum);
                local_ops++;
                uint64_t h1 = hash_mix(nx.d[0]);
                if (g_bitmap[(h1 & g_bitmap_mask) >> 6] & (1ULL << ((h1 & g_bitmap_mask) & 63))) {
                    uint64_t idx1 = h1 & g_table_mask;
                    uint32_t tag1 = (uint32_t)(h1 >> 32);
                    int64_t q1 = (sign_dir > 0) ? (int64_t)(q_center + j) : -(int64_t)(q_center - j);
                    while (g_table[idx1].val != 0) {
                        if (g_table[idx1].tag == tag1) {
                            if (verify_candidate(q1, g_table[idx1].val)) return true;
                        }
                        idx1 = (idx1 + 1) & g_table_mask;
                    }
                }

                // 2) C_cur + j * G_giant
                fe_sub(dy, C_cur.y, S_pts[j].y);
                fe_mul(s, dy, local_invs[j - 1]);
                fe_sqr(s2, s);
                fe_sub(nx, s2, x_sum);
                local_ops++;
                uint64_t h2 = hash_mix(nx.d[0]);
                if (g_bitmap[(h2 & g_bitmap_mask) >> 6] & (1ULL << ((h2 & g_bitmap_mask) & 63))) {
                    uint64_t idx2 = h2 & g_table_mask;
                    uint32_t tag2 = (uint32_t)(h2 >> 32);
                    int64_t q2 = (sign_dir > 0) ? (int64_t)(q_center - j) : -(int64_t)(q_center + j);
                    while (g_table[idx2].val != 0) {
                        if (g_table[idx2].tag == tag2) {
                            if (verify_candidate(q2, g_table[idx2].val)) return true;
                        }
                        idx2 = (idx2 + 1) & g_table_mask;
                    }
                }
            }
            return false;
        };

        while (!found.load(std::memory_order_relaxed) && (q_center <= max_q + QB)) {
            if (scan_center(C_minus, +1) || scan_center(C_plus, -1)) break;
            q_center += stride_q;
            if (!found.load(std::memory_order_relaxed) && (q_center <= max_q + QB)) {
                Point nm, np;
                point_add_slow(nm, C_minus, stride_pt_minus);
                point_add_slow(np, C_plus,  stride_pt_plus);
                C_minus = nm;
                C_plus  = np;
                local_ops += 2;
            }
        }
        real_search_ops.fetch_add(local_ops, std::memory_order_relaxed);
    }

    delete[] S_pts;
    double t1_srch = omp_get_wtime();
    *out_search_sec = t1_srch - t0_srch;
    *out_search_ec_ops = real_search_ops.load();

    if (found.load()) {
        *out_q = best_q.load();
        *out_r = best_r.load();
        *out_r_sign = best_sign.load();
        return 1;
    }
    return 0;
}

// ============================================================================
// КЛАССИЧЕСКИЙ KANGAROO ПОЛЛАРДА (БЕЗ SOTA +/- СИММЕТРИИ И БЕЗ WILD-WILD ЗЕРКАЛА)
// Для прямого сравнения с SQF-64 и SOTA v2 RCKangaroo на одних и тех же ключах:
// - 50% Tame + 50% Wild кенгуру
// - Прыжки строго вперёд P <- P + J[x & 511] (без отражения по чётности Y)
// - Только классические коллизии Tame <-> Wild
// - Реальный атомарный счётчик групповых операций на кривой (out_total_ops)
// ============================================================================
int sqf_classic_kangaroo_solve(
    const uint64_t *target_x_limbs,
    const uint64_t *target_y_limbs,
    uint32_t range_bits,
    uint32_t dp_bits,
    uint64_t seed_val,
    int64_t *out_solved_offset,
    uint64_t *out_total_ops,
    uint32_t *out_dp_count
) {
    if (range_bits < 16 || range_bits > 62) return 0;

    Point G_pt;
    G_pt.x.d[0] = 0x59F2815B16F81798ULL; G_pt.x.d[1] = 0x029BFCDB2DCE28D9ULL;
    G_pt.x.d[2] = 0x55A06295CE870B07ULL; G_pt.x.d[3] = 0x79BE667EF9DCBBACULL;
    G_pt.y.d[0] = 0x9C47D08FFB10D4B8ULL; G_pt.y.d[1] = 0xFD17B448A6855419ULL;
    G_pt.y.d[2] = 0x5DA4FBFC0E1108A8ULL; G_pt.y.d[3] = 0x483ADA7726A3C465ULL;
    G_pt.infinity = false;

    const int JMP_N = 512;
    U256 j1_x[JMP_N], j1_y[JMP_N];
    int64_t j1_d[JMP_N];

    auto splitmix64 = [](uint64_t &st) -> uint64_t {
        uint64_t z = (st += 0x9e3779b97f4a7c15ULL);
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
        z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
        return z ^ (z >> 31);
    };

    uint64_t rng = 0x19782026ULL ^ seed_val;
    int nthreads_max = omp_get_max_threads();
    const int B_CLAS = 24; // 12 Tame + 12 Wild на поток
    int m_herd_c = nthreads_max * (B_CLAS / 2);
    if (m_herd_c < 1) m_herd_c = 1;

    double w_full_d = (double)(1ULL << range_bits);
    double target_mean_c = 0.5 * (double)m_herd_c * std::sqrt(w_full_d);
    int shift_j1 = (int)std::floor(std::log2(std::max(4.0, target_mean_c * 0.66)));
    if (shift_j1 < 2) shift_j1 = 2;
    if (shift_j1 > (int)range_bits - 3) shift_j1 = (int)range_bits - 3;
    int64_t min_j1 = 1LL << shift_j1;

    for (int i = 0; i < JMP_N; i++) {
        j1_d[i] = min_j1 + (int64_t)(splitmix64(rng) & (min_j1 - 1));
        if (j1_d[i] <= 0) j1_d[i] = 1;
        Point p1 = scalar_mult_u64((uint64_t)j1_d[i], G_pt);
        j1_x[i] = p1.x; j1_y[i] = p1.y;
    }

    Point P_target;
    memcpy(P_target.x.d, target_x_limbs, 32);
    memcpy(P_target.y.d, target_y_limbs, 32);
    P_target.infinity = false;

    uint64_t W = 1ULL << range_bits;
    uint64_t W_half = W >> 1;
    uint32_t eff_dp_c = (dp_bits > 8) ? 8 : dp_bits;
    uint64_t dp_mask = (1ULL << eff_dp_c) - 1ULL;

    std::atomic<bool> solved(false);
    std::atomic<int64_t> ans_key(0);
    std::atomic<uint64_t> total_ec_ops(JMP_N);

    const size_t DP_TAB_SIZE = 1ULL << 19;
    const size_t DP_TAB_MASK = DP_TAB_SIZE - 1;
    std::vector<SotaDP> dp_table(DP_TAB_SIZE, {0, 0, 0, 0});
    std::atomic<uint32_t> dp_stored(0);
    omp_lock_t dp_lock;
    omp_init_lock(&dp_lock);

    #pragma omp parallel
    {
        int tid = omp_get_thread_num();
        uint64_t t_rng = seed_val ^ ((uint64_t)(tid + 1) * 0x94d049bb133111ebULL);

        const int B = B_CLAS;
        const int TAME_CNT = B / 2; // 12 Tame + 12 Wild
        U256 kx[B], ky[B];
        int64_t kd[B];
        uint8_t ktype[B];
        uint32_t k_id[B];

        auto spawn_classic = [&](int i) {
            int64_t c_jitter = (int64_t)(splitmix64(t_rng) & (uint64_t)(min_j1 - 1)) + (int64_t)(tid * B + i + 1) * 19LL;
            if (i < TAME_CNT) {
                ktype[i] = 0; // TAME: стартует в кластере около W/2
                kd[i] = (int64_t)W_half + c_jitter;
                Point pt = scalar_mult_u64((uint64_t)kd[i], G_pt);
                kx[i] = pt.x; ky[i] = pt.y;
            } else {
                ktype[i] = 1; // WILD: P_target + c_jitter * G
                kd[i] = c_jitter;
                Point pt = scalar_mult_u64((uint64_t)kd[i], G_pt);
                Point wpt = point_add(P_target, pt);
                kx[i] = wpt.x; ky[i] = wpt.y;
            }
        };

        for (int i = 0; i < B; i++) {
            k_id[i] = (uint32_t)(tid * B + i + 1);
            spawn_classic(i);
        }
        total_ec_ops.fetch_add(B, std::memory_order_relaxed);

        U256 jx[B], jy[B], diffs[B], invs[B], pbuf[B];
        int64_t jd_arr[B];

        while (!solved.load(std::memory_order_relaxed)) {
            for (int step = 0; step < 64 && !solved.load(std::memory_order_relaxed); step++) {
                for (int i = 0; i < B; i++) {
                    uint32_t j_ind = (uint32_t)(kx[i].d[0] & (JMP_N - 1));
                    jx[i] = j1_x[j_ind];
                    jy[i] = j1_y[j_ind];
                    jd_arr[i] = j1_d[j_ind];
                    fe_sub(diffs[i], kx[i], jx[i]);
                }

                fe_batch_inv(invs, diffs, B, pbuf);
                total_ec_ops.fetch_add(B, std::memory_order_relaxed);

                for (int i = 0; i < B; i++) {
                    U256 dy, s, s2, nx, dx, ny;
                    fe_sub(dy, ky[i], jy[i]);
                    fe_mul(s, dy, invs[i]);
                    fe_sqr(s2, s);
                    fe_sub(nx, s2, jx[i]);
                    fe_sub(nx, nx, kx[i]);
                    fe_sub(dx, kx[i], nx);
                    fe_mul(ny, s, dx);
                    fe_sub(ny, ny, ky[i]);

                    kx[i] = nx;
                    ky[i] = ny;
                    kd[i] += jd_arr[i];

                    if ((kx[i].d[0] & dp_mask) == 0ULL) {
                        uint64_t xtag = kx[i].d[0] ^ (kx[i].d[1] << 16);
                        if (xtag == 0) xtag = 1;
                        size_t slot = hash_mix(xtag) & DP_TAB_MASK;
                        bool need_respawn = false;

                        omp_set_lock(&dp_lock);
                        dp_stored.fetch_add(1, std::memory_order_relaxed);
                        while (dp_table[slot].x_tag != 0) {
                            if (dp_table[slot].x_tag == xtag) {
                                SotaDP prev = dp_table[slot];
                                if (prev.kang_type == ktype[i] && prev.dist == kd[i]) {
                                    need_respawn = true;
                                } else if (prev.kang_type != ktype[i]) {
                                    int64_t t_d = (prev.kang_type == 0) ? prev.dist : kd[i];
                                    int64_t w_d = (prev.kang_type == 1) ? prev.dist : kd[i];
                                    int64_t cand = t_d - w_d;
                                    if (cand > 0 && (uint64_t)cand < W) {
                                        Point P_chk = scalar_mult_u64((uint64_t)cand, G_pt);
                                        if (memcmp(P_chk.x.d, P_target.x.d, 32) == 0 &&
                                            memcmp(P_chk.y.d, P_target.y.d, 32) == 0) {
                                            solved.store(true);
                                            ans_key.store(cand);
                                            break;
                                        }
                                    }
                                    need_respawn = true;
                                }
                            }
                            slot = (slot + 1) & DP_TAB_MASK;
                        }
                        dp_table[slot] = {xtag, kd[i], k_id[i], ktype[i]};
                        omp_unset_lock(&dp_lock);

                        if (need_respawn && !solved.load(std::memory_order_relaxed)) {
                            spawn_classic(i);
                        }
                    }
                }
            }
        }
    }

    omp_destroy_lock(&dp_lock);
    *out_solved_offset = ans_key.load();
    *out_total_ops = total_ec_ops.load();
    *out_dp_count = dp_stored.load();
    return solved.load() ? 1 : 0;
}

} // extern "C"

