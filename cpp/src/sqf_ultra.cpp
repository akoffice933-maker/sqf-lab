// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 akoffice933-maker <https://github.com/akoffice933-maker>

#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <atomic>
#include <omp.h>
#include <gmp.h>

typedef unsigned __int128 uint128_t;

struct U256 {
    uint64_t d[4];
};

static const uint64_t SECP_P[4] = {
    0xFFFFFFFEFFFFFC2FULL,
    0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL
};

static const uint64_t SECP_K = 0x1000003D1ULL;

inline bool u256_gte_p(const U256 &a) {
    if (a.d[3] != SECP_P[3]) return a.d[3] > SECP_P[3];
    if (a.d[2] != SECP_P[2]) return a.d[2] > SECP_P[2];
    if (a.d[1] != SECP_P[1]) return a.d[1] > SECP_P[1];
    return a.d[0] >= SECP_P[0];
}

inline void fe_normalize(U256 &a) {
    if (u256_gte_p(a)) {
        uint128_t acc = (uint128_t)a.d[0] + SECP_K;
        a.d[0] = (uint64_t)acc;
        acc = (uint128_t)a.d[1] + (uint64_t)(acc >> 64);
        a.d[1] = (uint64_t)acc;
        acc = (uint128_t)a.d[2] + (uint64_t)(acc >> 64);
        a.d[2] = (uint64_t)acc;
        a.d[3] += (uint64_t)(acc >> 64);
    }
}

inline void fe_add(U256 &r, const U256 &a, const U256 &b) {
    uint128_t c = 0;
    for (int i = 0; i < 4; i++) {
        c += (uint128_t)a.d[i] + b.d[i];
        r.d[i] = (uint64_t)c;
        c >>= 64;
    }
    if (c) {
        uint128_t acc = (uint128_t)r.d[0] + SECP_K;
        r.d[0] = (uint64_t)acc;
        acc = (uint128_t)r.d[1] + (uint64_t)(acc >> 64);
        r.d[1] = (uint64_t)acc;
        acc = (uint128_t)r.d[2] + (uint64_t)(acc >> 64);
        r.d[2] = (uint64_t)acc;
        r.d[3] += (uint64_t)(acc >> 64);
    }
    fe_normalize(r);
}

inline void fe_sub(U256 &r, const U256 &a, const U256 &b) {
    uint128_t borrow = 0;
    U256 tmp;
    for (int i = 0; i < 4; i++) {
        uint128_t diff = (uint128_t)a.d[i] - b.d[i] - borrow;
        tmp.d[i] = (uint64_t)diff;
        borrow = (diff >> 127) & 1;
    }
    if (borrow) {
        uint128_t b2 = 0;
        uint128_t d0 = (uint128_t)tmp.d[0] - SECP_K;
        tmp.d[0] = (uint64_t)d0;
        b2 = (d0 >> 127) & 1;
        for (int i = 1; i < 4; i++) {
            uint128_t di = (uint128_t)tmp.d[i] - b2;
            tmp.d[i] = (uint64_t)di;
            b2 = (di >> 127) & 1;
        }
    }
    r = tmp;
}

inline void fe_neg(U256 &r, const U256 &a) {
    U256 p_val = {{SECP_P[0], SECP_P[1], SECP_P[2], SECP_P[3]}};
    fe_sub(r, p_val, a);
}

inline void fe_mul(U256 &r, const U256 &a, const U256 &b) {
    uint64_t t[8] = {0};
    for (int i = 0; i < 4; i++) {
        uint128_t carry = 0;
        for (int j = 0; j < 4; j++) {
            uint128_t prod = (uint128_t)a.d[i] * b.d[j] + t[i + j] + carry;
            t[i + j] = (uint64_t)prod;
            carry = prod >> 64;
        }
        t[i + 4] = (uint64_t)carry;
    }

    uint64_t u[5] = {0};
    uint128_t carry = 0;
    for (int i = 0; i < 4; i++) {
        uint128_t prod = (uint128_t)t[i + 4] * SECP_K + t[i] + carry;
        u[i] = (uint64_t)prod;
        carry = prod >> 64;
    }
    u[4] = (uint64_t)carry;

    uint128_t c2 = (uint128_t)u[4] * SECP_K + u[0];
    r.d[0] = (uint64_t)c2;
    c2 = (uint128_t)u[1] + (uint64_t)(c2 >> 64);
    r.d[1] = (uint64_t)c2;
    c2 = (uint128_t)u[2] + (uint64_t)(c2 >> 64);
    r.d[2] = (uint64_t)c2;
    c2 = (uint128_t)u[3] + (uint64_t)(c2 >> 64);
    r.d[3] = (uint64_t)c2;

    if (c2 >> 64) {
        uint128_t acc = (uint128_t)r.d[0] + SECP_K;
        r.d[0] = (uint64_t)acc;
        r.d[1] += (uint64_t)(acc >> 64);
    }
    fe_normalize(r);
}

inline void fe_sqr(U256 &r, const U256 &a) {
    uint64_t t[8] = {0};
    uint128_t c = 0;

    // Недиагональные произведения a.d[i] * a.d[j] (i < j), всего 6 умножений:
    uint128_t p01 = (uint128_t)a.d[0] * a.d[1];
    uint128_t p02 = (uint128_t)a.d[0] * a.d[2];
    uint128_t p03 = (uint128_t)a.d[0] * a.d[3];
    uint128_t p12 = (uint128_t)a.d[1] * a.d[2];
    uint128_t p13 = (uint128_t)a.d[1] * a.d[3];
    uint128_t p23 = (uint128_t)a.d[2] * a.d[3];

    t[1] = (uint64_t)p01;
    c = (p01 >> 64) + (uint64_t)p02;
    t[2] = (uint64_t)c;
    c = (c >> 64) + (p02 >> 64) + (uint64_t)p03 + (uint64_t)p12;
    t[3] = (uint64_t)c;
    c = (c >> 64) + (p03 >> 64) + (p12 >> 64) + (uint64_t)p13;
    t[4] = (uint64_t)c;
    c = (c >> 64) + (p13 >> 64) + (uint64_t)p23;
    t[5] = (uint64_t)c;
    t[6] = (uint64_t)((c >> 64) + (p23 >> 64));

    // Удваиваем недиагональную сумму (сдвиг влево на 1 бит):
    t[7] = t[6] >> 63;
    t[6] = (t[6] << 1) | (t[5] >> 63);
    t[5] = (t[5] << 1) | (t[4] >> 63);
    t[4] = (t[4] << 1) | (t[3] >> 63);
    t[3] = (t[3] << 1) | (t[2] >> 63);
    t[2] = (t[2] << 1) | (t[1] >> 63);
    t[1] = (t[1] << 1);

    // Прибавляем 4 квадрата диагонали a.d[i]^2:
    uint128_t d0 = (uint128_t)a.d[0] * a.d[0];
    uint128_t d1 = (uint128_t)a.d[1] * a.d[1];
    uint128_t d2 = (uint128_t)a.d[2] * a.d[2];
    uint128_t d3 = (uint128_t)a.d[3] * a.d[3];

    c = d0;
    t[0] = (uint64_t)c;
    c = (c >> 64) + t[1];
    t[1] = (uint64_t)c;
    c = (c >> 64) + t[2] + (uint64_t)d1;
    t[2] = (uint64_t)c;
    c = (c >> 64) + t[3] + (d1 >> 64);
    t[3] = (uint64_t)c;
    c = (c >> 64) + t[4] + (uint64_t)d2;
    t[4] = (uint64_t)c;
    c = (c >> 64) + t[5] + (d2 >> 64);
    t[5] = (uint64_t)c;
    c = (c >> 64) + t[6] + (uint64_t)d3;
    t[6] = (uint64_t)c;
    c = (c >> 64) + t[7] + (d3 >> 64);
    t[7] = (uint64_t)c;

    // Редукция по модулю P через SECP_K = 0x1000003D1:
    uint64_t u[5] = {0};
    uint128_t carry = 0;
    for (int i = 0; i < 4; i++) {
        uint128_t prod = (uint128_t)t[i + 4] * SECP_K + t[i] + carry;
        u[i] = (uint64_t)prod;
        carry = prod >> 64;
    }
    u[4] = (uint64_t)carry;

    uint128_t c2 = (uint128_t)u[4] * SECP_K + u[0];
    r.d[0] = (uint64_t)c2;
    c2 = (uint128_t)u[1] + (uint64_t)(c2 >> 64);
    r.d[1] = (uint64_t)c2;
    c2 = (uint128_t)u[2] + (uint64_t)(c2 >> 64);
    r.d[2] = (uint64_t)c2;
    c2 = (uint128_t)u[3] + (uint64_t)(c2 >> 64);
    r.d[3] = (uint64_t)c2;

    if (c2 >> 64) {
        uint128_t acc = (uint128_t)r.d[0] + SECP_K;
        r.d[0] = (uint64_t)acc;
        r.d[1] += (uint64_t)(acc >> 64);
    }
    fe_normalize(r);
}

void fe_inv(U256 &r, const U256 &a) {
    static thread_local bool initialized = false;
    static thread_local mpz_t ma, mp, mres;
    if (!initialized) {
        mpz_inits(ma, mp, mres, NULL);
        mpz_import(mp, 4, -1, sizeof(uint64_t), 0, 0, SECP_P);
        initialized = true;
    }
    mpz_import(ma, 4, -1, sizeof(uint64_t), 0, 0, a.d);
    mpz_invert(mres, ma, mp);
    memset(r.d, 0, sizeof(r.d));
    size_t count = 0;
    mpz_export(r.d, &count, -1, sizeof(uint64_t), 0, 0, mres);
}

void fe_batch_inv(U256 *out, const U256 *in, int n, U256 *prefix_buf) {
    prefix_buf[0] = in[0];
    for (int i = 1; i < n; i++) {
        fe_mul(prefix_buf[i], prefix_buf[i - 1], in[i]);
    }
    U256 inv_all;
    fe_inv(inv_all, prefix_buf[n - 1]);
    for (int i = n - 1; i > 0; i--) {
        fe_mul(out[i], inv_all, prefix_buf[i - 1]);
        fe_mul(inv_all, inv_all, in[i]);
    }
    out[0] = inv_all;
}

struct Point {
    U256 x;
    U256 y;
    bool infinity;
};

void point_double(Point &r, const Point &p) {
    if (p.infinity) { r.infinity = true; return; }
    U256 x2, num, den, inv_den, s, s2, two_x, dx;
    fe_sqr(x2, p.x);
    fe_add(num, x2, x2);
    fe_add(num, num, x2);
    fe_add(den, p.y, p.y);
    fe_inv(inv_den, den);
    fe_mul(s, num, inv_den);
    fe_sqr(s2, s);
    fe_add(two_x, p.x, p.x);
    fe_sub(r.x, s2, two_x);
    fe_sub(dx, p.x, r.x);
    fe_mul(r.y, s, dx);
    fe_sub(r.y, r.y, p.y);
    r.infinity = false;
}

void point_add_slow(Point &r, const Point &p1, const Point &p2) {
    if (p1.infinity) { r = p2; return; }
    if (p2.infinity) { r = p1; return; }
    if (memcmp(p1.x.d, p2.x.d, 32) == 0) {
        if (memcmp(p1.y.d, p2.y.d, 32) == 0) {
            point_double(r, p1);
        } else {
            r.infinity = true;
        }
        return;
    }
    U256 dy, dx, inv_dx, s, s2, nx, ny, tx;
    fe_sub(dy, p2.y, p1.y);
    fe_sub(dx, p2.x, p1.x);
    fe_inv(inv_dx, dx);
    fe_mul(s, dy, inv_dx);
    fe_sqr(s2, s);
    fe_sub(nx, s2, p1.x);
    fe_sub(nx, nx, p2.x);
    fe_sub(tx, p1.x, nx);
    fe_mul(ny, s, tx);
    fe_sub(ny, ny, p1.y);
    r.x = nx;
    r.y = ny;
    r.infinity = false;
}

void scalar_mult_point(Point &r, const Point &base, uint64_t k) {
    r.infinity = true;
    Point addend = base;
    while (k > 0) {
        if (k & 1) {
            Point next_r;
            point_add_slow(next_r, r, addend);
            r = next_r;
        }
        Point next_a;
        point_double(next_a, addend);
        addend = next_a;
        k >>= 1;
    }
}

// Двухуровневая пакетная генерация точек 1..B (всего ~34 инверсии вместо B!)
uint32_t generate_base_table(Point *pts, const Point &base, int B) {
    uint32_t inv_cnt = 0;
    const int b0 = 32;
    pts[1] = base;
    for (int i = 2; i <= b0; i++) {
        point_add_slow(pts[i], pts[i - 1], base);
        inv_cnt++;
    }
    Point step_2b0;
    point_double(step_2b0, pts[b0]);
    inv_cnt++;

    Point center = pts[b0];
    int c_idx = b0;
    U256 diffs[b0], invs[b0], pbuf[b0];

    while (c_idx - (b0 - 1) <= B) {
        for (int j = 1; j < b0; j++) {
            fe_sub(diffs[j - 1], center.x, pts[j].x);
        }
        fe_batch_inv(invs, diffs, b0 - 1, pbuf);
        inv_cnt++;

        for (int j = 1; j < b0; j++) {
            U256 x_sum;
            fe_add(x_sum, center.x, pts[j].x);

            int ip = c_idx + j;
            if (ip <= B) {
                U256 dy, s, s2, nx, tx, ny;
                fe_sub(dy, center.y, pts[j].y);
                fe_mul(s, dy, invs[j - 1]);
                fe_sqr(s2, s);
                fe_sub(nx, s2, x_sum);
                fe_sub(tx, center.x, nx);
                fe_mul(ny, s, tx);
                fe_sub(ny, ny, center.y);
                pts[ip].x = nx; pts[ip].y = ny; pts[ip].infinity = false;
            }
            int im = c_idx - j;
            if (im > b0 && im <= B) {
                U256 dy, s, s2, nx, tx, ny;
                fe_add(dy, center.y, pts[j].y);
                fe_mul(s, dy, invs[j - 1]);
                fe_sqr(s2, s);
                fe_sub(nx, s2, x_sum);
                fe_sub(tx, center.x, nx);
                fe_mul(ny, s, tx);
                fe_sub(ny, ny, center.y);
                pts[im].x = nx; pts[im].y = ny; pts[im].infinity = false;
            }
        }
        if (c_idx + b0 <= B) {
            point_add_slow(pts[c_idx + b0], center, pts[b0]);
            inv_cnt++;
        }
        c_idx += 2 * b0;
        if (c_idx - (b0 - 1) <= B) {
            Point next_c;
            point_add_slow(next_c, center, step_2b0);
            inv_cnt++;
            center = next_c;
            if (c_idx <= B) pts[c_idx] = center;
        }
    }
    return inv_cnt;
}

// Компактная 8-байтная запись хеш-таблицы (в 2 раза меньше ОЗУ!)
struct CompactEntry {
    uint32_t tag; // верхние 32 бита перемешанного ключа
    uint32_t val; // индекс r (1..M)
};

extern "C" {

int sqf_solve_ultra(
    const uint64_t *k0_x_limbs,
    const uint64_t *k0_y_limbs,
    uint32_t M,
    uint32_t max_q,
    int64_t *out_q,
    uint32_t *out_r,
    uint32_t *out_inversions
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

    Point K0;
    memcpy(K0.x.d, k0_x_limbs, 32);
    memcpy(K0.y.d, k0_y_limbs, 32);
    K0.infinity = false;

    std::atomic<uint32_t> inv_count(0);

    // 1. Выделяем компактную 8-байтную таблицу и L3-кэш битовый фильтр (Bitmap)
    uint64_t table_cap = 1;
    while (table_cap < (uint64_t)M * 2ULL) table_cap <<= 1;
    uint64_t table_mask = table_cap - 1;
    CompactEntry *table = (CompactEntry *)calloc(table_cap, sizeof(CompactEntry));

    // Битовый фильтр в 16 * table_cap бит (отсекает >94% промахов без чтения таблицы в ОЗУ!)
    uint64_t bitmap_bits = table_cap * 8ULL;
    uint64_t bitmap_mask = bitmap_bits - 1;
    uint64_t *bitmap = (uint64_t *)calloc(bitmap_bits >> 6, sizeof(uint64_t));

    auto hash_mix = [](uint64_t k) -> uint64_t {
        k ^= k >> 33;
        k *= 0xff51afd7ed558ccdULL;
        k ^= k >> 33;
        return k;
    };

    auto table_insert_parallel = [&](uint64_t raw_x, uint32_t r_val) {
        uint64_t h = hash_mix(raw_x);
        uint64_t b_idx = h & bitmap_mask;
        __atomic_fetch_or(&bitmap[b_idx >> 6], 1ULL << (b_idx & 63), __ATOMIC_RELAXED);

        uint64_t idx = h & table_mask;
        uint32_t tag = (uint32_t)(h >> 32);
        while (true) {
            uint32_t cur = __atomic_load_n(&table[idx].val, __ATOMIC_RELAXED);
            if (cur == 0) {
                uint32_t expected = 0;
                if (__atomic_compare_exchange_n(&table[idx].val, &expected, r_val, false, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
                    __atomic_store_n(&table[idx].tag, tag, __ATOMIC_RELAXED);
                    break;
                }
            }
            idx = (idx + 1) & table_mask;
        }
    };

    auto table_lookup = [&](uint64_t raw_x) -> uint32_t {
        uint64_t h = hash_mix(raw_x);
        uint64_t b_idx = h & bitmap_mask;
        if ((bitmap[b_idx >> 6] & (1ULL << (b_idx & 63))) == 0) {
            return 0; // Мгновенный отсев в кэше процессора!
        }
        uint64_t idx = h & table_mask;
        uint32_t tag = (uint32_t)(h >> 32);
        while (table[idx].val != 0) {
            if (table[idx].tag == tag) return table[idx].val;
            idx = (idx + 1) & table_mask;
        }
        return 0;
    };

    // 2. Двухуровневая генерация базового ядра B = 1024 точек (всего ~50 инверсий!)
    const int B = 1024;
    Point *small_pts = new Point[B + 1];
    inv_count += generate_base_table(small_pts, G_pt, B);

    for (uint32_t i = 1; i <= (M < (uint32_t)B ? M : (uint32_t)B); i++) {
        table_insert_parallel(small_pts[i].x.d[0], i);
    }

    // Многопоточная генерация всех блоков r * G (1..M) на всех ядрах CPU (OpenMP)
    Point step_2B;
    point_double(step_2B, small_pts[B]);
    inv_count++;

    int num_blocks = (M + (2 * B) - 1) / (2 * B);
    #pragma omp parallel
    {
        U256 local_diffs[B];
        U256 local_invs[B];
        U256 local_pbuf[B];
        uint32_t local_inv = 0;

        int tid = omp_get_thread_num();
        int nthreads = omp_get_num_threads();
        int blk_start = (num_blocks * tid) / nthreads;
        int blk_end   = (num_blocks * (tid + 1)) / nthreads;

        Point center_pt;
        if (blk_start < blk_end) {
            scalar_mult_point(center_pt, small_pts[B], (uint64_t)(2 * blk_start + 1));
            local_inv += 12;
        }

        for (int blk = blk_start; blk < blk_end; blk++) {
            uint32_t c_idx = (uint32_t)(2 * blk + 1) * B;
            if (blk > blk_start) {
                Point next_c;
                point_add_slow(next_c, center_pt, step_2B);
                center_pt = next_c;
                local_inv++;
            }

            if (c_idx <= M && c_idx > (uint32_t)B) {
                table_insert_parallel(center_pt.x.d[0], c_idx);
            }

            for (int j = 1; j < B; j++) {
                fe_sub(local_diffs[j - 1], center_pt.x, small_pts[j].x);
            }
            fe_batch_inv(local_invs, local_diffs, B - 1, local_pbuf);
            local_inv++;

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
                    table_insert_parallel(nx.d[0], idx_p);
                }

                uint32_t idx_m = c_idx - j;
                if (idx_m > (uint32_t)B && idx_m <= M) {
                    U256 dy, s, s2, nx;
                    fe_add(dy, center_pt.y, small_pts[j].y);
                    fe_mul(s, dy, local_invs[j - 1]);
                    fe_sqr(s2, s);
                    fe_sub(nx, s2, x_sum);
                    table_insert_parallel(nx.d[0], idx_m);
                }
            }

            uint32_t border_idx = c_idx + B;
            if (border_idx <= M) {
                Point bp;
                point_add_slow(bp, center_pt, small_pts[B]);
                local_inv++;
                table_insert_parallel(bp.x.d[0], border_idx);
            }
        }
        inv_count += local_inv;
    }

    // Проверка q = 0
    uint32_t r0 = table_lookup(K0.x.d[0]);
    if (r0 != 0) {
        *out_q = 0;
        *out_r = r0;
        *out_inversions = inv_count.load();
        free(table); free(bitmap); delete[] small_pts;
        return 1;
    }

    // 3. Многопоточный поиск гигантских шагов (Moving-Center Quartet Folding)
    Point G_giant;
    scalar_mult_point(G_giant, G_pt, 2ULL * (uint64_t)M);
    inv_count += 25;

    const int QB = 1024;
    Point *S_pts = new Point[QB + 1];
    inv_count += generate_base_table(S_pts, G_giant, QB);

    Point step_2QB;
    point_double(step_2QB, S_pts[QB]);
    inv_count++;

    std::atomic<bool> found(false);
    std::atomic<int64_t> best_q(0);
    std::atomic<uint32_t> best_r(0);

    int total_q_blocks = (max_q + (2 * QB) - 1) / (2 * QB);

    // Поток 0 идёт в сторону C_minus (+q), Поток 1 идёт в сторону C_plus (-q),
    // либо блоки распределяются параллельно между всеми ядрами CPU!
    #pragma omp parallel
    {
        U256 local_diffs[QB];
        U256 local_invs[QB];
        U256 local_pbuf[QB];
        uint32_t local_inv = 0;

        int tid = omp_get_thread_num();
        int nthreads = omp_get_num_threads();

        // Каждый поток шагает со своим смещением через nthreads * 2 * QB
        uint64_t stride_q = (uint64_t)nthreads * 2ULL * QB;
        Point stride_pt_plus, stride_pt_minus;
        scalar_mult_point(stride_pt_plus, G_giant, stride_q);
        stride_pt_minus = stride_pt_plus;
        fe_neg(stride_pt_minus.y, stride_pt_plus.y);

        uint64_t start_q_center = (uint64_t)(2 * tid + 1) * QB;
        Point shift_start_plus, shift_start_minus;
        scalar_mult_point(shift_start_plus, G_giant, start_q_center);
        shift_start_minus = shift_start_plus;
        fe_neg(shift_start_minus.y, shift_start_plus.y);

        Point C_minus, C_plus;
        point_add_slow(C_minus, K0, shift_start_minus);
        point_add_slow(C_plus,  K0, shift_start_plus);
        local_inv += 20;

        uint64_t q_center = start_q_center;

        auto scan_center = [&](const Point &C_pt, int64_t sign_dir) -> bool {
            uint32_t rc = table_lookup(C_pt.x.d[0]);
            if (rc != 0) {
                best_q.store(sign_dir * (int64_t)q_center);
                best_r.store(rc);
                found.store(true);
                return true;
            }

            for (int j = 1; j <= QB; j++) {
                fe_sub(local_diffs[j - 1], C_pt.x, S_pts[j].x);
            }
            fe_batch_inv(local_invs, local_diffs, QB, local_pbuf);
            local_inv++;

            for (int j = 1; j <= QB; j++) {
                U256 x_sum, dy, s, s2, nx;
                fe_add(x_sum, C_pt.x, S_pts[j].x);

                // Ветвь C_pt - j * G_giant
                fe_add(dy, C_pt.y, S_pts[j].y);
                fe_mul(s, dy, local_invs[j - 1]);
                fe_sqr(s2, s);
                fe_sub(nx, s2, x_sum);
                uint32_t r_hit = table_lookup(nx.d[0]);
                if (r_hit != 0) {
                    int64_t hq = (sign_dir > 0) ? (int64_t)(q_center + j) : -(int64_t)(q_center - j);
                    best_q.store(hq);
                    best_r.store(r_hit);
                    found.store(true);
                    return true;
                }

                // Ветвь C_pt + j * G_giant
                fe_sub(dy, C_pt.y, S_pts[j].y);
                fe_mul(s, dy, local_invs[j - 1]);
                fe_sqr(s2, s);
                fe_sub(nx, s2, x_sum);
                r_hit = table_lookup(nx.d[0]);
                if (r_hit != 0) {
                    int64_t hq = (sign_dir > 0) ? (int64_t)(q_center - j) : -(int64_t)(q_center + j);
                    best_q.store(hq);
                    best_r.store(r_hit);
                    found.store(true);
                    return true;
                }
            }
            return false;
        };

        while (!found.load(std::memory_order_relaxed) && (q_center - QB <= max_q)) {
            if (scan_center(C_minus, +1) || scan_center(C_plus, -1)) {
                break;
            }
            q_center += stride_q;
            if (!found.load(std::memory_order_relaxed) && (q_center - QB <= max_q)) {
                Point nm, np;
                point_add_slow(nm, C_minus, stride_pt_minus);
                point_add_slow(np, C_plus,  stride_pt_plus);
                C_minus = nm;
                C_plus  = np;
                local_inv += 2;
            }
        }
        inv_count += local_inv;
    }

    *out_inversions = inv_count.load();
    free(table); free(bitmap); delete[] small_pts; delete[] S_pts;

    if (found.load()) {
        *out_q = best_q.load();
        *out_r = best_r.load();
        return 1;
    }
    return 0;
}

} // extern "C"
