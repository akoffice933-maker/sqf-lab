// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 akoffice933-maker <https://github.com/akoffice933-maker>

#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <cstdio>
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

void fe_inv(U256 &r, const U256 &a) {
    mpz_t ma, mp, mres;
    mpz_inits(ma, mp, mres, NULL);
    mpz_import(ma, 4, -1, sizeof(uint64_t), 0, 0, a.d);
    mpz_import(mp, 4, -1, sizeof(uint64_t), 0, 0, SECP_P);
    mpz_invert(mres, ma, mp);
    memset(r.d, 0, sizeof(r.d));
    size_t count = 0;
    mpz_export(r.d, &count, -1, sizeof(uint64_t), 0, 0, mres);
    mpz_clears(ma, mp, mres, NULL);
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
    fe_mul(x2, p.x, p.x);
    fe_add(num, x2, x2);
    fe_add(num, num, x2);
    fe_add(den, p.y, p.y);
    fe_inv(inv_den, den);
    fe_mul(s, num, inv_den);
    fe_mul(s2, s, s);
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
    fe_mul(s2, s, s);
    fe_sub(nx, s2, p1.x);
    fe_sub(nx, nx, p2.x);
    fe_sub(tx, p1.x, nx);
    fe_mul(ny, s, tx);
    fe_sub(ny, ny, p1.y);
    r.x = nx;
    r.y = ny;
    r.infinity = false;
}

struct HashEntry {
    uint64_t key;
    uint32_t val;
};

extern "C" {

int sqf_solve_native(
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

    uint32_t inv_count = 0;

    // 1. Открытая хеш-таблица для X-координат r * G (r = 1..M)
    uint64_t table_cap = 1;
    while (table_cap < (uint64_t)M * 2ULL) table_cap <<= 1;
    uint64_t table_mask = table_cap - 1;
    HashEntry *table = (HashEntry *)calloc(table_cap, sizeof(HashEntry));

    auto table_insert = [&](uint64_t key, uint32_t r_val) {
        if (key == 0) key = 1;
        uint64_t idx = (key * 11400714819323198485ULL) & table_mask;
        while (table[idx].val != 0) {
            idx = (idx + 1) & table_mask;
        }
        table[idx].key = key;
        table[idx].val = r_val;
    };

    auto table_lookup = [&](uint64_t key) -> uint32_t {
        if (key == 0) key = 1;
        uint64_t idx = (key * 11400714819323198485ULL) & table_mask;
        while (table[idx].val != 0) {
            if (table[idx].key == key) return table[idx].val;
            idx = (idx + 1) & table_mask;
        }
        return 0;
    };

    // 2. Генерация r * G (r = 1..M) пачками по 2048 точек за 1 инверсию
    const int B = 1024;
    Point *small_pts = new Point[B + 1];
    small_pts[1] = G_pt;
    for (int i = 2; i <= B; i++) {
        point_add_slow(small_pts[i], small_pts[i - 1], G_pt);
        inv_count++;
    }
    for (uint32_t i = 1; i <= (M < (uint32_t)B ? M : (uint32_t)B); i++) {
        table_insert(small_pts[i].x.d[0], i);
    }

    Point step_2B;
    point_double(step_2B, small_pts[B]);
    inv_count++;

    Point center_pt = small_pts[B];
    uint32_t center_idx = B;

    U256 *diffs = new U256[B];
    U256 *invs  = new U256[B];
    U256 *pbuf  = new U256[B];

    Point M_pt = (M <= (uint32_t)B) ? small_pts[M] : small_pts[B];

    while (center_idx - (B - 1) <= M) {
        for (int j = 1; j < B; j++) {
            fe_sub(diffs[j - 1], center_pt.x, small_pts[j].x);
        }
        fe_batch_inv(invs, diffs, B - 1, pbuf);
        inv_count++;

        for (int j = 1; j < B; j++) {
            U256 x_sum;
            fe_add(x_sum, center_pt.x, small_pts[j].x);

            // C + j*G
            uint32_t idx_p = center_idx + j;
            if (idx_p <= M) {
                U256 dy, s, s2, nx;
                fe_sub(dy, center_pt.y, small_pts[j].y);
                fe_mul(s, dy, invs[j - 1]);
                fe_mul(s2, s, s);
                fe_sub(nx, s2, x_sum);
                table_insert(nx.d[0], idx_p);
                if (idx_p == M) {
                    U256 tx, ny;
                    fe_sub(tx, center_pt.x, nx);
                    fe_mul(ny, s, tx);
                    fe_sub(ny, ny, center_pt.y);
                    M_pt.x = nx; M_pt.y = ny; M_pt.infinity = false;
                }
            }

            // C - j*G
            uint32_t idx_m = center_idx - j;
            if (idx_m > (uint32_t)B && idx_m <= M) {
                U256 dy, s, s2, nx;
                fe_add(dy, center_pt.y, small_pts[j].y);
                fe_mul(s, dy, invs[j - 1]);
                fe_mul(s2, s, s);
                fe_sub(nx, s2, x_sum);
                table_insert(nx.d[0], idx_m);
                if (idx_m == M) {
                    U256 tx, ny;
                    fe_sub(tx, center_pt.x, nx);
                    fe_mul(ny, s, tx);
                    fe_sub(ny, ny, center_pt.y);
                    M_pt.x = nx; M_pt.y = ny; M_pt.infinity = false;
                }
            }
        }

        uint32_t border_idx = center_idx + B;
        if (border_idx <= M) {
            Point bp;
            point_add_slow(bp, center_pt, small_pts[B]);
            inv_count++;
            table_insert(bp.x.d[0], border_idx);
            if (border_idx == M) M_pt = bp;
        }

        center_idx += 2 * B;
        if (center_idx - (B - 1) <= M) {
            Point next_c;
            point_add_slow(next_c, center_pt, step_2B);
            inv_count++;
            center_pt = next_c;
            if (center_idx <= M) {
                table_insert(center_pt.x.d[0], center_idx);
                if (center_idx == M) M_pt = center_pt;
            }
        }
    }

    // Проверка q = 0
    uint32_t r0 = table_lookup(K0.x.d[0]);
    if (r0 != 0) {
        *out_q = 0;
        *out_r = r0;
        *out_inversions = inv_count;
        free(table); delete[] small_pts; delete[] diffs; delete[] invs; delete[] pbuf;
        return 1;
    }

    // 3. Гигантский шаг с ДВУМЯ ДВИЖУЩИМИСЯ ЦЕНТРАМИ (Moving-Center SQF):
    // Вместо генерации миллионов точек q * G_giant заранее,
    // предвычисляем всего QB = 512 точек S_j = j * G_giant (j = 1..512),
    // и двигаем два центра C_plus и C_minus от K0 с шагом 2*QB * G_giant!
    Point G_giant;
    point_double(G_giant, M_pt); // 2 * M * G
    inv_count++;

    const int QB = 512;
    Point *S_pts = new Point[QB + 1];
    S_pts[1] = G_giant;
    for (int j = 2; j <= QB; j++) {
        point_add_slow(S_pts[j], S_pts[j - 1], G_giant);
        inv_count++;
    }

    Point step_2QB;
    point_double(step_2QB, S_pts[QB]); // 2 * QB * G_giant
    inv_count++;

    Point neg_S_QB = S_pts[QB];
    fe_neg(neg_S_QB.y, S_pts[QB].y);
    Point neg_step_2QB = step_2QB;
    fe_neg(neg_step_2QB.y, step_2QB.y);

    // Центры первого блока стоят в K0 - QB*G_giant (чтобы покрыть q = 1..2*QB)
    // и K0 + QB*G_giant (чтобы покрыть -q = 1..2*QB)
    Point C_minus, C_plus;
    point_add_slow(C_minus, K0, neg_S_QB); // K0 - QB * G_giant
    point_add_slow(C_plus,  K0, S_pts[QB]); // K0 + QB * G_giant
    inv_count += 2;

    uint32_t q_center = QB;

    auto check_center = [&](const Point &C_pt, int64_t sign_dir, int64_t &hit_q, uint32_t &hit_r) -> bool {
        // Проверяем сам центр (соответствует q = q_center)
        uint32_t rc = table_lookup(C_pt.x.d[0]);
        if (rc != 0) {
            hit_q = sign_dir * (int64_t)q_center;
            hit_r = rc;
            return true;
        }
        // Групповое обращение (C_pt.x - S_pts[j].x) для j = 1..QB
        for (int j = 1; j <= QB; j++) {
            fe_sub(diffs[j - 1], C_pt.x, S_pts[j].x);
        }
        fe_batch_inv(invs, diffs, QB, pbuf);
        inv_count++;

        for (int j = 1; j <= QB; j++) {
            U256 x_sum, dy, s, s2, nx;
            fe_add(x_sum, C_pt.x, S_pts[j].x);

            // C_pt - j * G_giant -> наклон (C_pt.y + S_pts[j].y) / (C_pt.x - S_pts[j].x)
            fe_add(dy, C_pt.y, S_pts[j].y);
            fe_mul(s, dy, invs[j - 1]);
            fe_mul(s2, s, s);
            fe_sub(nx, s2, x_sum);
            uint32_t r_hit = table_lookup(nx.d[0]);
            if (r_hit != 0) {
                // C_minus - j*G_giant = K0 - (q_center + j)*G_giant -> q = +(q_center + j)
                // C_plus  - j*G_giant = K0 + (q_center - j)*G_giant -> q = -(q_center - j)
                hit_q = (sign_dir > 0) ? (int64_t)(q_center + j) : -(int64_t)(q_center - j);
                hit_r = r_hit;
                return true;
            }

            // C_pt + j * G_giant -> наклон (C_pt.y - S_pts[j].y) / (C_pt.x - S_pts[j].x)
            fe_sub(dy, C_pt.y, S_pts[j].y);
            fe_mul(s, dy, invs[j - 1]);
            fe_mul(s2, s, s);
            fe_sub(nx, s2, x_sum);
            r_hit = table_lookup(nx.d[0]);
            if (r_hit != 0) {
                // C_minus + j*G_giant = K0 - (q_center - j)*G_giant -> q = +(q_center - j)
                // C_plus  + j*G_giant = K0 + (q_center + j)*G_giant -> q = -(q_center + j)
                hit_q = (sign_dir > 0) ? (int64_t)(q_center - j) : -(int64_t)(q_center + j);
                hit_r = r_hit;
                return true;
            }
        }
        return false;
    };

    while (q_center - QB <= max_q) {
        int64_t hit_q = 0;
        uint32_t hit_r = 0;

        if (check_center(C_minus, +1, hit_q, hit_r) || check_center(C_plus, -1, hit_q, hit_r)) {
            *out_q = hit_q;
            *out_r = hit_r;
            *out_inversions = inv_count;
            free(table); delete[] small_pts; delete[] diffs; delete[] invs; delete[] pbuf; delete[] S_pts;
            return 1;
        }

        q_center += 2 * QB;
        if (q_center - QB <= max_q) {
            Point next_m, next_p;
            point_add_slow(next_m, C_minus, neg_step_2QB);
            point_add_slow(next_p, C_plus,  step_2QB);
            C_minus = next_m;
            C_plus  = next_p;
            inv_count += 2;
        }
    }

    *out_inversions = inv_count;
    free(table); delete[] small_pts; delete[] diffs; delete[] invs; delete[] pbuf; delete[] S_pts;
    return 0;
}

} // extern "C"
