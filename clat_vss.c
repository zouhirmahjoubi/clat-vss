/*
 * clat_vss.c - CLAT-VSS v2
 *              Cauchy-Lagrange Algebraic Threshold Verifiable Secret Sharing
 *
 * Single-file C11 implementation of docs/SPEC_V2.md, sections 1-7:
 *   1. prime field F_q, q = 2^31 - 1
 *   2. CLAT-P: public 24-round permutation of F_q^16 (x^5 S-box, Cauchy MDS)
 *   3. sponge hash with domain separation in the capacity
 *   4. CLAT-SIV: deterministic authenticated key wrap over a keyed sponge
 *   5. hash-committed verifiable secret sharing (no discrete-log assumption)
 *   6. first-order 2-share arithmetic masking, masks from the OS CSPRNG
 *   7. test suite and threshold key-vault demo
 *
 * Build:  gcc -std=c11 -O3 -Wall -Wextra -Werror -pedantic clat_vss.c -lm -o clat_vss
 * Run:    ./clat_vss          default suite
 *         ./clat_vss --full   longer timing and leakage runs
 *
 * Conventions
 *   - Field elements are uint32_t in canonical form [0, q).
 *   - Secret-dependent code uses no branches, no secret-indexed memory, and no
 *     % or / operators. % and / appear only on public values (test statistics,
 *     subgroup orders, loop bounds).
 *   - Every number printed by the test suite is computed at run time, except
 *     the recorded known-answer values, which are checked, not printed as
 *     measurements.
 *
 * Status: research code for a hackathon submission. It has not had external
 * review. Do not use it to protect real keys.
 */

/* ===================================================================== */
/*  0. Platform                                                          */
/* ===================================================================== */

#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#  define _POSIX_C_SOURCE 200809L          /* clock_gettime */
#endif
#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#  define _DARWIN_C_SOURCE                  /* getentropy */
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#if defined(_WIN32)
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
/* RtlGenRandom is exported by advapi32.dll as SystemFunction036. MinGW links
   advapi32 by default, so no extra library is needed. */
BOOLEAN WINAPI SystemFunction036(PVOID buffer, ULONG length);
#elif defined(__linux__)
#  include <errno.h>
#  include <time.h>
#  include <sys/random.h>                   /* getrandom, glibc >= 2.25 */
#else
#  include <time.h>
#  include <unistd.h>                       /* getentropy (macOS, BSD) */
#  if defined(__APPLE__)
#    include <sys/random.h>
#  endif
#endif

/* _mm_lfence needs SSE2: plain i386/i686 builds fall back to the OS timer. */
#if defined(__x86_64__) || (defined(__i386__) && defined(__SSE2__))
#  include <x86intrin.h>                    /* __rdtsc, _mm_lfence */
#  define CLAT_HAVE_RDTSC 1
#endif

#if defined(__GNUC__) || defined(__clang__)
#  define CLAT_NOINLINE __attribute__((noinline))
#else
#  define CLAT_NOINLINE
#endif

static void fatal(const char *msg)
{
    fprintf(stderr, "fatal: %s\n", msg);
    exit(2);
}

/* ===================================================================== */
/*  1. Constant-time helpers and zeroization                             */
/* ===================================================================== */

/* Value barriers: stop the compiler from reasoning about a mask's value
   and turning a select back into a branch. */
static inline uint32_t ct_barrier32(uint32_t x)
{
#if defined(__GNUC__) || defined(__clang__)
    __asm__("" : "+r"(x));
#endif
    return x;
}

static inline uint64_t ct_barrier64(uint64_t x)
{
#if defined(__GNUC__) || defined(__clang__)
    __asm__("" : "+r"(x));
#endif
    return x;
}

/* 1 if x == 0, else 0. */
static inline uint32_t ct_is_zero(uint32_t x)
{
    return (uint32_t)(((uint64_t)x - 1u) >> 63);
}

/* bit in {0,1} -> 0x00000000 or 0xFFFFFFFF. */
static inline uint32_t ct_mask(uint32_t bit)
{
    return ct_barrier32(0u - bit);
}

static inline void ct_cswap(uint32_t bit, uint32_t *a, uint32_t *b)
{
    uint32_t t = ct_mask(bit) & (*a ^ *b);
    *a ^= t;
    *b ^= t;
}

/* 1 if a[0..n) == b[0..n), else 0; time independent of the contents. */
static uint32_t ct_words_equal(const uint32_t *a, const uint32_t *b, size_t n)
{
    uint32_t d = 0;
    for (size_t i = 0; i < n; i++)
        d |= a[i] ^ b[i];
    return ct_is_zero(d);
}

/* Zero memory in a way the optimiser cannot drop: volatile stores followed
   by a compiler barrier that claims to read the buffer. */
static void secure_zeroize(void *p, size_t n)
{
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (n--)
        *v++ = 0;
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
}

/* Stack burn. The public entry points that touch keys or shares run their
   body in a separate non-inlined function and then call stack_burn() from
   the same frame depth, so the dead stack those calls leave behind (local
   arrays such as mds_apply's y[], register spills, sponge states) is
   overwritten with zeros before control returns to the caller. The buffer
   size bounds the deepest call chain below an entry point (well under
   2 KiB for every entry point in this file). */
#define STACK_BURN_BYTES 8192

static CLAT_NOINLINE void stack_burn(void)
{
    unsigned char buf[STACK_BURN_BYTES];
    memset(buf, 0, sizeof buf);
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : : "r"(buf) : "memory");   /* keep the stores */
#else
    secure_zeroize(buf, sizeof buf);
#endif
}

static inline unsigned popcount32(uint32_t v)
{
    v = v - ((v >> 1) & 0x55555555u);
    v = (v & 0x33333333u) + ((v >> 2) & 0x33333333u);
    return (unsigned)((((v + (v >> 4)) & 0x0F0F0F0Fu) * 0x01010101u) >> 24);
}

/* ===================================================================== */
/*  2. Timers (measurement only, never used by the cryptography)          */
/* ===================================================================== */

static inline uint64_t cycle_count(void)
{
#if defined(CLAT_HAVE_RDTSC)
    uint64_t t;
    _mm_lfence();
    t = __rdtsc();
    _mm_lfence();
    return t;
#elif defined(_WIN32)
    LARGE_INTEGER c;
    QueryPerformanceCounter(&c);
    return (uint64_t)c.QuadPart;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000u + (uint64_t)ts.tv_nsec;
#endif
}

static double wall_seconds(void)
{
#if defined(_WIN32)
    LARGE_INTEGER c, f;
    QueryPerformanceCounter(&c);
    QueryPerformanceFrequency(&f);
    return (double)c.QuadPart / (double)f.QuadPart;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + 1e-9 * (double)ts.tv_nsec;
#endif
}

/* ===================================================================== */
/*  3. OS randomness                                                     */
/* ===================================================================== */

#if defined(_WIN32)
#  define CLAT_RNG_NAME "RtlGenRandom (advapi32 SystemFunction036)"
#elif defined(__linux__)
#  define CLAT_RNG_NAME "getrandom(2)"
#else
#  define CLAT_RNG_NAME "getentropy(3)"
#endif

static void os_random_bytes(void *buf, size_t len)
{
    unsigned char *p = (unsigned char *)buf;
#if defined(_WIN32)
    while (len > 0) {
        ULONG n = (len > 65536u) ? 65536u : (ULONG)len;
        if (!SystemFunction036(p, n))
            fatal("RtlGenRandom failed");
        p += n;
        len -= n;
    }
#elif defined(__linux__)
    while (len > 0) {
        ssize_t n = getrandom(p, len, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            fatal("getrandom failed");
        }
        p += (size_t)n;
        len -= (size_t)n;
    }
#else
    while (len > 0) {
        size_t n = (len > 256u) ? 256u : len;  /* getentropy limit */
        if (getentropy(p, n) != 0)
            fatal("getentropy failed");
        p += n;
        len -= n;
    }
#endif
}

/* Buffered word source. Consumed words are cleared from the buffer. Every
   entry point that draws secret randomness (dealing, share masking, masked
   verification and unwrap) calls rng_wipe() on entry and on exit: it starts
   from fresh OS randomness, so a forked child never replays the parent's
   buffered words, and no unused mask outlives the operation.
   Threads: the buffer is process-wide and unlocked, so callers must not run
   these entry points from two threads at once (this program is single
   threaded). C11 _Thread_local would remove that rule, but MinGW implements
   it with emulated TLS, a function call per access, which made the masked
   unwrap about 7x slower in a measured run. */
#define RNG_BUF_WORDS 4096
static uint32_t rng_buf[RNG_BUF_WORDS];
static size_t   rng_pos = RNG_BUF_WORDS;

static uint32_t rng_u32(void)
{
    uint32_t w;
    if (rng_pos == RNG_BUF_WORDS) {
        os_random_bytes(rng_buf, sizeof rng_buf);
        rng_pos = 0;
    }
    w = rng_buf[rng_pos];
    rng_buf[rng_pos++] = 0;
    return w;
}

static void rng_wipe(void)
{
    secure_zeroize(rng_buf, sizeof rng_buf);
    rng_pos = RNG_BUF_WORDS;
}

/* ===================================================================== */
/*  4. Field F_q, q = 2^31 - 1   (SPEC section 1)                         */
/* ===================================================================== */

#define FQ_Q    0x7FFFFFFFu     /* q = 2^31 - 1 */
#define FQ_DINV 1717986917u     /* 5^-1 mod (q-1); x -> x^FQ_DINV inverts x^5 */

/* x < 2q  ->  x mod q, by a masked conditional subtraction. */
static inline uint32_t fq_csub(uint64_t x)
{
    uint64_t y = x - FQ_Q;                              /* wraps iff x < q */
    uint64_t keep = ct_barrier64(0u - (y >> 63));       /* ones iff x < q  */
    return (uint32_t)((x & keep) | (y & ~keep));
}

/* x < 2^62  ->  x mod q. Two Mersenne folds (2^31 = 1 mod q), then one
   conditional subtraction. */
static inline uint32_t fq_reduce(uint64_t x)
{
    x = (x & FQ_Q) + (x >> 31);     /* < 2^32         */
    x = (x & FQ_Q) + (x >> 31);     /* <= 2^31 = q+1  */
    return fq_csub(x);
}

static inline uint32_t fq_add(uint32_t a, uint32_t b) { return fq_csub((uint64_t)a + b); }
static inline uint32_t fq_sub(uint32_t a, uint32_t b) { return fq_csub((uint64_t)a + FQ_Q - b); }
static inline uint32_t fq_neg(uint32_t a)             { return fq_csub((uint64_t)FQ_Q - a); }
static inline uint32_t fq_mul(uint32_t a, uint32_t b) { return fq_reduce((uint64_t)a * b); }

/* base^e using the low nbits of e. Montgomery ladder: the same squarings
   and multiplications run for every exponent of that bit length. */
static uint32_t fq_pow(uint32_t base, uint32_t e, unsigned nbits)
{
    uint32_t r0 = 1, r1 = base;
    for (unsigned i = nbits; i-- > 0;) {
        uint32_t bit = (e >> i) & 1u;
        ct_cswap(bit, &r0, &r1);
        r1 = fq_mul(r0, r1);
        r0 = fq_mul(r0, r0);
        ct_cswap(bit, &r0, &r1);
    }
    return r0;
}

/* a^(q-2) = a^-1 for a != 0; returns 0 for a = 0. */
static uint32_t fq_inv(uint32_t a)
{
    return fq_pow(a, FQ_Q - 2u, 31);
}

/* 1 if every word is < q. */
static uint32_t fq_all_canonical(const uint32_t *w, size_t n)
{
    uint64_t bad = 0;
    for (size_t i = 0; i < n; i++)
        bad |= ((uint64_t)FQ_Q - 1u - w[i]) >> 63;
    return (uint32_t)(1u ^ bad);
}

/* Uniform field element by rejection on 31-bit words (rejects only 2^31-1). */
static uint32_t rng_fq(void)
{
    for (;;) {
        uint32_t w = rng_u32() & FQ_Q;
        if (w != FQ_Q)
            return w;
    }
}

static uint32_t rng_fq_nonzero(void)
{
    for (;;) {
        uint32_t w = rng_fq();
        if (w != 0)
            return w;
    }
}

/* Uniform integer in [0, n), n >= 1, for public test choices. */
static uint32_t rng_below(uint32_t n)
{
    uint32_t m = n - 1u;
    m |= m >> 1; m |= m >> 2; m |= m >> 4; m |= m >> 8; m |= m >> 16;
    for (;;) {
        uint32_t v = rng_u32() & m;
        if (v < n)
            return v;
    }
}

/* ===================================================================== */
/*  5. Leakage hook (for the simulated-leakage TVLA, test 6)             */
/* ===================================================================== */
/* Every intermediate of the masked and unmasked permutations, and of the
   masked vault pipeline (masked hash absorb, g-check, Lagrange, keystream
   extraction, tag comparison), passes through LEAK(). The hook is always
   compiled in; while g_leak.on is set (by test 6) it records two leakage
   models per sample: the Hamming weight of the value (HW, value model) and
   the Hamming distance to the previous LEAK value (HD, transition model,
   as when consecutive values pass through the same register or bus). */

static struct {
    int      on;
    size_t   n;     /* samples seen in the current trace */
    size_t   cap;
    uint32_t prev;  /* previous value, for the HD model */
    uint8_t *hw;
    uint8_t *hd;
} g_leak;

static void leak_record(uint32_t v)
{
    if (g_leak.n < g_leak.cap) {
        g_leak.hw[g_leak.n] = (uint8_t)popcount32(v);
        g_leak.hd[g_leak.n] = (uint8_t)popcount32(v ^ g_leak.prev);
    }
    g_leak.prev = v;
    g_leak.n++;
}

#define LEAK(v) do { if (g_leak.on) leak_record((uint32_t)(v)); } while (0)

/* ===================================================================== */
/*  6. CLAT-P permutation on F_q^16   (SPEC section 2)                    */
/* ===================================================================== */

#define CLAT_T      16
#define CLAT_ROUNDS 24

static uint32_t RC[CLAT_ROUNDS][CLAT_T];   /* c[r][i] = 7^(16r+i+1)          */
static uint32_t MDS[CLAT_T][CLAT_T];       /* M[i][j] = (i+j+16)^-1, Cauchy  */

static void clat_init(void)
{
    uint32_t c = 1;
    for (unsigned r = 0; r < CLAT_ROUNDS; r++)
        for (unsigned i = 0; i < CLAT_T; i++) {
            c = fq_mul(c, 7);
            RC[r][i] = c;
        }
    for (unsigned i = 0; i < CLAT_T; i++)
        for (unsigned j = 0; j < CLAT_T; j++)
            MDS[i][j] = fq_inv(i + j + 16u);
}

/* x <- M x. Each product (< 2^62) is folded once to < 2^32; 16 folded
   terms sum to < 2^36, then one full reduction. */
static void mds_apply(uint32_t x[CLAT_T])
{
    uint32_t y[CLAT_T];
    for (unsigned i = 0; i < CLAT_T; i++) {
        uint64_t acc = 0;
        for (unsigned j = 0; j < CLAT_T; j++) {
            uint64_t p = (uint64_t)MDS[i][j] * x[j];
            uint64_t f = (p & FQ_Q) + (p >> 31);
            LEAK(f);
            acc += f;
        }
        y[i] = fq_reduce(acc);
        LEAK(y[i]);
    }
    memcpy(x, y, sizeof y);
}

/* First nrounds rounds of CLAT-P (nrounds <= 24). Reduced-round versions
   exist only for the degree tests; the cipher always uses all 24. */
static void clat_perm_rounds(uint32_t st[CLAT_T], unsigned nrounds)
{
    for (unsigned i = 0; i < CLAT_T; i++)
        LEAK(st[i]);
    for (unsigned r = 0; r < nrounds; r++) {
        for (unsigned i = 0; i < CLAT_T; i++) {
            uint32_t x = fq_add(st[i], RC[r][i]);
            uint32_t x2, x4;
            LEAK(x);
            x2 = fq_mul(x, x);   LEAK(x2);
            x4 = fq_mul(x2, x2); LEAK(x4);
            st[i] = fq_mul(x4, x);
            LEAK(st[i]);
        }
        mds_apply(st);
    }
}

static void clat_perm(uint32_t st[CLAT_T])
{
    clat_perm_rounds(st, CLAT_ROUNDS);
}

/* ===================================================================== */
/*  7. Masking: 2-share arithmetic, first-order   (SPEC section 6)       */
/* ===================================================================== */
/* A secret x is held as (x0, x1) with x = x0 + x1 mod q. Linear operations
   act share-wise; public constants are added to share 0 only. */

static void mask_split(const uint32_t *x, uint32_t *x0, uint32_t *x1, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        uint32_t r = rng_fq();
        x0[i] = r;
        x1[i] = fq_sub(x[i], r);
    }
}

static void mask_join(const uint32_t *x0, const uint32_t *x1, uint32_t *x, size_t n)
{
    for (size_t i = 0; i < n; i++)
        x[i] = fq_add(x0[i], x1[i]);
}

/* Precharge: a fresh random word written between two values that must not
   meet in one register or bus transition (the two shares of one secret).
   Under the HD model, HW(prev ^ p) and HW(p ^ next) are each independent
   of the secret. This fixes the order of the simulated leakage trace; how
   a compiler allocates registers on real hardware is outside the model. */
static inline void leak_precharge(void)
{
    uint32_t p = rng_u32();
    LEAK(p);
}

/* (a0 + r, a1 - r) with fresh r. The two output shares are separated by a
   precharge so their transition does not reveal a0 + a1. */
static inline void sec_refresh(const uint32_t a[2], uint32_t out[2])
{
    uint32_t r = rng_fq();
    LEAK(r);
    out[0] = fq_add(a[0], r); LEAK(out[0]);
    leak_precharge();
    out[1] = fq_sub(a[1], r); LEAK(out[1]);
}

/* ISW multiplication for two shares, fresh r:
     z0 = a0 b0 + r
     z1 = a1 b1 + ((a0 b1 - r) + a1 b0)     (this evaluation order) */
static inline void sec_mult(const uint32_t a[2], const uint32_t b[2], uint32_t z[2])
{
    uint32_t r = rng_fq();
    uint32_t p00, p01, p10, p11, t;
    LEAK(r);
    p00 = fq_mul(a[0], b[0]); LEAK(p00);
    z[0] = fq_add(p00, r);    LEAK(z[0]);
    p01 = fq_mul(a[0], b[1]); LEAK(p01);
    t = fq_sub(p01, r);       LEAK(t);
    p10 = fq_mul(a[1], b[0]); LEAK(p10);
    t = fq_add(t, p10);       LEAK(t);
    p11 = fq_mul(a[1], b[1]); LEAK(p11);
    z[1] = fq_add(p11, t);    LEAK(z[1]);
}

/* Masked x^5. Each multiplication gets a refreshed copy of one operand so
   the two inputs of sec_mult never share a mask. */
static void sec_sbox(const uint32_t x[2], uint32_t out[2])
{
    uint32_t y[2], x2[2], x4[2];
    sec_refresh(x, y);
    sec_mult(x, y, x2);
    sec_refresh(x2, y);
    sec_mult(x2, y, x4);
    sec_refresh(x, y);
    sec_mult(x4, y, out);
}

/* Share vectors are processed one after the other (all of s0, then all of
   s1), never s0[i] next to s1[i]. */
static void clat_perm_masked(uint32_t s0[CLAT_T], uint32_t s1[CLAT_T])
{
    for (unsigned i = 0; i < CLAT_T; i++)
        LEAK(s0[i]);
    for (unsigned i = 0; i < CLAT_T; i++)
        LEAK(s1[i]);
    for (unsigned r = 0; r < CLAT_ROUNDS; r++) {
        for (unsigned i = 0; i < CLAT_T; i++) {
            uint32_t x[2], y[2];
            x[0] = fq_add(s0[i], RC[r][i]);
            x[1] = s1[i];
            LEAK(x[0]);
            sec_sbox(x, y);
            s0[i] = y[0];
            s1[i] = y[1];
        }
        mds_apply(s0);
        mds_apply(s1);
    }
}

/* ===================================================================== */
/*  8. Sponge, hash, key limbs   (SPEC section 3)                         */
/* ===================================================================== */

#define SPONGE_RATE   7          /* words 0..6                               */
#define DIGEST_WORDS  9          /* 279-bit digests                          */
#define DOM_HASH      0u         /* word 15 = key_limb8 + DOM * 2^29         */
#define DOM_MAC       1u
#define DOM_ENC       2u
#define HT_COMMIT     1u         /* hash tags (first IV word, unkeyed mode)  */
#define HT_CHALLENGE  2u
#define HT_KAT        3u

#define KEY_BYTES     32
#define KEY_LIMBS     9          /* 8 x 29 bits + 24 bits = 256 bits         */
#define LIMB_MASK     0x1FFFFFFFu

/* Add a word stream into the rate in 7-word blocks, permuting after each
   block. The last block is zero-padded; lengths are fixed by the IV. */
static void sponge_absorb(uint32_t st[CLAT_T], const uint32_t *in, size_t n)
{
    for (size_t off = 0; off < n; off += SPONGE_RATE) {
        for (size_t j = 0; j < SPONGE_RATE && off + j < n; j++)
            st[j] = fq_add(st[j], in[off + j]);
        clat_perm(st);
    }
}

/* Read the rate, permuting between 7-word blocks. */
static void sponge_squeeze(uint32_t st[CLAT_T], uint32_t *out, size_t outlen)
{
    size_t k = 0;
    for (;;) {
        for (size_t j = 0; j < SPONGE_RATE && k < outlen; j++)
            out[k++] = st[j];
        if (k == outlen)
            break;
        clat_perm(st);
    }
}

/* H(tag, x[0..n)): IV rate = (tag, n, 0, ...), zero capacity (DOM_HASH),
   permute, absorb, squeeze outlen words. Inputs must be canonical. */
static void clat_hash(uint32_t tag, const uint32_t *in, size_t n,
                      uint32_t *out, size_t outlen)
{
    uint32_t st[CLAT_T] = {0};
    st[0] = tag;
    st[1] = (uint32_t)n;
    clat_perm(st);
    sponge_absorb(st, in, n);
    sponge_squeeze(st, out, outlen);
    secure_zeroize(st, sizeof st);
}

/* Same hash with a masked input; only the (public) digest is unmasked. */
static void clat_hash_masked(uint32_t tag, const uint32_t *in0, const uint32_t *in1,
                             size_t n, uint32_t *out, size_t outlen)
{
    uint32_t s0[CLAT_T] = {0}, s1[CLAT_T] = {0};
    size_t k = 0;
    s0[0] = tag;
    s0[1] = (uint32_t)n;
    clat_perm_masked(s0, s1);
    for (size_t off = 0; off < n; off += SPONGE_RATE) {
        for (size_t j = 0; j < SPONGE_RATE && off + j < n; j++) {
            s0[j] = fq_add(s0[j], in0[off + j]);
            LEAK(s0[j]);
        }
        for (size_t j = 0; j < SPONGE_RATE && off + j < n; j++) {
            s1[j] = fq_add(s1[j], in1[off + j]);
            LEAK(s1[j]);
        }
        clat_perm_masked(s0, s1);
    }
    for (;;) {
        for (size_t j = 0; j < SPONGE_RATE && k < outlen; j++)
            out[k++] = fq_add(s0[j], s1[j]);    /* public digest word (published) */
        if (k == outlen)
            break;
        clat_perm_masked(s0, s1);
    }
    secure_zeroize(s0, sizeof s0);
    secure_zeroize(s1, sizeof s1);
}

/* 32 little-endian bytes -> 9 limbs: limb l holds bits [29l, 29l+29),
   limb 8 holds the top 24 bits. */
static void key_to_limbs(const uint8_t key[KEY_BYTES], uint32_t limbs[KEY_LIMBS])
{
    uint64_t acc = 0;
    unsigned nbits = 0, l = 0;
    for (size_t i = 0; i < KEY_BYTES; i++) {
        acc |= (uint64_t)key[i] << nbits;
        nbits += 8;
        if (nbits >= 29 && l < 8) {
            limbs[l++] = (uint32_t)(acc & LIMB_MASK);
            acc >>= 29;
            nbits -= 29;
        }
    }
    limbs[8] = (uint32_t)acc;
    secure_zeroize(&acc, sizeof acc);
}

/* Inverse of key_to_limbs. Rejects (in constant time) limbs 0..7 >= 2^29
   and limb 8 >= 2^24; on rejection the output is all zero. 0 / -1. */
static int limbs_to_key(const uint32_t limbs[KEY_LIMBS], uint8_t key[KEY_BYTES])
{
    uint32_t bad = 0, keep;
    uint64_t acc = 0;
    unsigned nbits = 0;
    size_t o = 0;
    for (unsigned l = 0; l < 8; l++)
        bad |= limbs[l] >> 29;
    bad |= limbs[8] >> 24;
    keep = ct_mask(ct_is_zero(bad));
    for (unsigned l = 0; l < KEY_LIMBS; l++) {
        acc |= (uint64_t)(limbs[l] & keep) << nbits;
        nbits += (l < 8) ? 29u : 24u;
        while (nbits >= 8) {
            key[o++] = (uint8_t)acc;
            acc >>= 8;
            nbits -= 8;
        }
    }
    secure_zeroize(&acc, sizeof acc);
    return (int)ct_is_zero(bad) - 1;
}

/* 1 if the limbs are in key range (limbs 0..7 < 2^29, limb 8 < 2^24), the
   range key_to_limbs produces. Constant time; only the verdict is public.
   The capacity domain separation (word 15 = limb 8 + DOM * 2^29) is
   injective only on this range, so every unmasked key entry point checks it. */
static uint32_t key_limbs_ok(const uint32_t limbs[KEY_LIMBS])
{
    uint32_t bad = 0;
    for (unsigned l = 0; l < 8; l++)
        bad |= limbs[l] >> 29;
    bad |= limbs[8] >> 24;
    return ct_is_zero(bad);
}

/* ===================================================================== */
/*  9. CLAT-SIV deterministic key wrap   (SPEC section 4)                */
/* ===================================================================== */

#define CLAT_VERSION_WORD 2u    /* header word 0 */
#define SIV_NONCE_WORDS 7
#define SIV_HDR_WORDS   4       /* (version, key id, T, N) */
#define SIV_TAG_WORDS   7       /* 217-bit tag */
#define SIV_MAC_IV_TAG  0x434C4154u     /* ASCII "CLAT", < q */
#define SIV_MAC_IN      (SIV_NONCE_WORDS + SIV_HDR_WORDS + KEY_LIMBS)   /* 20 */

typedef struct {
    uint32_t nonce[SIV_NONCE_WORDS];
    uint32_t ct[KEY_LIMBS];
    uint32_t tag[SIV_TAG_WORDS];
} clat_wrapped;

/* Keyed state: rate = iv, capacity words 7..14 = key limbs 0..7,
   word 15 = key limb 8 + dom * 2^29 (key limbs < 2^29, dom <= 2).
   Precondition: key_limbs_ok(key). The unmasked entry points that take a
   key (clat_siv_wrap, clat_siv_unwrap, vss_deal) reject keys outside that
   range, so no MAC state can equal an ENC state under a related key. The
   masked path gets its key by Lagrange interpolation of shares of a secret
   that vss_deal range-checked. */
static void keyed_init(uint32_t st[CLAT_T], const uint32_t key[KEY_LIMBS],
                       uint32_t dom, const uint32_t iv[SPONGE_RATE])
{
    for (unsigned i = 0; i < SPONGE_RATE; i++)
        st[i] = iv[i];
    for (unsigned i = 0; i < 8; i++)
        st[7 + i] = key[i];
    st[15] = fq_add(key[8], dom << 29);
}

static void keyed_init_masked(uint32_t s0[CLAT_T], uint32_t s1[CLAT_T],
                              const uint32_t k0[KEY_LIMBS], const uint32_t k1[KEY_LIMBS],
                              uint32_t dom, const uint32_t iv[SPONGE_RATE])
{
    for (unsigned i = 0; i < SPONGE_RATE; i++) {
        s0[i] = iv[i];
        s1[i] = 0;
    }
    for (unsigned i = 0; i < 8; i++) {
        s0[7 + i] = k0[i];
        s1[7 + i] = k1[i];
    }
    s0[15] = fq_add(k0[8], dom << 29);
    s1[15] = k1[8];
}

static void siv_mac_input(const uint32_t nonce[SIV_NONCE_WORDS],
                          const uint32_t hdr[SIV_HDR_WORDS],
                          const uint32_t msg[KEY_LIMBS], uint32_t buf[SIV_MAC_IN])
{
    memcpy(buf, nonce, SIV_NONCE_WORDS * sizeof(uint32_t));
    memcpy(buf + SIV_NONCE_WORDS, hdr, SIV_HDR_WORDS * sizeof(uint32_t));
    memcpy(buf + SIV_NONCE_WORDS + SIV_HDR_WORDS, msg, KEY_LIMBS * sizeof(uint32_t));
}

static const uint32_t SIV_MAC_IV[SPONGE_RATE] = {
    SIV_MAC_IV_TAG, SIV_NONCE_WORDS, SIV_HDR_WORDS, KEY_LIMBS, 0, 0, 0
};

/* tag = MAC_K(N, A, M): keyed init (DOM_MAC), permute, absorb N||A||M,
   tag = rate words 0..6. */
static void siv_mac(const uint32_t key[KEY_LIMBS], const uint32_t nonce[SIV_NONCE_WORDS],
                    const uint32_t hdr[SIV_HDR_WORDS], const uint32_t msg[KEY_LIMBS],
                    uint32_t tag[SIV_TAG_WORDS])
{
    uint32_t st[CLAT_T], buf[SIV_MAC_IN];
    keyed_init(st, key, DOM_MAC, SIV_MAC_IV);
    clat_perm(st);
    siv_mac_input(nonce, hdr, msg, buf);
    sponge_absorb(st, buf, SIV_MAC_IN);
    memcpy(tag, st, SIV_TAG_WORDS * sizeof(uint32_t));
    secure_zeroize(st, sizeof st);
    secure_zeroize(buf, sizeof buf);
}

/* Keystream: keyed init with IV = tag (DOM_ENC); block j = rate after
   permutation j+1. 9 words = 7 + 2. */
static void siv_keystream(const uint32_t key[KEY_LIMBS], const uint32_t tag[SIV_TAG_WORDS],
                          uint32_t ks[KEY_LIMBS])
{
    uint32_t st[CLAT_T];
    keyed_init(st, key, DOM_ENC, tag);
    clat_perm(st);
    sponge_squeeze(st, ks, KEY_LIMBS);
    secure_zeroize(st, sizeof st);
}

static CLAT_NOINLINE int clat_siv_wrap_impl(const uint32_t key[KEY_LIMBS],
                                            const uint32_t nonce[SIV_NONCE_WORDS],
                                            const uint32_t hdr[SIV_HDR_WORDS],
                                            const uint32_t msg[KEY_LIMBS], clat_wrapped *out)
{
    uint32_t ks[KEY_LIMBS];
    if (!key_limbs_ok(key) || !fq_all_canonical(msg, KEY_LIMBS) ||
        !fq_all_canonical(nonce, SIV_NONCE_WORDS) || !fq_all_canonical(hdr, SIV_HDR_WORDS)) {
        memset(out, 0, sizeof *out);
        return -1;
    }
    memcpy(out->nonce, nonce, sizeof out->nonce);
    siv_mac(key, nonce, hdr, msg, out->tag);
    siv_keystream(key, out->tag, ks);
    for (unsigned i = 0; i < KEY_LIMBS; i++)
        out->ct[i] = fq_add(msg[i], ks[i]);
    secure_zeroize(ks, sizeof ks);
    return 0;
}

/* Wrap msg under key. Rejects a key outside key range and non-canonical
   message, nonce or header words. 0 / -1 (output zeroed). */
static int clat_siv_wrap(const uint32_t key[KEY_LIMBS], const uint32_t nonce[SIV_NONCE_WORDS],
                         const uint32_t hdr[SIV_HDR_WORDS], const uint32_t msg[KEY_LIMBS],
                         clat_wrapped *out)
{
    int rc = clat_siv_wrap_impl(key, nonce, hdr, msg, out);
    stack_burn();
    return rc;
}

/* Public range check on the wrapped blob and header. */
static int siv_public_inputs_ok(const uint32_t hdr[SIV_HDR_WORDS], const clat_wrapped *in)
{
    return fq_all_canonical(in->nonce, SIV_NONCE_WORDS) &&
           fq_all_canonical(in->ct, KEY_LIMBS) &&
           fq_all_canonical(in->tag, SIV_TAG_WORDS) &&
           fq_all_canonical(hdr, SIV_HDR_WORDS);
}

/* Unmasked reference unwrap: M' = C - KS(tag); tag' = MAC(N, A, M');
   constant-time compare; output wiped on failure. 0 / -1. */
static CLAT_NOINLINE int clat_siv_unwrap_impl(const uint32_t key[KEY_LIMBS],
                                              const uint32_t hdr[SIV_HDR_WORDS],
                                              const clat_wrapped *in, uint32_t msg[KEY_LIMBS])
{
    uint32_t ks[KEY_LIMBS], m[KEY_LIMBS], tag2[SIV_TAG_WORDS], ok, keep;
    if (!siv_public_inputs_ok(hdr, in) || !key_limbs_ok(key)) {
        memset(msg, 0, KEY_LIMBS * sizeof(uint32_t));
        return -1;
    }
    siv_keystream(key, in->tag, ks);
    for (unsigned i = 0; i < KEY_LIMBS; i++)
        m[i] = fq_sub(in->ct[i], ks[i]);
    siv_mac(key, in->nonce, hdr, m, tag2);
    ok = ct_words_equal(tag2, in->tag, SIV_TAG_WORDS);
    keep = ct_mask(ok);
    for (unsigned i = 0; i < KEY_LIMBS; i++)
        msg[i] = m[i] & keep;
    secure_zeroize(ks, sizeof ks);
    secure_zeroize(m, sizeof m);
    secure_zeroize(tag2, sizeof tag2);
    return (int)ok - 1;
}

static int clat_siv_unwrap(const uint32_t key[KEY_LIMBS], const uint32_t hdr[SIV_HDR_WORDS],
                           const clat_wrapped *in, uint32_t msg[KEY_LIMBS])
{
    int rc = clat_siv_unwrap_impl(key, hdr, in, msg);
    stack_burn();
    return rc;
}

/* Masked unwrap: key arrives as (k0, k1); the plaintext leaves as (m0, m1).
   The tag comparison unmasks rho_j * (tag'_j - tag_j) with a fresh nonzero
   rho_j per word: zero iff the words match, otherwise uniform in F_q^*, so
   only match / no-match is revealed. 0 / -1; outputs wiped on failure. */
static CLAT_NOINLINE int clat_siv_unwrap_masked_impl(const uint32_t k0[KEY_LIMBS],
                                                     const uint32_t k1[KEY_LIMBS],
                                                     const uint32_t hdr[SIV_HDR_WORDS],
                                                     const clat_wrapped *in,
                                                     uint32_t m0[KEY_LIMBS], uint32_t m1[KEY_LIMBS])
{
    uint32_t s0[CLAT_T], s1[CLAT_T];
    uint32_t b0[SIV_MAC_IN], b1[SIV_MAC_IN];
    uint32_t diff = 0, ok, keep;
    size_t k = 0;

    if (!siv_public_inputs_ok(hdr, in) || !fq_all_canonical(k0, KEY_LIMBS) ||
        !fq_all_canonical(k1, KEY_LIMBS)) {
        memset(m0, 0, KEY_LIMBS * sizeof(uint32_t));
        memset(m1, 0, KEY_LIMBS * sizeof(uint32_t));
        return -1;
    }

    /* keystream (masked), M' = C - KS; share 0 of a block, then share 1 */
    keyed_init_masked(s0, s1, k0, k1, DOM_ENC, in->tag);
    clat_perm_masked(s0, s1);
    for (;;) {
        size_t k_start = k;
        for (size_t j = 0; j < SPONGE_RATE && k < KEY_LIMBS; j++, k++) {
            m0[k] = fq_sub(in->ct[k], s0[j]);
            LEAK(m0[k]);
        }
        k = k_start;
        for (size_t j = 0; j < SPONGE_RATE && k < KEY_LIMBS; j++, k++) {
            m1[k] = fq_neg(s1[j]);
            LEAK(m1[k]);
        }
        if (k == KEY_LIMBS)
            break;
        clat_perm_masked(s0, s1);
    }

    /* tag' = MAC(N, A, M'), masked; N and A are public (share 1 = 0) */
    siv_mac_input(in->nonce, hdr, m0, b0);
    memset(b1, 0, (SIV_NONCE_WORDS + SIV_HDR_WORDS) * sizeof(uint32_t));
    memcpy(b1 + SIV_NONCE_WORDS + SIV_HDR_WORDS, m1, KEY_LIMBS * sizeof(uint32_t));
    keyed_init_masked(s0, s1, k0, k1, DOM_MAC, SIV_MAC_IV);
    clat_perm_masked(s0, s1);
    for (size_t off = 0; off < SIV_MAC_IN; off += SPONGE_RATE) {
        for (size_t j = 0; j < SPONGE_RATE && off + j < SIV_MAC_IN; j++) {
            s0[j] = fq_add(s0[j], b0[off + j]);
            LEAK(s0[j]);
        }
        for (size_t j = 0; j < SPONGE_RATE && off + j < SIV_MAC_IN; j++) {
            s1[j] = fq_add(s1[j], b1[off + j]);
            LEAK(s1[j]);
        }
        clat_perm_masked(s0, s1);
    }

    for (unsigned j = 0; j < SIV_TAG_WORDS; j++) {
        uint32_t rho = rng_fq_nonzero(), t0, u0, u1, u;
        LEAK(rho);
        t0 = fq_sub(s0[j], in->tag[j]); LEAK(t0);
        u0 = fq_mul(rho, t0);           LEAK(u0);
        u1 = fq_mul(rho, s1[j]);        LEAK(u1);
        u = fq_add(u0, u1);             LEAK(u);      /* public: 0 iff match */
        diff |= u;
    }
    ok = ct_is_zero(diff);
    keep = ct_mask(ok);
    for (unsigned i = 0; i < KEY_LIMBS; i++) {
        m0[i] &= keep;
        m1[i] &= keep;
    }
    secure_zeroize(s0, sizeof s0);
    secure_zeroize(s1, sizeof s1);
    secure_zeroize(b0, sizeof b0);
    secure_zeroize(b1, sizeof b1);
    return (int)ok - 1;
}

static int clat_siv_unwrap_masked(const uint32_t k0[KEY_LIMBS], const uint32_t k1[KEY_LIMBS],
                                  const uint32_t hdr[SIV_HDR_WORDS], const clat_wrapped *in,
                                  uint32_t m0[KEY_LIMBS], uint32_t m1[KEY_LIMBS])
{
    int rc;
    rng_wipe();
    rc = clat_siv_unwrap_masked_impl(k0, k1, hdr, in, m0, m1);
    stack_burn();
    rng_wipe();
    return rc;
}

/* ===================================================================== */
/* 10. Hash-committed VSS   (SPEC section 5)                              */
/* ===================================================================== */

#define VSS_MAX_N    16
#define VSS_MAX_T    16
#define VSS_M        5                       /* masking polynomials r_k  */
#define VSS_SALT     9
#define VSS_COMMIT_IN (1 + KEY_LIMBS + VSS_M + VSS_SALT)   /* 24 words  */
#define VSS_D_WORDS  (VSS_M * KEY_LIMBS)                    /* 45 words  */

typedef struct {
    uint32_t x;                     /* custodian index i, 1..N    */
    uint32_t f[KEY_LIMBS];          /* f_l(i)                     */
    uint32_t r[VSS_M];              /* r_k(i)                     */
    uint32_t salt[VSS_SALT];
} vss_share;

typedef struct {                    /* the same share, 2-share masked */
    uint32_t x;
    uint32_t f[2][KEY_LIMBS];
    uint32_t r[2][VSS_M];
    uint32_t salt[2][VSS_SALT];
} vss_share_masked;

typedef struct {                    /* public transcript */
    uint32_t T, N;
    uint32_t c[VSS_MAX_N][DIGEST_WORDS];    /* c_i, custodian i at index i-1 */
    uint32_t g[VSS_M][VSS_MAX_T];           /* coefficients of g_k           */
} vss_transcript;

typedef struct {                    /* dealer's secret polynomials */
    uint32_t T;
    uint32_t f[KEY_LIMBS][VSS_MAX_T];
    uint32_t r[VSS_M][VSS_MAX_T];
} vss_polys;

static uint32_t poly_eval(const uint32_t *coef, uint32_t T, uint32_t x)
{
    uint32_t acc = coef[T - 1];
    for (uint32_t t = T - 1; t-- > 0;)
        acc = fq_add(fq_mul(acc, x), coef[t]);
    return acc;
}

static int vss_params_ok(uint32_t T, uint32_t N)
{
    return T >= 2 && T <= N && N <= VSS_MAX_N && T <= VSS_MAX_T;
}

/* A transcript is public, untrusted input. Before anything indexes by its
   T or N or computes with its words: parameters in range, and every
   published word (c_1..c_N and the T coefficients of each g_k) canonical,
   so a mod-q-equivalent copy cannot make honest shares fail. */
static int vss_transcript_wellformed(const vss_transcript *tr)
{
    if (!vss_params_ok(tr->T, tr->N))
        return 0;
    for (uint32_t i = 0; i < tr->N; i++)
        if (!fq_all_canonical(tr->c[i], DIGEST_WORDS))
            return 0;
    for (unsigned k = 0; k < VSS_M; k++)
        if (!fq_all_canonical(tr->g[k], tr->T))
            return 0;
    return 1;
}

/* f_l(X) = s_l + a_{l,1} X + ... ; r_k(X) fully random; degree <= T-1. */
static void vss_make_polys(const uint32_t secret[KEY_LIMBS], uint32_t T, vss_polys *p)
{
    p->T = T;
    for (unsigned l = 0; l < KEY_LIMBS; l++) {
        p->f[l][0] = secret[l];
        for (uint32_t t = 1; t < T; t++)
            p->f[l][t] = rng_fq();
    }
    for (unsigned k = 0; k < VSS_M; k++)
        for (uint32_t t = 0; t < T; t++)
            p->r[k][t] = rng_fq();
}

static void vss_eval_share(const vss_polys *p, uint32_t x, vss_share *s)
{
    s->x = x;
    for (unsigned l = 0; l < KEY_LIMBS; l++)
        s->f[l] = poly_eval(p->f[l], p->T, x);
    for (unsigned k = 0; k < VSS_M; k++)
        s->r[k] = poly_eval(p->r[k], p->T, x);
    for (unsigned j = 0; j < VSS_SALT; j++)
        s->salt[j] = rng_fq();
}

/* c_i = H(HT_COMMIT, [i, f_0(i)..f_8(i), r_0(i)..r_4(i), salt_i[0..8]]) */
static void vss_commit_input(const vss_share *s, uint32_t in[VSS_COMMIT_IN])
{
    in[0] = s->x;
    memcpy(in + 1, s->f, sizeof s->f);
    memcpy(in + 1 + KEY_LIMBS, s->r, sizeof s->r);
    memcpy(in + 1 + KEY_LIMBS + VSS_M, s->salt, sizeof s->salt);
}

static void vss_commit(const vss_share *s, uint32_t c[DIGEST_WORDS])
{
    uint32_t in[VSS_COMMIT_IN];
    vss_commit_input(s, in);
    clat_hash(HT_COMMIT, in, VSS_COMMIT_IN, c, DIGEST_WORDS);
    secure_zeroize(in, sizeof in);
}

/* d = H(HT_CHALLENGE, [T, N, c_1..c_N]) squeezed to 45 words d_{k,l}.
   0, or -1 (d zeroed) for a malformed transcript; N <= VSS_MAX_N is
   checked before the loop that fills in[]. */
static int vss_challenge(const vss_transcript *tr, uint32_t d[VSS_D_WORDS])
{
    uint32_t in[2 + VSS_MAX_N * DIGEST_WORDS];
    size_t n = 0;
    if (!vss_transcript_wellformed(tr)) {
        memset(d, 0, VSS_D_WORDS * sizeof(uint32_t));
        return -1;
    }
    in[n++] = tr->T;
    in[n++] = tr->N;
    for (uint32_t i = 0; i < tr->N; i++)
        for (unsigned w = 0; w < DIGEST_WORDS; w++)
            in[n++] = tr->c[i][w];
    clat_hash(HT_CHALLENGE, in, n, d, VSS_D_WORDS);
    return 0;
}

/* Commit to the given shares, derive d, publish g_k = r_k + sum_l d_{k,l} f_l. */
static void vss_publish(const vss_polys *p, const vss_share *shares, uint32_t N,
                        vss_transcript *tr)
{
    uint32_t d[VSS_D_WORDS];
    memset(tr, 0, sizeof *tr);
    tr->T = p->T;
    tr->N = N;
    for (uint32_t i = 0; i < N; i++)
        vss_commit(&shares[i], tr->c[i]);
    vss_challenge(tr, d);
    for (unsigned k = 0; k < VSS_M; k++)
        for (uint32_t t = 0; t < p->T; t++) {
            uint32_t acc = p->r[k][t];
            for (unsigned l = 0; l < KEY_LIMBS; l++)
                acc = fq_add(acc, fq_mul(d[k * KEY_LIMBS + l], p->f[l][t]));
            tr->g[k][t] = acc;
        }
}

static CLAT_NOINLINE int vss_deal_impl(const uint32_t secret[KEY_LIMBS], uint32_t T, uint32_t N,
                                       vss_share shares[], vss_transcript *tr)
{
    vss_polys p;
    if (!vss_params_ok(T, N) || !key_limbs_ok(secret))
        return -1;
    vss_make_polys(secret, T, &p);
    for (uint32_t i = 0; i < N; i++)
        vss_eval_share(&p, i + 1, &shares[i]);
    vss_publish(&p, shares, N, tr);
    secure_zeroize(&p, sizeof p);
    return 0;
}

/* Dealer: split a KEK (9 limbs in key range) T-of-N. Shares go to
   custodians 1..N. The vault header that the KEK's blob authenticates must
   carry the same (T, N): verifiers check the transcript against it. */
static int vss_deal(const uint32_t secret[KEY_LIMBS], uint32_t T, uint32_t N,
                    vss_share shares[], vss_transcript *tr)
{
    int rc;
    rng_wipe();
    rc = vss_deal_impl(secret, T, N, shares, tr);
    stack_burn();
    rng_wipe();
    return rc;
}

/* g-check only: OR over k of (g_k(i) - r_k(i) - sum_l d_{k,l} f_l(i)).
   Zero iff the share lies on the committed codeword for all 5 challenges. */
static uint32_t vss_gcheck_diff(const vss_transcript *tr, const uint32_t d[VSS_D_WORDS],
                                const vss_share *s)
{
    uint32_t bad = 0;
    for (unsigned k = 0; k < VSS_M; k++) {
        uint32_t acc = s->r[k];
        for (unsigned l = 0; l < KEY_LIMBS; l++)
            acc = fq_add(acc, fq_mul(d[k * KEY_LIMBS + l], s->f[l]));
        bad |= fq_sub(poly_eval(tr->g[k], tr->T, s->x), acc);
    }
    return bad;
}

static int vss_share_shape_ok(const vss_transcript *tr, uint32_t x)
{
    return vss_transcript_wellformed(tr) && x >= 1 && x <= tr->N;
}

/* Full check of one share: commitment AND g-check. 1 = valid. */
static uint32_t vss_share_valid(const vss_transcript *tr, const uint32_t d[VSS_D_WORDS],
                                const vss_share *s)
{
    uint32_t c[DIGEST_WORDS], ok;
    if (!vss_share_shape_ok(tr, s->x) ||
        !fq_all_canonical(s->f, KEY_LIMBS) || !fq_all_canonical(s->r, VSS_M) ||
        !fq_all_canonical(s->salt, VSS_SALT))
        return 0;   /* malformed input: rejected before any secret arithmetic */
    vss_commit(s, c);
    ok = ct_words_equal(c, tr->c[s->x - 1], DIGEST_WORDS);
    ok &= ct_is_zero(vss_gcheck_diff(tr, d, s));
    return ok;
}

#define VSS_FAIL_TRANSCRIPT 1u   /* bit 0 of the failure mask */

static CLAT_NOINLINE uint32_t vss_verify_all_impl(const vss_transcript *tr, uint32_t T, uint32_t N,
                                                  const vss_share *shares, size_t count)
{
    uint32_t d[VSS_D_WORDS], failed = 0;
    size_t nmark = (count < VSS_MAX_N) ? count : VSS_MAX_N;
    uint32_t everyone = ((1u << nmark) - 1u) << 1;
    if (tr->T != T || tr->N != N || count > tr->N || vss_challenge(tr, d) != 0)
        return VSS_FAIL_TRANSCRIPT | everyone;
    for (size_t i = 0; i < count; i++) {
        uint32_t ok = vss_share_valid(tr, d, &shares[i]) & (uint32_t)(shares[i].x == i + 1);
        failed |= (1u ^ ok) << (i + 1);
    }
    return failed;
}

/* Reference (unmasked) verifier, for the dealer's audit or a custodian
   checking its own share on its own device; the combiner uses the masked
   path. shares[i] is what custodian i+1 sent. The transcript must be well
   formed and carry the policy (T, N) of the authenticated vault header.
   Returns a bitmask: bit i+1 set = custodian i+1 failed (commitment,
   g-check, or a share labelled with another custodian's index), so blame
   always lands on the sender. Bit 0 (VSS_FAIL_TRANSCRIPT) = malformed
   transcript, policy mismatch or count > N; every listed custodian is then
   marked too, since none of them can be verified. */
static uint32_t vss_verify_all(const vss_transcript *tr, uint32_t T, uint32_t N,
                               const vss_share *shares, size_t count)
{
    uint32_t failed = vss_verify_all_impl(tr, T, N, shares, count);
    stack_burn();
    return failed;
}

/* Complaint round (SPEC section 5.4). A custodian whose share fails its
   own check broadcasts a complaint against the dealer. The dealer must then
   open that custodian's share in public, and everyone runs the full check
   (commitment and g-check) on the opening. An opening that passes replaces
   the complainer's share. Each opening reveals one share to everyone, so
   T or more complaints would reveal the KEK: the dealer is then
   disqualified instead of answering. With at most T-1 dishonest
   custodians, false complaints cannot disqualify an honest dealer. */
#define VSS_QUALIFIED     0
#define VSS_DISQUALIFIED  1
#define VSS_BAD_COMPLAINTS (-1)

/* Full check of one share against a transcript whose policy is (T, N),
   challenge included. Used on a custodian's own share and on public
   openings, so the unmasked path is fine. 1 = valid. */
static uint32_t vss_share_valid_public(const vss_transcript *tr, uint32_t T, uint32_t N,
                                       const vss_share *s)
{
    uint32_t d[VSS_D_WORDS], ok;
    if (tr->T != T || tr->N != N || vss_challenge(tr, d) != 0)
        return 0;
    ok = vss_share_valid(tr, d, s);
    stack_burn();
    return ok;
}

/* Custodian side: 1 if custodian `slot` must complain about the share it
   received (it fails the full check or carries another index). */
static int vss_should_complain(const vss_transcript *tr, uint32_t T, uint32_t N,
                               const vss_share *mine, uint32_t slot)
{
    return mine->x != slot || !vss_share_valid_public(tr, T, N, mine);
}

/* Everyone: resolve the complaints from custodians who[0..n) using the
   dealer's openings (openings[j] answers who[j]; NULL = the dealer stayed
   silent). Returns VSS_QUALIFIED, VSS_DISQUALIFIED, or VSS_BAD_COMPLAINTS
   for a malformed complaint list (an index outside 1..N or a repeat),
   which is the complainers' fault, not the dealer's. */
static int vss_resolve_complaints(const vss_transcript *tr, uint32_t T, uint32_t N,
                                  const uint32_t *who, size_t n,
                                  const vss_share *const *openings)
{
    uint32_t seen = 0;
    if (n > VSS_MAX_N)
        return VSS_BAD_COMPLAINTS;
    for (size_t j = 0; j < n; j++) {
        if (who[j] < 1 || who[j] > N || who[j] > VSS_MAX_N || (seen >> who[j]) & 1u)
            return VSS_BAD_COMPLAINTS;
        seen |= 1u << who[j];
    }
    if (n == 0)
        return VSS_QUALIFIED;
    if (n >= T)
        return VSS_DISQUALIFIED;
    for (size_t j = 0; j < n; j++)
        if (openings[j] == NULL || openings[j]->x != who[j] ||
            !vss_share_valid_public(tr, T, N, openings[j]))
            return VSS_DISQUALIFIED;
    return VSS_QUALIFIED;
}

static CLAT_NOINLINE void vss_share_mask_impl(const vss_share *s, vss_share_masked *m)
{
    m->x = s->x;
    mask_split(s->f, m->f[0], m->f[1], KEY_LIMBS);
    mask_split(s->r, m->r[0], m->r[1], VSS_M);
    mask_split(s->salt, m->salt[0], m->salt[1], VSS_SALT);
}

/* Custodian side: split the share into two arithmetic shares on the
   custodian's own device, before it is sent. The combiner only ever
   receives vss_share_masked and never handles a share value in clear. */
static void vss_share_mask(const vss_share *s, vss_share_masked *m)
{
    rng_wipe();
    vss_share_mask_impl(s, m);
    stack_burn();
    rng_wipe();
}

/* Masked verification. The commitment is recomputed with the masked hash
   (only the public digest is unmasked); the g-check unmasks only the
   difference g_k(i) - r_k(i) - sum_l d_{k,l} f_l(i), zero for honest shares.
   Like vss_verify_all, it binds the share to its sender and the transcript
   to the authenticated policy: slot is the custodian the share came from
   (it must equal m->x), and T, N come from the vault header. 1 = valid. */
static CLAT_NOINLINE uint32_t vss_share_valid_masked_impl(const vss_transcript *tr,
                                                          const uint32_t d[VSS_D_WORDS],
                                                          const vss_share_masked *m,
                                                          uint32_t slot, uint32_t T, uint32_t N)
{
    uint32_t in0[VSS_COMMIT_IN], in1[VSS_COMMIT_IN], c[DIGEST_WORDS];
    uint32_t ok, bad = 0;
    if (tr->T != T || tr->N != N || m->x != slot || !vss_share_shape_ok(tr, m->x) ||
        !fq_all_canonical(m->f[0], KEY_LIMBS) || !fq_all_canonical(m->f[1], KEY_LIMBS) ||
        !fq_all_canonical(m->r[0], VSS_M) || !fq_all_canonical(m->r[1], VSS_M) ||
        !fq_all_canonical(m->salt[0], VSS_SALT) || !fq_all_canonical(m->salt[1], VSS_SALT))
        return 0;

    in0[0] = m->x;
    in1[0] = 0;
    memcpy(in0 + 1, m->f[0], sizeof m->f[0]);
    memcpy(in1 + 1, m->f[1], sizeof m->f[1]);
    memcpy(in0 + 1 + KEY_LIMBS, m->r[0], sizeof m->r[0]);
    memcpy(in1 + 1 + KEY_LIMBS, m->r[1], sizeof m->r[1]);
    memcpy(in0 + 1 + KEY_LIMBS + VSS_M, m->salt[0], sizeof m->salt[0]);
    memcpy(in1 + 1 + KEY_LIMBS + VSS_M, m->salt[1], sizeof m->salt[1]);
    clat_hash_masked(HT_COMMIT, in0, in1, VSS_COMMIT_IN, c, DIGEST_WORDS);
    ok = ct_words_equal(c, tr->c[m->x - 1], DIGEST_WORDS);

    /* Share 0 chain, then share 1 chain, then g - a0 (equal to a1 for an
       honest share), then the public difference. a0 is never next to
       g - a0: their sum is the public g_k(i), so in the HD model that
       transition would track a public value. */
    for (unsigned k = 0; k < VSS_M; k++) {
        uint32_t a0 = m->r[0][k], a1 = m->r[1][k], e;
        for (unsigned l = 0; l < KEY_LIMBS; l++) {
            a0 = fq_add(a0, fq_mul(d[k * KEY_LIMBS + l], m->f[0][l]));
            LEAK(a0);
        }
        for (unsigned l = 0; l < KEY_LIMBS; l++) {
            a1 = fq_add(a1, fq_mul(d[k * KEY_LIMBS + l], m->f[1][l]));
            LEAK(a1);
        }
        e = fq_sub(poly_eval(tr->g[k], tr->T, m->x), a0);   /* still a share */
        LEAK(e);
        e = fq_sub(e, a1);                                  /* public difference */
        LEAK(e);
        bad |= e;
    }
    ok &= ct_is_zero(bad);
    secure_zeroize(in0, sizeof in0);
    secure_zeroize(in1, sizeof in1);
    return ok;
}

static uint32_t vss_share_valid_masked(const vss_transcript *tr, const uint32_t d[VSS_D_WORDS],
                                       const vss_share_masked *m,
                                       uint32_t slot, uint32_t T, uint32_t N)
{
    uint32_t ok;
    rng_wipe();
    ok = vss_share_valid_masked_impl(tr, d, m, slot, T, N);
    stack_burn();
    rng_wipe();
    return ok;
}

/* Lagrange coefficients at X = 0 for distinct public points xs[0..n). */
static void lagrange_at_zero(const uint32_t *xs, size_t n, uint32_t *lam)
{
    for (size_t j = 0; j < n; j++) {
        uint32_t num = 1, den = 1;
        for (size_t m = 0; m < n; m++) {
            if (m == j)
                continue;
            num = fq_mul(num, xs[m]);
            den = fq_mul(den, fq_sub(xs[m], xs[j]));
        }
        lam[j] = fq_mul(num, fq_inv(den));
    }
}

/* 1 if every point is a custodian index (1..VSS_MAX_N, so nonzero and
   canonical) and no two are equal: then every Lagrange denominator is a
   product of nonzero differences, and fq_inv never sees 0. */
static int points_valid(const uint32_t *xs, size_t n)
{
    for (size_t a = 0; a < n; a++) {
        if (xs[a] == 0 || xs[a] > VSS_MAX_N)
            return 0;
        for (size_t b = a + 1; b < n; b++)
            if (xs[a] == xs[b])
                return 0;
    }
    return 1;
}

/* Unmasked reconstruction (reference). */
static CLAT_NOINLINE int vss_reconstruct_impl(const vss_share *const *sh, size_t n,
                                              uint32_t out[KEY_LIMBS])
{
    uint32_t xs[VSS_MAX_N], lam[VSS_MAX_N];
    if (n == 0 || n > VSS_MAX_N)
        return -1;
    for (size_t j = 0; j < n; j++)
        xs[j] = sh[j]->x;
    if (!points_valid(xs, n))
        return -1;
    lagrange_at_zero(xs, n, lam);
    for (unsigned l = 0; l < KEY_LIMBS; l++) {
        uint32_t acc = 0;
        for (size_t j = 0; j < n; j++)
            acc = fq_add(acc, fq_mul(lam[j], sh[j]->f[l]));
        out[l] = acc;
    }
    return 0;
}

static int vss_reconstruct(const vss_share *const *sh, size_t n, uint32_t out[KEY_LIMBS])
{
    int rc = vss_reconstruct_impl(sh, n, out);
    stack_burn();
    return rc;
}

/* Masked Lagrange interpolation at 0: linear, so applied share-wise with
   public coefficients (share 0 of a limb, then share 1). Output is the
   secret as (out0, out1). */
static CLAT_NOINLINE int vss_reconstruct_masked_impl(const vss_share_masked *const *sh, size_t n,
                                                     uint32_t out0[KEY_LIMBS],
                                                     uint32_t out1[KEY_LIMBS])
{
    uint32_t xs[VSS_MAX_N], lam[VSS_MAX_N];
    if (n == 0 || n > VSS_MAX_N)
        return -1;
    for (size_t j = 0; j < n; j++)
        xs[j] = sh[j]->x;
    if (!points_valid(xs, n))
        return -1;
    lagrange_at_zero(xs, n, lam);
    for (unsigned l = 0; l < KEY_LIMBS; l++) {
        uint32_t a0 = 0, a1 = 0;
        for (size_t j = 0; j < n; j++) {
            a0 = fq_add(a0, fq_mul(lam[j], sh[j]->f[0][l]));
            LEAK(a0);
        }
        for (size_t j = 0; j < n; j++) {
            a1 = fq_add(a1, fq_mul(lam[j], sh[j]->f[1][l]));
            LEAK(a1);
        }
        out0[l] = a0;
        out1[l] = a1;
    }
    return 0;
}

static int vss_reconstruct_masked(const vss_share_masked *const *sh, size_t n,
                                  uint32_t out0[KEY_LIMBS], uint32_t out1[KEY_LIMBS])
{
    int rc = vss_reconstruct_masked_impl(sh, n, out0, out1);
    stack_burn();
    return rc;
}

/* ===================================================================== */
/* 11. Test harness                                                      */
/* ===================================================================== */

static int g_func_fail;        /* functional failures: decide the exit code */
static int g_func_total;
static int g_stat_fail;        /* statistical tests over their threshold     */
static int g_stat_total;
static int g_full;             /* --full */

static void check(int ok, const char *what)
{
    g_func_total++;
    if (!ok)
        g_func_fail++;
    printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
}

static void stat_verdict(int ok, const char *what)
{
    g_stat_total++;
    if (!ok)
        g_stat_fail++;
    printf("  [%s] %s (statistical)\n", ok ? "PASS" : "FAIL", what);
}

static void print_words(const char *label, const uint32_t *w, size_t n)
{
    printf("    %s:", label);
    for (size_t i = 0; i < n; i++)
        printf("%s%08x", (i % 8 == 0) ? "\n      " : " ", (unsigned)w[i]);
    printf("\n");
}

static void banner(const char *title)
{
    printf("\n== %s ==\n", title);
}

static void rand_state(uint32_t st[CLAT_T])
{
    for (unsigned i = 0; i < CLAT_T; i++)
        st[i] = rng_fq();
}

static void rand_limbs(uint32_t k[KEY_LIMBS])
{
    uint8_t b[KEY_BYTES];
    os_random_bytes(b, sizeof b);
    key_to_limbs(b, k);
    secure_zeroize(b, sizeof b);
}

typedef struct { double n, mean, m2; } welford;

static void welford_add(welford *w, double x)
{
    double d = x - w->mean;
    w->n += 1.0;
    w->mean += d / w->n;
    w->m2 += d * (x - w->mean);
}

static double welch_t_from(double n0, double m0, double v0, double n1, double m1, double v1)
{
    double den;
    if (n0 < 2.0 || n1 < 2.0)
        return 0.0;
    den = sqrt(v0 / n0 + v1 / n1);
    if (den == 0.0)
        return (m0 == m1) ? 0.0 : INFINITY;
    return (m0 - m1) / den;
}

static double welch_t(const welford *a, const welford *b)
{
    if (a->n < 2.0 || b->n < 2.0)
        return 0.0;
    return welch_t_from(a->n, a->mean, a->m2 / (a->n - 1.0),
                        b->n, b->mean, b->m2 / (b->n - 1.0));
}

/* ===================================================================== */
/* 12. Test 1: known-answer tests                                        */
/* ===================================================================== */
/* Recorded from the first run of this file and checked on every later run.
   The same values are reproduced by a separate Python implementation
   written from SPEC_V2.md, shipped as tools/ref_kat.py
   (run: python tools/ref_kat.py). Inputs:
     KAT_PERM : CLAT-P applied to (0, 1, ..., 15)
     KAT_HASH : H(HT_KAT, empty input), 9 words
     KAT_SIV  : wrap with key bytes 00..1f, message bytes 80..9f,
                nonce (1..7), header (2, 1, 3, 5); nonce || ct || tag */

static const uint32_t KAT_PERM[CLAT_T] = {
    0x5f0d27c8, 0x4a31df17, 0x74646b11, 0x47f73390, 0x2a465712, 0x705c8c70, 0x051385f1, 0x75f8a285,
    0x294ee63a, 0x0ac56767, 0x7d0f1903, 0x412b9a80, 0x60e36308, 0x6b8ebc10, 0x2aa487a7, 0x0dc08878
};
static const uint32_t KAT_HASH[DIGEST_WORDS] = {
    0x0fcb86a3, 0x77e744d8, 0x7d4aa4bb, 0x0ebfa8eb, 0x4a149c3c, 0x63dd9090, 0x7d325847, 0x01918bb0,
    0x29c15fa8
};
static const uint32_t KAT_SIV[SIV_NONCE_WORDS + KEY_LIMBS + SIV_TAG_WORDS] = {
    0x00000001, 0x00000002, 0x00000003, 0x00000004, 0x00000005, 0x00000006, 0x00000007, /* nonce */
    0x47d31d57, 0x5959755a, 0x029d6d58, 0x4f9ff3a4, 0x4d858144, 0x7685ef07, 0x08d0534e,
    0x63bb3982, 0x3417916c,                                                             /* ct    */
    0x67266edd, 0x47930486, 0x4f02a937, 0x58b4a5d0, 0x23705f82, 0x75e67e31, 0x557e8976  /* tag   */
};

static void kat_siv_inputs(uint32_t key[KEY_LIMBS], uint32_t nonce[SIV_NONCE_WORDS],
                           uint32_t hdr[SIV_HDR_WORDS], uint32_t msg[KEY_LIMBS])
{
    uint8_t kb[KEY_BYTES], mb[KEY_BYTES];
    for (unsigned i = 0; i < KEY_BYTES; i++) {
        kb[i] = (uint8_t)i;
        mb[i] = (uint8_t)(0x80u + i);
    }
    key_to_limbs(kb, key);
    key_to_limbs(mb, msg);
    for (unsigned i = 0; i < SIV_NONCE_WORDS; i++)
        nonce[i] = i + 1;
    hdr[0] = CLAT_VERSION_WORD;
    hdr[1] = 1;
    hdr[2] = 3;
    hdr[3] = 5;
}

static void test_kat(void)
{
    uint32_t st[CLAT_T], h[DIGEST_WORDS], key[KEY_LIMBS], nonce[SIV_NONCE_WORDS];
    uint32_t hdr[SIV_HDR_WORDS], msg[KEY_LIMBS], back[KEY_LIMBS];
    uint32_t blob_words[SIV_NONCE_WORDS + KEY_LIMBS + SIV_TAG_WORDS];
    clat_wrapped w;

    banner("Test 1: known-answer tests");
    for (unsigned i = 0; i < CLAT_T; i++)
        st[i] = i;
    clat_perm(st);
    print_words("CLAT-P(0..15)", st, CLAT_T);
    check(ct_words_equal(st, KAT_PERM, CLAT_T), "CLAT-P(0..15) matches recorded value");

    clat_hash(HT_KAT, NULL, 0, h, DIGEST_WORDS);
    print_words("H(HT_KAT, empty)", h, DIGEST_WORDS);
    check(ct_words_equal(h, KAT_HASH, DIGEST_WORDS), "H(HT_KAT, empty) matches recorded value");

    kat_siv_inputs(key, nonce, hdr, msg);
    if (clat_siv_wrap(key, nonce, hdr, msg, &w) != 0)
        printf("    SIV wrap rejected the KAT inputs\n");
    memcpy(blob_words, w.nonce, sizeof w.nonce);
    memcpy(blob_words + SIV_NONCE_WORDS, w.ct, sizeof w.ct);
    memcpy(blob_words + SIV_NONCE_WORDS + KEY_LIMBS, w.tag, sizeof w.tag);
    print_words("SIV wrap (nonce || ct || tag)", blob_words,
                SIV_NONCE_WORDS + KEY_LIMBS + SIV_TAG_WORDS);
    check(ct_words_equal(blob_words, KAT_SIV, SIV_NONCE_WORDS + KEY_LIMBS + SIV_TAG_WORDS),
          "SIV wrap matches recorded value");
    check(clat_siv_unwrap(key, hdr, &w, back) == 0 && ct_words_equal(back, msg, KEY_LIMBS),
          "SIV unwrap of the KAT blob returns the message");
}

/* ===================================================================== */
/* 13. Test 2: self-tests                                                */
/* ===================================================================== */

/* Gaussian elimination over F_q on the k x k minor of MDS with the given
   rows and columns (public data). 1 if nonsingular. */
static int mds_minor_nonsingular(const unsigned *rows, const unsigned *cols, unsigned k)
{
    uint32_t a[CLAT_T][CLAT_T];
    for (unsigned i = 0; i < k; i++)
        for (unsigned j = 0; j < k; j++)
            a[i][j] = MDS[rows[i]][cols[j]];
    for (unsigned c = 0; c < k; c++) {
        unsigned p = c;
        uint32_t inv;
        while (p < k && a[p][c] == 0)
            p++;
        if (p == k)
            return 0;
        if (p != c)
            for (unsigned j = 0; j < k; j++) {
                uint32_t t = a[p][j];
                a[p][j] = a[c][j];
                a[c][j] = t;
            }
        inv = fq_inv(a[c][c]);
        for (unsigned r = c + 1; r < k; r++) {
            uint32_t f = fq_mul(a[r][c], inv);
            for (unsigned j = c; j < k; j++)
                a[r][j] = fq_sub(a[r][j], fq_mul(f, a[c][j]));
        }
    }
    return 1;
}

static void random_subset16(unsigned *out, unsigned k)
{
    unsigned idx[CLAT_T];
    for (unsigned i = 0; i < CLAT_T; i++)
        idx[i] = i;
    for (unsigned i = 0; i < k; i++) {
        unsigned j = i + rng_below(CLAT_T - i);
        unsigned t = idx[i];
        idx[i] = idx[j];
        idx[j] = t;
        out[i] = idx[i];
    }
}

static int all_zero(const uint32_t *w, size_t n)
{
    uint32_t acc = 0;
    for (size_t i = 0; i < n; i++)
        acc |= w[i];
    return acc == 0;
}

/* Dead-stack probes. stack_scan() reads the dead stack just below its
   caller's frame, where the frames of the caller's previous callee were.
   The buffer is never written: unsigned char has no trap representations,
   and the asm barrier tells the compiler the buffer may have been written,
   so the reads are kept. The scan region (2 KiB) lies inside the region
   stack_burn() clears (8 KiB). GCC / Clang only. */
#define SCAN_BYTES 2048

/* AddressSanitizer adds redzones and frame headers to every stack frame,
   so the dead-stack layout these probes rely on does not hold under it. */
#if defined(__SANITIZE_ADDRESS__)
#  define CLAT_ASAN 1
#elif defined(__has_feature)
#  if __has_feature(address_sanitizer)
#    define CLAT_ASAN 1
#  endif
#endif

#if (defined(__GNUC__) || defined(__clang__)) && !defined(CLAT_ASAN)
static CLAT_NOINLINE void stack_scan(size_t *nonzero, size_t *run_a5)
{
    unsigned char buf[SCAN_BYTES];
    size_t nz = 0, run = 0, best = 0;
    __asm__ __volatile__("" : : "r"(buf) : "memory");
    for (size_t i = 0; i < SCAN_BYTES; i++) {
        nz += buf[i] != 0;
        run = (buf[i] == 0xA5) ? run + 1 : 0;
        if (run > best)
            best = run;
    }
    *nonzero = nz;
    *run_a5 = best;
}

/* A 256-byte 0xA5 pattern that is really stored (the barrier reads it),
   then wiped while the buffer is dead: a plain memset there is a dead
   store the optimiser may drop; secure_zeroize must not be dropped. */
static CLAT_NOINLINE void zeroize_probe_secure(void)
{
    unsigned char buf[256];
    memset(buf, 0xA5, sizeof buf);
    __asm__ __volatile__("" : : "r"(buf) : "memory");
    secure_zeroize(buf, sizeof buf);
}

static CLAT_NOINLINE void zeroize_probe_memset(void)
{
    unsigned char buf[256];
    memset(buf, 0xA5, sizeof buf);
    __asm__ __volatile__("" : : "r"(buf) : "memory");
    memset(buf, 0, sizeof buf);
}

static void test_dead_stack(void)
{
    uint32_t key[KEY_LIMBS], msg[KEY_LIMBS], nonce[SIV_NONCE_WORDS], hdr[SIV_HDR_WORDS];
    size_t nz_ctrl, nz_burn, run_secure, run_memset, unused;
    clat_wrapped w;
    char line[240];

    stack_burn();
    zeroize_probe_memset();
    stack_scan(&unused, &run_memset);
    stack_burn();
    zeroize_probe_secure();
    stack_scan(&unused, &run_secure);
    snprintf(line, sizeof line, "secure_zeroize on a dead buffer survives optimisation: longest "
             "0xA5 run left = %zu bytes (control, plain memset: %zu bytes)", run_secure, run_memset);
    check(run_secure < 8, line);

    rand_limbs(key);
    rand_limbs(msg);
    for (unsigned i = 0; i < SIV_NONCE_WORDS; i++)
        nonce[i] = rng_fq();
    hdr[0] = CLAT_VERSION_WORD; hdr[1] = 1; hdr[2] = 3; hdr[3] = 5;
    stack_burn();
    (void)clat_siv_wrap_impl(key, nonce, hdr, msg, &w);     /* control: no burn */
    stack_scan(&nz_ctrl, &unused);
    stack_burn();
    (void)clat_siv_wrap(key, nonce, hdr, msg, &w);          /* entry point: burns */
    stack_scan(&nz_burn, &unused);
    snprintf(line, sizeof line, "dead stack after clat_siv_wrap: %zu nonzero bytes of %d "
             "(control without the burn: %zu nonzero bytes)", nz_burn, SCAN_BYTES, nz_ctrl);
    check(nz_burn == 0 && nz_ctrl > 0, line);
    secure_zeroize(key, sizeof key);
    secure_zeroize(msg, sizeof msg);
}
#else
static void test_dead_stack(void)
{
    printf("    dead-stack probes need GCC or Clang and no ASan build; skipped\n");
}
#endif

static void test_selftests(void)
{
    static const uint32_t primes[7] = { 2, 3, 7, 11, 31, 151, 331 };
    static const unsigned exps[7]   = { 1, 2, 1, 1, 1, 1, 1 };
    uint64_t prod = 1;
    int ok;
    unsigned rows[CLAT_T], cols[CLAT_T];
    size_t n1 = 0, n2 = 0, nk = 0, bad1 = 0, bad2 = 0, badk = 0;
    char line[200];

    banner("Test 2: self-tests");

    /* field structure */
    for (unsigned i = 0; i < 7; i++)
        for (unsigned e = 0; e < exps[i]; e++)
            prod *= primes[i];
    check(prod == (uint64_t)FQ_Q - 1u, "q-1 = 2 * 3^2 * 7 * 11 * 31 * 151 * 331");
    ok = 1;
    for (unsigned i = 0; i < 7; i++)
        ok &= fq_pow(7, (FQ_Q - 1u) / primes[i], 31) != 1u;
    check(ok, "7 is a primitive root: 7^((q-1)/p) != 1 for every prime p | q-1");
    check(((uint64_t)5 * FQ_DINV) % ((uint64_t)FQ_Q - 1u) == 1u,
          "5 * D_INV = 1 mod (q-1), D_INV = 1717986917");

    /* arithmetic edge cases, then random identities against 64-bit % */
    ok = fq_mul(FQ_Q - 1u, FQ_Q - 1u) == 1u && fq_add(FQ_Q - 1u, 1) == 0 &&
         fq_sub(0, 1) == FQ_Q - 1u && fq_neg(0) == 0 && fq_inv(0) == 0 &&
         fq_reduce(((uint64_t)1 << 62) - 1u) == (uint32_t)((((uint64_t)1 << 62) - 1u) % FQ_Q) &&
         fq_reduce(FQ_Q) == 0 && fq_reduce((uint64_t)FQ_Q * 2u) == 0;
    for (unsigned i = 0; i < 10000 && ok; i++) {
        uint32_t a = rng_fq(), b = rng_fq();
        uint64_t ab = (uint64_t)a * b;
        ok &= fq_mul(a, b) == (uint32_t)(ab % FQ_Q);
        ok &= fq_add(a, b) == (uint32_t)(((uint64_t)a + b) % FQ_Q);
        ok &= fq_sub(a, b) == (uint32_t)(((uint64_t)a + FQ_Q - b) % FQ_Q);
        ok &= fq_pow(fq_pow(a, 5, 3), FQ_DINV, 31) == a;
        if (a != 0)
            ok &= fq_mul(a, fq_inv(a)) == 1u;
    }
    check(ok, "field ops match a 64-bit % reference on 10^4 random pairs; x^D_INV inverts x^5");

    /* Cauchy MDS: every square minor must be nonsingular */
    for (unsigned i = 0; i < CLAT_T; i++)
        for (unsigned j = 0; j < CLAT_T; j++) {
            n1++;
            bad1 += MDS[i][j] == 0;
        }
    for (unsigned i1 = 0; i1 < CLAT_T; i1++)
        for (unsigned i2 = i1 + 1; i2 < CLAT_T; i2++)
            for (unsigned j1 = 0; j1 < CLAT_T; j1++)
                for (unsigned j2 = j1 + 1; j2 < CLAT_T; j2++) {
                    uint32_t det = fq_sub(fq_mul(MDS[i1][j1], MDS[i2][j2]),
                                          fq_mul(MDS[i1][j2], MDS[i2][j1]));
                    n2++;
                    bad2 += det == 0;
                }
    for (unsigned it = 0; it < 10000; it++) {
        unsigned k = 1 + rng_below(CLAT_T);
        random_subset16(rows, k);
        random_subset16(cols, k);
        nk++;
        badk += !mds_minor_nonsingular(rows, cols, k);
    }
    snprintf(line, sizeof line, "Cauchy MDS minors nonsingular: %zu/%zu 1x1, %zu/%zu 2x2, "
             "%zu/%zu random k x k (k = 1..16)", n1 - bad1, n1, n2 - bad2, n2, nk - badk, nk);
    check(bad1 == 0 && bad2 == 0 && badk == 0, line);

    /* masked implementations agree with the unmasked ones */
    ok = 1;
    for (unsigned it = 0; it < 200; it++) {
        uint32_t x[CLAT_T], s0[CLAT_T], s1[CLAT_T], y[CLAT_T];
        rand_state(x);
        mask_split(x, s0, s1, CLAT_T);
        clat_perm_masked(s0, s1);
        mask_join(s0, s1, y, CLAT_T);
        clat_perm(x);
        ok &= (int)ct_words_equal(x, y, CLAT_T);
    }
    check(ok, "masked CLAT-P == CLAT-P on 200 random states");

    ok = 1;
    for (unsigned it = 0; it < 50; it++) {
        uint32_t in[VSS_COMMIT_IN], i0[VSS_COMMIT_IN], i1[VSS_COMMIT_IN];
        uint32_t h1[DIGEST_WORDS], h2[DIGEST_WORDS];
        for (unsigned i = 0; i < VSS_COMMIT_IN; i++)
            in[i] = rng_fq();
        mask_split(in, i0, i1, VSS_COMMIT_IN);
        clat_hash(HT_COMMIT, in, VSS_COMMIT_IN, h1, DIGEST_WORDS);
        clat_hash_masked(HT_COMMIT, i0, i1, VSS_COMMIT_IN, h2, DIGEST_WORDS);
        ok &= (int)ct_words_equal(h1, h2, DIGEST_WORDS);
    }
    check(ok, "masked sponge hash == sponge hash on 50 random 24-word inputs");

    ok = 1;
    for (unsigned it = 0; it < 20; it++) {
        uint32_t key[KEY_LIMBS], msg[KEY_LIMBS], nonce[SIV_NONCE_WORDS], hdr[SIV_HDR_WORDS];
        uint32_t k0[KEY_LIMBS], k1[KEY_LIMBS], m0[KEY_LIMBS], m1[KEY_LIMBS];
        uint32_t ref[KEY_LIMBS], got[KEY_LIMBS];
        clat_wrapped w;
        int r1, r2;
        rand_limbs(key);
        rand_limbs(msg);
        for (unsigned i = 0; i < SIV_NONCE_WORDS; i++)
            nonce[i] = rng_fq();
        hdr[0] = CLAT_VERSION_WORD; hdr[1] = it; hdr[2] = 3; hdr[3] = 5;
        ok &= clat_siv_wrap(key, nonce, hdr, msg, &w) == 0;
        if (it & 1u)                                /* odd: forged tag */
            w.tag[it % SIV_TAG_WORDS] = fq_add(w.tag[it % SIV_TAG_WORDS], 1);
        r1 = clat_siv_unwrap(key, hdr, &w, ref);
        mask_split(key, k0, k1, KEY_LIMBS);
        r2 = clat_siv_unwrap_masked(k0, k1, hdr, &w, m0, m1);
        mask_join(m0, m1, got, KEY_LIMBS);
        ok &= r1 == r2 && ct_words_equal(ref, got, KEY_LIMBS);
        ok &= (it & 1u) ? (r1 == -1 && all_zero(ref, KEY_LIMBS))
                        : (r1 == 0 && ct_words_equal(ref, msg, KEY_LIMBS));
    }
    check(ok, "masked SIV unwrap == unmasked unwrap on 20 blobs (10 valid, 10 forged tags)");

    /* key limb encoding */
    ok = 1;
    for (unsigned it = 0; it < 1000; it++) {
        uint8_t kb[KEY_BYTES], back[KEY_BYTES];
        uint32_t limbs[KEY_LIMBS];
        os_random_bytes(kb, sizeof kb);
        key_to_limbs(kb, limbs);
        for (unsigned l = 0; l < 8; l++)
            ok &= limbs[l] < (1u << 29);
        ok &= limbs[8] < (1u << 24);
        ok &= limbs_to_key(limbs, back) == 0 && memcmp(kb, back, KEY_BYTES) == 0;
    }
    {
        uint32_t limbs[KEY_LIMBS] = { 0 };
        uint8_t back[KEY_BYTES];
        limbs[3] = 1u << 29;
        ok &= limbs_to_key(limbs, back) == -1;
        limbs[3] = 0;
        limbs[8] = 1u << 24;
        ok &= limbs_to_key(limbs, back) == -1;
        for (unsigned i = 0; i < KEY_BYTES; i++)
            ok &= back[i] == 0;
    }
    check(ok, "256-bit key <-> 9 limbs round-trips 1000 keys; non-canonical limbs rejected");

    test_dead_stack();
}

/* ===================================================================== */
/* 14. Test 3: threshold vault demo                                      */
/* ===================================================================== */

static void test_vault(void)
{
    const uint32_t T = 3, N = 5;
    uint8_t mk_bytes[KEY_BYTES], kek_bytes[KEY_BYTES], out_bytes[KEY_BYTES];
    uint32_t mk[KEY_LIMBS], kek[KEY_LIMBS], nonce[SIV_NONCE_WORDS], hdr[SIV_HDR_WORDS];
    uint32_t d[VSS_D_WORDS], k0[KEY_LIMBS], k1[KEY_LIMBS], m0[KEY_LIMBS], m1[KEY_LIMBS];
    uint32_t tmp[KEY_LIMBS], c[DIGEST_WORDS], failed;
    vss_share sh[VSS_MAX_N], alt[VSS_MAX_N];
    vss_share_masked ms[VSS_MAX_N], mbad;
    vss_transcript tr, trc;
    vss_polys p;
    clat_wrapped blob, b2;
    char line[200];
    int ok, rc;
    double t0, t1;

    banner("Test 3: threshold key vault demo (3-of-5)");
    os_random_bytes(mk_bytes, sizeof mk_bytes);
    os_random_bytes(kek_bytes, sizeof kek_bytes);
    key_to_limbs(mk_bytes, mk);
    key_to_limbs(kek_bytes, kek);
    secure_zeroize(kek_bytes, sizeof kek_bytes);
    for (unsigned i = 0; i < SIV_NONCE_WORDS; i++)
        nonce[i] = rng_fq();
    hdr[0] = CLAT_VERSION_WORD; hdr[1] = 1; hdr[2] = T; hdr[3] = N;
    printf("    MK and KEK: 32 bytes each from %s\n", CLAT_RNG_NAME);

    rc = clat_siv_wrap(kek, nonce, hdr, mk, &blob);
    check(rc == 0 && vss_deal(kek, T, N, sh, &tr) == 0,
          "MK wrapped under KEK; dealer split KEK 3-of-5");

    /* dealer audit / custodian side: reference verifier, policy from the header */
    failed = vss_verify_all(&tr, hdr[2], hdr[3], sh, N);
    check(failed == 0, "all 5 shares verify against the header's 3-of-5 policy "
          "(unmasked reference verifier, dealer / custodian side)");

    /* custodian side: each custodian splits its share before sending it */
    for (uint32_t i = 0; i < N; i++)
        vss_share_mask(&sh[i], &ms[i]);

    /* combiner: sees only split shares and public data */
    t0 = wall_seconds();
    ok = vss_challenge(&tr, d) == 0;
    for (uint32_t i = 0; i < N; i++)
        ok &= (int)vss_share_valid_masked(&tr, d, &ms[i], i + 1, hdr[2], hdr[3]);
    t1 = wall_seconds();
    snprintf(line, sizeof line, "combiner: all 5 split shares verify on the masked path "
             "(%.2f ms total)", 1e3 * (t1 - t0));
    check(ok, line);

    {
        const vss_share_masked *sel[3] = { &ms[1], &ms[3], &ms[4] };
        t0 = wall_seconds();
        rc = vss_reconstruct_masked(sel, 3, k0, k1);
        mask_join(k0, k1, tmp, KEY_LIMBS);          /* unmasked here only for the check */
        check(rc == 0 && ct_words_equal(tmp, kek, KEY_LIMBS),
              "masked Lagrange at 0 from custodians {2,4,5} yields the KEK");
        rc = clat_siv_unwrap_masked(k0, k1, hdr, &blob, m0, m1);
        t1 = wall_seconds();
        mask_join(m0, m1, tmp, KEY_LIMBS);          /* unmasked here only for the check */
        snprintf(line, sizeof line, "masked SIV unwrap returns MK as 2 shares; joined MK matches "
                 "(%.2f ms reconstruct + unwrap)", 1e3 * (t1 - t0));
        check(rc == 0 && ct_words_equal(tmp, mk, KEY_LIMBS), line);
        check(limbs_to_key(tmp, out_bytes) == 0 && memcmp(out_bytes, mk_bytes, KEY_BYTES) == 0,
              "recovered MK bytes equal the original 32 bytes");
    }

    {   /* every 3-subset reconstructs; no 2-subset does */
        int ok3 = 0, n3 = 0, ok2 = 0, n2 = 0;
        for (uint32_t a = 0; a < N; a++)
            for (uint32_t b = a + 1; b < N; b++) {
                const vss_share *two[2];
                two[0] = &sh[a]; two[1] = &sh[b];
                n2++;
                ok2 += vss_reconstruct(two, 2, tmp) == 0 && ct_words_equal(tmp, kek, KEY_LIMBS);
                for (uint32_t e = b + 1; e < N; e++) {
                    const vss_share *three[3];
                    three[0] = &sh[a]; three[1] = &sh[b]; three[2] = &sh[e];
                    n3++;
                    ok3 += vss_reconstruct(three, 3, tmp) == 0 && ct_words_equal(tmp, kek, KEY_LIMBS);
                }
            }
        snprintf(line, sizeof line, "%d/%d three-custodian subsets recover the KEK; "
                 "%d/%d two-custodian subsets do", ok3, n3, ok2, n2);
        check(ok3 == n3 && ok2 == 0, line);
    }

    /* Tamper A: one bit flipped in custodian 4's share */
    memcpy(alt, sh, sizeof sh);
    alt[3].f[2] ^= 1u;
    failed = vss_verify_all(&tr, T, N, alt, N);
    vss_share_mask(&alt[3], &mbad);
    snprintf(line, sizeof line, "1-bit flip in custodian 4's share rejected (failure mask 0x%02x "
             "names custodian 4; masked verifier agrees)", (unsigned)failed);
    check(failed == (1u << 4) && vss_share_valid_masked(&tr, d, &mbad, 4, T, N) == 0, line);

    /* Tamper B: v1-style consistent forgery on custodian 2. Shift f by delta
       and adjust r so that every g-check still holds. Without a preimage
       of the commitment the forger cannot make c_2 match. */
    memcpy(alt, sh, sizeof sh);
    for (unsigned l = 0; l < KEY_LIMBS; l++) {
        uint32_t delta = rng_fq_nonzero();
        alt[1].f[l] = fq_add(alt[1].f[l], delta);
        for (unsigned k = 0; k < VSS_M; k++)
            alt[1].r[k] = fq_sub(alt[1].r[k], fq_mul(d[k * KEY_LIMBS + l], delta));
    }
    check(vss_gcheck_diff(&tr, d, &alt[1]) == 0,
          "forged share for custodian 2 satisfies every g-check (consistent forgery)");
    failed = vss_verify_all(&tr, T, N, alt, N);
    snprintf(line, sizeof line, "the forged share is rejected by its commitment (failure mask 0x%02x)",
             (unsigned)failed);
    check(failed == (1u << 2), line);
    {
        vss_share_masked fm;
        const vss_share_masked *sel[3];
        vss_share_mask(&alt[1], &fm);
        sel[0] = &fm; sel[1] = &ms[3]; sel[2] = &ms[4];
        vss_reconstruct_masked(sel, 3, k0, k1);
        rc = clat_siv_unwrap_masked(k0, k1, hdr, &blob, m0, m1);
        check(rc == -1 && all_zero(m0, KEY_LIMBS) && all_zero(m1, KEY_LIMBS),
              "if used anyway, the forged share gives a wrong KEK: unwrap fails, output wiped");
        secure_zeroize(&fm, sizeof fm);
    }

    /* Tamper C: cheating dealer gives custodian 3 an off-polynomial share
       and commits to that share */
    vss_make_polys(kek, T, &p);
    for (uint32_t i = 0; i < N; i++)
        vss_eval_share(&p, i + 1, &alt[i]);
    alt[2].f[0] = fq_add(alt[2].f[0], 1);
    vss_publish(&p, alt, N, &trc);
    secure_zeroize(&p, sizeof p);
    vss_commit(&alt[2], c);
    failed = vss_verify_all(&trc, T, N, alt, N);
    snprintf(line, sizeof line, "dealer's off-polynomial share for custodian 3 caught by the "
             "g-check (its commitment matches; failure mask 0x%02x)", (unsigned)failed);
    check(failed == (1u << 3) && ct_words_equal(c, trc.c[2], DIGEST_WORDS), line);

    /* Tamper J: complaint round. Custodian 3 complains about the cheating
       dealer of Tamper C; the dealer opens, substitutes or stays silent. */
    {
        const uint32_t who3[1] = { 3 }, who2[1] = { 2 }, who23[2] = { 2, 3 };
        const uint32_t whoT[3] = { 1, 2, 4 }, dup[2] = { 2, 2 }, out[1] = { 6 };
        const vss_share *open[3];
        vss_share sub = alt[2];
        int honest_quiet = 1, rq, rs, rn, rf, rt, rd, ro, r2;

        for (uint32_t i = 0; i < N; i++)
            honest_quiet &= !vss_should_complain(&tr, T, N, &sh[i], i + 1);
        check(honest_quiet && vss_resolve_complaints(&tr, T, N, NULL, 0, NULL) == VSS_QUALIFIED,
              "complaint round: no custodian complains about an honest dealer, who stays qualified");

        open[0] = &alt[2];
        rq = vss_resolve_complaints(&trc, T, N, who3, 1, open);
        check(vss_should_complain(&trc, T, N, &alt[2], 3) && rq == VSS_DISQUALIFIED,
              "custodian 3 complains; the dealer opens the committed bad share and is disqualified");

        sub.f[0] = fq_sub(sub.f[0], 1);                 /* back on the polynomial */
        for (unsigned j = 0; j < VSS_SALT; j++)
            sub.salt[j] = rng_fq();
        open[0] = &sub;
        rs = vss_resolve_complaints(&trc, T, N, who3, 1, open);
        open[0] = NULL;
        rn = vss_resolve_complaints(&trc, T, N, who3, 1, open);
        check(rs == VSS_DISQUALIFIED && rn == VSS_DISQUALIFIED,
              "a substituted on-polynomial opening fails the commitment, and silence also "
              "disqualifies the dealer");

        open[0] = &sh[1];                                /* false complaint by custodian 2 */
        rf = vss_resolve_complaints(&tr, T, N, who2, 1, open);
        failed = vss_verify_all(&tr, T, N, sh, N);
        check(rf == VSS_QUALIFIED && failed == 0,
              "a false complaint against an honest dealer: the opening passes, the dealer stays "
              "qualified, and custodian 2 keeps a valid share");

        open[0] = &sh[1]; open[1] = &sh[2];
        r2 = vss_resolve_complaints(&tr, T, N, who23, 2, open);
        open[0] = &sh[0]; open[1] = &sh[1]; open[2] = &sh[3];
        rt = vss_resolve_complaints(&tr, T, N, whoT, 3, open);
        check(r2 == VSS_QUALIFIED && rt == VSS_DISQUALIFIED,
              "T-1 = 2 complaints are answered; T = 3 complaints disqualify the dealer instead "
              "of opening enough shares to reveal the KEK");

        rd = vss_resolve_complaints(&tr, T, N, dup, 2, open);
        ro = vss_resolve_complaints(&tr, T, N, out, 1, open);
        check(rd == VSS_BAD_COMPLAINTS && ro == VSS_BAD_COMPLAINTS,
              "a repeated complainer or an index outside 1..N is rejected as a malformed "
              "complaint list");
        secure_zeroize(&sub, sizeof sub);
    }

    /* Tamper D: ciphertext, tag, nonce and header modifications */
    {
        static const char *what[4] = { "ciphertext", "tag", "nonce", "header" };
        int all = 1;
        for (unsigned v = 0; v < 4; v++) {
            uint32_t h2[SIV_HDR_WORDS];
            const vss_share_masked *sel[3];
            sel[0] = &ms[1]; sel[1] = &ms[3]; sel[2] = &ms[4];
            memcpy(h2, hdr, sizeof h2);
            b2 = blob;
            if (v == 0) b2.ct[4] ^= 1u;
            if (v == 1) b2.tag[6] ^= 1u;
            if (v == 2) b2.nonce[0] ^= 1u;
            if (v == 3) h2[1] = 2;                  /* different key id */
            vss_reconstruct_masked(sel, 3, k0, k1);
            memset(m0, 0xFF, sizeof m0);
            memset(m1, 0xFF, sizeof m1);
            rc = clat_siv_unwrap_masked(k0, k1, h2, &b2, m0, m1);
            ok = rc == -1 && all_zero(m0, KEY_LIMBS) && all_zero(m1, KEY_LIMBS);
            printf("    %-10s modified: %s\n", what[v], ok ? "rejected, output wiped" : "NOT rejected");
            all &= ok;
        }
        check(all, "ciphertext / tag / nonce / header modifications rejected and output wiped");
    }

    /* Tamper E: malformed public transcripts are rejected before use */
    {
        vss_transcript trx;
        uint32_t f17, fg, dz[VSS_D_WORDS];
        trx = tr;
        trx.N = VSS_MAX_N + 1;                  /* would overflow vss_challenge's buffer */
        f17 = vss_verify_all(&trx, T, trx.N, sh, N);
        ok = (f17 & VSS_FAIL_TRANSCRIPT) && vss_challenge(&trx, dz) == -1 &&
             vss_share_valid_masked(&trx, d, &ms[0], 1, T, trx.N) == 0;
        trx = tr;
        trx.g[0][0] += FQ_Q;                    /* same polynomial mod q, non-canonical */
        fg = vss_verify_all(&trx, T, N, sh, N);
        ok &= (fg & VSS_FAIL_TRANSCRIPT) && vss_share_valid_masked(&trx, d, &ms[0], 1, T, N) == 0;
        snprintf(line, sizeof line, "transcript with N = %u rejected before hashing (mask 0x%02x); "
                 "non-canonical g coefficient rejected as malformed (mask 0x%02x)",
                 (unsigned)(VSS_MAX_N + 1), (unsigned)f17, (unsigned)fg);
        check(ok, line);
    }

    /* Tamper F: blame lands on the sender, not on the index it claims */
    {
        uint32_t fr, f34, mr, m34;
        vss_share_masked mm;
        memcpy(alt, sh, sizeof sh);
        alt[4] = sh[1];                         /* custodian 5 replays custodian 2's share */
        fr = vss_verify_all(&tr, T, N, alt, N);
        vss_share_mask(&alt[4], &mm);
        mr = vss_share_valid_masked(&tr, d, &mm, 5, T, N);
        memcpy(alt, sh, sizeof sh);
        alt[4].x = 34;                          /* = 2 + 32: used to alias bit 2 */
        f34 = vss_verify_all(&tr, T, N, alt, N);
        vss_share_mask(&alt[4], &mm);
        m34 = vss_share_valid_masked(&tr, d, &mm, 5, T, N);
        snprintf(line, sizeof line, "custodian 5 sending custodian 2's share, or index 34, is "
                 "blamed itself (masks 0x%02x, 0x%02x; masked verifier rejects both)",
                 (unsigned)fr, (unsigned)f34);
        check(fr == (1u << 5) && f34 == (1u << 5) && mr == 0 && m34 == 0, line);
    }

    /* Tamper G: the sharing's threshold must be the header's threshold */
    {
        uint32_t fp, mp, dg[VSS_D_WORDS];
        vss_share_masked mg;
        rc = vss_deal(kek, N, N, alt, &trc);    /* dealer secretly uses 5-of-5 */
        fp = vss_verify_all(&trc, hdr[2], hdr[3], alt, N);
        vss_share_mask(&alt[0], &mg);
        mp = (uint32_t)(vss_challenge(&trc, dg) == 0) &
             vss_share_valid_masked(&trc, dg, &mg, 1, hdr[2], hdr[3]);
        snprintf(line, sizeof line, "5-of-5 sharing under a 3-of-5 header rejected as a policy "
                 "mismatch (mask 0x%02x; masked verifier agrees)", (unsigned)fp);
        check(rc == 0 && (fp & VSS_FAIL_TRANSCRIPT) && mp == 0, line);
    }

    /* Tamper H: reconstruction refuses points outside 1..VSS_MAX_N */
    {
        const vss_share *three[3];
        int r_big, r_zero;
        memcpy(alt, sh, sizeof sh);
        alt[2].x = 3u + FQ_Q;                   /* = 3 mod q, but not canonical */
        three[0] = &alt[0]; three[1] = &alt[1]; three[2] = &alt[2];
        r_big = vss_reconstruct(three, 3, tmp);
        alt[2].x = 0;
        r_zero = vss_reconstruct(three, 3, tmp);
        check(r_big == -1 && r_zero == -1,
              "reconstruction rejects x = 3 + q and x = 0 instead of returning a wrong secret");
    }

    /* Tamper I: keys outside key range (domain separation needs limb 8 < 2^24) */
    {
        uint32_t kbad[KEY_LIMBS];
        int r_wrap, r_deal;
        memcpy(kbad, kek, sizeof kbad);
        kbad[8] += 1u << 29;                    /* still < q: MAC state would equal ENC state */
        r_wrap = clat_siv_wrap(kbad, nonce, hdr, mk, &b2);
        r_deal = vss_deal(kbad, T, N, alt, &trc);
        check(r_wrap == -1 && r_deal == -1 && key_limbs_ok(kek) == 1,
              "wrap and deal reject a canonical key with limb 8 >= 2^24 (domain collision)");
        secure_zeroize(kbad, sizeof kbad);
    }

    secure_zeroize(mk, sizeof mk);
    secure_zeroize(kek, sizeof kek);
    secure_zeroize(mk_bytes, sizeof mk_bytes);
    secure_zeroize(out_bytes, sizeof out_bytes);
    secure_zeroize(k0, sizeof k0);
    secure_zeroize(k1, sizeof k1);
    secure_zeroize(m0, sizeof m0);
    secure_zeroize(m1, sizeof m1);
    secure_zeroize(tmp, sizeof tmp);
    secure_zeroize(sh, sizeof sh);
    secure_zeroize(alt, sizeof alt);
    secure_zeroize(ms, sizeof ms);
    secure_zeroize(&mbad, sizeof mbad);
}

/* ===================================================================== */
/* 15. Test 4: degree growth / integral property on reduced rounds        */
/* ===================================================================== */
/* After R rounds every output word is a polynomial of degree <= 5^R in t
   along the line a + t e_0. For a subgroup H < F_q^* of order d > 5^R,
   sum_{t in H} t^k = 0 for 0 < k < d, so sum_{t in H} E_R(a + t e_0) =
   d * E_R(a) with probability 1. */

static int cmp_u32(const void *a, const void *b)
{
    uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;
    return (x > y) - (x < y);
}

static size_t divisors_qm1(uint32_t *out)
{
    static const uint32_t primes[7] = { 2, 3, 7, 11, 31, 151, 331 };
    static const unsigned exps[7]   = { 1, 2, 1, 1, 1, 1, 1 };
    size_t n = 1;
    out[0] = 1;
    for (unsigned i = 0; i < 7; i++) {
        size_t cur = n;
        uint32_t pk = 1;
        for (unsigned e = 1; e <= exps[i]; e++) {
            pk *= primes[i];
            for (size_t j = 0; j < cur; j++)
                out[n++] = out[j] * pk;
        }
    }
    qsort(out, n, sizeof *out, cmp_u32);
    return n;
}

static int integral_sum_holds(unsigned R, uint32_t d, const uint32_t a[CLAT_T])
{
    uint32_t h = fq_pow(7, (FQ_Q - 1u) / d, 31), t = 1;
    uint32_t sum[CLAT_T] = { 0 }, x[CLAT_T], base[CLAT_T];
    for (uint32_t k = 0; k < d; k++) {
        memcpy(x, a, sizeof x);
        x[0] = fq_add(x[0], t);
        clat_perm_rounds(x, R);
        for (unsigned i = 0; i < CLAT_T; i++)
            sum[i] = fq_add(sum[i], x[i]);
        t = fq_mul(t, h);
    }
    memcpy(base, a, sizeof base);
    clat_perm_rounds(base, R);
    for (unsigned i = 0; i < CLAT_T; i++)
        if (sum[i] != fq_mul(d, base[i]))
            return 0;
    return 1;
}

static void test_degree(void)
{
    uint32_t divs[256];
    size_t nd = divisors_qm1(divs);
    int all_pos = 1, all_neg = 1;
    uint64_t pw = 1;

    banner("Test 4: degree growth (integral property) on reduced rounds");
    printf("    q-1 has %zu divisors; d = subgroup order, 5^R = degree bound after R rounds\n", nd);
    printf("     R      5^R   d > 5^R   relation   control d <= 5^R   relation\n");
    for (unsigned R = 1; R <= 7; R++) {
        uint32_t dpos = 0, dneg = 0, a[CLAT_T];
        int hp, hn;
        pw *= 5;
        for (size_t i = 0; i < nd; i++) {
            if (divs[i] > pw && dpos == 0)
                dpos = divs[i];
            if (divs[i] <= pw)
                dneg = divs[i];
        }
        rand_state(a);
        hp = integral_sum_holds(R, dpos, a);
        hn = integral_sum_holds(R, dneg, a);
        printf("    %2u %8llu   %7u   %-8s   %7u            %s\n", R, (unsigned long long)pw,
               (unsigned)dpos, hp ? "holds" : "fails", (unsigned)dneg, hn ? "holds" : "fails");
        all_pos &= hp;
        all_neg &= !hn;
    }
    check(all_pos, "sum over H equals d * E_R(a) for every R = 1..7 when d > 5^R");
    check(all_neg, "negative control (d <= 5^R) fails for every R = 1..7");

    /* Arithmetic on the constants, printed as information (not a check).
       On a set that is a full product F_q^k x {const}, the first S-box
       layer (x + c)^5 is a bijection on each free word, so it maps the set
       onto another such set; only the remaining R - 1 rounds raise the
       degree, to at most 5^(R-1). Single word: summing over the whole line
       (F_q^* plus 0) is a zero-sum while 5^(R-1) < q-1. k words: a zero-sum
       over F_q^k (data q^k) is guaranteed while 5^(R-1) < k(q-1), so an
       R-round zero-sum needs k >= floor(5^(R-1) / (q-1)) + 1 words. */
    {
        uint64_t pr = 1;            /* 5^(R-1) */
        unsigned reach4 = 0;        /* last R whose zero-sum needs k <= 4 */
        for (unsigned R = 1; R <= CLAT_ROUNDS; R++) {
            uint64_t k = pr / ((uint64_t)FQ_Q - 1u) + 1u;
            if (k <= 4)
                reach4 = R;
            if (R == 14 || R == 15 || R == 16 || R == CLAT_ROUNDS)
                printf("    info: R = %2u, 5^(R-1) = %llu: whole-line sum %s; a full-space "
                       "zero-sum needs k >= %llu input words\n", R, (unsigned long long)pr,
                       pr < (uint64_t)FQ_Q - 1u ? "available" : "unavailable",
                       (unsigned long long)k);
            pr *= 5;
        }
        printf("    info: with at most 2^128 data (k <= 4) a forward zero-sum reaches "
               "R = %u; one backward round adds 1, leaving a %u-round margin at R = %u\n",
               reach4, (unsigned)CLAT_ROUNDS - reach4 - 1u, (unsigned)CLAT_ROUNDS);
    }
}

/* ===================================================================== */
/* 16. Test 5: dudect timing test                                        */
/* ===================================================================== */
/* Fixed-vs-random input classes, class drawn per measurement from the OS
   RNG, inputs prepared before timing. Welch t on raw timings and on
   timings cropped at several upper percentiles; the verdict uses the
   largest |t| over all crops. */

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

static double dudect_analyse(const uint64_t *t, const uint8_t *cls, size_t n)
{
    static const double crop[6] = { 1.0, 0.99, 0.95, 0.90, 0.75, 0.50 };
    uint64_t *sorted = malloc(n * sizeof *sorted);
    double maxt = 0.0;
    if (!sorted)
        fatal("out of memory");
    memcpy(sorted, t, n * sizeof *sorted);
    qsort(sorted, n, sizeof *sorted, cmp_u64);
    printf("      crop   n(fixed)  n(random)  mean fixed  mean random        t\n");
    for (unsigned c = 0; c < 6; c++) {
        uint64_t thr = sorted[(size_t)(crop[c] * (double)(n - 1))];
        welford w[2] = { { 0, 0, 0 }, { 0, 0, 0 } };
        double tt;
        for (size_t i = 0; i < n; i++)
            if (t[i] <= thr)
                welford_add(&w[cls[i]], (double)t[i]);
        tt = welch_t(&w[0], &w[1]);
        printf("      %3.0f%%  %9.0f  %9.0f  %10.1f  %11.1f  %7.2f\n", 100.0 * crop[c],
               w[0].n, w[1].n, w[0].mean, w[1].mean, tt);
        if (fabs(tt) > maxt)
            maxt = fabs(tt);
    }
    free(sorted);
    return maxt;
}

static void dudect_perm(size_t n)
{
    const size_t B = 8192;
    uint32_t (*in)[CLAT_T] = malloc(B * sizeof *in);
    uint64_t *t = malloc(n * sizeof *t);
    uint8_t *cls = malloc(n);
    uint32_t fixed[CLAT_T];
    double maxt;
    char line[160];
    if (!in || !t || !cls)
        fatal("out of memory");
    rand_state(fixed);
    for (size_t done = 0; done < n;) {
        size_t b = (n - done < B) ? n - done : B;
        for (size_t i = 0; i < b; i++) {
            cls[done + i] = (uint8_t)(rng_u32() & 1u);
            if (cls[done + i])
                rand_state(in[i]);
            else
                memcpy(in[i], fixed, sizeof fixed);
        }
        for (size_t i = 0; i < b; i++) {
            uint64_t t0 = cycle_count();
            clat_perm(in[i]);
            t[done + i] = cycle_count() - t0;
        }
        done += b;
    }
    printf("    (a) CLAT-P, %zu measurements\n", n);
    maxt = dudect_analyse(t, cls, n);
    snprintf(line, sizeof line, "dudect CLAT-P: max |t| = %.2f (threshold 4.5)", maxt);
    stat_verdict(maxt < 4.5, line);
    free(in);
    free(t);
    free(cls);
}

/* Masked unwrap. Fixed class: the KEK that opens the blob. Random class:
   a fresh random key, so the tag check fails. A constant-time unwrap must
   not separate the two. Every call gets fresh masks in both classes. */
static void dudect_unwrap(size_t n)
{
    const size_t B = 2048;
    uint32_t (*k0)[KEY_LIMBS] = malloc(B * sizeof *k0);
    uint32_t (*k1)[KEY_LIMBS] = malloc(B * sizeof *k1);
    uint64_t *t = malloc(n * sizeof *t);
    uint8_t *cls = malloc(n);
    uint32_t kek[KEY_LIMBS], mk[KEY_LIMBS], nonce[SIV_NONCE_WORDS], hdr[SIV_HDR_WORDS];
    uint32_t m0[KEY_LIMBS], m1[KEY_LIMBS], key[KEY_LIMBS];
    size_t opened[2] = { 0, 0 }, count[2] = { 0, 0 };
    clat_wrapped blob;
    double maxt;
    char line[200];
    if (!k0 || !k1 || !t || !cls)
        fatal("out of memory");
    rand_limbs(kek);
    rand_limbs(mk);
    for (unsigned i = 0; i < SIV_NONCE_WORDS; i++)
        nonce[i] = rng_fq();
    hdr[0] = CLAT_VERSION_WORD; hdr[1] = 1; hdr[2] = 3; hdr[3] = 5;
    clat_siv_wrap(kek, nonce, hdr, mk, &blob);

    for (size_t done = 0; done < n;) {
        size_t b = (n - done < B) ? n - done : B;
        for (size_t i = 0; i < b; i++) {
            cls[done + i] = (uint8_t)(rng_u32() & 1u);
            if (cls[done + i])
                rand_limbs(key);
            else
                memcpy(key, kek, sizeof key);
            mask_split(key, k0[i], k1[i], KEY_LIMBS);
        }
        for (size_t i = 0; i < b; i++) {
            uint64_t t0 = cycle_count();
            int rc = clat_siv_unwrap_masked(k0[i], k1[i], hdr, &blob, m0, m1);
            t[done + i] = cycle_count() - t0;
            count[cls[done + i]]++;
            opened[cls[done + i]] += (rc == 0);
        }
        done += b;
    }
    printf("    (b) masked SIV unwrap, %zu measurements\n", n);
    maxt = dudect_analyse(t, cls, n);
    snprintf(line, sizeof line, "fixed-class key opened the blob %zu/%zu times; random keys "
             "opened it %zu/%zu times", opened[0], count[0], opened[1], count[1]);
    check(opened[0] == count[0] && opened[1] == 0, line);
    snprintf(line, sizeof line, "dudect masked unwrap: max |t| = %.2f (threshold 4.5)", maxt);
    stat_verdict(maxt < 4.5, line);
    secure_zeroize(kek, sizeof kek);
    secure_zeroize(mk, sizeof mk);
    secure_zeroize(key, sizeof key);
    secure_zeroize(m0, sizeof m0);
    secure_zeroize(m1, sizeof m1);
    secure_zeroize(k0, B * sizeof *k0);
    secure_zeroize(k1, B * sizeof *k1);
    free(k0);
    free(k1);
    free(t);
    free(cls);
}

static void test_dudect(void)
{
    size_t n_perm = g_full ? 1000000 : 100000;
    size_t n_unwrap = g_full ? 400000 : 100000;
    banner("Test 5: dudect constant-time test (fixed vs random)");
#if defined(CLAT_HAVE_RDTSC)
    printf("    timer: rdtsc with lfence\n");
#elif defined(_WIN32)
    printf("    timer: QueryPerformanceCounter\n");
#else
    printf("    timer: clock_gettime(CLOCK_MONOTONIC)\n");
#endif
    dudect_perm(n_perm);
    dudect_unwrap(n_unwrap);
}

/* ===================================================================== */
/* 17. Test 6: simulated-leakage TVLA                                     */
/* ===================================================================== */
/* Two leakage models per sample, no noise: HW of the value (value model)
   and HD to the previous LEAK value (transition model). Fixed vs random
   secret input, class drawn per trace, fresh masks in both classes. Welch
   t per sample and model. As in the usual TVLA procedure, two independent
   data sets are collected and a sample counts as leaking only if |t| > 4.5
   in both. Targets:
     unmasked  CLAT-P on a secret state
     masked    masked CLAT-P on a secret state
     combine   combiner pipeline: masked Lagrange at 0 from three split
               shares, then masked SIV unwrap to MK shares. Secret: the
               share values (fixed set vs a fresh sharing of the same KEK),
               so the public blob is identical in both classes
     verify    masked verification of one split share: masked commitment
               hash and g-check (secret: the share; the public transcript
               of each fresh sharing differs, as it must)
   KEK and MK leakage inside the permutation calls is covered by the
   masked target. Public values (digests, transcript, blob) are not
   traced. This is a
   simulation of the trace order in this C code; it says nothing about
   what a compiler or CPU does with registers on real hardware. */

#define LEAK_CAP (1u << 18)

enum { TV_PLAIN, TV_MASKED, TV_COMBINE, TV_VERIFY };

typedef struct {
    int            kind;
    uint32_t       state[CLAT_T];          /* fixed class, perm targets   */
    vss_share      sh[VSS_MAX_N];          /* fixed class, vault targets  */
    vss_transcript tr;
    uint32_t       d[VSS_D_WORDS];
    clat_wrapped   blob;
    uint32_t       hdr[SIV_HDR_WORDS];
    uint32_t       kek[KEY_LIMBS];
    size_t         func_fail;              /* traces whose operation failed */
} tvla_ctx;

static tvla_ctx g_tv;

static void tvla_fixed_inputs(int kind)
{
    uint32_t kek[KEY_LIMBS], mk[KEY_LIMBS], nonce[SIV_NONCE_WORDS];
    memset(&g_tv, 0, sizeof g_tv);
    g_tv.kind = kind;
    rand_state(g_tv.state);
    rand_limbs(kek);
    rand_limbs(mk);
    for (unsigned i = 0; i < SIV_NONCE_WORDS; i++)
        nonce[i] = rng_fq();
    g_tv.hdr[0] = CLAT_VERSION_WORD; g_tv.hdr[1] = 1; g_tv.hdr[2] = 3; g_tv.hdr[3] = 5;
    if (clat_siv_wrap(kek, nonce, g_tv.hdr, mk, &g_tv.blob) != 0 ||
        vss_deal(kek, 3, 5, g_tv.sh, &g_tv.tr) != 0 || vss_challenge(&g_tv.tr, g_tv.d) != 0)
        fatal("TVLA setup failed");
    memcpy(g_tv.kek, kek, sizeof kek);
    secure_zeroize(kek, sizeof kek);
    secure_zeroize(mk, sizeof mk);
}

/* One trace of class c (0 = fixed, 1 = random). Inputs are prepared and
   split before recording starts; only the target runs while recording. */
static void tvla_trace(unsigned c)
{
    uint32_t st[CLAT_T], s0[CLAT_T], s1[CLAT_T];
    uint32_t k0[KEY_LIMBS], k1[KEY_LIMBS], m0[KEY_LIMBS], m1[KEY_LIMBS];
    uint32_t dr[VSS_D_WORDS];
    vss_share rsh[VSS_MAX_N];
    vss_share_masked ms[3];
    vss_transcript rtr;
    const vss_share *src = g_tv.sh;
    const vss_transcript *tr = &g_tv.tr;
    const uint32_t *d = g_tv.d;
    int fail = 0;

    if (g_tv.kind == TV_PLAIN || g_tv.kind == TV_MASKED) {
        if (c)
            rand_state(st);
        else
            memcpy(st, g_tv.state, sizeof st);
        if (g_tv.kind == TV_MASKED)
            mask_split(st, s0, s1, CLAT_T);
    } else if (c) {                             /* fresh sharing of the same KEK */
        if (vss_deal(g_tv.kek, 3, 5, rsh, &rtr) != 0 || vss_challenge(&rtr, dr) != 0)
            fatal("TVLA setup failed");
        src = rsh; tr = &rtr; d = dr;
    }
    if (g_tv.kind == TV_COMBINE) {              /* custodians 2, 4, 5 split their shares */
        vss_share_mask(&src[1], &ms[0]);
        vss_share_mask(&src[3], &ms[1]);
        vss_share_mask(&src[4], &ms[2]);
    } else if (g_tv.kind == TV_VERIFY) {
        vss_share_mask(&src[1], &ms[0]);
    }

    g_leak.n = 0;
    g_leak.prev = 0;
    g_leak.on = 1;
    switch (g_tv.kind) {
    case TV_PLAIN:
        clat_perm(st);
        break;
    case TV_MASKED:
        clat_perm_masked(s0, s1);
        break;
    case TV_COMBINE: {
        const vss_share_masked *sel[3] = { &ms[0], &ms[1], &ms[2] };
        fail = vss_reconstruct_masked(sel, 3, k0, k1) != 0;
        fail |= clat_siv_unwrap_masked(k0, k1, g_tv.hdr, &g_tv.blob, m0, m1) != 0;
        break;
    }
    default:
        fail = vss_share_valid_masked(tr, d, &ms[0], 2, tr->T, tr->N) != 1;   /* ms[0] is custodian 2 */
        break;
    }
    g_leak.on = 0;
    g_tv.func_fail += (size_t)fail;
    secure_zeroize(rsh, sizeof rsh);
    secure_zeroize(ms, sizeof ms);
    secure_zeroize(k0, sizeof k0);
    secure_zeroize(k1, sizeof k1);
    secure_zeroize(m0, sizeof m0);
    secure_zeroize(m1, sizeof m1);
}

typedef struct {
    size_t  ns;
    double  maxt[2];        /* [0] HW model, [1] HD model */
    double *t[2];
} tvla_set;

static void tvla_collect(size_t ntraces, tvla_set *out)
{
    uint64_t *sum[2][2], *sq[2][2], n[2] = { 0, 0 };   /* [model][class] */
    size_t ns = 0;
    for (int m = 0; m < 2; m++)
        for (int c = 0; c < 2; c++) {
            sum[m][c] = calloc(LEAK_CAP, sizeof(uint64_t));
            sq[m][c] = calloc(LEAK_CAP, sizeof(uint64_t));
            if (!sum[m][c] || !sq[m][c])
                fatal("out of memory");
        }
    for (size_t tr = 0; tr < ntraces; tr++) {
        unsigned c = rng_u32() & 1u;
        tvla_trace(c);
        if (g_leak.n > LEAK_CAP || (ns != 0 && g_leak.n != ns))
            fatal("leakage trace length unexpected");
        ns = g_leak.n;
        for (size_t i = 0; i < ns; i++) {
            uint64_t hw = g_leak.hw[i], hd = g_leak.hd[i];
            sum[0][c][i] += hw;
            sq[0][c][i] += hw * hw;
            sum[1][c][i] += hd;
            sq[1][c][i] += hd * hd;
        }
        n[c]++;
    }
    out->ns = ns;
    for (int m = 0; m < 2; m++) {
        out->maxt[m] = 0.0;
        out->t[m] = malloc(ns * sizeof(double));
        if (!out->t[m])
            fatal("out of memory");
        for (size_t i = 0; i < ns; i++) {
            double n0 = (double)n[0], n1 = (double)n[1];
            double m0 = (double)sum[m][0][i] / n0, m1 = (double)sum[m][1][i] / n1;
            double v0 = ((double)sq[m][0][i] - n0 * m0 * m0) / (n0 - 1.0);
            double v1 = ((double)sq[m][1][i] - n1 * m1 * m1) / (n1 - 1.0);
            double t = welch_t_from(n0, m0, v0 < 0 ? 0 : v0, n1, m1, v1 < 0 ? 0 : v1);
            out->t[m][i] = t;
            if (fabs(t) > out->maxt[m])
                out->maxt[m] = fabs(t);
        }
    }
    for (int m = 0; m < 2; m++)
        for (int c = 0; c < 2; c++) {
            free(sum[m][c]);
            free(sq[m][c]);
        }
}

/* Writes the number of samples with |t| > 4.5 in both data sets, per model. */
static void tvla_run(const char *name, int kind, size_t ntraces, size_t confirmed[2])
{
    static const char *model[2] = { "HW", "HD" };
    tvla_set a, b;
    double t0 = wall_seconds();
    tvla_fixed_inputs(kind);
    tvla_collect(ntraces, &a);
    tvla_collect(ntraces, &b);
    printf("    %-8s %6zu samples/trace, 2 sets x %zu traces  (%.1f s)\n",
           name, a.ns, ntraces, wall_seconds() - t0);
    for (int m = 0; m < 2; m++) {
        size_t over_a = 0, over_b = 0;
        confirmed[m] = 0;
        for (size_t i = 0; i < a.ns; i++) {
            int oa = fabs(a.t[m][i]) > 4.5, ob = fabs(b.t[m][i]) > 4.5;
            over_a += oa;
            over_b += ob;
            confirmed[m] += oa && ob;
        }
        printf("             %s: max|t| = %.2f / %.2f, samples over 4.5: %zu / %zu, "
               "in both sets: %zu\n", model[m], a.maxt[m], b.maxt[m], over_a, over_b,
               confirmed[m]);
        free(a.t[m]);
        free(b.t[m]);
    }
}

static void test_tvla(void)
{
    static const char *tname[4] = { "unmasked", "masked", "combine", "verify" };
    size_t ntr[4], leaks[4][2], vault_fail = 0;
    char line[240];

    ntr[TV_PLAIN] = g_full ? 20000 : 2000;
    ntr[TV_MASKED] = g_full ? 100000 : 10000;
    ntr[TV_COMBINE] = g_full ? 20000 : 3000;
    ntr[TV_VERIFY] = g_full ? 20000 : 3000;

    banner("Test 6: simulated-leakage TVLA (HW value model and HD transition model)");
    g_leak.hw = malloc(LEAK_CAP);
    g_leak.hd = malloc(LEAK_CAP);
    g_leak.cap = LEAK_CAP;
    if (!g_leak.hw || !g_leak.hd)
        fatal("out of memory");
    for (int k = TV_PLAIN; k <= TV_VERIFY; k++) {
        tvla_run(tname[k], k, ntr[k], leaks[k]);
        if (k >= TV_COMBINE)
            vault_fail += g_tv.func_fail;
    }
    secure_zeroize(&g_tv, sizeof g_tv);

    snprintf(line, sizeof line, "unmasked CLAT-P leaks at %zu (HW) / %zu (HD) samples "
             "(the test detects leakage)", leaks[TV_PLAIN][0], leaks[TV_PLAIN][1]);
    check(leaks[TV_PLAIN][0] > 0 && leaks[TV_PLAIN][1] > 0, line);
    snprintf(line, sizeof line, "every traced combine and verify operation succeeded "
             "(%zu failures in %zu traces)", vault_fail, 2 * (ntr[TV_COMBINE] + ntr[TV_VERIFY]));
    check(vault_fail == 0, line);
    for (int k = TV_MASKED; k <= TV_VERIFY; k++) {
        snprintf(line, sizeof line, "%s: %zu (HW) / %zu (HD) samples leak at first order in the "
                 "simulated HW and HD models", tname[k], leaks[k][0], leaks[k][1]);
        stat_verdict(leaks[k][0] == 0 && leaks[k][1] == 0, line);
    }
    free(g_leak.hw);
    free(g_leak.hd);
    g_leak.hw = NULL;
    g_leak.hd = NULL;
    g_leak.cap = 0;
}

/* ===================================================================== */
/* 18. Test 7: statistical sanity checks (sanity, not proof)             */
/* ===================================================================== */

#define SAC_BITS (CLAT_T * 31)      /* 496 input and output bits */

static void test_sanity(void)
{
    static uint32_t cnt[SAC_BITS][SAC_BITS];
    uint32_t nin[SAC_BITS];
    size_t trials = g_full ? 1000 : 200, skipped = 0, over5 = 0;
    double total = 0.0, flips = 0.0, maxz = 0.0, zmean;
    uint64_t ones[31] = { 0 }, bytes[256] = { 0 }, nwords = 0, nbytes = 0;
    double maxzb = 0.0, H = 0.0, chi2 = 0.0, wh;
    size_t nperm = g_full ? 65536 : 8192;
    uint64_t acc = 0;
    unsigned accbits = 0;
    char line[200];

    banner("Test 7: statistical sanity checks (sanity, not proof)");

    /* strict avalanche: flip each input bit, count flipped output bits */
    memset(cnt, 0, sizeof cnt);
    memset(nin, 0, sizeof nin);
    for (size_t tr = 0; tr < trials; tr++) {
        uint32_t x[CLAT_T], y[CLAT_T];
        rand_state(x);
        memcpy(y, x, sizeof y);
        clat_perm(y);
        for (unsigned w = 0; w < CLAT_T; w++)
            for (unsigned b = 0; b < 31; b++) {
                uint32_t x2[CLAT_T];
                unsigned ib = w * 31 + b;
                memcpy(x2, x, sizeof x2);
                x2[w] ^= 1u << b;
                if (x2[w] == FQ_Q) {     /* not a field element: skip */
                    skipped++;
                    continue;
                }
                clat_perm(x2);
                nin[ib]++;
                for (unsigned ow = 0; ow < CLAT_T; ow++) {
                    uint32_t dif = x2[ow] ^ y[ow];
                    for (unsigned ob = 0; ob < 31; ob++)
                        cnt[ib][ow * 31 + ob] += (dif >> ob) & 1u;
                }
            }
    }
    for (unsigned ib = 0; ib < SAC_BITS; ib++)
        for (unsigned ob = 0; ob < SAC_BITS; ob++) {
            double p = (double)cnt[ib][ob] / (double)nin[ib];
            double z = (p - 0.5) / sqrt(0.25 / (double)nin[ib]);
            flips += cnt[ib][ob];
            total += nin[ib];
            if (fabs(z) > maxz)
                maxz = fabs(z);
            over5 += fabs(z) > 5.0;
        }
    zmean = (flips / total - 0.5) / sqrt(0.25 / total);
    printf("    SAC: %zu trials x 496 input bits (%zu skipped), 496 output bits\n", trials, skipped);
    printf("         mean flip rate %.6f (z = %.2f), max per-cell |z| = %.2f,"
           " cells with |z| > 5: %zu of %d\n", flips / total, zmean, maxz, over5, SAC_BITS * SAC_BITS);
    snprintf(line, sizeof line, "SAC: |z| of mean flip rate %.2f < 5 and max per-cell |z| %.2f < 6",
             fabs(zmean), maxz);
    stat_verdict(fabs(zmean) < 5.0 && maxz < 6.0, line);

    /* bit balance and byte entropy of CLAT-P(i, 0, ..., 0), i = 0, 1, ... */
    for (size_t i = 0; i < nperm; i++) {
        uint32_t st[CLAT_T] = { 0 };
        st[0] = (uint32_t)i;
        clat_perm(st);
        for (unsigned w = 0; w < CLAT_T; w++) {
            nwords++;
            for (unsigned b = 0; b < 31; b++)
                ones[b] += (st[w] >> b) & 1u;
            acc |= (uint64_t)st[w] << accbits;   /* pack 31-bit words into a bit stream */
            accbits += 31;
            while (accbits >= 8) {
                bytes[acc & 0xFFu]++;
                nbytes++;
                acc >>= 8;
                accbits -= 8;
            }
        }
    }
    for (unsigned b = 0; b < 31; b++) {
        double z = ((double)ones[b] / (double)nwords - 0.5) / sqrt(0.25 / (double)nwords);
        if (fabs(z) > maxzb)
            maxzb = fabs(z);
    }
    for (unsigned v = 0; v < 256; v++) {
        double pv = (double)bytes[v] / (double)nbytes;
        double e = (double)nbytes / 256.0;
        if (bytes[v])
            H -= pv * log2(pv);
        chi2 += ((double)bytes[v] - e) * ((double)bytes[v] - e) / e;
    }
    /* Wilson-Hilferty approximation of the chi^2(255) quantile at z = 3.719 (p = 0.9999) */
    wh = 255.0 * pow(1.0 - 2.0 / (9.0 * 255.0) + 3.719 * sqrt(2.0 / (9.0 * 255.0)), 3.0);
    printf("    bit balance: %llu words, max |z| over 31 bit positions = %.2f\n",
           (unsigned long long)nwords, maxzb);
    printf("    bytes: %llu, Shannon entropy = %.5f bits/byte, chi^2(255) = %.1f"
           " (0.9999 quantile %.1f)\n", (unsigned long long)nbytes, H, chi2, wh);
    snprintf(line, sizeof line, "bit balance max |z| %.2f < 5; byte chi^2 %.1f below the 0.9999 quantile",
             maxzb, chi2);
    stat_verdict(maxzb < 5.0 && chi2 < wh, line);
}

/* ===================================================================== */
/* 19. main                                                              */
/* ===================================================================== */

int main(int argc, char **argv)
{
    double t_start, t;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--full") == 0) {
            g_full = 1;
        } else {
            fprintf(stderr, "usage: %s [--full]\n", argv[0]);
            return 2;
        }
    }

    t_start = wall_seconds();
    printf("CLAT-VSS v2 test suite (%s mode)\n", g_full ? "full" : "default");
    printf("  field q = 2^31 - 1; CLAT-P t = %d, R = %d; sponge rate 7, capacity 9\n",
           CLAT_T, CLAT_ROUNDS);
    printf("  OS randomness: %s\n", CLAT_RNG_NAME);
#if defined(__VERSION__)
    printf("  compiler: %s\n", __VERSION__);
#endif
    clat_init();

    t = wall_seconds(); test_kat();       printf("  (%.2f s)\n", wall_seconds() - t);
    t = wall_seconds(); test_selftests(); printf("  (%.2f s)\n", wall_seconds() - t);
    t = wall_seconds(); test_vault();     printf("  (%.2f s)\n", wall_seconds() - t);
    t = wall_seconds(); test_degree();    printf("  (%.2f s)\n", wall_seconds() - t);
    t = wall_seconds(); test_dudect();    printf("  (%.2f s)\n", wall_seconds() - t);
    t = wall_seconds(); test_tvla();      printf("  (%.2f s)\n", wall_seconds() - t);
    t = wall_seconds(); test_sanity();    printf("  (%.2f s)\n", wall_seconds() - t);

    printf("\n== Summary ==\n");
    printf("  functional checks : %d/%d passed\n", g_func_total - g_func_fail, g_func_total);
    printf("  statistical tests : %d/%d passed\n", g_stat_total - g_stat_fail, g_stat_total);
    printf("  total time        : %.1f s\n", wall_seconds() - t_start);
    secure_zeroize(rng_buf, sizeof rng_buf);
    return g_func_fail ? 1 : 0;
}
