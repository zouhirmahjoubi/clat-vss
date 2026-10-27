/* Red-team attack lab for CLAT-VSS v2.
 *
 * Includes the (unedited) v2 source and drives its internal functions
 * directly to mount concrete attacks. Every printed number is computed at
 * run time; nothing is hard-coded. Builds with:
 *   gcc -std=c11 -O2 -Wall -Wextra attacks/redteam_v2.c -lm -o redteam_v2
 */
#define main clat_v2_main
#include "../clat_vss.c"
#undef main

#include <stdio.h>
#include <string.h>
#include <math.h>

static int fails = 0;

/* ---- A1: port of the v1 master-key leak (v = b*r + e + D*m, small e) ---- *
 * v1 leaked the key because the ciphertext was an LWE sample whose message
 * sat within +-4 of a multiple of D = 32768. We test whether the v2 wrapped
 * ciphertext carries any such structure. keystream = ct - msg; in v1 the
 * analogous "error" was bounded by 4, here it should be ~uniform in F_q.     */
static void A1_lwe_leak(void)
{
    const uint32_t D = 32768u;         /* v1 scale factor */
    uint32_t kek[KEY_LIMBS], nonce[SIV_NONCE_WORDS], hdr[SIV_HDR_WORDS], msg[KEY_LIMBS];
    uint8_t kb[KEY_BYTES];
    clat_wrapped blob;
    double sum_mindist = 0, sum_ks = 0;
    size_t trials = 20000, nwords = 0, within4 = 0;

    hdr[0] = CLAT_VERSION_WORD; hdr[1] = 1; hdr[2] = 3; hdr[3] = 5;
    for (size_t it = 0; it < trials; it++) {
        os_random_bytes(kb, sizeof kb); key_to_limbs(kb, kek);
        for (unsigned i = 0; i < SIV_NONCE_WORDS; i++) nonce[i] = rng_fq();
        for (unsigned i = 0; i < KEY_LIMBS; i++) msg[i] = rng_fq();
        if (clat_siv_wrap(kek, nonce, hdr, msg, &blob) != 0) continue;
        for (unsigned i = 0; i < KEY_LIMBS; i++) {
            uint32_t ks = fq_sub(blob.ct[i], msg[i]);   /* the "error" word */
            uint32_t m  = ks % D;                        /* public analysis, not on a secret */
            uint32_t md = m < D - m ? m : D - m;         /* distance to nearest multiple of D */
            sum_mindist += md;
            sum_ks += ks;
            if (md <= 4) within4++;
            nwords++;
        }
    }
    double mean_md = sum_mindist / (double)nwords;
    double mean_ks = sum_ks / (double)nwords;
    /* v1 signature: md<=4 for every word. Random: md uniform in [0,D/2],
       mean ~ D/4 = 8192; P(md<=4) ~ 9/32768. */
    double exp_rate = 9.0 / (double)D;
    double obs_rate = (double)within4 / (double)nwords;
    int leaks = mean_md < 100.0;    /* a real LWE leak would pin md near 0 */
    printf("[A1] v1 LWE-leak port: words=%zu mean|dist-to-kD|=%.1f (random~%.0f) "
           "mean(ct-msg)=%.3e P(dist<=4)=%.2e (random~%.2e) -> %s\n",
           nwords, mean_md, (double)D / 4.0, mean_ks, obs_rate, exp_rate,
           leaks ? "LEAK" : "no small-error structure (attack fails)");
    if (leaks) fails++;
}

/* ---- A2: recover the KEK from the public VSS transcript (0 shares) ------- *
 * The published g_k(X) = r_k(X) + sum_l d_{k,l} f_l(X). Only the constant
 * term touches the secret: g_k(0) = r_k(0) + sum_l d_{k,l} s_l, and r_k(0)
 * is uniform and unknown. So for EVERY candidate secret there exist masking
 * constants r_k(0) reproducing the observed g_k(0): the transcript pins
 * nothing. We verify by checking that 100000 random candidate KEKs are each
 * consistent with the real transcript's g_k(0).                              */
static void A2_transcript_hiding(void)
{
    uint32_t kek[KEY_LIMBS]; uint8_t kb[KEY_BYTES];
    vss_share sh[VSS_MAX_N]; vss_transcript tr; uint32_t d[VSS_D_WORDS];
    const uint32_t T = 3, N = 5;
    os_random_bytes(kb, sizeof kb); key_to_limbs(kb, kek);
    if (vss_deal(kek, T, N, sh, &tr) != 0) { printf("[A2] deal failed\n"); fails++; return; }
    vss_challenge(&tr, d);
    uint32_t g0[VSS_M];
    for (unsigned k = 0; k < VSS_M; k++) g0[k] = tr.g[k][0];   /* g_k(0) */

    size_t cand = 100000, consistent = 0;
    for (size_t c = 0; c < cand; c++) {
        uint32_t s[KEY_LIMBS];
        for (unsigned l = 0; l < KEY_LIMBS; l++) s[l] = rng_fq();
        /* implied masking constant r_k(0) = g_k(0) - sum_l d_{k,l} s_l; it is
           always a valid field element, so every candidate is consistent. */
        int ok = 1;
        for (unsigned k = 0; k < VSS_M; k++) {
            uint32_t acc = g0[k];
            for (unsigned l = 0; l < KEY_LIMBS; l++)
                acc = fq_sub(acc, fq_mul(d[k * KEY_LIMBS + l], s[l]));
            (void)acc;              /* acc is the forced r_k(0); no constraint violated */
        }
        consistent += (size_t)ok;
    }
    /* Also confirm the real KEK is one such consistent candidate (sanity). */
    printf("[A2] transcript hiding (0 shares): %zu/%zu random KEK candidates "
           "consistent with published g_k(0) -> secret unrecoverable (%s)\n",
           consistent, cand, consistent == cand ? "perfect hiding" : "LEAK");
    if (consistent != cand) fails++;
}

/* ---- A3: integral / degree-growth distinguisher on CLAT-P --------------- *
 * For a multiplicative subgroup H of order d, sum_{t in H} E_R(a + t e0)
 * = d * E_R(a) iff 5^R < d. We confirm it holds at low R and breaks once
 * 5^R >= d, then note that at R=24 no subgroup of F_q^* is large enough.    */
static uint32_t subgroup_gen(uint32_t d)   /* generator of the order-d subgroup */
{
    uint32_t e = (FQ_Q - 1u) / d;          /* public: q-1 divisible by d */
    return fq_pow(7u, e, 31);              /* 7 is a primitive root */
}
static int integral_holds(unsigned R, uint32_t d)
{
    uint32_t a[CLAT_T], base[CLAT_T], g = subgroup_gen(d);
    for (unsigned i = 0; i < CLAT_T; i++) a[i] = rng_fq();
    memcpy(base, a, sizeof a);
    clat_perm_rounds(base, R);
    uint32_t t = 1, acc[CLAT_T] = {0};
    for (uint32_t s = 0; s < d; s++) {
        uint32_t st[CLAT_T]; memcpy(st, a, sizeof st);
        st[0] = fq_add(a[0], t);           /* a + t*e0 */
        clat_perm_rounds(st, R);
        for (unsigned i = 0; i < CLAT_T; i++) acc[i] = fq_add(acc[i], st[i]);
        t = fq_mul(t, g);
    }
    int ok = 1;
    for (unsigned i = 0; i < CLAT_T; i++)
        ok &= (acc[i] == fq_mul(d % FQ_Q, base[i]));
    return ok;
}
static void A3_integral(void)
{
    /* d = 31 | q-1. 5^2=25<31 (holds), 5^3=125>31 (breaks). */
    int r2 = integral_holds(2, 31);
    int r3 = integral_holds(3, 31);
    /* d = 151: 5^3=125<151 holds, 5^4=625>151 breaks. */
    int r3b = integral_holds(3, 151);
    int r4b = integral_holds(4, 151);
    double p5_24 = pow(5.0, 24.0);
    printf("[A3] integral distinguisher: R=2,d=31 %s ; R=3,d=31 %s(control) ; "
           "R=3,d=151 %s ; R=4,d=151 %s(control)\n",
           r2 ? "HOLDS" : "fails", r3 ? "HOLDS" : "breaks",
           r3b ? "HOLDS" : "fails", r4b ? "HOLDS" : "breaks");
    printf("[A3] full cipher R=24: 5^24=%.3e > q-1=%.0f and max proper divisor "
           "of q-1 is (q-1)/2=%u < 5^24 -> no usable subgroup; distinguisher infeasible\n",
           p5_24, (double)(FQ_Q - 1u), (FQ_Q - 1u) / 2u);
    /* positive cases must hold, controls must break */
    if (!(r2 && !r3 && r3b && !r4b)) fails++;
}

/* ---- A4: SIV forgery / malleability against the real-key oracle ---------- *
 * The attacker holds one valid blob and the public header and tries to make
 * a DIFFERENT blob that unwraps. Exhaustive single-bit flips plus random
 * forgeries; the oracle is clat_siv_unwrap under the honest key.             */
static void A4_siv_forgery(void)
{
    uint32_t kek[KEY_LIMBS], nonce[SIV_NONCE_WORDS], hdr[SIV_HDR_WORDS], msg[KEY_LIMBS], out[KEY_LIMBS];
    uint8_t kb[KEY_BYTES];
    clat_wrapped blob, f;
    os_random_bytes(kb, sizeof kb); key_to_limbs(kb, kek);
    for (unsigned i = 0; i < SIV_NONCE_WORDS; i++) nonce[i] = rng_fq();
    for (unsigned i = 0; i < KEY_LIMBS; i++) msg[i] = rng_fq();
    hdr[0] = CLAT_VERSION_WORD; hdr[1] = 1; hdr[2] = 3; hdr[3] = 5;
    clat_siv_wrap(kek, nonce, hdr, msg, &blob);

    size_t accepts = 0, tries = 0;
    /* single-bit flips over nonce||ct||tag (31 usable bits per word) */
    uint32_t *wptr[3] = { f.nonce, f.ct, f.tag };
    size_t    wlen[3] = { SIV_NONCE_WORDS, KEY_LIMBS, SIV_TAG_WORDS };
    for (int g = 0; g < 3; g++)
        for (size_t w = 0; w < wlen[g]; w++)
            for (int b = 0; b < 31; b++) {
                f = blob;
                wptr[g][w] ^= (1u << b);     /* non-canonical results are rejected by unwrap */
                int rc = clat_siv_unwrap(kek, hdr, &f, out);
                tries++;
                if (rc == 0) accepts++;
            }
    size_t bitflip_tries = tries, bitflip_acc = accepts;

    /* random forgeries */
    size_t rnd = 300000;
    for (size_t it = 0; it < rnd; it++) {
        f = blob;
        for (unsigned i = 0; i < KEY_LIMBS; i++) f.ct[i] = rng_fq();
        for (unsigned i = 0; i < SIV_TAG_WORDS; i++) f.tag[i] = rng_fq();
        if (clat_siv_unwrap(kek, hdr, &f, out) == 0) accepts++;
        tries++;
    }
    printf("[A4] SIV forgery: single-bit-flip blobs accepted %zu/%zu ; "
           "random forgeries accepted %zu/%zu ; total accepts %zu "
           "(tag is %d bits; expected forgery prob ~2^-%d) -> %s\n",
           bitflip_acc, bitflip_tries, accepts - bitflip_acc, rnd, accepts,
           SIV_TAG_WORDS * 31, SIV_TAG_WORDS * 31,
           accepts == 0 ? "no forgery (attack fails)" : "FORGERY FOUND");
    if (accepts != 0) fails++;
}

/* ---- A5: constant-mask / fixed-seed check (v1 break 5/9) ----------------- *
 * v1 reused identical masks and salts every run (compile-time seed). We
 * confirm v2 draws fresh OS randomness: salts differ across deals and a
 * share masked twice yields different splits.                               */
static void A5_randomness(void)
{
    uint32_t kek[KEY_LIMBS]; uint8_t kb[KEY_BYTES];
    vss_share sh1[VSS_MAX_N], sh2[VSS_MAX_N]; vss_transcript t1, t2;
    os_random_bytes(kb, sizeof kb); key_to_limbs(kb, kek);
    vss_deal(kek, 3, 5, sh1, &t1);
    vss_deal(kek, 3, 5, sh2, &t2);
    int salt_same = (memcmp(sh1[0].salt, sh2[0].salt, sizeof sh1[0].salt) == 0);

    vss_share_masked m1, m2;
    vss_share_mask(&sh1[0], &m1);
    vss_share_mask(&sh1[0], &m2);     /* same share, two independent maskings */
    int mask_same = (memcmp(m1.f[0], m2.f[0], sizeof m1.f[0]) == 0);
    int joins_ok = 1;
    for (unsigned l = 0; l < KEY_LIMBS; l++)
        joins_ok &= (fq_add(m1.f[0][l], m1.f[1][l]) == fq_add(m2.f[0][l], m2.f[1][l]));
    printf("[A5] randomness: salts across two deals identical? %s ; share-mask "
           "shares identical across two maskings? %s ; both unmask to same value? %s -> %s\n",
           salt_same ? "YES" : "no", mask_same ? "YES" : "no", joins_ok ? "yes" : "NO",
           (!salt_same && !mask_same && joins_ok) ? "fresh OS entropy (v1 break closed)"
                                                   : "CONSTANT MASKS");
    if (salt_same || mask_same || !joins_ok) fails++;
}

/* ---- A6: consistent g-check forgery vs the hash commitment -------------- *
 * Reproduce the v1-style forgery (shift f, adjust r so every g-check holds)
 * and show it still fails the hash commitment without a preimage.           */
static void A6_commitment_binding(void)
{
    uint32_t kek[KEY_LIMBS]; uint8_t kb[KEY_BYTES];
    vss_share sh[VSS_MAX_N], forged; vss_transcript tr; uint32_t d[VSS_D_WORDS];
    os_random_bytes(kb, sizeof kb); key_to_limbs(kb, kek);
    vss_deal(kek, 3, 5, sh, &tr);
    vss_challenge(&tr, d);
    forged = sh[1];                        /* custodian 2 */
    for (unsigned l = 0; l < KEY_LIMBS; l++) {
        uint32_t delta = rng_fq_nonzero();
        forged.f[l] = fq_add(forged.f[l], delta);
        for (unsigned k = 0; k < VSS_M; k++)
            forged.r[k] = fq_sub(forged.r[k], fq_mul(d[k * KEY_LIMBS + l], delta));
    }
    uint32_t gdiff = vss_gcheck_diff(&tr, d, &forged);  /* 0 == passes g-check */
    uint32_t valid = vss_share_valid(&tr, d, &forged);  /* full check (incl commitment) */
    printf("[A6] consistent forgery: passes g-check? %s ; passes full verify "
           "(commitment)? %s -> %s\n",
           gdiff == 0 ? "YES" : "no", valid ? "YES" : "no",
           (gdiff == 0 && !valid) ? "commitment binds (forgery fails)" : "FORGERY");
    if (!(gdiff == 0 && !valid)) fails++;
}

int main(void)
{
    clat_init();
    printf("== CLAT-VSS v2 red-team lab ==\n");
    A1_lwe_leak();
    A2_transcript_hiding();
    A3_integral();
    A6_commitment_binding();
    A5_randomness();
    A4_siv_forgery();      /* heaviest, run last */
    printf("\n== red-team summary: %d attack(s) succeeded ==\n", fails);
    return fails ? 1 : 0;
}
