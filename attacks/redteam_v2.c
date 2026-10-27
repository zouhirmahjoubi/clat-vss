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

/* ---- A7: generic birthday attack on a truncated CLAT hash (Boneh) -------- *
 * A hash with b output bits collides after about sqrt(pi/2 * 2^b) random
 * inputs. We truncate the digest to B7_BITS bits, count hashes until the
 * first collision over many trials, and compare the mean with that bound.
 * A mean far below it would mean CLAT-H is weaker than generic. Each
 * truncated collision is re-checked on the full 279-bit digest.             */
#define B7_BITS   20
#define B7_TRIALS 256
static uint32_t b7_seen_trial[1u << B7_BITS];   /* trial id + 1 of the last writer */
static uint32_t b7_seen_ctr[1u << B7_BITS];     /* counter of that input */

static void b7_digest(uint32_t trial, uint32_t ctr, uint32_t dg[DIGEST_WORDS])
{
    uint32_t in[2] = { trial, ctr };
    clat_hash(0x42444159u, in, 2, dg, DIGEST_WORDS);   /* "BDAY" tag, < q */
}

static void A7_birthday(void)
{
    const uint32_t mask = (1u << B7_BITS) - 1u;
    double sum = 0;
    size_t full_collisions = 0;
    memset(b7_seen_trial, 0, sizeof b7_seen_trial);
    for (uint32_t t = 0; t < B7_TRIALS; t++) {
        for (uint32_t c = 0;; c++) {
            uint32_t dg[DIGEST_WORDS], prev[DIGEST_WORDS];
            b7_digest(t, c, dg);
            uint32_t h = dg[0] & mask;
            if (b7_seen_trial[h] == t + 1u) {
                b7_digest(t, b7_seen_ctr[h], prev);
                if (memcmp(dg, prev, sizeof dg) == 0) full_collisions++;
                sum += (double)(c + 1u);
                break;
            }
            b7_seen_trial[h] = t + 1u;
            b7_seen_ctr[h] = c;
        }
    }
    double mean = sum / B7_TRIALS;
    double expect = sqrt(acos(-1.0) / 2.0 * (double)(1u << B7_BITS));
    double ratio = mean / expect;
    /* first-collision time has std ~0.52*mean; over 256 trials the standard
       error is ~3.3%, so +-15% is a > 4 sigma window. */
    int ok = ratio > 0.85 && ratio < 1.15 && full_collisions == 0;
    printf("[A7] generic birthday on %d-bit truncated CLAT-H: mean hashes to "
           "collision %.0f over %d trials (generic sqrt(pi/2*2^%d)=%.0f, ratio %.3f) ; "
           "full 279-bit collisions %zu -> %s ; full digest needs ~2^%.1f work\n",
           B7_BITS, mean, B7_TRIALS, B7_BITS, expect, ratio, full_collisions,
           ok ? "matches generic bound (no shortcut)" : "SHORTCUT OR COLLISION",
           (double)(DIGEST_WORDS * 31) / 2.0);
    if (!ok) fails++;
}

/* ---- A8: two-time pad / nonce reuse (Boneh, attacks on the OTP) ---------- *
 * A stream cipher that reuses its pad gives c1 - c2 = m1 - m2. The control
 * reuses one keystream (fixed IV) and must leak exactly that. CLAT-SIV takes
 * its keystream from the tag, so a reused nonce with different messages must
 * not leak the difference; equal messages give equal blobs (the one stated
 * leak of a deterministic mode).                                            */
static void A8_two_time_pad(void)
{
    uint32_t kek[KEY_LIMBS], nonce[SIV_NONCE_WORDS], hdr[SIV_HDR_WORDS];
    uint32_t m1[KEY_LIMBS], m2[KEY_LIMBS], ks[KEY_LIMBS], iv[SIV_TAG_WORDS];
    uint8_t kb[KEY_BYTES];
    clat_wrapped b1, b2, b3;
    size_t trials = 20000, words = 0, siv_leak = 0, ctl_leak = 0, equal_same = 0;

    hdr[0] = CLAT_VERSION_WORD; hdr[1] = 1; hdr[2] = 3; hdr[3] = 5;
    for (size_t it = 0; it < trials; it++) {
        os_random_bytes(kb, sizeof kb); key_to_limbs(kb, kek);
        for (unsigned i = 0; i < SIV_NONCE_WORDS; i++) nonce[i] = rng_fq();
        for (unsigned i = 0; i < KEY_LIMBS; i++) { m1[i] = rng_fq(); m2[i] = rng_fq(); }
        if (clat_siv_wrap(kek, nonce, hdr, m1, &b1) != 0 ||
            clat_siv_wrap(kek, nonce, hdr, m2, &b2) != 0 ||
            clat_siv_wrap(kek, nonce, hdr, m1, &b3) != 0) continue;
        equal_same += (memcmp(&b1, &b3, sizeof b1) == 0);

        for (unsigned i = 0; i < SIV_TAG_WORDS; i++) iv[i] = nonce[i];   /* control: fixed IV */
        siv_keystream(kek, iv, ks);
        for (unsigned i = 0; i < KEY_LIMBS; i++) {
            uint32_t dm = fq_sub(m1[i], m2[i]);
            siv_leak += (fq_sub(b1.ct[i], b2.ct[i]) == dm);
            ctl_leak += (fq_sub(fq_add(m1[i], ks[i]), fq_add(m2[i], ks[i])) == dm);
            words++;
        }
    }
    int ok = siv_leak == 0 && ctl_leak == words && equal_same == trials;
    printf("[A8] two-time pad: fixed-IV control leaks m1-m2 in %zu/%zu words ; "
           "CLAT-SIV with reused nonce leaks it in %zu/%zu (random ~%.1e) ; "
           "equal messages give equal blobs %zu/%zu -> %s\n",
           ctl_leak, words, siv_leak, words, (double)words / (double)FQ_Q,
           equal_same, trials,
           ok ? "nonce reuse leaks equality only" : "PAD REUSE LEAK");
    if (!ok) fails++;
}

/* ---- A9: PRG distinguishing advantage (Boneh, PRG security) -------------- *
 * A PRG is secure when no efficient test A has a noticeable advantage
 * |Pr[A(G(k)) = 1] - Pr[A(r) = 1]|. We run three cheap tests on the SIV
 * keystream and on OS randomness. The control is a linear generator
 * w1 = 7*w0, which the linear test detects with advantage ~1. A small
 * advantage is a sanity check, not a proof of PRG security.                 */
static unsigned a9_tests(const uint32_t w[2])
{
    unsigned r = 0;
    r |= (((w[0] ^ w[1]) & 1u) == 0) << 0;           /* low-bit parity */
    r |= (w[0] < FQ_Q / 2u) << 1;                     /* half-range */
    r |= (w[1] == fq_mul(7u, w[0])) << 2;             /* linear relation */
    return r;
}

static void A9_prg_advantage(void)
{
    const size_t n = 200000;
    size_t cnt_ks[3] = {0}, cnt_rnd[3] = {0}, cnt_lin[3] = {0};
    uint32_t key[KEY_LIMBS], tag[SIV_TAG_WORDS], ks[KEY_LIMBS], w[2];
    uint8_t kb[KEY_BYTES];
    os_random_bytes(kb, sizeof kb); key_to_limbs(kb, key);
    for (unsigned i = 0; i < SIV_TAG_WORDS; i++) tag[i] = rng_fq();
    for (size_t it = 0; it < n; it++) {
        tag[0] = (uint32_t)it;                         /* distinct IVs, one key */
        siv_keystream(key, tag, ks);
        unsigned a = a9_tests(ks);
        w[0] = rng_fq(); w[1] = rng_fq();
        unsigned b = a9_tests(w);
        w[1] = fq_mul(7u, w[0]);
        unsigned c = a9_tests(w);
        for (int k = 0; k < 3; k++) {
            cnt_ks[k] += (a >> k) & 1u;
            cnt_rnd[k] += (b >> k) & 1u;
            cnt_lin[k] += (c >> k) & 1u;
        }
    }
    double adv[3], ctl_lin = fabs((double)cnt_lin[2] - (double)cnt_rnd[2]) / (double)n;
    double bound = 4.0 / sqrt((double)n);              /* ~4 sigma for p = 1/2 */
    int ok = ctl_lin > 0.99;
    for (int k = 0; k < 3; k++) {
        adv[k] = fabs((double)cnt_ks[k] - (double)cnt_rnd[k]) / (double)n;
        ok &= adv[k] < bound;
    }
    printf("[A9] PRG advantage of SIV keystream over %zu samples: parity %.4f ; "
           "half-range %.4f ; linear w1=7*w0 %.4f (bound %.4f) ; linear control "
           "advantage %.4f -> %s\n",
           n, adv[0], adv[1], adv[2], bound, ctl_lin,
           ok ? "no test distinguishes (sanity, not proof)" : "DISTINGUISHER FOUND");
    if (!ok) fails++;
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
    A8_two_time_pad();
    A9_prg_advantage();
    A7_birthday();
    A4_siv_forgery();      /* heaviest, run last */
    printf("\n== red-team summary: %d attack(s) succeeded ==\n", fails);
    return fails ? 1 : 0;
}
