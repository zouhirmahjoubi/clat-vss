# CLAT-VSS v2 build spec

Read docs/DESIGN_NOTES.md first (v1 breaks + v2 design). This file fixes the exact algorithms so code, tests and paper agree.
Name: CLAT-VSS = Cauchy-Lagrange Algebraic Threshold Verifiable Secret Sharing. Single C file `clat_vss.c`, C11,
no external crypto, builds clean with `gcc -std=c11 -O3 -Wall -Wextra -Werror -pedantic clat_vss.c -lm -o clat_vss`
on Linux (glibc) and Windows (WinLibs MinGW-w64 UCRT gcc). No `%` or `/` on secret data anywhere.

## 1. Field F_q, q = 2^31 - 1
- fq_reduce(x < 2^62): two Mersenne folds + branchless conditional subtract. add, sub, neg, mul.
- fq_pow(base, exp, nbits): Montgomery ladder, fixed iteration count. fq_inv = a^(q-2).
- Self-test at startup: 7 is a primitive root (7^((q-1)/p) != 1 for p in {2,3,7,11,31,151,331}); q-1 factorisation
  multiplies back; 5 * D_INV = 1 mod (q-1) with D_INV = 1717986917.

## 2. Permutation CLAT-P on F_q^16 (public, unkeyed)
- t = 16, R = 24 full rounds. Round r (0..23): x_i += c[r][i]; x_i = x_i^5 (x2=x*x, x4=x2*x2, x5=x4*x); x = M x.
- M[i][j] = (i + j + 16)^(-1) mod q (Cauchy with x_i = i, y_j = 16 + j), branch number 17.
- c[r][i] = 7^(16 r + i + 1) mod q.
- Expose a reduced-round variant clat_perm_rounds(state, nrounds) for the degree tests.

## 3. Sponge and domains
- rate = words 0..6 (7 words), capacity = words 7..15 (9 words, 279 bits, ~139-bit collision resistance).
- Domains (stored in word 15 as  key_limb8 + DOM * 2^29, injective because key limbs < 2^29 and DOM <= 2):
  DOM_HASH = 0 (unkeyed: capacity words 7..14 = 0, word 15 = 0), DOM_MAC = 1, DOM_ENC = 2.
- Unkeyed hash H(tag, x[0..n)): IV rate = (tag, n, 0..), absorb x in 7-word blocks by addition (zero-pad the last
  block, length is in the IV), permute after every block (also after the IV block), squeeze 9 words (7 + permute + 2).
  Hash tags: HT_COMMIT = 1, HT_CHALLENGE = 2, HT_KAT = 3.
- 256-bit key <-> 9 limbs of 29 bits (limb 8 holds the top 24 bits). Decode rejects limbs >= 2^29 in constant time.

## 4. CLAT-SIV key wrap (deterministic AE, nonce optional)
- Keyed state init: rate = IV words, capacity words 7..14 = K limbs 0..7, word 15 = K limb 8 + DOM * 2^29.
- MAC: IV = (MAC_IV_TAG, lenN, lenA, lenM, 0,0,0); permute; absorb N || A || M (7-word blocks, add, permute each);
  tag = rate words 0..6 (7 words, 217 bits).
- ENC: IV = tag[0..6]; capacity DOM_ENC; keystream block j = rate after permutation j+1; C = M + KS.
- Wrap: N = 7 fresh OS-random words (may be fixed for KATs), A = header (version, key id, T, N custodians),
  output (N, C[9], tag[7]). Unwrap: M' = C - KS(tag); tag' = MAC(N, A, M'); constant-time compare; on failure
  wipe M' and return error.

## 5. Hash-committed VSS (no discrete log, post-quantum)
- Secret = KEK as 9 limbs s_l. f_l(X) = s_l + sum_{t=1}^{T-1} a_{l,t} X^t. Masking polys r_k(X), k = 0..4, degree <= T-1,
  all coefficients uniform. Party i (x = i, 1..N): share = (f_l(i))_l, (r_k(i))_k, salt_i (9 random words).
- c_i = H(HT_COMMIT, [i, f_0(i)..f_8(i), r_0(i)..r_4(i), salt_i[0..8]]) (24 words in, 9 out).
- d = H-squeeze(HT_CHALLENGE, [T, N, c_1..c_N]) -> 45 words d_{k,l} (squeeze as many blocks as needed).
- Publish g_k(X) = r_k(X) + sum_l d_{k,l} f_l(X) (T coefficients each). Transcript = (T, N, c_i, g_k).
- Verify share i: commitment matches AND for all k: g_k(i) == r_k(i) + sum_l d_{k,l} f_l(i). Constant-time accumulate,
  return which custodian failed.
- Soundness: a share vector off a degree-(T-1) codeword survives one random d_k with prob <= 1/q; 5 independent
  challenges -> q^-5 ~ 2^-155 per Fiat-Shamir query. Hiding: r_k(0) uniform masks g_k(0); T-1 shares reveal nothing.

## 6. Masking (2-share arithmetic, first-order probing model)
- x = x0 + x1 mod q. Linear ops share-wise, constants on share 0.
- SecMult(a, b) with fresh r: z0 = a0 b0 + r; z1 = a1 b1 + ((a0 b1 - r) + a1 b0) (keep this evaluation order).
- Refresh(a): a0 += r, a1 -= r. S-box: y = Refresh(x); x2 = SecMult(x, y); x4 = SecMult(x2, Refresh(x2));
  x5 = SecMult(x4, Refresh(x)).
- Mask randomness: OS CSPRNG, buffered (getrandom / getentropy / RtlGenRandom via SystemFunction036), 31-bit
  rejection sampling. Never a fixed seed.
- Masked path end to end: custodian shares arrive split -> masked commitment hashing + g-check (unmask only public
  digests and the check difference) -> masked Lagrange at 0 -> masked KEK -> masked SIV unwrap -> MK out as 2 shares.

## 7. Tests printed by `./clat_vss` (every number measured at run time, nothing hard-coded)
1. KATs: CLAT-P on (0..15); H(HT_KAT, empty); SIV wrap with fixed key/nonce. Print hex, check fixed expected values
   once they are recorded.
2. Self-tests: primitive root, D_INV, Cauchy minors (all 1x1, all 2x2, 10^4 random k x k for k <= 16).
3. Vault demo: MK + KEK from OS RNG; wrap; split 3-of-5; verify all; masked reconstruct from {2,4,5}; masked unwrap;
   exact match. Tamper: 1-bit flip in a custodian share (rejected, names custodian); v1-style consistent forgery
   (recompute g-check-consistent values without commitment preimage) rejected; dealer sending an off-polynomial
   share is caught by the g-check; ciphertext/tag bit flip rejected and output wiped.
4. Degree growth (integral) on reduced rounds R = 1..7 with d | q-1, d > 5^R: sum relation holds (prob 1);
   negative control with d <= 5^R fails; print that for R = 24, 5^24 > q - 1 so no subgroup is large enough.
5. dudect: fixed-vs-random class, random interleaving, >= 10^5 measurements, crop at percentiles, Welch t for
   (a) CLAT-P, (b) masked unwrap. Threshold |t| < 4.5 (report value, do not fake PASS).
6. Simulated leakage TVLA: compile-time hook records Hamming weight of every intermediate of one masked and one
   unmasked CLAT-P call on a secret state; fixed-vs-random t-test per sample; report max |t| for both (unmasked
   must fail, masked should pass first order).
7. Statistical sanity (labelled "sanity, not proof"): SAC on CLAT-P, bit balance, byte entropy.
Exit code non-zero on any functional failure.

## 8. Attack lab `attacks/v1_attacks.c` (separate binary, includes the untouched v1 source)
- `#define main clat_v1_main` then `#include "../v1/clat_vss_v1.c"`.
- A1 master-key recovery from (pk.b, ct.v_hi, ct.v_lo) only. A2 BSGS discrete log of h base g in G_q, then a forged
  share that passes clat_vss_verify_share and changes the reconstructed key. A3 integral distinguisher on the 6-round
  SPN with d = 32767. A4 interpolation forgery: 15626 chosen plaintexts on a line, predict a fresh ciphertext.
  A5 masks identical across two decryptions (fixed seed). Print timings and PASS/FAIL per attack.
