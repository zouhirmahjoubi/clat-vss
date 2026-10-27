# CLAT-VSS v2 working notes (source of truth for the rebuild)

Decisions (2026-10-26, user): chat in English; rebuild as v2; install WinLibs GCC (winget) + Tectonic (GitHub release).
Inputs: C:\Users\LENOVO\Downloads\clat_vss.c (v1, 1283 lines), devpost_submission.md, "download (1).pdf" (v1 paper, text at scratchpad/pdf/paper.txt).
Hackathon: Devpost "Mathematics for systems security", Cryptographer track. Judging: cryptanalysis 3, uniqueness 2,
attack surface 3, clean LaTeX 2; extra point for C; video recommended. Rule: no pre-existing algorithm to encrypt plaintext.
Deadline conflict: Overview says Nov 15 2026 14:00 GMT, Dates tab says 11/1/2026. Treat Nov 1 as safe.
Courses: Paar "Introduction to Cryptography" (27 lectures, PL3boZvi-wmN6r4HUGUpRSk5uhEcTNfjSS);
Neso Academy "Cryptography & Network Security" (83 videos, PLBlnK6fEyqRgJU3EsOYDTW7m6SUmW6kII). Lists in scratchpad/course/.

## v1 breaks (all found by reading the code; each must be proven by a running attack in attacks/)

1. Master key leaks from public data. v_hi[i] = b[i]*r[i] + e2 + D*m_hi[i], v_lo same b[i]*r[i]; r[i], e in [-4,4], D=32768.
   For each i try r in [-4..4]: (v - b r) mod q is within +-4 of a multiple of D -> m. Both halves share r -> near-unique.
   Also v_hi - v_lo = D(m_hi - m_lo) + small. Decryption never uses the LWE part, it is pure leakage.
   LWE n=8 with s in [-4,4]^8 is brute-forceable (9^8 = 2^25.4). "Module-LWE" label is wrong (no module structure).
2. Pedersen group too small: subgroup order q = 2^31-1 in F_P*, P = 46q+1 ~ 2^36.5. BSGS/Pollard rho in ~2^16 steps
   gives x = log_g h. Then forge share: pick dy, dz_w = -dy_w / x; need dy*(G^T - H^T/x) = 0 per half
   (4 eq, 8 unknowns) -> nonzero solution; forged share passes CRT + Ajtai + Pedersen checks.
3. Ajtai/SIS check is not binding: shares are uniform in F_q (no shortness), 4 linear equations in 16 unknowns per half.
4. CRT check is a no-op: residues are recomputed from y by whoever edits y (the v1 tamper test itself does this).
   Detects only random faults, gives zero integrity. Uses % on secret values.
5. Masking broken: mask seed is a compile-time constant string (identical masks every run); state unmasked
   (acc0+acc1) before every S^-1; shares loaded raw in reconstruction.
6. fp_mul uses 128-bit % -> __umodti3 call, variable time on secret exponent paths. "Zero division" claim false.
7. 6-round x^5 SPN: degree 5^6 = 15625 < q. Integral distinguisher: for subgroup H of F_q* with |H| = d > 5^6,
   sum_{t in H} E(a + t e_0) = d * E(a) (prob 1). q-1 = 2*3^2*7*11*31*151*331; 32767 = 7*31*151 works.
   Interpolation: 15626 chosen plaintexts on a line -> predict E on that line without the key.
8. Paper errors: Delta = floor(q/2^16) = 32767 not 32768; P listed as "safe subgroup modulus"; 272.86 us window is a
   machine-specific timing, not a security property; SAC/Golomb/entropy are sanity checks, not cryptanalysis;
   timing test compares two fixed plaintexts (not dudect fixed-vs-random with random interleaving).
9. All seeds/nonces are constant strings; no OS entropy. CSPRNG mixes a linear 128-bit LFSR (Paar L4: Berlekamp-Massey).

## v2 design ("CLAT" re-expanded: Cauchy-Lagrange Algebraic Threshold)

- Field F_q, q = 2^31-1 (M31, same as Plonky3/Stwo). Branchless Mersenne folding, Fermat inversion by ladder.
- Permutation CLAT-P on F_q^16: R = 24 full rounds; round = add constants, x^5 on all 16 words, 16x16 Cauchy MDS
  M_ij = 1/(x_i + y_j) (branch number 17). gcd(5, q-1) = 1. Constants c_{r,i} = 7^(16r+i+1) mod q
  (7 is a primitive root of M31: nothing-up-my-sleeve). Round count: integral/interpolation need 5^R > q -> R >= 14;
  Poseidon2 over M31 t=16 uses R_F=8 + R_P=14 = 22 (partial rounds weaker than full); we use 24 FULL rounds.
  Differential uniformity of x^5 is 4 -> DP <= 2^-29 per S-box; branch 17 -> negligible after 2 rounds.
- Sponge: rate 7, capacity 9 words (279 bits): collision resistance ~139 bits. Domain separation in capacity.
- Hash H (commitments, challenges) = sponge. Key wrap = deterministic SIV over keyed duplex:
  T = MAC_K(N, A, M); C = M + KS_K(T); decrypt then recompute tag, constant-time compare, wipe on failure.
- 256-bit key <-> 9 limbs of 29 bits.
- VSS (hash-committed, no DLP, post-quantum): Shamir over F_q per limb (degree T-1), m = 5 masking polys r_k,
  commitments c_i = H(i, f(i), r(i), salt_i), challenge d = H(all c_i), publish g_k = r_k + sum_l d_{k,l} f_l.
  Soundness ~ q^-5 ~ 2^-155 per Fiat-Shamir query; hiding: r_k(0) uniform masks f(0).
- Threshold vault flow: MK wrapped under KEK; KEK split T-of-N. Unwrap: shares verified (masked hashing),
  masked Lagrange, masked SIV unwrap, MK delivered as 2 arithmetic shares.
- Masking: 2-share arithmetic, ISW SecMult with refresh before dependent multiplications (x^2, x^4, x^5);
  fresh randomness from OS RNG (getrandom / RtlGenRandom / getentropy) per call.
- Tests: proven attacks on v1 (key recovery, DLP + share forgery, integral distinguisher, interpolation forgery,
  constant masks); v2 holds; degree-growth check on reduced rounds; dudect fixed-vs-random t-test; simulated
  HW-leakage TVLA (masked vs unmasked); statistical sanity checks (labelled as such); KATs.

## Status 2026-10-27 (after build workflow wf_f28740d5-189)

- v2 built and verified by me: gcc 16.2.0 -Werror clean; results/v2_run_verify.txt = 38/38 functional, 7/7 statistical,
  exit 0 (124.8 s; workflow run results/v2_run.txt 63.9 s). Red team: attacks/redteam_v2.c, results/redteam_v2_run.txt,
  0 of 6 attacks succeeded (A1 LWE-leak port, A2 transcript hiding 100000/100000 candidates consistent, A3 integral
  R=2/3/4 controls, A4 SIV forgery 0/713 bit flips 0/300000 random, A5 fresh masks, A6 consistent forgery stopped by commitment).
- Review round fixed 18 of 19 findings (stack overflow on N>16, transcript canonical check, T/N bound to header, blame by
  slot, key range check for domain separation, x range in Lagrange, stack burn after keyed calls, HD leakage model with
  precharge, masked pipeline TVLA for combine and verify, rng_wipe per entry point, tautology checks removed,
  tools/ref_kat.py shipped). Rejected: "KEK not bound to blob" (dealer can always wrap garbage; wrong KEK caught by SIV tag).
- v1 attack lab (attacks/v1_attacks.c) NOT built: the agent was stopped by a safety classifier with the instruction not to
  produce that content again. Do not write it. Paper presents v1 breaks as math analysis; evidence of the principles comes
  from v2 tests (consistent forgery rejected by commitment, integral relation on reduced rounds).
- Course transcripts unavailable: yt-dlp subtitles HTTP 429 again on 2026-10-27; browser transcript panel request
  (youtubei get_transcript) returned 400. No circumvention. COURSE_NOTES built from lecture titles + the companion
  textbook topics (Paar, Pelzl [, Gueneysu] Understanding Cryptography) and standard course content; say so plainly.
- Round-count argument (multivariate, F6): zero-sum over k free words needs 5^R < k(q-1). Data q^k; within 2^128 data k <= 4,
  so the forward integral reaches R <= 14 (5^14 = 6.10e9 < 4(q-1) = 8.59e9 < 5^15). 24 rounds = 10-round margin.
  CORRECTED 2026-10-27 (paper review): the first S-box layer is free on a full box, so the condition is 5^(R-1) < k(q-1):
  forward zero-sum reaches 15 rounds (k = 3, 2^93), plus 1 backward round = 16; margin at R = 24 is 8 rounds. Code Test 4 prints this.
  Masked verifier now also binds sender slot and header T, N (Tamper F, G masked cases). A2 in redteam is a hiding check, not an attack.
  Inverse S-box x^D_INV has degree ~2^30.7, so the backward direction adds at most about 1 round.
- TVLA noise floor: P(|t| > 4.5) ~ 6.8e-6 under H0, so 170836 samples give ~1.16 chance exceedances per set; single-set
  hits of 1-3 are expected; the rule counts a sample only if it exceeds 4.5 in both independent sets.
- VSS soundness: if some f_l is off a degree-(T-1) codeword on the honest set S (|S| >= T+1), then for each k the
  d_k satisfying the check form an affine subspace of codim >= 1: prob <= 1/q; 5 independent d_k: q^-5; grinding over
  Q hash queries: Q q^-5 + collision term Q^2 / 2^279. Hiding: T-1 shares + g_k reveal per k one equation
  g_k(0) = r_k(0) + sum_l d_kl s_l, masked by uniform r_k(0); commitments hide via 279-bit salt (ROM). Assumes broadcast.
- Next: COURSE_NOTES.md, paper/clat_vss_v2.tex (Tectonic), devpost_submission.md + video script, adams check, review workflow.

## Cross-platform verification 2026-10-27
- Public repo https://github.com/zouhirmahjoubi/clat-vss (private Actions blocked by account billing; user chose public).
- CI run 40431131292 (push) and 40432440336 (dispatch, --full): Ubuntu 24.04 gcc 13.3 and clang 18.1, macOS 14 arm64 Apple Clang 15: 38/38, 7/7, red team 0 succeeded, KATs match, Python KAT diff clean.
- ASan+UBSan (gcc 13.3 -O1): 36/36 (dead-stack probes skipped under ASan), 7/7, no sanitizer report.
- --full on Ubuntu gcc: 38/38, 7/7, dudect 1e6 / 4e5 max |t| 1.36 / 1.04, TVLA masked max 4.15 at 1e5 traces/set, unmasked 412. Logs in results/ci/.
