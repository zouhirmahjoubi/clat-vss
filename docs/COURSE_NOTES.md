# Course concept map for CLAT-VSS v2

Three courses were requested:

- Christof Paar, "Introduction to Cryptography" (27 lectures, Ruhr University Bochum).
- Neso Academy, "Cryptography & Network Security" (83 videos).
- Dan Boneh, "Cryptography I" (Stanford), part 1 as uploaded by Nerd's lesson (video `j_8PLI_wCVU`, 8 h 17 min, 31 chapters).

## How this was studied

The full lecture lists were fetched with `yt-dlp --flat-playlist` and are kept in the session scratchpad.

The video transcripts could not be downloaded:

- On 2026-10-26 YouTube's subtitle endpoint returned HTTP 429 (Too Many Requests) and the transcript API reported the IP as blocked.
- A second try on 2026-10-27 also returned 429. The transcript panel in a normal browser returned HTTP 400.
- The Boneh video's subtitles returned 429 the same day. Its chapter list was read from the video description.
- No rate-limit workaround was used.

This map is therefore built from three sources:

- lecture and chapter titles;
- chapter structure of the companion textbook (Paar, Pelzl, Gueneysu, *Understanding Cryptography*, 2nd ed.), which Paar's lectures follow;
- standard content of each topic.

Every row names the place in this project where the concept is used, defended against, or tested.

Column guide: **Use** = the concept is part of v2. **Defense** = v2 is built to resist it. **Attack** = it breaks v1 or is tried against v2. **Test** = a measured check in `clat_vss.c` or `attacks/redteam_v2.c`.

## Paar, Introduction to Cryptography

| # | Lecture | Concept taken | Where it lands in CLAT-VSS v2 |
|---|---|---|---|
| 1 | Introduction | Kerckhoffs' principle, symmetric vs asymmetric, attack classes | **Use.** Every constant is public and derived from 7 and i+j+16. Security rests on the key only. |
| 2 | Modular arithmetic, historical ciphers | Modular arithmetic; affine cipher broken by linearity | **Use.** All arithmetic is in F_q, q = 2^31-1. **Attack.** The v1 Ajtai check is linear, so it is not binding (affine-cipher lesson). |
| 3 | Stream ciphers, RNG, one-time pad | TRNG vs PRNG vs CSPRNG; OTP needs a fresh, never-reused pad | **Use.** Masks come from the OS CSPRNG. The SIV keystream is keyed by the tag. **Attack.** v1 seeds its masks from a constant string (break 9). |
| 4 | Stream ciphers and LFSRs | LFSRs are linear; Berlekamp-Massey recovers them from 2L output bits | **Attack.** v1 mixes a 128-bit LFSR into its CSPRNG. **Defense.** v2 has no LFSR. |
| 5 | DES encryption | Confusion and diffusion, S-box as the only nonlinear part, avalanche | **Use.** x^5 is the only nonlinear map, and the Cauchy MDS gives diffusion. **Test.** SAC flip rate 0.4999 (sanity only). |
| 6 | DES key schedule, decryption | Invertible round structure; weak keys | **Use.** CLAT-P is invertible (gcd(5, q-1) = 1, x^D_INV inverts x^5, checked). No key schedule: the key enters through the sponge capacity. |
| 7 | Galois fields for AES | Prime fields, extension fields, inverses, irreducible polynomials | **Use.** F_q arithmetic, Fermat inversion a^(q-2), Montgomery ladder. |
| 8 | AES | SPN rounds, MixColumns as an MDS code, branch number, wide-trail strategy | **Use.** CLAT-P is a 16-word SPN with a 16x16 MDS (branch number 17). **Test.** All 1x1 and 2x2 minors, plus 10^4 random kxk minors, are nonsingular. |
| 9 | Modes of operation | ECB leaks patterns; CTR and OFB need unique IVs; nonce misuse | **Use.** CLAT-SIV is deterministic, with IV = tag. Nonce reuse leaks only message equality. |
| 10 | Multiple encryption, brute force | Key length vs brute force; meet-in-the-middle | **Use.** 256-bit key, 279-bit capacity, 217-bit tag. **Attack.** v1 LWE secret space 9^8 = 2^25.4 is brute-forceable. |
| 11 | Euclid, Euler phi, Euler's theorem | gcd, EEA, phi, a^phi = 1 | **Use.** 5 * D_INV = 1 mod (q-1). Lagrange coefficients need inverses of x_i - x_j. |
| 12 | RSA, fast exponentiation | Square-and-multiply leaks its key through timing; constant-time ladder | **Use.** Fixed-iteration Montgomery ladder for fq_pow. **Test.** dudect max \|t\| 1.71 (CLAT-P) and 0.49 (masked unwrap). **Attack.** v1 uses 128-bit `%` (variable-time __umodti3). |
| 13 | Diffie-Hellman, DLP | DLP in Z_p^* | **Attack.** v1 Pedersen commitments rely on a DLP in a subgroup of order 2^31-1. |
| 14 | Generalized DLP, security of DH | Generic attacks: baby-step giant-step, Pollard rho, cost sqrt(group order); Pohlig-Hellman | **Attack.** BSGS solves v1's 31-bit subgroup in about 2^16 steps. **Defense.** v2 drops discrete logs and uses hash commitments. |
| 15 | Elgamal encryption | Randomized encryption; malleability | **Defense.** SIV is not malleable. **Test.** 0 of 713 one-bit flips and 0 of 300000 random forgeries were accepted. |
| 16 | Introduction to elliptic curves | Group law over F_p | Not used. v2 avoids every group-based assumption so the VSS stays plausibly post-quantum. |
| 17 | ECC | ECDLP and generic attacks | Not used, for the same reason as lecture 16. |
| 18 | Digital signatures, security services | Integrity, authentication, non-repudiation | **Use.** The SIV tag gives integrity and authenticity. Failed checks name the custodian at fault. |
| 19 | Elgamal signature | Nonce reuse leaks the key | **Use.** v2 has no per-signature nonce. Every random value comes from the OS CSPRNG, and the buffer is wiped per operation. |
| 20 | Hash functions | Preimage, second preimage, collision; birthday bound | **Use.** The sponge hash has a 279-bit digest and capacity, giving about 2^139 collision resistance. Commitments rely on binding. |
| 21 | SHA-1 | Merkle-Damgard and its length extension | **Use.** The sponge, with the length in the IV, has no length extension. |
| 22 | SHA-3 | Sponge construction, rate and capacity, generic security c/2 | **Use.** Rate 7, capacity 9 words. Domain separation lives in the capacity. |
| 23 | Hash-based PQC | Security from hash functions alone survives Shor | **Use.** The VSS rests only on CLAT-P hash commitments and Fiat-Shamir, with no DLP. |
| 24 | Merkle signature scheme | Commit with a hash, open later | **Use.** c_i = H(i, f(i), r(i), salt_i) is a hash commitment, opened by the custodian to the combiner. |
| 25 | MAC and HMAC | Keyed hashing, MAC forgery, constant-time tag compare | **Use.** The keyed sponge MAC needs no HMAC nesting in a sponge. Tag compare is constant time, and the output is wiped on failure. |
| 26 | Symmetric key establishment, Kerberos | Key encryption keys, key wrapping, key hierarchy | **Use.** The MK is wrapped under a KEK, and the KEK is split 3-of-5 across custodians. |
| 27 | MITM, certificates, PKI | Authenticated public data; broadcast assumption | **Use.** The VSS transcript must reach every custodian unchanged. The paper states this as a broadcast assumption, and T and N are bound to the authenticated header. |

## Neso Academy, Cryptography & Network Security

| Videos | Topic | Where it lands in CLAT-VSS v2 |
|---|---|---|
| 1-7 | CIA triad, X.800 OSI security architecture, attacks, services, mechanisms, network security model | **Use.** The threat model section maps each v2 mechanism to an X.800 service. Confidentiality comes from SIV encryption, integrity from the SIV tag and VSS commitments, and availability from the T-of-N threshold. |
| 8-11 | Cryptography terms, cryptanalysis, brute force | **Use.** Attack models (ciphertext-only through chosen-plaintext) structure the cryptanalysis section. |
| 12-28 | Classical ciphers: Caesar, monoalphabetic, Playfair, Hill, Vigenere, Vernam, OTP, transposition, steganography | **Attack.** The Hill cipher falls to known plaintext because it is linear. v1's Ajtai/SIS check has the same flaw (4 linear equations in 16 unknowns). **Use.** The Vernam/OTP idea appears in C = M + KS over F_q. |
| 29-34 | Number theory, primes, modular arithmetic and exponentiation | **Use.** Mersenne reduction, ladder exponentiation. |
| 35-46 | Euclid, coprimality, Euler phi, Fermat, Euler, primitive roots, inverses, EEA | **Use.** 7 is a primitive root of q, so the round constants 7^(16r+i+1) are nothing-up-my-sleeve. Inverses use Fermat. **Test.** The primitive root check covers all 7 prime factors of q-1. |
| 47-48 | Chinese Remainder Theorem | **Attack.** v1's CRT check is a no-op, because residues are recomputed by whoever edits y. |
| 49-50 | Discrete logarithm problem | **Attack.** v1's 31-bit subgroup DLP. |
| 51-53 | Fermat factoring, Fermat and Miller-Rabin primality | **Use.** q-1 is factored and checked at startup: q-1 = 2 * 3^2 * 7 * 11 * 31 * 151 * 331. That factorization sets the integral-attack subgroup sizes. |
| 54-56 | Groups, abelian and cyclic groups, rings, fields | **Use.** F_q^* is cyclic of order q-1. Its subgroups of order d \| q-1 drive the integral distinguisher. |
| 57-58 | Stream vs block cipher, Feistel structure | **Use.** CLAT-P is an SPN, not a Feistel network. SIV uses it as a stream (keystream) inside an AE mode. |
| 59-64 | DES rounds, F function, key schedule, avalanche, strength | **Test.** Avalanche/SAC is used as a sanity check, labelled as not proof. |
| 65-69 | AES, round transformation, key expansion, security and implementation aspects | **Use.** MDS diffusion. **Defense.** Implementation attacks (timing, power) are addressed by constant-time code, masking, dudect and TVLA. |
| 70 | Multiple encryption, 3DES | **Use.** A key-size argument instead of cascading. |
| 71-77 | ECB, CBC, CFB, OFB, CTR | **Use.** SIV is a deterministic AE mode, chosen because key wrapping needs misuse resistance. |
| 78-79 | PRNG, Golomb's postulates | **Attack.** v1 relied on Golomb-style statistics as evidence of security. **Defense.** v2 keeps them only as sanity checks and uses OS randomness. |
| 80-83 | Chapter intros: PKC, hash and signatures, system security, web/email/IP security | Covered by Paar 11-27 above. |

## Boneh, Cryptography I (part 1)

Three chapters of this course became new red-team tests (A7, A8, A9 in `attacks/redteam_v2.c`). Each test has a control that the attack must break, so a pass shows the test can see a weakness. The numbers below come from `results/redteam_v2_run.txt`.

| Chapters | Topic | Where it lands in CLAT-VSS v2 |
|---|---|---|
| 1-3 | Course overview, what cryptography is, history | **Use.** Same threat model as Paar 1: public design, secret key. |
| 4-5 | Discrete probability: union bound, independence, birthday paradox | **Use.** Forgery and collision bounds in the paper are union bounds over adversary queries. |
| 6 | Information-theoretic security, one-time pad | **Use.** T-1 Shamir shares reveal nothing about the KEK, which is perfect secrecy in Shannon's sense. **Test.** A2 shows 100000 of 100000 random KEKs fit the public transcript. |
| 7 | Stream ciphers and PRGs | **Use.** The SIV keystream is a PRG keyed by the KEK and seeded by the tag. |
| 8 | Attacks on stream ciphers: two-time pad, malleability | **Test (A8).** A fixed-IV control leaks m1 - m2 in 180000 of 180000 words. CLAT-SIV with a reused nonce leaks it in 0 of 180000, and equal messages give equal blobs 20000 of 20000 times. Nonce reuse leaks equality and nothing more. **Defense.** A4 shows the tag stops malleability: 0 of 713 bit flips accepted. |
| 9 | Real-world stream ciphers (RC4, CSS, Salsa20) | **Attack.** RC4 and CSS fail through biased or linear state, the same flaw as v1's LFSR. v2 has no such state. |
| 10-12 | PRG security, semantic security, stream ciphers are semantically secure | **Test (A9).** Over 200000 keystream samples, three tests (parity, half range, linear w1 = 7 w0) show advantage at most 0.0019 against a 4-sigma bound of 0.0089. The linear control reaches advantage 1.0000. This is a sanity check, not a proof. |
| 14-19 | Block ciphers, DES, exhaustive search, more attacks, AES, block ciphers from PRGs | **Use.** CLAT-P is an SPN like AES. 256-bit keys rule out exhaustive search. The linear and differential attacks covered here are why v2 uses an MDS layer with branch number 17. |
| 20 | PRPs and PRFs | **Use.** The sponge proof treats CLAT-P as a random permutation. The MAC and keystream are PRFs of the key. |
| 21-24 | Modes: one-time key, many-time key, CBC, CTR | **Use.** Deterministic encryption cannot be CPA secure, so SIV states that a repeated (nonce, header, key) repeats the blob. A8 measures that exact leak. |
| 25-27 | MACs, PRF-based MACs, CBC-MAC and NMAC | **Use.** The keyed sponge MAC is a PRF-based MAC. The final permutation and the fixed lengths in the IV do the job of NMAC's outer key. |
| 28 | MAC padding | **Use.** Every input length is fixed and absorbed into the IV, so zero padding cannot create two messages with one tag. |
| 29 | PMAC and the Carter-Wegman MAC | Not used. A one-time polynomial MAC would need a fresh key per message, and key wrap has no such key. |
| 30-31 | Collision resistance, generic birthday attack | **Test (A7).** Truncating CLAT-H to 20 bits, the first collision came after 1278 hashes on average over 256 trials. The generic bound is sqrt(pi/2 * 2^20) = 1283, ratio 0.996. None of those collisions held on the full 279-bit digest. The full digest needs about 2^139.5 work. |

## Lessons applied, in one list

1. A linear check is not a security check. The Hill cipher, LFSRs and v1's Ajtai and CRT checks all fail this way. v2 uses hash commitments.
2. Discrete-log security needs a large group. Generic attacks cost about sqrt(n), so v1's 31-bit subgroup falls in about 2^16 steps. v2 drops DLP entirely.
3. Low algebraic degree is an attack surface. v1 reaches degree 5^6 = 15625 < q. v2's 24 rounds leave an 8-round margin over the best integral zero-sum (16 rounds).
4. Randomness must be fresh. A one-time pad, Elgamal nonces and masks fail when reused. v2 draws from the OS CSPRNG and wipes the buffer per operation.
5. Constant time comes from code shape, not a claim. Use the ladder, and avoid `%`, `/` and branches on secrets. dudect measures the result.
6. Statistics are not proofs. SAC, entropy and Golomb tests appear only as sanity checks.
7. A test must show it can fail. A7, A8 and A9 each run a control that the attack breaks, so their passes mean something.
