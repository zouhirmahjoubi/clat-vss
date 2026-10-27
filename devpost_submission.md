# CLAT-VSS v2

CLAT-VSS v2 is a threshold key vault written in one C file. It replaces our first submission, v1, after we found nine weaknesses in v1.

**Track:** Cryptographer Track (Track 1), Mathematics for Systems Security
**Language:** C11, single file, no crypto libraries. Builds with `gcc -std=c11 -O3 -Wall -Wextra -Werror -pedantic`.
**Paper:** `paper/clat_vss_v2.pdf` (LaTeX)
**Code:** https://github.com/zouhirmahjoubi/clat-vss

## Inspiration

v1 combined LWE encryption, Pedersen commitments, a lattice check, CRT residues and masking. Before resubmitting, we read the v1 code as attackers and found these nine weaknesses (eight in the code, one in the paper):

1. Anyone can recover the master key from the public ciphertext, because its LWE part uses tiny randomness for each coordinate.
2. Pedersen commitments sit in a 31-bit group, where a discrete log takes about 2^16 steps.
3. A forged share can satisfy the lattice (SIS) check, because that check is linear.
4. CRT residues are recomputed from the share itself, so that check catches nothing.
5. Masks came from a fixed seed, so they were the same in every run.
6. Secret values pass through a 128-bit `%`, which runs in variable time.
7. Six rounds of x^5 reach degree 15625, below the field size, so an integral attack works.
8. Our v1 paper had wrong constants and presented statistics as proof.
9. Nonces and seeds were constant strings.

The paper (Section 3) gives the math for each break. v2 drops every part that relied on a small or linear structure.

## What it does

A master key (MK) is wrapped under a key-encryption key (KEK), and the KEK is split among N custodians so that any T of them can recover it. In the demo, T = 3 and N = 5.

With fewer than T custodians, nothing about the key is revealed. If a custodian sends a bad share, the check fails and reports which custodian sent it. If the dealer hands out shares that do not fit one polynomial, the custodians' checks catch that as well. The custodian who got the bad share files a complaint, and the dealer must show that share in public or be disqualified. The device that recombines the shares keeps the KEK and the MK split into two random shares at every step, and hands the MK out still split.

## How it works

**Field.** All arithmetic is mod q = 2^31 - 1. Reduction uses shifts and adds, and there is no `%` or `/` on secret values.

**The permutation, CLAT-P.** The state is 16 field elements. Each of the 24 rounds does three things:

- adds round constants (powers of 7, a primitive root of q);
- raises every word to the 5th power;
- multiplies by a 16x16 Cauchy MDS matrix with branch number 17.

**Sponge.** The sponge has 7 rate words and 9 capacity words (279 bits). The same sponge builds the hash, the share commitments, the Fiat-Shamir challenges, the MAC and the keystream.

**Key wrap, CLAT-SIV.** The wrap computes a MAC tag over the nonce, the header and the key. It then adds a keystream derived from that tag to the key. On unwrap, a wrong tag wipes the output. If a nonce is ever reused, an attacker learns whether two wrapped keys are equal, and nothing more.

**Verifiable secret sharing without discrete logs.**

- Each 29-bit limb of the KEK is shared with Shamir's scheme.
- Every share is committed with a salted hash.
- A challenge is derived from all the commitments.
- The dealer publishes five check polynomials, each a random mask polynomial plus a challenge-weighted sum of the sharing polynomials.
- A custodian whose share fails files a complaint. The dealer must open that share in public, and everyone checks it. A failed or missing opening, or complaints from T custodians, disqualifies the dealer.

A dealer who hands out inconsistent shares passes with probability about 2^-155 for each challenge attempt. T-1 shares, plus everything public, reveal nothing about the key. Both proofs are in Section 5.3 of the paper. The scheme relies only on hashing, so Shor's algorithm does not apply to it.

**Masked combiner.** Every secret value on the combining device is held as two random shares that add up to it. Multiplications use the ISW method, with fresh OS randomness for each operation. Four steps run on the shares:

- commitment hashing;
- the consistency checks;
- Lagrange interpolation;
- unwrapping.

## Why 24 rounds

Integral attacks sum the output over a large set of inputs and work while the algebraic degree stays low. On a full input set the first S-box layer only permutes the set, so after R rounds the degree is at most 5^(R-1). Summing over 3 free input words (about 2^93 work) gives a zero-sum through 15 rounds, since 5^14 < 3(q-1). Within 2^128 data it goes no further, and one round worked backwards adds 1, for 16 rounds. At 24 rounds that leaves a margin of 8, and the program prints these bounds when it runs.

For comparison, Poseidon2 over 31-bit fields, with width 16 and x^5, uses 8 full rounds and 14 partial rounds. That is 142 S-box evaluations, compared with 384 in CLAT-P.

## Results

The program prints every number below at run time. The machine was an Intel i5-6300U running Windows 10, built with GCC 16.2.0.

| Test | Result |
|---|---|
| Functional checks | 44 of 44 pass with the complaint round (Windows); 38 of 38 before it |
| Statistical tests | 7 of 7 pass |
| Known answers | match an independent Python implementation (`tools/ref_kat.py`) |
| Cauchy MDS minors | 256/256 1x1, 14400/14400 2x2 and 10000/10000 random kxk are nonsingular |
| 3-of-5 vault | all 10 three-custodian subsets open it; none of the 10 two-custodian subsets do |
| v1-style forged share | passes the polynomial check, rejected by the hash commitment |
| Degree test, rounds 1 to 7 | the integral sum holds whenever the subgroup size is above 5^R, and fails as expected when it is not |
| dudect timing, 10^5 runs | largest abs(t) is 1.71 for the permutation and 0.49 for masked unwrap (threshold 4.5) |
| Simulated power leakage (TVLA) | unmasked code leaks at 7170 points; the three masked code paths leak at 0 |
| Platforms | 38 of 38 on Windows (GCC), Ubuntu (GCC and Clang) and macOS arm64 (Apple Clang), before the complaint round |
| Sanitizers | no reports under AddressSanitizer and UndefinedBehaviorSanitizer |
| Masked check of 5 shares | 2.27 ms |
| Masked reconstruct and unwrap | 0.38 ms |

**Red team.** A separate harness (`attacks/redteam_v2.c`) attacks v2 directly. All nine attacks failed, and a tenth check confirms the hiding property.

- **v1 key-leak attack, ported to v2.** The ciphertext shows no small-noise structure.
- **Hiding check.** For any candidate key there is a mask value that explains the public transcript, so the transcript rules out no key. The harness shows this on 100000 random candidates.
- **Integral distinguisher.** It holds on reduced rounds (tested from 1 to 7) and has no valid subgroup at 24.
- **Key-wrap forgery.** 0 of 713 bit flips and 0 of 300000 random tags were accepted.
- **Mask reuse.** The masks differ on every run.
- **Consistent share forgery.** The hash commitment rejects it.
- **Birthday attack.** On a 20-bit cut of the hash, collisions came after 1278 hashes on average, matching the generic 1283.
- **Nonce reuse.** A reused nonce leaks the message difference in 0 of 180000 words. A weak control leaks it in all of them.
- **Keystream tests.** No test told the keystream from random (advantage at most 0.0019). A linear control is caught every time.
- **Cheating dealer.** In 100000 tries, the dealer never answered a complaint with a forged share that passed. False complaints from 2 custodians did not remove an honest dealer.

Before the red team, three reviews (cryptanalysis, side channels, correctness) raised 19 findings. We fixed 18 and added a regression test for each. One of them was a stack overflow that a crafted transcript could trigger. The paper explains why we rejected the 19th.

## What we learned

We studied Christof Paar's Introduction to Cryptography and Neso Academy's Cryptography & Network Security. Several lectures map directly onto a v1 break and the v2 fix:

- In the Hill cipher lectures, a linear cipher falls to linear algebra. v1's lattice and CRT checks failed in the same way, so v2 uses hash commitments.
- Discrete-log lectures, with baby-step giant-step, explain why a 31-bit group gives only about 16 bits of security. v2 does not use discrete logs.
- Confusion and diffusion, from the DES and AES lectures, led to the Cauchy MDS layer. The degree argument from integral attacks set the round count.
- Square-and-multiply timing, from the RSA lecture, led to a fixed-length exponentiation ladder and the dudect test.
- Reuse breaks the one-time pad and Elgamal signatures, as their lectures show. v2 draws its masks from the OS and wipes them after each operation.
- Golomb's randomness postulates get their own lecture. v2 reports its avalanche and entropy figures only as sanity checks.

The full lecture-by-lecture map is in `docs/COURSE_NOTES.md`.

## Build and run

```
gcc -std=c11 -O3 -Wall -Wextra -Werror -pedantic clat_vss.c -lm -o clat_vss
./clat_vss
```

GitHub Actions runs the same build and suite on Ubuntu and macOS on every push. The default run takes 1 to 2 minutes. `./clat_vss --full` runs longer timing and leakage tests. Both exit with a non-zero status if any functional check fails.

## Limitations

- CLAT-P is a new design and has not had outside cryptanalysis.
- Power leakage is simulated in two models and has not been measured on hardware. The masking protects against first-order attacks only.
- The Linux and macOS timing tests ran on shared CI machines, so their timing figures are noisier than the laptop run.
- The secret sharing assumes every custodian sees the same public transcript.
- A dealer with a quantum computer could use Grover search to cheat in about 2^78 tries instead of 2^155. Using 9 mask polynomials instead of 5 would restore about 2^139.

## Files

- `clat_vss.c`: v2 implementation and test suite
- `paper/clat_vss_v2.tex`, `paper/clat_vss_v2.pdf`: paper
- `attacks/redteam_v2.c`: red-team harness
- `results/`: raw output of the runs quoted above
- `v1/`: the original submission, unchanged
- `docs/`: design notes, build spec, course map
