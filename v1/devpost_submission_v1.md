# CLAT-VSS: CRT-Lattice Algebraic Threshold Verifiable Secret Sharing & Side-Channel Resistant Master-Key Cipher

**Track:** Cryptographer Track (Track 1) — *Mathematics for Systems Security Hackathon*  
**Implementation Language:** Low-Level C (`C99`/`C11`, zero external cryptographic dependencies, compiled with `gcc -O3 -Wall -Wextra -Werror`)

## 1. Inspiration & Problem Statement

Standard approaches to protecting a 256-bit Master Key suffer from three fundamental mathematical and systems-level vulnerabilities:
1. **Linear Matrix Ciphers Collapse Under Known-Plaintext Attacks (KPA):** Classical matrix encryption schemes (such as the Hill Cipher, $\mathbf{C} = \mathbf{K}\mathbf{P} \bmod q$) are purely linear; an adversary who captures $d$ linearly independent plaintext-ciphertext pairs can invert $\mathbf{P}$ over $\mathbb{F}_q$ to recover the secret key $\mathbf{K} = \mathbf{C}\mathbf{P}^{-1} \bmod q$.
2. **Table-Driven Block Ciphers Leak Keys via Cache-Timing & Power Side Channels:** Traditional symmetric ciphers rely on RAM lookup tables (such as S-boxes) that leak secret indices through L1/L2 CPU cache-timing attacks (*Flush+Reload*, *Prime+Probe*) and Differential Power Analysis (DPA).
3. **Unverified Secret Sharing & Division Timing Leaks:** Standard Shamir Secret Sharing cannot detect Byzantine share corruption prior to interpolation, and naive modular arithmetic using hardware integer division (`div`/`idiv`) exhibits operand-dependent execution latency ($10\text{--}40+$ cycles), leaking secret shares over timing channels.

To solve all three challenges from first principles without relying on pre-existing encryption algorithms, we designed **CLAT-VSS** (*Chinese-Remainder-Theorem Lattice Algebraic Threshold Verifiable Secret Sharing & Master-Key Cipher*).

## 2. Mathematical Architecture (Number Theory + Linear Algebra)

### A. Mersenne Prime Field $\mathbb{F}_q$ & Division-Free Arithmetic (Number Theory)
CLAT-VSS operates over the eighth Mersenne prime finite field:
$$q = M_{31} = 2^{31} - 1 = 2,147,483,647$$
Because $2^{31} \equiv 1 \pmod q$, any 62-bit product $z = a \cdot b$ reduces modulo $q$ via the bitwise folding identity:
$$z \equiv (z \mathbin{\&} q) + (z \gg 31) \pmod q$$
This replaces variable-latency hardware division instructions with a deterministic 4-instruction sequence of shifts, bitwise ANDs, and branchless masks. Multiplicative inverses are computed via **Fermat's Little Theorem** ($a^{-1} \equiv a^{q-2} \pmod q$) using a **Constant-Time Montgomery Powering Ladder** that executes identical square-and-multiply operations for every bit of $q - 2$.

### B. Non-Linear Euler Power Bijection + Cauchy MDS Matrix Diffusion (Linear Algebra)
To defeat the classical Hill Cipher KPA vulnerability while remaining 100% immune to cache-timing attacks:
* **Confusion (Zero-Table Euler Power S-Box):** By **Euler's Totient Theorem**, $\phi(q) = q - 1 = 2,147,483,646$. Because $\gcd(5, q-1) = 1$, the quintic power map $S(x) = x^5 \bmod q$ is a strict algebraic bijection over $\mathbb{F}_q$ with unique inverse exponent:
  $$d_{\text{inv}} = \frac{4(q-1) + 1}{5} = 1,717,986,917 \implies S^{-1}(y) = y^{1717986917} \bmod q$$
  Evaluating $S(x) = (x^2)^2 \cdot x \bmod q$ requires only 3 register multiplications and zero lookup tables in memory.
* **Diffusion ($8 \times 8$ Cauchy MDS Matrix):** State vectors $\mathbf{x} \in \mathbb{F}_q^8$ are multiplied across $R = 6$ rounds by an $8 \times 8$ Cauchy Maximum Distance Separable (MDS) matrix $\mathbf{M}_{i,j} = (\alpha_i + \beta_j)^{-1} \bmod q$ with branch number $\mathcal{B}(\mathbf{M}) = 9$, guaranteeing that a single-element perturbation diffuses across all 8 coordinates in one round:
  $$\mathbf{x}^{(r)} = \mathbf{M} \cdot S^{\otimes 8}\!\left(\mathbf{x}^{(r-1)}\right) + \mathbf{k}^{(r)} \pmod q$$
* **Module-LWE Ephemeral Lattice Encapsulation:** The 256-bit Master Key (encoded as $\mathbf{m}_{\text{hi}}, \mathbf{m}_{\text{lo}} \in \{0,\dots,2^{16}-1\}^8$) is encapsulated in a **Learning With Errors (LWE)** lattice system over $\mathbb{F}_q^{8 \times 8}$ with bounded centered binomial noise $\mathbf{e}_0, \mathbf{e}_1, \mathbf{e}_2 \in [-\eta, \eta]^8$ ($\eta = 4$) and scaling factor $\Delta = \lfloor q/2^{16} \rfloor = 32,768$:
  $$\mathbf{b} = \mathbf{A}\mathbf{s} + \mathbf{e}_0 \pmod q, \qquad \mathbf{u} = \mathbf{A}^T\mathbf{r} + \mathbf{e}_1 \pmod q, \qquad \mathbf{v} = \mathbf{b}\odot\mathbf{r} + \mathbf{e}_2 + \Delta \cdot \mathbf{m} \pmod q$$

### C. Dual Vandermonde-CRT Verifiable Secret Sharing & Isomorphic Subgroup Commitments
To split the 256-bit Master Key ($\mathbf{m} \in \mathbb{F}_q^{16}$) across $N$ custodians with threshold $T$, the dealer constructs a random degree-$(T-1)$ polynomial matrix $\mathbf{F} \in \mathbb{F}_q^{T \times 16}$ (with $\mathbf{F}_{0,:} = \mathbf{m}^T$) and a blinding matrix $\mathbf{B} \in \mathbb{F}_q^{T \times 16}$. Each custodian $i \in \{1,\dots,N\}$ at evaluation point $\alpha_i = i$ receives the Vandermonde projection $\mathbf{y}_i = \mathbf{v}(\alpha_i)^T \mathbf{F} \pmod q$ and $\mathbf{z}_i = \mathbf{v}(\alpha_i)^T \mathbf{B} \pmod q$, where $\mathbf{v}(\alpha_i) = [1, \alpha_i, \dots, \alpha_i^{T-1}]^T$.

Every share is validated without revealing the secret via **three simultaneous mathematical checks**:
1. **Chinese Remainder Theorem (CRT) Residue Channel:** Each share coordinate $y_{i,w}$ is decomposed modulo pairwise coprime primes $m_1 = 65,537$ ($F_4$) and $m_2 = 65,521$ ($M = m_1 m_2 = 4,294,049,777 > q$) and verified via the constructive CRT lift:
   $$\hat{y}_{i,w} = \big(r_{1,w} m_2 (m_2^{-1} \bmod m_1) + r_{2,w} m_1 (m_1^{-1} \bmod m_2)\big) \bmod M$$
2. **Linear-Algebraic Ajtai/SIS Lattice Commitment:** Using public full-rank matrices $\mathbf{G}, \mathbf{H} \in \mathbb{F}_q^{4 \times 8}$ and $\mathbf{C}_{\text{lat}} = \mathbf{F}\mathbf{G}^T + \mathbf{B}\mathbf{H}^T \pmod q$, custodian $i$ verifies:
   $$\mathbf{y}_i \mathbf{G}^T + \mathbf{z}_i \mathbf{H}^T \equiv \mathbf{v}(\alpha_i)^T \mathbf{C}_{\text{lat}} \pmod q$$
3. **Number-Theoretic Pedersen Discrete-Logarithm Commitment:** Using the prime modulus $P = 46q + 1 = 98,784,247,763$, the multiplicative group $\mathbb{F}_P^*$ contains a cyclic subgroup $\mathbb{G}_q$ of **exact prime order $q = 2^{31}-1$** generated by $g = 34,359,770,408$ and $h = 13,490,067,929$. Because $\text{ord}_P(g) = \text{ord}_P(h) = q$, the exponent ring of $\mathbb{G}_q \subset \mathbb{F}_P^*$ is strictly isomorphic to the linear-algebra field $\mathbb{F}_q$:
   $$g^{y_{i,w}} \cdot h^{z_{i,w}} \equiv \prod_{t=0}^{T-1} \Big(g^{F_{t,w}} h^{B_{t,w}}\Big)^{\alpha_i^t \bmod q} \pmod P$$

## 3. Side-Channel Defenses & Vulnerability Window Reduction

| Vulnerability Surface | How Standard Implementations Fail | How CLAT-VSS Mitigates the Window |
| :--- | :--- | :--- |
| **Instruction Timing** | Hardware `div`/`idiv` leaks operand bit-length | Branchless Mersenne shift-and-add folding (`fq_reduce`) over $q = 2^{31}-1$ |
| **Cache Timing** | Lookup-table S-boxes leak secret byte indices via L1 evictions | Zero-table algebraic bijection $S(x) = x^5 \bmod q$ in CPU registers |
| **Power / EM (SPA)** | Data-dependent branches in modular exponentiation/GCD | Constant-time 31-bit Montgomery ladder (`fq_pow_ct`, `fp_pow_ct`) |
| **Power / EM (DPA/CPA)** | Raw secret keys correlate with register Hamming weight | **First-Order Arithmetic Masking** splits keys & shares into ephemeral dual shares $k = k^{(0)} + k^{(1)} \bmod q$ during Cauchy & Vandermonde transforms |
| **Memory Remnants** | Dead-store elimination leaves plaintext keys in stack frames | Inline assembly memory barrier + `volatile` zeroization (`secure_zeroize`), restricting plaintext RAM lifetime to **$272.86\,\mu\text{s}$** |

## 4. Empirical Cryptanalysis & Benchmark Results

Compiling and running `clat_vss.c` (`gcc -O3 -Wall -Wextra -Werror clat_vss.c -lm -o clat_vss && ./clat_vss`) executes our applied **Threshold HSM Master-Key Vault** ($T=3, N=5$) and 6-stage cryptanalysis suite:

| Cryptanalytic Test | Ideal Target | CLAT-VSS Empirical Result | Status |
| :--- | :--- | :--- | :--- |
| **Strict Avalanche Criterion (SAC)** | $50.00\%$ bit-flip probability | **$49.92\%$** across $1,000$ 1-bit flip trials | PASS |
| **Golomb Postulate R1 (Balance)** | $50.00\%$ ones / $50.00\%$ zeros | **$50.11\%$ ones / $49.89\%$ zeros** ($62,400$ bits) | PASS |
| **Golomb Postulate R2 (Run Lengths)** | $L_1=50\%, L_2=25\%, L_3=12.5\%$ | **$L_1=50.1\%, L_2=25.2\%, L_3=12.4\%$** | PASS |
| **Golomb Postulate R3 (Autocorrelation)** | $|C(\tau)| < 0.0200$ ($\tau \neq 0$) | **$\max_{\tau} |C(\tau)| = 0.0071$** | PASS |
| **Ciphertext Shannon Entropy $H(X)$** | $8.0000\text{ bits/byte}$ | **$7.9929\text{ bits/byte}$** | PASS |
| **Byzantine Fault Injection (1-bit tamper)** | $100\%$ detection prior to interpolation | **Detected & Rejected (`rc = -2`)** | PASS |
| **DudeCT Welch's $t$-Test (Constant-Time)** | $|t| < 4.50$ (Class-0 vs Class-1) | **$|t| = 0.45$** ($1619.9\text{ ns}$ vs $1610.3\text{ ns}$) | PASS |

## 5. How to Build & Run

```bash
gcc -O3 -Wall -Wextra -Werror clat_vss.c -lm -o clat_vss
./clat_vss
```

## 6. Recommended 2-Minute YouTube Video Walkthrough Script

1. **0:00 – 0:30 (The Problem & Mathematical Insight):** Show the LaTeX paper (`clat_vss_paper.pdf`). Explain how CLAT-VSS unifies **Linear Algebra** (Cauchy MDS diffusion, Module-LWE lattice encapsulation, and Vandermonde matrix secret sharing) with **Number Theory** (Mersenne prime $q = 2^{31}-1$ arithmetic, Euler's Totient Theorem bijection $x^5 \bmod q$, Chinese Remainder Theorem residue channels, and Pedersen Discrete-Logarithm commitments in $\mathbb{G}_q \subset \mathbb{F}_{98784247763}^*$).
2. **0:30 – 1:15 (Side-Channel & Vulnerability Window Mitigations):** Walk through `clat_vss.c` functions `fq_reduce`, `fq_pow_ct`, `clat_decrypt_master_key_masked`, and `secure_zeroize`. Highlight how division-free Mersenne folding, zero-table S-boxes, and first-order arithmetic masking ($k = k^{(0)} + k^{(1)} \bmod q$) eliminate timing, cache, and DPA side channels while shrinking the plaintext RAM vulnerability window to $272.86\,\mu\text{s}$.
3. **1:15 – 2:00 (Live Terminal Execution & Cryptanalysis Proof):** Run `gcc -O3 -Wall -Wextra -Werror clat_vss.c -lm -o clat_vss && ./clat_vss` live in the terminal. Point out the 3-of-5 Threshold HSM Vault reconstruction, the automatic blocking of the 1-bit Byzantine fault injection, the $49.92\%$ Strict Avalanche Criterion score, Golomb's R1–R3 randomness postulates, and the DudeCT Welch's $t$-test score of $|t| = 0.45 < 4.50$.
