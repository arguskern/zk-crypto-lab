# ZK Crypto Lab 🔐

> **Interactive Zero-Knowledge Proofs (ZK-SNARK / R1CS), Post-Quantum Lattice Cryptography & Elliptic Curves.**

[![CI & CD](https://github.com/arguskern/zk-crypto-lab/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/arguskern/zk-crypto-lab/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-teal.svg)](https://opensource.org/licenses/MIT)

**Live Interactive Platform:** [https://arguskern.github.io/zk-crypto-lab/](https://arguskern.github.io/zk-crypto-lab/)

---

## 🚀 Key Modules & Capabilities

### 1. Zero-Knowledge SNARKs & R1CS (Rank-1 Constraint Systems)
- **Arithmetic Circuit Compiler:** Translates high-level computations into quadratic constraints $(A \cdot w) \circ (B \cdot w) = C \cdot w$.
- **Witness Generation & Satisfaction:** Computes intermediate wire variables and evaluates constraint matrix validity.
- **Circuit Demonstrations:** Cubic polynomial verification ($x^3 + x + 5 = 35$) and factor knowledge proofs.

### 2. Schnorr Sigma Protocol & Discrete Logarithm ZKP
- **Interactive Prover/Verifier Dialogue:** Step-by-step Commitment ($t = g^r \pmod p$), Challenge ($c$), and Response ($s = r + c \cdot x \pmod{p-1}$).
- **Fiat-Shamir Transformation:** Cryptographic hash heuristic for non-interactive proofs.
- **Tamper Simulation:** Interactive forgery detection verifying $g^s \equiv t \cdot y^c \pmod p$.

### 3. Post-Quantum Cryptography (ML-KEM / Kyber - NIST FIPS 203)
- **Polynomial Ring Arithmetic:** Computations in $\mathbb{Z}_{3329}[X] / (X^{256} + 1)$ with Number Theoretic Transform (NTT) support.
- **Module Learning With Errors (M-LWE):** Centered Binomial Distribution $\text{CBD}(\eta=2)$ noise generation and lattice hardness.
- **Key Encapsulation & Error-Correcting Decapsulation:** Full cycle key generation $(A, t)$, encapsulation $(u, v)$, and noise-tolerant secret recovery.

### 4. Elliptic Curve Cryptography (ECC) & ECDH
- **Weierstrass Curves:** Point addition, point doubling, point at infinity over finite fields $\mathbb{F}_p$.
- **Scalar Multiplication:** Double-and-Add algorithm for $k \cdot P$.
- **ECDH Key Agreement:** Mutual shared secret computation between parties with affine plane visualization.

---

## 🛠️ Getting Started

```bash
# Clone the repository
git clone https://github.com/arguskern/zk-crypto-lab.git
cd zk-crypto-lab

# Install dependencies
npm install

# Run unit test suite
npm test

# Build production artifacts
npm run build
```

---

## 👤 Author
**Argus Kern** — Software Engineer at Delos (`argus.kern@delos-beta.dls.so`)
