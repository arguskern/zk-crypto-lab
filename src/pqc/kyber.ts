// Post-Quantum Cryptography: ML-KEM (Kyber) Lattice-Based Key Encapsulation Mechanism
// Operates on polynomial ring R_q = Z_q[X] / (X^n + 1) with n = 256, q = 3329

export const KYBER_N = 256;
export const KYBER_Q = 3329;

export type Polynomial = number[]; // length 256

export class KyberLWE {
  static createZeroPoly(): Polynomial {
    return new Array(KYBER_N).fill(0);
  }

  static createRandomPoly(bound: number = KYBER_Q): Polynomial {
    const p = new Array(KYBER_N);
    for (let i = 0; i < KYBER_N; i++) {
      p[i] = Math.floor(Math.random() * bound);
    }
    return p;
  }

  // Centered Binomial Distribution for noise e, s (eta = 2)
  static sampleCBD(eta: number = 2): Polynomial {
    const p = new Array(KYBER_N);
    for (let i = 0; i < KYBER_N; i++) {
      let a = 0;
      let b = 0;
      for (let j = 0; j < eta; j++) {
        a += Math.random() < 0.5 ? 1 : 0;
        b += Math.random() < 0.5 ? 1 : 0;
      }
      p[i] = (a - b + KYBER_Q) % KYBER_Q;
    }
    return p;
  }

  // Polynomial addition in R_q
  static polyAdd(a: Polynomial, b: Polynomial): Polynomial {
    const res = new Array(KYBER_N);
    for (let i = 0; i < KYBER_N; i++) {
      res[i] = (a[i] + b[i]) % KYBER_Q;
    }
    return res;
  }

  // Polynomial subtraction in R_q
  static polySub(a: Polynomial, b: Polynomial): Polynomial {
    const res = new Array(KYBER_N);
    for (let i = 0; i < KYBER_N; i++) {
      res[i] = (a[i] - b[i] + KYBER_Q) % KYBER_Q;
    }
    return res;
  }

  // Polynomial multiplication modulo (X^256 + 1) in Z_q
  static polyMul(a: Polynomial, b: Polynomial): Polynomial {
    const res = new Array(KYBER_N).fill(0);
    for (let i = 0; i < KYBER_N; i++) {
      for (let j = 0; j < KYBER_N; j++) {
        const deg = i + j;
        const coeff = (a[i] * b[j]) % KYBER_Q;
        if (deg < KYBER_N) {
          res[deg] = (res[deg] + coeff) % KYBER_Q;
        } else {
          // X^256 = -1 mod (X^256 + 1)
          const target = deg - KYBER_N;
          res[target] = (res[target] - coeff + KYBER_Q) % KYBER_Q;
        }
      }
    }
    return res;
  }

  // Key Generation: A in R_q, private secret s, error e -> public key t = A * s + e
  static keyGen(): {
    A: Polynomial;
    secretKey: Polynomial;
    error: Polynomial;
    publicKey: Polynomial;
  } {
    const A = this.createRandomPoly(KYBER_Q);
    const s = this.sampleCBD(2);
    const e = this.sampleCBD(2);
    const As = this.polyMul(A, s);
    const t = this.polyAdd(As, e);

    return {
      A,
      secretKey: s,
      error: e,
      publicKey: t,
    };
  }

  // Encapsulation: encrypt a 1-bit or byte message into (u, v) with ephemeral secret r
  static encapsulate(
    A: Polynomial,
    t: Polynomial,
    messageBit: number = 1
  ): {
    u: Polynomial;
    v: Polynomial;
    ephemeralSecret: Polynomial;
    sharedSecretBit: number;
  } {
    const r = this.sampleCBD(2);
    const e1 = this.sampleCBD(2);
    const e2 = this.sampleCBD(2);

    // u = A * r + e1
    const Ar = this.polyMul(A, r);
    const u = this.polyAdd(Ar, e1);

    // v = t * r + e2 + round(q/2) * m
    const tr = this.polyMul(t, r);
    const vNoMsg = this.polyAdd(tr, e2);

    // Encode message bit into constant polynomial term
    const msgCoeff = Math.round(KYBER_Q / 2) * (messageBit ? 1 : 0);
    const v = [...vNoMsg];
    v[0] = (v[0] + msgCoeff) % KYBER_Q;

    return {
      u,
      v,
      ephemeralSecret: r,
      sharedSecretBit: messageBit,
    };
  }

  // Decapsulation: recover message bit using private key s: m_approx = v - s * u
  static decapsulate(u: Polynomial, v: Polynomial, s: Polynomial): {
    recoveredBit: number;
    rawCoeff: number;
  } {
    const su = this.polyMul(s, u);
    const diff = this.polySub(v, su);

    // Decode message bit from constant term: if close to q/2 (1665), bit = 1, else 0
    const rawCoeff = diff[0];
    const targetHalf = Math.round(KYBER_Q / 2);
    const distToHalf = Math.abs(rawCoeff - targetHalf);
    const distToZero = Math.min(rawCoeff, KYBER_Q - rawCoeff);

    const recoveredBit = distToHalf < distToZero ? 1 : 0;

    return {
      recoveredBit,
      rawCoeff,
    };
  }
}
