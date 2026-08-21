// Schnorr Identification Protocol & Zero-Knowledge Proof for Discrete Logarithm
// Prover proves knowledge of secret x such that y = g^x (mod p) without revealing x.

export interface SchnorrParams {
  p: bigint; // Prime modulus
  g: bigint; // Generator
}

export interface SchnorrProof {
  commitment: bigint; // t = g^r (mod p)
  challenge: bigint;  // c
  response: bigint;   // s = r + c * x (mod p - 1)
  publicKey: bigint;  // y = g^x (mod p)
}

export function modExp(base: bigint, exp: bigint, mod: bigint): bigint {
  if (mod === 1n) return 0n;
  let res = 1n;
  let b = base % mod;
  let e = exp;
  while (e > 0n) {
    if (e % 2n === 1n) res = (res * b) % mod;
    b = (b * b) % mod;
    e = e / 2n;
  }
  return res;
}

export class SchnorrZKP {
  public params: SchnorrParams;

  constructor(p: bigint = 2147483647n, g: bigint = 7n) {
    // Default: Mersenne prime 2^31 - 1, generator 7
    this.params = { p, g };
  }

  generatePublicKey(secret: bigint): bigint {
    return modExp(this.params.g, secret, this.params.p);
  }

  // Step 1: Prover creates random commitment
  createCommitment(r: bigint): bigint {
    return modExp(this.params.g, r, this.params.p);
  }

  // Step 2: Fiat-Shamir hash challenge or Verifier random challenge
  hashChallenge(publicKey: bigint, commitment: bigint, message: string = ''): bigint {
    const data = `${this.params.g}:${this.params.p}:${publicKey}:${commitment}:${message}`;
    let hash = 0n;
    for (let i = 0; i < data.length; i++) {
      hash = (hash * 31n + BigInt(data.charCodeAt(i))) % (this.params.p - 1n);
    }
    return hash === 0n ? 1n : hash;
  }

  // Step 3: Prover calculates response s = (r + c * x) mod (p - 1)
  createResponse(r: bigint, challenge: bigint, secret: bigint): bigint {
    const q = this.params.p - 1n;
    return (r + ((challenge % q) * (secret % q)) % q) % q;
  }

  // Step 4: Verifier checks g^s == t * y^c (mod p)
  verifyProof(proof: SchnorrProof): { valid: boolean; leftSide: bigint; rightSide: bigint } {
    const leftSide = modExp(this.params.g, proof.response, this.params.p);
    const yExpC = modExp(proof.publicKey, proof.challenge, this.params.p);
    const rightSide = (proof.commitment * yExpC) % this.params.p;

    return {
      valid: leftSide === rightSide,
      leftSide,
      rightSide,
    };
  }
}
