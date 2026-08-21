// Elliptic Curve Cryptography (ECC) over Finite Field F_p
// Curve Equation: y^2 = x^3 + a*x + b (mod p)

export interface ECPoint {
  x: bigint;
  y: bigint;
  infinity: boolean;
}

export class EllipticCurve {
  constructor(
    public a: bigint = 0n,
    public b: bigint = 7n,
    public p: bigint = 2147483647n // Mersenne prime 2^31 - 1
  ) {}

  getInfinityPoint(): ECPoint {
    return { x: 0n, y: 0n, infinity: true };
  }

  isInfinity(P: ECPoint): boolean {
    return P.infinity;
  }

  // Modulo helper handling negative numbers
  mod(n: bigint): bigint {
    const r = n % this.p;
    return r >= 0n ? r : r + this.p;
  }

  // Modular inverse using Extended Euclidean Algorithm
  modInverse(n: bigint): bigint {
    let a = this.mod(n);
    let m = this.p;
    let m0 = m;
    let y = 0n;
    let x = 1n;

    if (m === 1n) return 0n;

    while (a > 1n) {
      const q = a / m;
      let t = m;
      m = a % m;
      a = t;
      t = y;
      y = x - q * y;
      x = t;
    }

    if (x < 0n) x = x + m0;
    return x;
  }

  // Verify if point satisfies curve equation
  isOnCurve(P: ECPoint): boolean {
    if (P.infinity) return true;
    const left = this.mod(P.y * P.y);
    const right = this.mod(P.x * P.x * P.x + this.a * P.x + this.b);
    return left === right;
  }

  // Point Addition: R = P + Q
  add(P: ECPoint, Q: ECPoint): ECPoint {
    if (P.infinity) return Q;
    if (Q.infinity) return P;

    // Check if P == -Q (same x, opposite y)
    if (P.x === Q.x && this.mod(P.y + Q.y) === 0n) {
      return this.getInfinityPoint();
    }

    let lambda: bigint;

    if (P.x === Q.x && P.y === Q.y) {
      // Point Doubling
      if (P.y === 0n) return this.getInfinityPoint();
      const num = this.mod(3n * P.x * P.x + this.a);
      const den = this.modInverse(2n * P.y);
      lambda = this.mod(num * den);
    } else {
      // Distinct Points
      const num = this.mod(Q.y - P.y);
      const den = this.modInverse(Q.x - P.x);
      lambda = this.mod(num * den);
    }

    const rx = this.mod(lambda * lambda - P.x - Q.x);
    const ry = this.mod(lambda * (P.x - rx) - P.y);

    return { x: rx, y: ry, infinity: false };
  }

  // Scalar Multiplication using Double-and-Add: k * P
  scalarMultiply(k: bigint, P: ECPoint): ECPoint {
    let result = this.getInfinityPoint();
    let current = P;
    let scalar = k;

    while (scalar > 0n) {
      if (scalar % 2n === 1n) {
        result = this.add(result, current);
      }
      current = this.add(current, current);
      scalar = scalar / 2n;
    }

    return result;
  }

  // ECDH Simulation
  simulateECDH(
    generator: ECPoint,
    aliceSecret: bigint,
    bobSecret: bigint
  ): {
    alicePublic: ECPoint;
    bobPublic: ECPoint;
    aliceShared: ECPoint;
    bobShared: ECPoint;
    match: boolean;
  } {
    const alicePublic = this.scalarMultiply(aliceSecret, generator);
    const bobPublic = this.scalarMultiply(bobSecret, generator);

    const aliceShared = this.scalarMultiply(aliceSecret, bobPublic);
    const bobShared = this.scalarMultiply(bobSecret, alicePublic);

    const match =
      !aliceShared.infinity &&
      !bobShared.infinity &&
      aliceShared.x === bobShared.x &&
      aliceShared.y === bobShared.y;

    return {
      alicePublic,
      bobPublic,
      aliceShared,
      bobShared,
      match,
    };
  }
}
