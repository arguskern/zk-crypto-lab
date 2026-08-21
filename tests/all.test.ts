import { describe, it } from 'node:test';
import assert from 'node:assert';
import { SchnorrZKP, modExp } from '../src/zkp/schnorr.js';
import { R1CSEngine } from '../src/zkp/r1cs.js';
import { KyberLWE, KYBER_N, KYBER_Q } from '../src/pqc/kyber.js';
import { EllipticCurve, ECPoint } from '../src/ecc/weierstrass.js';

describe('1. Zero-Knowledge Schnorr Identification Protocol', () => {
  it('should generate valid ZK proof and verify discrete log equality', () => {
    const zkp = new SchnorrZKP();
    const secretX = 123456789n;
    const publicKeyY = zkp.generatePublicKey(secretX);

    // Prover generates commitment
    const r = 987654321n;
    const commitmentT = zkp.createCommitment(r);

    // Verifier/Fiat-Shamir challenge
    const challengeC = zkp.hashChallenge(publicKeyY, commitmentT, 'auth_challenge');

    // Prover response
    const responseS = zkp.createResponse(r, challengeC, secretX);

    const verification = zkp.verifyProof({
      commitment: commitmentT,
      challenge: challengeC,
      response: responseS,
      publicKey: publicKeyY,
    });

    assert.strictEqual(verification.valid, true);
    assert.strictEqual(verification.leftSide, verification.rightSide);
  });

  it('should reject tampered or forged Schnorr proofs', () => {
    const zkp = new SchnorrZKP();
    const secretX = 42n;
    const publicKeyY = zkp.generatePublicKey(secretX);
    const r = 100n;
    const t = zkp.createCommitment(r);
    const c = zkp.hashChallenge(publicKeyY, t);
    const s = zkp.createResponse(r, c, secretX);

    // Tamper with response
    const badVerification = zkp.verifyProof({
      commitment: t,
      challenge: c,
      response: s + 1n,
      publicKey: publicKeyY,
    });

    assert.strictEqual(badVerification.valid, false);
  });
});

describe('2. R1CS Arithmetic Circuit & Witness Solver', () => {
  it('should compile cubic polynomial x^3 + x + 5 = 35 and verify satisfied constraints', () => {
    const system = R1CSEngine.createCubicPolynomialCircuit();
    const x = 3; // 3^3 + 3 + 5 = 27 + 3 + 5 = 35
    const { witness, out } = R1CSEngine.generateCubicWitness(x);

    assert.strictEqual(out, 35);
    const res = R1CSEngine.verifyWitness(system, witness);

    assert.strictEqual(res.satisfied, true);
    assert.strictEqual(res.constraintResults.length, 3);
    for (const cr of res.constraintResults) {
      assert.strictEqual(cr.satisfied, true);
    }
  });

  it('should fail verification if witness values are forged or inconsistent', () => {
    const system = R1CSEngine.createCubicPolynomialCircuit();
    // Forged witness where x = 3 but claimed out = 40
    const forgedWitness = [1, 40, 3, 9, 27];
    const res = R1CSEngine.verifyWitness(system, forgedWitness);

    assert.strictEqual(res.satisfied, false);
  });
});

describe('3. Post-Quantum ML-KEM (Kyber) Lattice Key Encapsulation', () => {
  it('should perform polynomial multiplication modulo (X^256 + 1) in Z_q', () => {
    const a = KyberLWE.createZeroPoly();
    const b = KyberLWE.createZeroPoly();
    a[0] = 3;
    b[0] = 5;
    const prod = KyberLWE.polyMul(a, b);
    assert.strictEqual(prod[0], 15);

    // Test degree overflow: X^200 * X^100 = X^300 = -X^44
    const a2 = KyberLWE.createZeroPoly();
    const b2 = KyberLWE.createZeroPoly();
    a2[200] = 1;
    b2[100] = 1;
    const prod2 = KyberLWE.polyMul(a2, b2);
    assert.strictEqual(prod2[44], (KYBER_Q - 1) % KYBER_Q);
  });

  it('should generate keys, encapsulate secret bit, and decapsulate with lattice noise tolerance', () => {
    const keypair = KyberLWE.keyGen();
    assert.strictEqual(keypair.publicKey.length, KYBER_N);
    assert.strictEqual(keypair.secretKey.length, KYBER_N);

    // Encapsulate bit 1
    const enc1 = KyberLWE.encapsulate(keypair.A, keypair.publicKey, 1);
    const dec1 = KyberLWE.decapsulate(enc1.u, enc1.v, keypair.secretKey);
    assert.strictEqual(dec1.recoveredBit, 1);

    // Encapsulate bit 0
    const enc0 = KyberLWE.encapsulate(keypair.A, keypair.publicKey, 0);
    const dec0 = KyberLWE.decapsulate(enc0.u, enc0.v, keypair.secretKey);
    assert.strictEqual(dec0.recoveredBit, 0);
  });
});

describe('4. Elliptic Curve Arithmetic & ECDH Key Exchange', () => {
  it('should verify point addition and scalar multiplication on Weierstrass curve', () => {
    // Curve y^2 = x^3 + 7 (mod 17)
    const curve = new EllipticCurve(0n, 7n, 17n);
    // Let's check point (2, 5): 5^2 = 25 = 8 mod 17; 2^3 + 7 = 8 + 7 = 15 != 8.
    // Let's check (2, 7): 7^2 = 49 = 15 mod 17; 2^3 + 7 = 15 mod 17. (2, 7) is on curve!
    const P: ECPoint = { x: 2n, y: 7n, infinity: false };
    assert.strictEqual(curve.isOnCurve(P), true);

    const P2 = curve.add(P, P);
    assert.strictEqual(curve.isOnCurve(P2), true);
    assert.strictEqual(P2.infinity, false);

    const P3 = curve.scalarMultiply(3n, P);
    assert.strictEqual(curve.isOnCurve(P3), true);
  });

  it('should execute ECDH key agreement yielding identical shared secrets', () => {
    const curve = new EllipticCurve(0n, 7n, 17n);
    const G: ECPoint = { x: 2n, y: 7n, infinity: false };

    const aliceSecret = 3n;
    const bobSecret = 5n;

    const ecdh = curve.simulateECDH(G, aliceSecret, bobSecret);
    assert.strictEqual(ecdh.match, true);
    assert.strictEqual(ecdh.aliceShared.x, ecdh.bobShared.x);
    assert.strictEqual(ecdh.aliceShared.y, ecdh.bobShared.y);
  });
});
