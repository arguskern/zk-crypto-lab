import { R1CSEngine } from './zkp/r1cs.js';
import { SchnorrZKP } from './zkp/schnorr.js';
import { KyberLWE, KYBER_N, KYBER_Q } from './pqc/kyber.js';
import { EllipticCurve, ECPoint } from './ecc/weierstrass.js';

window.addEventListener('DOMContentLoaded', () => {
  // Navigation Tabs
  const navBtns = document.querySelectorAll('.nav-btn');
  navBtns.forEach((btn) => {
    btn.addEventListener('click', () => {
      navBtns.forEach((b) => b.classList.remove('active'));
      document.querySelectorAll('.view-panel').forEach((p) => p.classList.remove('active'));

      btn.classList.add('active');
      const viewKey = (btn as HTMLElement).dataset.view;
      document.getElementById(`view-${viewKey}`)?.classList.add('active');
    });
  });

  // 1. R1CS Logic
  const r1csXInput = document.getElementById('r1cs-x-input') as HTMLInputElement;
  const r1csOutInput = document.getElementById('r1cs-out-input') as HTMLInputElement;
  const r1csWitnessDisplay = document.getElementById('r1cs-witness-display') as HTMLElement;
  const r1csStatus = document.getElementById('r1cs-status') as HTMLElement;
  const r1csTbody = document.getElementById('r1cs-tbody') as HTMLElement;
  const r1csVerifyBtn = document.getElementById('r1cs-verify-btn') as HTMLButtonElement;

  function updateR1CS() {
    const x = parseFloat(r1csXInput.value) || 0;
    const { witness, out } = R1CSEngine.generateCubicWitness(x);
    r1csOutInput.value = out.toString();

    r1csWitnessDisplay.textContent = `Witness Vector w = [ ${witness.join(', ')} ]\nVariable Mapping: [ 1, out=${out}, x=${x}, sym1=x²=${witness[3]}, sym2=x³=${witness[4]} ]`;

    const system = R1CSEngine.createCubicPolynomialCircuit();
    const res = R1CSEngine.verifyWitness(system, witness);

    r1csStatus.textContent = res.satisfied ? 'CONSTRAINTS SATISFIED' : 'CONSTRAINTS FAILED';
    r1csStatus.className = `status-badge ${res.satisfied ? 'status-success' : 'status-error'}`;

    r1csTbody.innerHTML = '';
    for (const cr of res.constraintResults) {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td style="text-align: left;">${cr.description}</td>
        <td>${cr.aEval}</td>
        <td>${cr.bEval}</td>
        <td>${cr.aEval * cr.bEval}</td>
        <td>${cr.cEval}</td>
        <td><span class="status-badge ${cr.satisfied ? 'status-success' : 'status-error'}">${cr.satisfied ? 'VALID' : 'FAIL'}</span></td>
      `;
      r1csTbody.appendChild(tr);
    }
  }

  r1csXInput.addEventListener('input', updateR1CS);
  r1csVerifyBtn.addEventListener('click', updateR1CS);
  updateR1CS();

  // 2. Schnorr Protocol Logic
  const schnorr = new SchnorrZKP();
  const schnorrSecretInput = document.getElementById('schnorr-secret') as HTMLInputElement;
  const schnorrPkInput = document.getElementById('schnorr-pk') as HTMLInputElement;
  const schnorrMsgInput = document.getElementById('schnorr-msg') as HTMLInputElement;
  const schnorrStatus = document.getElementById('schnorr-status') as HTMLElement;
  const schnorrTranscript = document.getElementById('schnorr-transcript') as HTMLElement;
  const schnorrRunBtn = document.getElementById('schnorr-run-btn') as HTMLButtonElement;
  const schnorrTamperBtn = document.getElementById('schnorr-tamper-btn') as HTMLButtonElement;

  function runSchnorr(tamper: boolean = false) {
    try {
      const secret = BigInt(schnorrSecretInput.value.trim() || '42');
      const pk = schnorr.generatePublicKey(secret);
      schnorrPkInput.value = pk.toString();

      const r = BigInt(Math.floor(Math.random() * 100000000) + 1000);
      const commitment = schnorr.createCommitment(r);
      const challenge = schnorr.hashChallenge(pk, commitment, schnorrMsgInput.value);
      let response = schnorr.createResponse(r, challenge, secret);

      if (tamper) {
        response = response + 1n; // Forgery attempt
      }

      const result = schnorr.verifyProof({
        commitment,
        challenge,
        response,
        publicKey: pk,
      });

      schnorrStatus.textContent = result.valid ? 'PROOF VERIFIED (ZKP OK)' : 'PROOF REJECTED (FORGERY)';
      schnorrStatus.className = `status-badge ${result.valid ? 'status-success' : 'status-error'}`;

      schnorrTranscript.textContent = [
        `[Setup] Prime p = ${schnorr.params.p}, Generator g = ${schnorr.params.g}`,
        `[Prover] Public Key y = g^x mod p = ${pk}`,
        `[1. Commitment] Pick random nonce r = ${r} -> t = g^r mod p = ${commitment}`,
        `[2. Fiat-Shamir] Challenge c = H(g, y, t, "${schnorrMsgInput.value}") = ${challenge}`,
        `[3. Response] s = (r + c * x) mod (p - 1) = ${response} ${tamper ? '⚠️ [TAMPERED]' : ''}`,
        `[4. Verification Check]`,
        `    Left Side:  g^s mod p        = ${result.leftSide}`,
        `    Right Side: t * y^c mod p    = ${result.rightSide}`,
        `    Equal: ${result.valid ? 'YES (Zero-Knowledge Authenticated)' : 'NO (Cryptographic Mismatch)'}`,
      ].join('\n');
    } catch (e: any) {
      schnorrTranscript.textContent = `Error: ${e.message}`;
    }
  }

  schnorrRunBtn.addEventListener('click', () => runSchnorr(false));
  schnorrTamperBtn.addEventListener('click', () => runSchnorr(true));
  runSchnorr(false);

  // 3. Post-Quantum Kyber Logic
  const kyberMsgSelect = document.getElementById('kyber-msg-select') as HTMLSelectElement;
  const kyberStatus = document.getElementById('kyber-status') as HTMLElement;
  const kyberLog = document.getElementById('kyber-log') as HTMLElement;
  const kyberRunBtn = document.getElementById('kyber-run-btn') as HTMLButtonElement;
  const kyberCanvas = document.getElementById('kyber-canvas') as HTMLCanvasElement;
  const kCtx = kyberCanvas.getContext('2d');

  function renderKyberNoisePlot(noise: number[]) {
    if (!kCtx) return;
    kyberCanvas.width = kyberCanvas.clientWidth;
    kyberCanvas.height = kyberCanvas.clientHeight;
    kCtx.clearRect(0, 0, kyberCanvas.width, kyberCanvas.height);

    const w = kyberCanvas.width;
    const h = kyberCanvas.height;
    const barWidth = w / noise.length;

    kCtx.fillStyle = 'rgba(29, 153, 150, 0.4)';
    kCtx.strokeStyle = '#38efeb';
    kCtx.lineWidth = 1;

    for (let i = 0; i < noise.length; i++) {
      // Map coeff [-2, 2] around 0/q
      const val = noise[i] > KYBER_Q / 2 ? noise[i] - KYBER_Q : noise[i];
      const barH = (val / 4) * (h / 2);
      const x = i * barWidth;
      const y = h / 2;

      kCtx.fillRect(x, y, barWidth, -barH);
    }

    // Zero center line
    kCtx.beginPath();
    kCtx.moveTo(0, h / 2);
    kCtx.lineTo(w, h / 2);
    kCtx.strokeStyle = 'rgba(255,255,255,0.2)';
    kCtx.stroke();
  }

  function runKyber() {
    const bit = parseInt(kyberMsgSelect.value);
    const keypair = KyberLWE.keyGen();
    const enc = KyberLWE.encapsulate(keypair.A, keypair.publicKey, bit);
    const dec = KyberLWE.decapsulate(enc.u, enc.v, keypair.secretKey);

    const success = dec.recoveredBit === bit;
    kyberStatus.textContent = success ? 'DEC_SUCCESS (BIT RECOVERED)' : 'DEC_FAIL';
    kyberStatus.className = `status-badge ${success ? 'status-success' : 'status-error'}`;

    kyberLog.textContent = [
      `[KeyGen] Sampled secret s, error e from CBD(η=2) in Z_${KYBER_Q}[X]/(X^256+1)`,
      `         Public Key t[0..3] = [${keypair.publicKey.slice(0, 4).join(', ')}...]`,
      `[Encapsulate] Message Bit = ${bit} (Target Coeff = ${bit ? Math.round(KYBER_Q / 2) : 0})`,
      `              Ciphertext u[0..3] = [${enc.u.slice(0, 4).join(', ')}...]`,
      `              Ciphertext v[0..3] = [${enc.v.slice(0, 4).join(', ')}...]`,
      `[Decapsulate] Computed v - s*u: Constant Term = ${dec.rawCoeff}`,
      `              Distance to 0: ${Math.min(dec.rawCoeff, KYBER_Q - dec.rawCoeff)}`,
      `              Distance to q/2 (${Math.round(KYBER_Q / 2)}): ${Math.abs(dec.rawCoeff - Math.round(KYBER_Q / 2))}`,
      `              Decoded Secret Bit: ${dec.recoveredBit} (${success ? 'MATCH' : 'MISMATCH'})`,
    ].join('\n');

    renderKyberNoisePlot(keypair.error);
  }

  kyberRunBtn.addEventListener('click', runKyber);
  runKyber();

  // 4. Elliptic Curves & ECDH Logic
  const eccAliceKeyInput = document.getElementById('ecc-alice-key') as HTMLInputElement;
  const eccBobKeyInput = document.getElementById('ecc-bob-key') as HTMLInputElement;
  const ecdhStatus = document.getElementById('ecdh-status') as HTMLElement;
  const eccLog = document.getElementById('ecc-log') as HTMLElement;
  const eccRunBtn = document.getElementById('ecc-run-btn') as HTMLButtonElement;
  const eccCanvas = document.getElementById('ecc-canvas') as HTMLCanvasElement;
  const eCtx = eccCanvas.getContext('2d');

  const curve = new EllipticCurve(0n, 7n, 17n); // y^2 = x^3 + 7 mod 17
  const G: ECPoint = { x: 2n, y: 7n, infinity: false };

  function renderCurveGrid(activePoints: ECPoint[]) {
    if (!eCtx) return;
    eccCanvas.width = eccCanvas.clientWidth;
    eccCanvas.height = eccCanvas.clientHeight;
    eCtx.clearRect(0, 0, eccCanvas.width, eccCanvas.height);

    const p = 17;
    const pad = 30;
    const w = eccCanvas.width - pad * 2;
    const h = eccCanvas.height - pad * 2;
    const stepX = w / (p - 1);
    const stepY = h / (p - 1);

    // Grid lines
    eCtx.strokeStyle = 'rgba(255,255,255,0.05)';
    eCtx.lineWidth = 1;
    for (let i = 0; i < p; i++) {
      eCtx.beginPath();
      eCtx.moveTo(pad + i * stepX, pad);
      eCtx.lineTo(pad + i * stepX, pad + h);
      eCtx.stroke();

      eCtx.beginPath();
      eCtx.moveTo(pad, pad + i * stepY);
      eCtx.lineTo(pad + w, pad + i * stepY);
      eCtx.stroke();
    }

    // Plot all curve points
    for (let x = 0n; x < 17n; x++) {
      for (let y = 0n; y < 17n; y++) {
        const pt: ECPoint = { x, y, infinity: false };
        if (curve.isOnCurve(pt)) {
          const px = pad + Number(x) * stepX;
          const py = pad + h - Number(y) * stepY;

          eCtx.beginPath();
          eCtx.arc(px, py, 4, 0, Math.PI * 2);
          eCtx.fillStyle = '#1d9996';
          eCtx.fill();
        }
      }
    }

    // Highlight Generator & active points
    for (let i = 0; i < activePoints.length; i++) {
      const pt = activePoints[i];
      if (pt.infinity) continue;
      const px = pad + Number(pt.x) * stepX;
      const py = pad + h - Number(pt.y) * stepY;

      eCtx.beginPath();
      eCtx.arc(px, py, 8, 0, Math.PI * 2);
      eCtx.strokeStyle = i === 0 ? '#10b981' : '#38efeb';
      eCtx.lineWidth = 2;
      eCtx.stroke();
    }
  }

  function runECC() {
    const aSec = BigInt(eccAliceKeyInput.value || '3');
    const bSec = BigInt(eccBobKeyInput.value || '5');

    const ecdh = curve.simulateECDH(G, aSec, bSec);

    ecdhStatus.textContent = ecdh.match ? 'SHARED SECRET MATCH' : 'MISMATCH';
    ecdhStatus.className = `status-badge ${ecdh.match ? 'status-success' : 'status-error'}`;

    eccLog.textContent = [
      `Curve: y^2 = x^3 + 7 (mod 17) | Generator G = (${G.x}, ${G.y})`,
      `[Alice] Private a = ${aSec} -> Public A = a * G = (${ecdh.alicePublic.x}, ${ecdh.alicePublic.y})`,
      `[Bob]   Private b = ${bSec} -> Public B = b * G = (${ecdh.bobPublic.x}, ${ecdh.bobPublic.y})`,
      `[Key Agreement]`,
      `  Alice computes: a * B = (${ecdh.aliceShared.x}, ${ecdh.aliceShared.y})`,
      `  Bob computes:   b * A = (${ecdh.bobShared.x}, ${ecdh.bobShared.y})`,
      `  Match: ${ecdh.match ? 'SUCCESS (Identical Shared Secret Point)' : 'FAILED'}`,
    ].join('\n');

    renderCurveGrid([G, ecdh.alicePublic, ecdh.bobPublic, ecdh.aliceShared]);
  }

  eccRunBtn.addEventListener('click', runECC);
  runECC();
});
