import './style.css';
import {
  generateNonce,
  generateKey,
  importGCMKey,
  encryptGCM,
  encryptSIV,
  xorBytes,
  toHex,
  xorToReadable,
  textToBytes,
  getSIVTagIVForDemo,
  runForbiddenAttack,
} from './crypto.ts';

// ── Theme toggle ──
function initThemeToggle(): void {
  const btn = document.getElementById('theme-toggle') as HTMLButtonElement;
  function update(): void {
    const current = document.documentElement.getAttribute('data-theme') ?? 'dark';
    btn.textContent = current === 'dark' ? '🌙' : '☀️';
    btn.setAttribute(
      'aria-label',
      current === 'dark' ? 'Switch to light mode' : 'Switch to dark mode',
    );
  }
  btn.addEventListener('click', () => {
    const current = document.documentElement.getAttribute('data-theme') ?? 'dark';
    const next = current === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('theme', next);
    update();
  });
  update();
}

// ── Section A: Nonce display ──
function initNonceDisplay(): void {
  const container = document.getElementById('nonce-display');
  if (!container) return;
  const nonce = generateNonce();
  container.innerHTML = Array.from(nonce)
    .map(
      (b) =>
        `<span class="nonce-byte" aria-label="byte ${b.toString(16).padStart(2, '0')}">${b.toString(16).padStart(2, '0')}</span>`,
    )
    .join('');
}

// ── Helpers: output rendering ──
function badge(type: 'safe' | 'warning' | 'broken', text: string): string {
  const icon = type === 'safe' ? '🟢' : type === 'warning' ? '🟡' : '🔴';
  // Emoji is decorative (color already encodes status); the enclosing output
  // area is aria-live, so the badge itself must not be a nested live region.
  return `<span class="status-badge ${type}"><span aria-hidden="true">${icon}</span> ${text}</span>`;
}

function hexBlock(label: string, hex: string): string {
  return `<div class="output-label">${label}</div><div class="hex-output">${hex}</div>`;
}

// Concise, polite announcement for screen-reader users. The detail panels hold
// long hex strings that should not be read aloud, so a short summary is sent
// to a dedicated live region instead.
function announce(message: string): void {
  const status = document.getElementById('demo-status');
  if (status) status.textContent = message;
}

// ── Section B: Live demo ──
interface EncryptionResult {
  nonce1: Uint8Array;
  nonce2: Uint8Array;
  ct1: Uint8Array;
  ct2: Uint8Array;
  tag1: Uint8Array;
  tag2: Uint8Array;
  sameNonce: boolean;
}

let gcmResult: EncryptionResult | null = null;
let sivResult: EncryptionResult | null = null;
let rawKey: Uint8Array | null = null;
let msg1Text = '';
let msg2Text = '';

// Shared nonce plumbing: both schemes need a pair of nonces where reuse means
// nonce2 === nonce1. Centralising it keeps the two schemes provably in sync.
function noncePair(sameNonce: boolean): { nonce1: Uint8Array; nonce2: Uint8Array } {
  const nonce1 = generateNonce();
  return { nonce1, nonce2: sameNonce ? nonce1 : generateNonce() };
}

async function doEncrypt(): Promise<void> {
  const msg1El = document.getElementById('msg1') as HTMLTextAreaElement;
  const msg2El = document.getElementById('msg2') as HTMLTextAreaElement;
  const sameNonceEl = document.getElementById('same-nonce') as HTMLInputElement;
  const attackBtn = document.getElementById('btn-attack') as HTMLButtonElement;

  msg1Text = msg1El.value;
  msg2Text = msg2El.value;
  const pt1 = textToBytes(msg1Text);
  const pt2 = textToBytes(msg2Text);
  const sameNonce = sameNonceEl.checked;

  // Generate shared key
  rawKey = generateKey();
  const gcmKey = await importGCMKey(rawKey);

  // GCM
  const gcmNonces = noncePair(sameNonce);
  const gcm1 = await encryptGCM(gcmKey, gcmNonces.nonce1, pt1);
  const gcm2 = await encryptGCM(gcmKey, gcmNonces.nonce2, pt2);
  gcmResult = {
    nonce1: gcmNonces.nonce1,
    nonce2: gcmNonces.nonce2,
    ct1: gcm1.ciphertext,
    ct2: gcm2.ciphertext,
    tag1: gcm1.tag,
    tag2: gcm2.tag,
    sameNonce,
  };

  // SIV
  const sivNonces = noncePair(sameNonce);
  const siv1 = encryptSIV(rawKey, sivNonces.nonce1, pt1);
  const siv2 = encryptSIV(rawKey, sivNonces.nonce2, pt2);
  sivResult = {
    nonce1: sivNonces.nonce1,
    nonce2: sivNonces.nonce2,
    ct1: siv1.ciphertext,
    ct2: siv2.ciphertext,
    tag1: siv1.tag,
    tag2: siv2.tag,
    sameNonce,
  };

  renderEncryptOutput();
  attackBtn.disabled = false;
  attackBtn.setAttribute('aria-disabled', 'false');

  announce(
    sameNonce
      ? 'Both messages encrypted with AES-GCM and AES-GCM-SIV using the same nonce. Run Attack is now available.'
      : 'Both messages encrypted with AES-GCM and AES-GCM-SIV using unique nonces. Run Attack is now available.',
  );
}

function renderEncryptOutput(): void {
  const gcmOut = document.getElementById('gcm-output')!;
  const sivOut = document.getElementById('siv-output')!;

  if (!gcmResult || !sivResult) return;

  const nonceBadge = (r: EncryptionResult) =>
    r.sameNonce
      ? badge('broken', 'SAME NONCE USED')
      : badge('safe', 'UNIQUE NONCES');

  gcmOut.innerHTML = `
    ${nonceBadge(gcmResult)}
    ${gcmResult.sameNonce ? hexBlock('Nonce', toHex(gcmResult.nonce1)) : hexBlock('Nonce 1', toHex(gcmResult.nonce1)) + hexBlock('Nonce 2', toHex(gcmResult.nonce2))}
    ${hexBlock('Ciphertext 1', toHex(gcmResult.ct1, 32))}
    ${hexBlock('Ciphertext 2', toHex(gcmResult.ct2, 32))}
    ${hexBlock('Tag 1', toHex(gcmResult.tag1))}
    ${hexBlock('Tag 2', toHex(gcmResult.tag2))}
    <div id="gcm-attack-output"></div>
  `;

  sivOut.innerHTML = `
    ${nonceBadge(sivResult)}
    ${sivResult.sameNonce ? hexBlock('Nonce', toHex(sivResult.nonce1)) : hexBlock('Nonce 1', toHex(sivResult.nonce1)) + hexBlock('Nonce 2', toHex(sivResult.nonce2))}
    ${hexBlock('Ciphertext 1', toHex(sivResult.ct1, 32))}
    ${hexBlock('Ciphertext 2', toHex(sivResult.ct2, 32))}
    ${hexBlock('Tag 1', toHex(sivResult.tag1))}
    ${hexBlock('Tag 2', toHex(sivResult.tag2))}
    <div id="siv-attack-output"></div>
  `;
}

function doAttack(): void {
  if (!gcmResult || !sivResult) return;

  const gcmAttack = document.getElementById('gcm-attack-output')!;
  const sivAttack = document.getElementById('siv-attack-output')!;

  if (!gcmResult.sameNonce) {
    gcmAttack.innerHTML = badge('safe', 'NO ATTACK — nonces are unique');
    sivAttack.innerHTML = badge('safe', 'NO ATTACK — nonces are unique');
    announce(
      'Nonces are unique, so no attack is possible against either scheme.',
    );
    return;
  }

  // ── GCM Level 1: keystream reuse (confidentiality) — real XOR recovery ──
  const gcmXor = xorBytes(gcmResult.ct1, gcmResult.ct2);

  // ── GCM Level 2: forbidden attack (integrity) — really recover H & forge ──
  // Run on the demo's own reused (key, nonce). This uses two fixed single-block
  // probes so the closed-form GF(2¹²⁸) solver applies; the key and nonce are
  // the exact pair reused above.
  let integrityHtml = '';
  if (rawKey) {
    try {
      const atk = runForbiddenAttack(rawKey, gcmResult.nonce1);
      const recoveredOk = atk.recovered && atk.forgeryAccepted;
      integrityHtml = `
        <h4>Level 2 — Authentication key recovery (Joux's forbidden attack)</h4>
        <p class="tag-note">Run on two 16-byte probes encrypted under this same reused nonce. The attacker sees only their (ciphertext, tag) pairs.</p>
        ${hexBlock('Recovered H (from ciphertexts + tags only)', toHex(atk.recoveredH))}
        ${hexBlock('True H = AES-256(key, 0¹²⁸) (ground truth)', toHex(atk.trueH))}
        ${
          atk.recovered
            ? badge('broken', 'H RECOVERED EXACTLY — the GHASH authentication key is now known')
            : badge('warning', 'H recovery did not match (unexpected)')
        }
        ${hexBlock('Forged ciphertext (attacker-chosen)', toHex(atk.forgedCiphertext, 32))}
        ${hexBlock('Forged tag (computed from recovered H + mask)', toHex(atk.forgedTag))}
        ${
          atk.forgeryAccepted
            ? badge('broken', 'FORGERY ACCEPTED — real AES-GCM verified this attacker-forged (ciphertext, tag)')
            : badge('warning', 'forgery was rejected (unexpected)')
        }
        ${
          recoveredOk
            ? badge('broken', 'INTEGRITY BROKEN — attacker can forge valid tags for arbitrary ciphertexts under this nonce')
            : ''
        }
        ${
          recoveredOk
            ? `<div class="threat-box" role="note" aria-label="Attacker capability summary">
                 <p class="threat-title">What the attacker just gained</p>
                 <p><strong>Started with:</strong> two intercepted ciphertexts and their tags, captured off the wire under a reused nonce. No key, no plaintext.</p>
                 <p class="threat-then"><strong>Now holds:</strong> the GHASH authentication key H itself — so they can stamp a valid tag on <em>any</em> message under this nonce, and real AES-GCM will accept it (proven above). This is the break the 2016 HTTPS-server survey found live in production.</p>
               </div>`
            : ''
        }
      `;
    } catch {
      integrityHtml = badge(
        'warning',
        "INTEGRITY: this two-message case is outside the toy solver's single-block domain, but the forbidden attack applies in general",
      );
    }
  }

  gcmAttack.innerHTML = `
    <h4>Level 1 — Keystream reuse (confidentiality)</h4>
    ${hexBlock('C₁ ⊕ C₂', toHex(gcmXor))}
    ${hexBlock('Recovered P₁ ⊕ P₂', toHex(gcmXor))}
    <div class="output-label">DECODED (PRINTABLE)</div>
    <div class="hex-output">${xorToReadable(gcmXor)}</div>
    ${badge('broken', 'CONFIDENTIALITY BROKEN — XOR of plaintexts recovered')}
    ${integrityHtml}
  `;

  // SIV: XOR does not reveal plaintext XOR
  const sivXor = xorBytes(sivResult.ct1, sivResult.ct2);
  const identicalPt = msg1Text === msg2Text;

  let sivHtml = `
    <h4>Attack Results</h4>
    ${hexBlock('C₁ ⊕ C₂', toHex(sivXor))}
  `;

  if (identicalPt) {
    sivHtml += badge(
      'warning',
      'IDENTICAL PLAINTEXT DETECTED — Only information leaked: these two messages were the same',
    );
  } else {
    sivHtml += badge(
      'warning',
      'NONCE REUSED — Ciphertexts differ because SIV derives IV from plaintext. Keystream was not reused.',
    );
  }
  sivHtml += badge(
    'safe',
    'INTEGRITY INTACT — the tag is AES-encrypted, so H stays hidden even though the nonce repeats',
  );

  sivAttack.innerHTML = sivHtml;

  announce(
    'Attack complete. AES-GCM: confidentiality and integrity broken — the XOR of the two plaintexts was recovered, the GHASH authentication key H was recovered exactly, and a forged tag was accepted by real AES-GCM. ' +
      (identicalPt
        ? 'AES-GCM-SIV: only leaked that the two plaintexts were identical; integrity intact.'
        : 'AES-GCM-SIV: ciphertexts differ and no keystream was reused; integrity intact.'),
  );
}

// ── Section C: Cancellation visualizers (the shared term cancels) ──
// Each button toggles the .is-cancelled state on its viz, fading the shared
// keystream/mask so the learner watches the algebra collapse. Toggling back
// restores it so they can replay. State is conveyed by text + the caption's
// aria-live announcement, never colour alone.
function initCancelViz(): void {
  const setup = (
    btnId: string,
    startCaption: string,
    doneCaption: string,
    replayLabel: string,
    cancelLabel: string,
  ): void => {
    const btn = document.getElementById(btnId) as HTMLButtonElement | null;
    if (!btn) return;
    const caption = document.getElementById(
      btn.getAttribute('aria-describedby') ?? '',
    );
    const viz = btn
      .closest('.card')
      ?.querySelector('.cancel-viz') as HTMLElement | null;
    if (!viz) return;
    btn.addEventListener('click', () => {
      const cancelled = viz.classList.toggle('is-cancelled');
      btn.textContent = cancelled ? replayLabel : cancelLabel;
      if (caption) caption.textContent = cancelled ? doneCaption : startCaption;
    });
  };

  setup(
    'cancel-l1-btn',
    'The same keystream (highlighted) sits in both ciphertexts.',
    'keystream ⊕ keystream = 0 — it cancelled. What remains is P₁ ⊕ P₂, no key needed.',
    'Replay ↺',
    'Cancel the shared keystream ▶',
  );
  setup(
    'cancel-l2-btn',
    'The same mask (highlighted) sits in both tags.',
    'mask ⊕ mask = 0 — it cancelled. What remains is a pure equation in H, which we solve.',
    'Replay ↺',
    'Cancel the shared mask ▶',
  );
}

// ── Section D: Interactive tag-as-IV demo ──
// Shows SIV's core safety property live: plaintext -> tag -> derived AES-CTR IV
// -> first ciphertext block, all moving together. A same-vs-diff toggle lets the
// learner produce the identical-plaintext leak (and its absence) themselves.
function initSIVDemo(): void {
  const input = document.getElementById('siv-input') as HTMLInputElement;
  const output = document.getElementById('siv-tag-output')!;
  const compareOut = document.getElementById('siv-compare-output')!;
  const modeSame = document.getElementById('siv-mode-same') as HTMLButtonElement;
  const modeDiff = document.getElementById('siv-mode-diff') as HTMLButtonElement;
  const key = generateKey();
  const nonce = generateNonce();
  let mode: 'same' | 'diff' = 'same';

  // The plaintext -> tag -> IV -> ct chain for one message, as a labelled block.
  function chain(title: string, textValue: string): string {
    const pt = textToBytes(textValue || ' ');
    const { tag, iv, ct1 } = getSIVTagIVForDemo(key, nonce, pt);
    return `
      <p class="output-label">${title}</p>
      ${hexBlock('Plaintext (UTF-8 hex)', toHex(pt, 32))}
      <div class="siv-chain-arrow" aria-hidden="true">↓ POLYVAL, then AES-encrypt</div>
      ${hexBlock('SIV Tag (128-bit)', toHex(tag))}
      <div class="siv-chain-arrow" aria-hidden="true">↓ copy tag, set MSB of last byte → AES-CTR IV</div>
      ${hexBlock('Derived AES-CTR IV', toHex(iv))}
      <div class="siv-chain-arrow" aria-hidden="true">↓ AES-CTR keystream ⊕ plaintext</div>
      ${hexBlock('First ciphertext block', toHex(ct1))}
    `;
  }

  // Message B for the comparison: identical to A, or A with its last byte
  // flipped (a genuine one-byte change), so the learner sees the consequence.
  function messageB(a: string): string {
    if (mode === 'same') return a;
    if (a.length === 0) return 'A';
    const flipped = a.slice(0, -1);
    const last = a.charCodeAt(a.length - 1);
    // Flip to a different printable char deterministically.
    const alt = String.fromCharCode(last === 33 ? 46 : last - 1);
    return flipped + alt;
  }

  function render(): void {
    const aText = input.value;
    output.innerHTML = chain('Message A', aText);

    const bText = messageB(aText);
    const aData = getSIVTagIVForDemo(key, nonce, textToBytes(aText || ' '));
    const bData = getSIVTagIVForDemo(key, nonce, textToBytes(bText || ' '));
    const identical = aText === bText;

    let verdict: string;
    if (identical) {
      // Same plaintext -> same tag -> same IV -> same ciphertext: the ONLY leak.
      verdict = badge(
        'warning',
        'IDENTICAL PLAINTEXT → IDENTICAL TAG → IDENTICAL IV → IDENTICAL CIPHERTEXT. This equality is the ONLY thing SIV leaks under nonce reuse.',
      );
    } else {
      verdict = badge(
        'safe',
        'ONE BYTE CHANGED → the tag, the derived IV, and the ciphertext all change completely. Different plaintext never reuses the keystream.',
      );
    }

    compareOut.innerHTML = `
      ${chain('Message B', bText)}
      <div class="siv-verdict">
        <p class="output-label">A vs B</p>
        ${hexBlock('Tag A', toHex(aData.tag))}
        ${hexBlock('Tag B', toHex(bData.tag))}
        ${verdict}
      </div>
    `;
  }

  function setMode(next: 'same' | 'diff'): void {
    mode = next;
    const sameActive = next === 'same';
    modeSame.classList.toggle('is-active', sameActive);
    modeDiff.classList.toggle('is-active', !sameActive);
    modeSame.setAttribute('aria-checked', String(sameActive));
    modeDiff.setAttribute('aria-checked', String(!sameActive));
    render();
  }

  input.addEventListener('input', render);
  modeSame.addEventListener('click', () => setMode('same'));
  modeDiff.addEventListener('click', () => setMode('diff'));
  render();
}

// ── Init ──
function init(): void {
  initThemeToggle();
  initNonceDisplay();
  initCancelViz();
  initSIVDemo();

  document.getElementById('btn-encrypt')!.addEventListener('click', doEncrypt);
  document.getElementById('btn-attack')!.addEventListener('click', doAttack);
}

init();

