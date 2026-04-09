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
  getSIVTagForDemo,
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
  return `<span class="status-badge ${type}" role="status">${icon} ${text}</span>`;
}

function hexBlock(label: string, hex: string): string {
  return `<div class="output-label">${label}</div><div class="hex-output">${hex}</div>`;
}

// ── Section B: Live demo ──
interface EncryptionResult {
  nonce: Uint8Array;
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
  const nonceGCM1 = generateNonce();
  const nonceGCM2 = sameNonce ? nonceGCM1 : generateNonce();
  const gcm1 = await encryptGCM(gcmKey, nonceGCM1, pt1);
  const gcm2 = await encryptGCM(gcmKey, nonceGCM2, pt2);
  gcmResult = {
    nonce: nonceGCM1,
    ct1: gcm1.ciphertext,
    ct2: gcm2.ciphertext,
    tag1: gcm1.tag,
    tag2: gcm2.tag,
    sameNonce,
  };

  // SIV
  const nonceSIV1 = generateNonce();
  const nonceSIV2 = sameNonce ? nonceSIV1 : generateNonce();
  const siv1 = encryptSIV(rawKey, nonceSIV1, pt1);
  const siv2 = encryptSIV(rawKey, nonceSIV2, pt2);
  sivResult = {
    nonce: nonceSIV1,
    ct1: siv1.ciphertext,
    ct2: siv2.ciphertext,
    tag1: siv1.tag,
    tag2: siv2.tag,
    sameNonce,
  };

  renderEncryptOutput();
  attackBtn.disabled = false;
  attackBtn.setAttribute('aria-disabled', 'false');
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
    ${hexBlock('Nonce', toHex(gcmResult.nonce))}
    ${hexBlock('Ciphertext 1', toHex(gcmResult.ct1, 32))}
    ${hexBlock('Ciphertext 2', toHex(gcmResult.ct2, 32))}
    ${hexBlock('Tag 1', toHex(gcmResult.tag1))}
    ${hexBlock('Tag 2', toHex(gcmResult.tag2))}
    <div id="gcm-attack-output"></div>
  `;

  sivOut.innerHTML = `
    ${nonceBadge(sivResult)}
    ${hexBlock('Nonce', toHex(sivResult.nonce))}
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
    return;
  }

  // GCM: XOR attack works
  const gcmXor = xorBytes(gcmResult.ct1, gcmResult.ct2);
  const ptXor = xorBytes(textToBytes(msg1Text), textToBytes(msg2Text));
  gcmAttack.innerHTML = `
    <h4>Attack Results</h4>
    ${hexBlock('C₁ ⊕ C₂', toHex(gcmXor))}
    ${hexBlock('Recovered P₁ ⊕ P₂', toHex(ptXor))}
    <div class="output-label">DECODED (PRINTABLE)</div>
    <div class="hex-output">${xorToReadable(ptXor)}</div>
    ${badge('broken', 'CONFIDENTIALITY BROKEN — XOR of plaintexts recovered')}
    ${badge('broken', 'INTEGRITY BROKEN — Authentication key H is recoverable from these two (ciphertext, tag) pairs')}
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
    'INTEGRITY INTACT — Authentication key is not recoverable',
  );

  sivAttack.innerHTML = sivHtml;
}

// ── Section C: Interactive SIV tag demo ──
function initSIVDemo(): void {
  const input = document.getElementById('siv-input') as HTMLInputElement;
  const output = document.getElementById('siv-tag-output')!;
  const key = generateKey();
  const nonce = generateNonce();

  function render(): void {
    const pt = textToBytes(input.value || ' ');
    const tag = getSIVTagForDemo(key, nonce, pt);
    output.innerHTML = `
      ${hexBlock('Plaintext (UTF-8 hex)', toHex(pt))}
      ${hexBlock('SIV Tag (128-bit)', toHex(tag))}
      <p class="tag-note">Change any character above — the tag changes completely (avalanche effect).</p>
    `;
  }

  input.addEventListener('input', render);
  render();
}

// ── Init ──
function init(): void {
  initThemeToggle();
  initNonceDisplay();
  initSIVDemo();

  document.getElementById('btn-encrypt')!.addEventListener('click', doEncrypt);
  document.getElementById('btn-attack')!.addEventListener('click', doAttack);
}

init();

