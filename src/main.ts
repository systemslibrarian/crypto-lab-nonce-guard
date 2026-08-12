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
  LEVEL2_MAX_CT_BYTES,
} from './crypto.ts';

/** Escape learner-influenced text before it reaches innerHTML. */
function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

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
  // No aria-label on the spans. `aria-label` on a role-less <span> is
  // PROHIBITED by ARIA and silently discarded, so the twelve labels never
  // reached a screen reader at all — and each one only restated the hex the span
  // already contains, inside a container that is `role="img"` with its own
  // label, which makes the children presentational anyway.
  container.innerHTML = Array.from(nonce)
    .map((b) => `<span class="nonce-byte">${b.toString(16).padStart(2, '0')}</span>`)
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
  // Runs on the learner's OWN two messages: the solver sees only the two
  // (ciphertext, tag) pairs rendered above and factors the resulting degree-n
  // key equation over GF(2¹²⁸). Both failure branches below are reachable by
  // typing — identical messages carry no information, and a message past the
  // root-search budget is declined rather than faked.
  let integrityHtml = '';
  // What the Level 2 attack actually achieved, so the announcement can state the
  // same outcome the badges show rather than the outcome we expect.
  let integrityOutcome = 'The Level 2 integrity attack did not run.';
  if (rawKey) {
    const atk = runForbiddenAttack(
      rawKey,
      gcmResult.nonce1,
      gcmResult.ct1,
      gcmResult.tag1,
      gcmResult.ct2,
      gcmResult.tag2,
      textToBytes(msg1Text),
    );
    const recoveredOk = atk.recovered && atk.forgeryAccepted;
    const preamble = `
      <h4>Level 2 — Key recovery and forgery from your two messages</h4>
      <p class="tag-note"><strong>Computed from your Message 1 and Message 2.</strong> The solver is handed only the four values above — Ciphertext 1, Tag 1, Ciphertext 2, Tag 2 — and builds the key equation GHASH<sub>H</sub>(C₁) ⊕ GHASH<sub>H</sub>(C₂) ⊕ (T₁ ⊕ T₂) = 0: a polynomial in the unknown H over GF(2¹²⁸) whose degree grows with your message length. It then factors that polynomial for every H satisfying it. The key never reaches the solver — it is used only to compute the ground-truth H shown for comparison, and to stand in for the receiver who checks a forged tag.</p>
    `;

    if (atk.failure === 'too-long') {
      const deg = Math.ceil(Math.max(gcmResult.ct1.length, gcmResult.ct2.length) / 16) + 1;
      integrityOutcome = `Level 2 declined to run: a message longer than ${LEVEL2_MAX_CT_BYTES} bytes puts the in-browser root search past its time budget. No key was recovered and no forgery was attempted.`;
      integrityHtml = `
        ${preamble}
        ${badge('warning', `NOT RUN — a message is longer than ${LEVEL2_MAX_CT_BYTES} bytes`)}
        <p class="tag-note">The key equation for these ciphertexts has degree ${deg}, and factoring it over GF(2¹²⁸) in a browser tab costs roughly the square of that. This lab caps the search at ${LEVEL2_MAX_CT_BYTES} bytes per message so the page stays responsive — a runtime budget of this demo, <strong>not</strong> a limit of Joux's attack, which is unaffected by message length. Shorten a message and run it again.</p>
      `;
    } else if (atk.failure === 'no-information') {
      integrityOutcome =
        'Level 2 recovered nothing: your two messages are identical, so the ciphertexts and tags are identical too, T₁ ⊕ T₂ = 0, and the key equation degenerates to 0 = 0 — satisfied by every possible H.';
      integrityHtml = `
        ${preamble}
        ${badge('warning', 'NO KEY RECOVERED — the two ciphertexts are identical')}
        <p class="tag-note">Both messages are the same, so C₁ = C₂ and T₁ = T₂. Every term of the key equation cancels and it becomes 0 = 0, which <em>every</em> element of GF(2¹²⁸) satisfies. The attacker has learned nothing about H. That is a real limit of the two-message attack, not a failure of the solver: put different text in the two boxes and the same run recovers H exactly.</p>
      `;
    } else if (atk.failure === 'no-keystream') {
      integrityOutcome =
        'Level 2 solved the key equation but had no keystream to build a forgery with, because Message 1 is empty.';
      integrityHtml = `
        ${preamble}
        ${badge('warning', 'NO FORGERY ATTEMPTED — Message 1 is empty, so there is no known-plaintext keystream to reuse')}
      `;
    } else if (atk.failure) {
      integrityOutcome = `Level 2 solved the key equation but no candidate produced a tag the receiver accepted (${atk.candidateCount} candidate${atk.candidateCount === 1 ? '' : 's'} tried).`;
      integrityHtml = `
        ${preamble}
        ${badge('warning', 'NO FORGERY ACCEPTED — every candidate key was rejected by real AES-GCM')}
      `;
    } else {
      integrityOutcome = recoveredOk
        ? `Integrity is also broken: the GHASH authentication key H was recovered exactly from your two messages by factoring a degree ${atk.equationDegree} equation over GF(2¹²⁸), and a forged tag was accepted by real AES-GCM after ${atk.verificationQueries} verification quer${atk.verificationQueries === 1 ? 'y' : 'ies'}.`
        : `H recovery ${atk.recovered ? 'succeeded' : 'did not match the true key'} and the forged tag was ${atk.forgeryAccepted ? 'accepted' : 'rejected'}, so this run did not complete the integrity break.`;
      integrityHtml = `
        ${preamble}
        <div class="output-label">KEY EQUATION SOLVED</div>
        <p class="tag-note">Degree <strong>${atk.equationDegree}</strong> over GF(2¹²⁸) — one term per 16-byte ciphertext block, plus the length block. The root search returned <strong>${atk.candidateCount}</strong> candidate key${atk.candidateCount === 1 ? '' : 's'}, and <strong>${atk.verificationQueries}</strong> forged tag${atk.verificationQueries === 1 ? '' : 's'} had to be checked by the receiver before one was accepted.</p>
        ${hexBlock('Recovered H (from ciphertexts + tags only)', toHex(atk.recoveredH ?? new Uint8Array(16)))}
        ${hexBlock('True H = AES-256(key, 0¹²⁸) (ground truth)', toHex(atk.trueH))}
        ${
          atk.recovered
            ? badge('broken', 'H RECOVERED EXACTLY — the GHASH authentication key is now known')
            : badge('warning', 'H recovery did not match the true key')
        }
        ${hexBlock('Forged ciphertext (attacker payload under the reused keystream)', toHex(atk.forgedCiphertext, 32))}
        ${hexBlock('Forged tag (computed from recovered H + mask)', toHex(atk.forgedTag ?? new Uint8Array(16)))}
        ${
          atk.forgeryAccepted
            ? badge('broken', 'FORGERY ACCEPTED — real AES-GCM verified this attacker-forged (ciphertext, tag)')
            : badge('warning', 'forgery was rejected')
        }
        ${
          atk.forgedDecryption
            ? `<div class="output-label">WHAT THE RECEIVER DECRYPTS FROM THE FORGED BLOB</div><div class="hex-output">${escapeHtml(new TextDecoder().decode(atk.forgedDecryption))}</div>`
            : ''
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
                 <p><strong>Started with:</strong> the two ciphertexts and tags shown above, plus knowledge of Message 1 — the same known-plaintext assumption Level 1 already leans on. No key.</p>
                 <p class="threat-then"><strong>Now holds:</strong> the GHASH authentication key H itself — so they can stamp a valid tag on <em>any</em> message under this nonce, and real AES-GCM will accept it (proven above). This is the break the 2016 HTTPS-server survey found live in production.</p>
               </div>`
            : ''
        }
      `;
    }
  }

  // The "extra information" the note names, actually applied: XOR the recovered
  // P₁ ⊕ P₂ against a known Message 1 and Message 2 falls out. Correctness is
  // checked byte-for-byte against the plaintext the learner actually typed, over
  // the overlap the keystream covers.
  const pt1Bytes = textToBytes(msg1Text);
  const pt2Bytes = textToBytes(msg2Text);
  const overlap = Math.min(gcmXor.length, pt1Bytes.length);
  const recoveredP2 = xorBytes(gcmXor.slice(0, overlap), pt1Bytes.slice(0, overlap));
  const expectedP2 = pt2Bytes.slice(0, overlap);
  const cribExact =
    overlap > 0 &&
    recoveredP2.length === expectedP2.length &&
    recoveredP2.every((b, i) => b === expectedP2[i]);
  const cribComplete = cribExact && overlap === pt2Bytes.length;

  gcmAttack.innerHTML = `
    <h4>Level 1 — Keystream reuse (confidentiality)</h4>
    ${hexBlock('C₁ ⊕ C₂', toHex(gcmXor))}
    ${hexBlock('Recovered P₁ ⊕ P₂', toHex(gcmXor))}
    <div class="output-label">ASCII PREVIEW OF XOR BYTES (NOT DECODED PLAINTEXT)</div>
    <div class="hex-output">${xorToReadable(gcmXor)}</div>
    <p class="tag-note">This is P₁ ⊕ P₂ rendered byte-by-byte: printable byte values appear as characters and all others as ·. It is not either plaintext. Recovering a message requires extra information, such as knowing or guessing the other plaintext.</p>
    ${badge('broken', 'CONFIDENTIALITY BROKEN — XOR of plaintexts recovered')}
    <div class="output-label">APPLYING THAT EXTRA INFORMATION: (P₁ ⊕ P₂) ⊕ P₁</div>
    <p class="tag-note">Assume the attacker knows Message 1 — a crib, a fixed header, a guessed greeting. XORing it into the block above cancels P₁ and leaves Message 2 in the clear. The result below is compared byte-for-byte against the Message 2 you typed; the keystream only covers ${overlap} byte${overlap === 1 ? '' : 's'}, so only that much of Message 2 can be recovered this way.</p>
    <div class="hex-output">${overlap > 0 ? escapeHtml(new TextDecoder().decode(recoveredP2)) : '(nothing — Message 1 is empty, so there is no crib)'}</div>
    ${
      cribComplete
        ? badge('broken', 'MESSAGE 2 RECOVERED IN FULL — every byte matches the plaintext you typed')
        : cribExact
          ? badge('broken', `MESSAGE 2 PARTIALLY RECOVERED — the first ${overlap} of ${pt2Bytes.length} bytes match; the crib is shorter than the message`)
          : badge('warning', 'NO PLAINTEXT RECOVERED — there is no known-plaintext overlap to XOR against')
    }
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

  const cribOutcome = cribComplete
    ? 'Message 2 was then recovered in full by XORing in a known Message 1, and every byte matches the plaintext typed into the form.'
    : cribExact
      ? `Message 2 was partially recovered by XORing in a known Message 1: the first ${overlap} of ${pt2Bytes.length} bytes match the plaintext typed into the form.`
      : 'No plaintext could be recovered, because there is no known-plaintext overlap to XOR against.';

  announce(
    'Attack complete. AES-GCM: confidentiality broken — the XOR of the two plaintexts was recovered. ' +
      cribOutcome +
      ' ' +
      integrityOutcome +
      ' ' +
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

