import { expect, test, type Page } from '@playwright/test';

/**
 * Read the `.hex-output` block that follows a given `.output-label`, so a test
 * can compare two computed values the page prints rather than trusting a badge.
 */
async function valueUnderLabel(page: Page, label: string): Promise<string> {
  return page.evaluate((needle) => {
    const labels = Array.from(document.querySelectorAll('.output-label'));
    const hit = labels.find((el) => (el.textContent ?? '').includes(needle));
    let next = hit?.nextElementSibling ?? null;
    while (next && !next.classList.contains('hex-output')) {
      if (next.classList.contains('output-label')) return '';
      next = next.nextElementSibling;
    }
    return next ? (next.textContent ?? '').trim() : '';
  }, label);
}

async function runAttack(page: Page, m1: string, m2: string): Promise<void> {
  await page.locator('#msg1').fill(m1);
  await page.locator('#msg2').fill(m2);
  await page.locator('#btn-encrypt').click();
  await page.locator('#btn-attack').click();
}

test('attack output accurately distinguishes XOR bytes from decoded plaintext', async ({ page }) => {
  await page.goto('.');
  await page.locator('#btn-encrypt').click();
  await page.locator('#btn-attack').click();

  const output = page.locator('#gcm-attack-output');
  await expect(output).toContainText('Recovered P₁ ⊕ P₂');
  await expect(output).toContainText('ASCII PREVIEW OF XOR BYTES (NOT DECODED PLAINTEXT)');
  await expect(output).toContainText('It is not either plaintext');
  await expect(output).not.toContainText('DECODED (PRINTABLE)');
});

test('Level 1 turns the XOR into a recovered Message 2 and checks it byte-for-byte', async ({
  page,
}) => {
  await page.goto('.');
  const m2 = 'Wire nine thousand to Mallory';
  await runAttack(page, 'Transfer one thousand to Alice', m2);

  const output = page.locator('#gcm-attack-output');
  await expect(output).toContainText('APPLYING THAT EXTRA INFORMATION');
  // The recovered text is computed as (C₁ ⊕ C₂) ⊕ P₁ — it must be the real M2.
  expect(await valueUnderLabel(page, 'APPLYING THAT EXTRA INFORMATION')).toBe(m2);
  await expect(output).toContainText('MESSAGE 2 RECOVERED IN FULL');

  // Failure path of the same badge: a crib shorter than Message 2 can only
  // recover the prefix the keystream covers, and the page must say so.
  await runAttack(page, 'short crib', 'a much longer second message than the crib');
  await expect(output).toContainText('MESSAGE 2 PARTIALLY RECOVERED');
  await expect(output).not.toContainText('MESSAGE 2 RECOVERED IN FULL');
  expect(await valueUnderLabel(page, 'APPLYING THAT EXTRA INFORMATION')).toBe('a much lon');
});

test('Level 2 recovers the real GHASH key from the learner-supplied messages', async ({ page }) => {
  await page.goto('.');
  // Deliberately unequal lengths and multiple blocks: outside the closed-form
  // single-block case, so this can only pass if the polynomial is really solved.
  await runAttack(
    page,
    'learner-selected first message that spans more than one AES block',
    'a second learner message of a different length entirely',
  );

  const output = page.locator('#gcm-attack-output');
  await expect(
    output.getByRole('heading', {
      name: 'Level 2 — Key recovery and forgery from your two messages',
    }),
  ).toBeVisible();
  await expect(output).toContainText('Computed from your Message 1 and Message 2');
  await expect(output).not.toContainText('Not derived from your Message 1 or Message 2');
  await expect(output).not.toContainText('two fixed 16-byte probes');

  // The equation that was solved must be the multi-block one, not H².
  await expect(output).toContainText('KEY EQUATION SOLVED');
  await expect(output).toContainText('Degree');

  // Recovery is exact: the value derived from ciphertexts and tags alone must
  // equal the independently computed E_K(0¹²⁸).
  const recovered = await valueUnderLabel(page, 'Recovered H (from ciphertexts + tags only)');
  const truth = await valueUnderLabel(page, 'True H = AES-256(key, 0¹²⁸) (ground truth)');
  expect(recovered).toHaveLength(32);
  expect(recovered).toBe(truth);

  await expect(output).toContainText('H RECOVERED EXACTLY');
  await expect(output).toContainText('FORGERY ACCEPTED');
  await expect(output).toContainText('INTEGRITY BROKEN');
  // The forged blob really opens under the receiver's key.
  await expect(output).toContainText('WHAT THE RECEIVER DECRYPTS FROM THE FORGED BLOB');
  expect(
    await valueUnderLabel(page, 'WHAT THE RECEIVER DECRYPTS FROM THE FORGED BLOB'),
  ).toContain('PWNED');
});

test('Level 2 declines honestly when two identical messages carry no information', async ({
  page,
}) => {
  await page.goto('.');
  await runAttack(page, 'identical text', 'identical text');

  const output = page.locator('#gcm-attack-output');
  const status = page.locator('#demo-status');
  await expect(output).toContainText('NO KEY RECOVERED — the two ciphertexts are identical');
  await expect(output).toContainText('0 = 0');
  await expect(output).not.toContainText('H RECOVERED EXACTLY');
  await expect(output).not.toContainText('FORGERY ACCEPTED');
  await expect(output).not.toContainText('INTEGRITY BROKEN');
  await expect(status).toContainText('Level 2 recovered nothing');
  await expect(status).not.toContainText('recovered exactly');
});

test('Level 2 declines, rather than faking, past its stated root-search budget', async ({
  page,
}) => {
  await page.goto('.');
  const long = 'A'.repeat(600);
  await runAttack(page, long, `${long}B`);

  const output = page.locator('#gcm-attack-output');
  const status = page.locator('#demo-status');
  await expect(output).toContainText('NOT RUN — a message is longer than 512 bytes');
  await expect(output).toContainText('not a limit of Joux');
  await expect(output).not.toContainText('H RECOVERED EXACTLY');
  await expect(output).not.toContainText('INTEGRITY BROKEN');
  await expect(status).toContainText('declined to run');

  // And it recovers: shortening a message brings the break straight back.
  await runAttack(page, 'back under the cap', 'a different short message');
  await expect(output).toContainText('H RECOVERED EXACTLY');
  await expect(output).toContainText('INTEGRITY BROKEN');
});

test('the screen-reader announcement claims the integrity break only when the badges do', async ({
  page,
}) => {
  await page.goto('.');
  await page.locator('#btn-encrypt').click();
  await page.locator('#btn-attack').click();

  const output = page.locator('#gcm-attack-output');
  const status = page.locator('#demo-status');
  await expect(status).not.toBeEmpty();

  // The visible badges are computed from the run; the announcement must report
  // that same outcome rather than a fixed success story.
  const brokeIntegrity = await output.getByText('INTEGRITY BROKEN').count();
  if (brokeIntegrity > 0) {
    await expect(output).toContainText('H RECOVERED EXACTLY');
    await expect(output).toContainText('FORGERY ACCEPTED');
    await expect(status).toContainText('recovered exactly');
    await expect(status).toContainText('forged tag was accepted');
  } else {
    await expect(status).not.toContainText('H was recovered exactly');
  }

  // Unique nonces must never announce any break at all.
  // The checkbox itself is visually hidden behind the styled switch, so drive
  // it through its visible label the way a pointer or keyboard user would.
  await page.locator('#nonce-toggle-label').click();
  await expect(page.locator('#same-nonce')).not.toBeChecked();
  await page.locator('#btn-encrypt').click();
  await page.locator('#btn-attack').click();
  await expect(status).toContainText('no attack is possible');
  await expect(status).not.toContainText('recovered exactly');
});
