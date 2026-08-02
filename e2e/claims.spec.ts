import { expect, test } from '@playwright/test';

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

test('Level 2 identifies its fixed probes as separate from learner messages', async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('#section-b > .section-lead')).toContainText(
    'Level 2 is a separate chosen-probe demonstration',
  );

  await page.locator('#msg1').fill('learner-selected first message');
  await page.locator('#msg2').fill('learner-selected second message');
  await page.locator('#btn-encrypt').click();
  await page.locator('#btn-attack').click();

  const output = page.locator('#gcm-attack-output');
  await expect(output.getByRole('heading', { name: 'Level 2 — Separate chosen-probe demonstration' })).toBeVisible();
  await expect(output).toContainText('Not derived from your Message 1 or Message 2');
  await expect(output).toContainText('two fixed 16-byte probes');
  await expect(output).toContainText('two chosen fixed probes');
  await expect(output).not.toContainText('two intercepted ciphertexts');
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

  // The visible badges are computed from the probe run; the announcement must
  // report that same outcome rather than a fixed success story.
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
