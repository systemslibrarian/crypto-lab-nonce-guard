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
