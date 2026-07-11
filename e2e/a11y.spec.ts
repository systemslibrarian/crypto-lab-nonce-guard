import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate. Deploys are already gated on cryptographic correctness;
 * this gates them on accessibility the same way. Scans the full page with every
 * collapsible expanded and the interactive demo output rendered, in both themes.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

// Kill transitions/animations/opacity fades: a mid-fade element produces phantom
// contrast failures that do not reflect the settled UI.
const NEUTRALIZE_MOTION = `
  *, *::before, *::after {
    transition: none !important;
    animation: none !important;
  }
`;

async function revealEverything(page: Page): Promise<void> {
  // Open any native <details> (this page has none today, but keep the gate
  // future-proof against added collapsibles).
  await page.evaluate(() => {
    for (const d of document.querySelectorAll('details')) {
      (d as HTMLDetailsElement).open = true;
    }
    // Reveal any class-toggled / hidden panels so their contents are scanned.
    for (const el of document.querySelectorAll<HTMLElement>('[hidden]')) {
      el.removeAttribute('hidden');
    }
  });
  await page.addStyleTag({ content: NEUTRALIZE_MOTION });
}

// Drive the Section B live demo so the dynamically injected output regions
// (badges, hex blocks, attack results) are present in the DOM when we scan.
async function runDemo(page: Page): Promise<void> {
  // Default checkbox state is "same nonce" (attack scenario) — leave it checked
  // so the broken/warning badges render.
  await page.locator('#btn-encrypt').click();
  await expect(page.locator('#gcm-output .status-badge').first()).toBeVisible();
  const attack = page.locator('#btn-attack');
  await expect(attack).toBeEnabled();
  await attack.click();
  await expect(page.locator('#gcm-attack-output .status-badge').first()).toBeVisible();
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.goto('.');
  await revealEverything(page);
  await runDemo(page);
  await scan(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await revealEverything(page);
  await runDemo(page);
  await scan(page);
});
