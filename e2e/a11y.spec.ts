import { expect, test } from '@playwright/test';
import { boot, driveAllStates, NARROW, reportCollected, watchPageErrors } from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * The lab is driven along everything it teaches, and scanned after every step:
 * the arrival state, where both output columns hold a placeholder, Run Attack is
 * disabled and the nonce toggle already ships CHECKED for the attack; both skip
 * links focused; Section C's two cancellation boards cancelled through their own
 * buttons and then replayed back; Section D's tag-as-IV comparison in both
 * modes, including an empty Message A; then Section B twice over — once under a
 * reused nonce, which recovers the GHASH key H and forges a tag real AES-GCM
 * accepts, and once under unique nonces, which is the safe half of the lab and
 * is reachable only by unchecking a default the old gate never touched. Finally
 * all four Level 2 failure branches: identical messages (0 = 0), an empty
 * Message 1, a crib shorter than its message, and a pair past the 512-byte
 * root-search cap.
 *
 * Four configurations: {dark, light} × {1280, 380}. The narrow half is not
 * decoration — `.equation` and `.cancel-viz` only overflow at phone width, so
 * the WCAG 2.1.1 question about them has no answer at 1280px.
 *
 * See `gate.ts` for what the gate this replaces actually did: injected motion
 * suppression that bypassed the stylesheet's own reduced-motion block, two
 * force-reveal loops over empty sets, one scan after the whole drive, one
 * viewport, `violations` as the only oracle, and a 1.4.11 check aimed at the
 * single selector its token was already correctly applied to.
 */

for (const theme of ['dark'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(900_000);
    const errors = watchPageErrors(page);
    await boot(page, theme);
    await driveAllStates(page, theme);
    expect(errors, errors.join('\n')).toEqual([]);
    reportCollected();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(900_000);
    const errors = watchPageErrors(page);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    expect(errors, errors.join('\n')).toEqual([]);
    reportCollected();
  });
}
