import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText, formatNonTextFailures } from './nontext';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/**
 * Best-practice rules to run ALONGSIDE the WCAG tags, by id.
 *
 * These four are not WCAG-tagged, so a tag-filtered run never reaches them, and
 * this page is the exact shape they catch: a `<header role="banner">` above a
 * `<div id="app">` that contains a SECOND `<header>` and an
 * `<aside role="complementary">` inside it.
 */
export const EXTRA_RULES = [
  'landmark-no-duplicate-banner',
  'landmark-unique',
  'landmark-one-main',
  'landmark-complementary-is-top-level',
];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Six rules govern everything here, and each one is a correction of the gate
 * this replaces (`e2e/a11y.spec.ts`, plus `e2e/border-contrast.spec.ts`).
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. `revealEverything()`
 *     ended by pushing `transition: none !important; animation: none !important`
 *     through `addStyleTag`. That BYPASSED this stylesheet's own
 *     `@media (prefers-reduced-motion: reduce)` block instead of exercising it,
 *     which matters on this page specifically: the block clamps
 *     `transition-duration` to `0.01ms` and nothing else, and the only
 *     transition that carries state is `.cancel-fadeable { transition: opacity
 *     0.6s }`. An injected `transition: none` and the real reduced-motion
 *     clamp happen to land on the same end state — but that is a fact about
 *     this stylesheet that has to be MEASURED, not assumed, because the whole
 *     class of defect is a reduced-motion block that cancels an animation
 *     without restoring its end state. `boot` asks for the preference, asserts
 *     it took effect, and `expectNotBlank` then measures the end state in every
 *     driven state.
 *
 *  2. IT FORCE-REVEALED EVERYTHING. `revealEverything()` set `.open = true` on
 *     every `<details>` and stripped `hidden` from every element carrying it.
 *     Both loops were dead: this page has ZERO `<details>` elements and ZERO
 *     `[hidden]` attributes — asserted in `boot`, so if either is ever added the
 *     gate says so rather than silently reaching around it. What the page really
 *     hides is hidden by JS state, not by an attribute: `.cancel-term.gone` is
 *     `display: none` until a `.cancel-viz` is cancelled, and
 *     `.cancel-viz.is-cancelled .cancel-fadeable` goes to `visibility: hidden`.
 *     This gate reaches both by pressing the buttons a reader presses.
 *
 *  3. IT SCANNED ONCE, AFTER THE WHOLE DRIVE. `runDemo()` encrypted, ran the
 *     attack, cancelled both Section C boards and switched the Section D
 *     comparison to "change one byte" — and then `scan()` ran a single axe pass
 *     over whatever was left on screen. Every intermediate state it built was
 *     overwritten before anything measured it, including both Section C boards
 *     in their UNCANCELLED state, which is the state every reader arrives at.
 *     This drive scans after every single step.
 *
 *  4. IT SCANNED ONE VIEWPORT. There was no `setViewportSize` anywhere, so
 *     every run was 1280px, and WCAG 1.4.10 (reflow) had never been asked about
 *     this page at all. Three containers carry `overflow-x: auto` —
 *     `.equation`, `.cancel-viz` and `.table-scroll` — and only the last is
 *     keyboard-reachable, so a 2.1.1 finding was the obvious candidate. It is
 *     not one, and that is a measurement rather than an assumption: at 380px all
 *     three report `scrollWidth === clientWidth` (`.cancel-viz` 312/312,
 *     `.equation` 311/311, `.table-scroll` 314/314), because `.cancel-row` wraps
 *     and `.comparison-table` is `width: 100%` with wrapping cells. The narrow
 *     viewport stays in the gate because reflow is unmeasured without it and
 *     because the widest states this drive builds — output columns of unbroken
 *     hex from a 630-byte message — only exist after the drive goes and builds
 *     them.
 *
 *  5. `violations` IS NOT THE WHOLE ORACLE. `scan()` asserted
 *     `results.violations` and nothing else. Two whole classes of finding on
 *     this page never reach that array: `aria-label`/`aria-labelledby` on a
 *     role-less `<div>` or `<span>` is PROHIBITED and axe files it under
 *     `incomplete`; and every verdict this lab prints sits on a
 *     `color-mix(… 15%, transparent)` badge fill, which axe also declines to
 *     resolve and files under `incomplete`. See `scan`.
 *
 *  6. ITS 1.4.11 CHECK POINTED AT THE ONE PLACE THE RULE WAS ALREADY KEPT.
 *     `border-contrast.spec.ts` measured exactly one element — `#msg1`, a
 *     `<textarea>` — and only its border against its OWN fill. `--control-border`
 *     is used once in the whole stylesheet, on the `textarea` rule, so the spec
 *     queried precisely the selector the correct token had been applied to and
 *     could not have failed. Every button, the `.chip-toggle` pair, and
 *     `.interactive-input` (which takes `--border`, not `--control-border`) went
 *     unmeasured. `nontext.ts` measures all of them, plus every `::before` and
 *     `::after` on the page — the class axe and the text walk both step over.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set.
 *
 * This page has one element whose visible state IS driven by an opacity
 * transition: `.cancel-fadeable`, the `⊕` and the `keystream ⊕ keystream` /
 * `mask ⊕ mask` terms that Section C's buttons fade out. It runs the safe way
 * round — the transition fades TOWARD hidden and the resting state is visible —
 * and the cancelled end state also sets `visibility: hidden`, so nothing is left
 * painting at zero opacity with live geometry. Both halves of that are measured
 * here rather than read off the stylesheet: the check runs in every driven
 * state, including the four where a board has been cancelled and the two where
 * it has been replayed back.
 *
 * `aria-hidden` subtrees are excluded, which on this page means the `↓` flow
 * arrows, the 🟢/🟡/🔴 badge dots, the toggle-switch track and `.cancel-term.gone`
 * — all enumerated and cleared in the header of `contrast.ts`.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      if (el.closest('[aria-hidden="true"]')) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Uncaught page errors and console errors, collected from the moment the page
 * is created. A renderer that throws halfway through leaves an earlier state on
 * screen, and a gate that scans that state reports green for a page that is
 * broken. Attach before `boot`, assert after the drive.
 *
 * This matters more than usual here: `doAttack` runs a GF(2^128) root search on
 * the main thread and writes its whole result panel with one `innerHTML`
 * assignment. A throw anywhere inside it leaves the PREVIOUS panel on screen,
 * fully rendered and entirely plausible.
 */
export function watchPageErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(`console.error: ${m.text()}`);
  });
  return errors;
}

/**
 * Exactly one banner landmark: the shared bar.
 *
 * This page has TWO `<header>` elements — the shared `.cl-topbar` and the lab's
 * own `.cl-hero` — and the hero is a child of `<div id="app">`, not of a
 * sectioning element, so it implies `banner` on its own. `index.html`'s
 * `dedupeBanner()` demotes it to `role="group"` at DOMContentLoaded. Asserting
 * the OUTCOME rather than the mechanism means a change to either the nesting or
 * the script is caught.
 */
export async function assertSingleBanner(page: Page): Promise<void> {
  const banners = await page.evaluate(() => {
    const scoped = new Set(['MAIN', 'ARTICLE', 'ASIDE', 'NAV', 'SECTION']);
    const isBanner = (el: Element): boolean => {
      if (el.getAttribute('role') === 'banner') return true;
      if (el.tagName !== 'HEADER') return false;
      if (el.getAttribute('role')) return false; // explicit non-banner role wins
      for (let p = el.parentElement; p; p = p.parentElement) if (scoped.has(p.tagName)) return false;
      return true;
    };
    return [...document.querySelectorAll('header,[role="banner"]')].filter(isBanner).length;
  });
  expect(banners, 'exactly one banner landmark').toBe(1);
}

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the content every scan relies on is really there — including the LAB'S
 * DEFAULTS, which are never assumed.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page.
 *
 * The theme is seeded through `localStorage` rather than by clicking the
 * toggle, which also pins down a real failure mode: `index.html`'s anti-flash
 * script reads `localStorage.getItem('theme')`, the shared bar's
 * `#cl-theme-toggle` writes `localStorage.setItem('theme', …)`, and this lab's
 * own `#theme-toggle` (hidden by the shared bar, but still wired) writes the
 * same key. If any of the three drift apart the theme silently stops
 * persisting, and this boot fails on `data-theme` rather than quietly scanning
 * dark twice.
 *
 * THE DEFAULT THAT MATTERS MOST IS `#same-nonce`, AND IT SHIPS CHECKED. The
 * page arrives configured for the attack, so the unique-nonce path — the SAFE
 * path, the one with the green UNIQUE NONCES badges and the "NO ATTACK" result
 * — is reached only by unchecking it. A gate that never touched the checkbox
 * measured the broken half of this lab and none of the working half. The drive
 * goes both ways; asserting the default here is what makes "both ways" mean
 * something.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the
  // whole test timeout and reports nothing useful. 20s turns that silent hang
  // into a named failure naming the locator.
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
  await assertSingleBanner(page);

  // Both loops the old gate ran were over empty sets. Asserted, not assumed, so
  // that adding either construct fails here instead of silently reintroducing
  // the force-reveal problem this gate exists to remove.
  await expect(page.locator('details')).toHaveCount(0);
  await expect(page.locator('[hidden]')).toHaveCount(0);

  // Everything below is mounted by `src/main.ts`; a navigation that resolves
  // proves none of it ran.
  await expect(page.locator('#nonce-display .nonce-byte')).toHaveCount(12);
  await expect(page.locator('#siv-tag-output .hex-output')).toHaveCount(4);
  await expect(page.locator('#siv-compare-output .hex-output')).toHaveCount(6);

  // ── The lab's shipped defaults ───────────────────────────────────────────
  // The attack toggle ships ON: this page arrives configured to break.
  await expect(page.locator('#same-nonce')).toBeChecked();
  await expect(page.locator('#btn-encrypt')).toBeEnabled();
  await expect(page.locator('#btn-attack')).toBeDisabled();
  await expect(page.locator('#btn-attack')).toHaveAttribute('aria-disabled', 'true');
  await expect(page.locator('#msg1')).toHaveValue('Transfer $1000 to Alice');
  await expect(page.locator('#msg2')).toHaveValue('Wire $9000 to Mallory instead');
  await expect(page.locator('#siv-input')).toHaveValue('Hello, world!');

  // Both output columns ship with a placeholder and nothing else.
  await expect(page.locator('#gcm-output .placeholder-text')).toBeVisible();
  await expect(page.locator('#siv-output .placeholder-text')).toBeVisible();
  await expect(page.locator('.status-badge')).toHaveCount(1); // only Section D's verdict

  // Section C's two boards arrive UNCANCELLED — the state every reader meets,
  // and the one the old gate overwrote before its only scan.
  await expect(page.locator('.cancel-viz')).toHaveCount(2);
  await expect(page.locator('.cancel-viz.is-cancelled')).toHaveCount(0);
  await expect(page.locator('#cancel-l1-btn')).toHaveText('Cancel the shared keystream ▶');
  await expect(page.locator('#cancel-l2-btn')).toHaveText('Cancel the shared mask ▶');

  // Section D's comparison arrives on "same message twice".
  await expect(page.locator('#siv-mode-same')).toHaveAttribute('aria-checked', 'true');
  await expect(page.locator('#siv-mode-diff')).toHaveAttribute('aria-checked', 'false');

  // The live region starts silent; every announcement in the drive is a change
  // from this.
  await expect(page.locator('#demo-status')).toBeEmpty();

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and the old gate
 * never opened a narrow viewport, so nothing in this repo had ever asked the
 * question. The page is the shape that breaks it: two 1fr/1fr grids, a
 * nine-row comparison table, four `.flow-diagram`s of monospace boxes, two
 * algebra boards full of `white-space: nowrap` terms, and — the part a drive
 * has to build — output columns of unbroken hex several hundred characters
 * long.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide box inside an `overflow-x: auto` wrapper has a huge bounding rect but
    // is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element. This page
    // has a decoy behind every `.table-scroll`, `.equation` and `.cancel-viz`.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * `<body>` must not clip its own overflow (a guard on the fix, not a checker).
 *
 * `overflow` set on `<body>` propagates to the VIEWPORT when `<html>` has
 * `overflow: visible`, so `documentElement.scrollWidth === clientWidth` becomes
 * true no matter how wide the content is — and the reflow assertion above turns
 * into an assertion that can never fail. It also does not make anything fit: it
 * CLIPS, and clipped content is unreachable, which under 1.4.10 is strictly
 * worse than a scrollbar.
 *
 * This stylesheet does not do it today. The assertion exists because it is the
 * standard "fix" for a reflow failure and would silently disable the oracle
 * that found the failure in the first place.
 */
export async function expectReflowFalsifiable(page: Page): Promise<void> {
  const clipping = await page.evaluate(() => {
    const b = getComputedStyle(document.body);
    const h = getComputedStyle(document.documentElement);
    return { bodyX: b.overflowX, bodyY: b.overflowY, htmlX: h.overflowX, htmlY: h.overflowY };
  });
  expect(
    clipping,
    'overflow on <body> propagates to the viewport and makes the reflow check unfalsifiable'
  ).toEqual({ bodyX: 'visible', bodyY: 'visible', htmlX: 'visible', htmlY: 'visible' });
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1). If
 * it holds no focusable content it needs `tabindex="0"`, so it becomes a focus
 * target arrow keys can then scroll.
 *
 * Three containers on this page scroll: `.table-scroll` around the comparison
 * table, which was already built with `role="region" tabindex="0"` and an
 * `aria-label`; and `.equation` and `.cancel-viz`, which were not. The latter
 * two do not overflow at 1280px, so this only has anything to say at 380px —
 * which is exactly why a single-viewport gate could not find it.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/** Every visible `tabindex="0"` region on the page right now, as a selector. */
async function focusableRegions(page: Page): Promise<string[]> {
  return page.evaluate(() =>
    Array.from(document.querySelectorAll<HTMLElement>('[tabindex="0"]'))
      .filter((el) => el.checkVisibility?.())
      .map((el) => {
        const cls = el.getAttribute('class');
        return (
          el.tagName.toLowerCase() +
          (el.id ? `#${el.id}` : '') +
          (cls ? `.${cls.trim().split(/\s+/).join('.')}` : '')
        );
      })
  );
}

/**
 * Every `tabindex="0"` region must show a focus indicator when a keyboard
 * actually reaches it (WCAG 2.4.7).
 *
 * This exists because a `tabindex` with no focus style is the classic defect
 * INTRODUCED by fixing a 2.1.1 scroller finding — elsewhere in this sweep one
 * pass made seven regions focusable and left every one of them without an
 * indicator. `.table-scroll` is the one such region this page ships.
 *
 * IT WALKS THE REAL TAB ORDER, and that is the whole point. The first version
 * of this called `el.focus()` from inside `page.evaluate` and read the computed
 * outline, and it reported `div.table-scroll` as having NO indicator in every
 * driven state — a finding that was entirely an artefact of the instrument.
 * Chromium only applies `:focus-visible` STYLING when the focus arrived through
 * a keyboard-ish route; a scripted `.focus()` leaves the element matching
 * `:focus-visible` to `Element.matches()` while the style engine still paints
 * the plain default ring. A CDP `CSS.forcePseudoState` query settled it: under a
 * real `:focus-visible` the author rule `:focus-visible { outline: 2px solid
 * var(--accent); outline-offset: 2px }` does match `.table-scroll`, and a
 * keyboard Tab produces exactly that. Pressing Tab is therefore not a
 * convenience here; it is the only way to measure the thing being asserted.
 *
 * Run once per configuration rather than per state: focus styling is a property
 * of the stylesheet, not of the driven state, and a tab walk is a round trip per
 * stop. What IS re-checked in every state is the SET of focusable regions — see
 * `expectNoUnverifiedFocusRegions` — so a state that introduces a new one is
 * still caught.
 */
export async function verifyFocusIndicators(page: Page): Promise<Set<string>> {
  const wanted = new Set(await focusableRegions(page));
  expect(wanted.size, 'no focusable regions found to verify').toBeGreaterThan(0);

  await page.evaluate(() => {
    const b = document.body;
    b.setAttribute('tabindex', '-1');
    b.focus();
    b.removeAttribute('tabindex');
  });

  const verified = new Set<string>();
  const bad: string[] = [];
  // Bounded: this page has well under 60 tab stops, and the loop exits as soon
  // as every wanted region has been reached.
  for (let i = 0; i < 60 && verified.size < wanted.size; i++) {
    await page.keyboard.press('Tab');
    const hit = await page.evaluate(() => {
      const el = document.activeElement as HTMLElement | null;
      if (!el || el === document.body || el.getAttribute('tabindex') !== '0') return null;
      const cs = getComputedStyle(el);
      const cls = el.getAttribute('class');
      return {
        sel:
          el.tagName.toLowerCase() +
          (el.id ? `#${el.id}` : '') +
          (cls ? `.${cls.trim().split(/\s+/).join('.')}` : ''),
        width: parseFloat(cs.outlineWidth || '0'),
        style: cs.outlineStyle,
        shadow: cs.boxShadow,
      };
    });
    if (!hit) continue;
    verified.add(hit.sel);
    const outlined = hit.style !== 'none' && hit.width >= 1;
    if (!outlined && hit.shadow === 'none') {
      bad.push(`${hit.sel} — outline ${hit.width}px ${hit.style}, box-shadow ${hit.shadow}`);
    }
  }
  expect(bad, 'focusable regions with no visible focus indicator under real keyboard focus').toEqual(
    []
  );
  expect(
    Array.from(wanted).filter((w) => !verified.has(w)),
    'focusable regions the tab walk never reached'
  ).toEqual([]);
  return verified;
}

/**
 * No driven state may introduce a focusable region the tab walk never measured.
 *
 * Cheap enough to run in every scan, and it is what keeps the once-per-config
 * tab walk honest: the walk covers the regions present at boot, this covers the
 * possibility that a later state adds one.
 */
export async function expectNoUnverifiedFocusRegions(
  page: Page,
  verified: Set<string>,
  label: string
): Promise<void> {
  const present = await focusableRegions(page);
  expect(
    Array.from(new Set(present.filter((p) => !verified.has(p)))),
    `focusable regions with no verified focus indicator in state: ${label}`
  ).toEqual([]);
}

/**
 * When `A11Y_COLLECT` is set, `scan` records failures instead of throwing.
 *
 * A strict gate reports the first failing assertion in the first failing state
 * and stops, so a page with defects in several states needs one full run per
 * defect to enumerate them. The collection pass turns that into a single run. It
 * is a debugging aid only: `A11Y_COLLECT` is never set in CI, and a run with it
 * set prints every finding as it happens and then FAILS at the end via
 * `reportCollected()`, so a green collection run cannot be mistaken for a green
 * gate.
 */
const COLLECTING = !!process.env.A11Y_COLLECT;
const collected: string[] = [];

function record(entry: string): void {
  collected.push(entry);
  // Printed as it happens, not only at the end: a hard assertion later in the
  // drive would otherwise abort the test before anything collected so far was
  // ever shown.
  console.log(`\n[A11Y_COLLECT #${collected.length}] ${entry}`);
}

export function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected);
    return;
  }
  try {
    expect(actual, message).toEqual(expected);
  } catch {
    record(`${message}\n  ${JSON.stringify(actual, null, 2)}`);
  }
}

/**
 * Fail the test if the collection pass recorded anything. Without this a
 * collection run would end green, and a green collection run is
 * indistinguishable from a green gate — which is the exact confusion the whole
 * exercise exists to remove.
 */
export function reportCollected(): void {
  if (!COLLECTING) return;
  expect(collected, `A11Y_COLLECT recorded ${collected.length} failure(s)`).toEqual([]);
}

/** Run a throwing async assertion, collecting instead when `A11Y_COLLECT` is set. */
async function soft(label: string, fn: () => Promise<void>): Promise<void> {
  if (!COLLECTING) return fn();
  try {
    await fn();
  } catch (e) {
    record(`${label}\n  ${String(e).slice(0, 900)}`);
  }
}

/**
 * Scan the page as it currently stands.
 *
 * Seven assertions, because axe's `violations` array — which is all the gate
 * this replaces looked at — is not a complete oracle:
 *
 *  - reduced-motion end state (`expectNotBlank`).
 *  - `violations`: the usual WCAG A/AA rule failures, plus four landmark
 *    best-practice rules that `withTags` does not run on its own. Those four
 *    matter here because the page has a `<header role="banner">` above a `<div
 *    id="app">` that contains a SECOND `<header>` and an `<aside
 *    role="complementary">` inside it — exactly the shape they catch, and none
 *    of them was enabled before.
 *  - `incomplete`: axe's "could not decide" bucket, which never reaches
 *    `violations`. `color-contrast` is the one id allowed to remain there,
 *    because the next assertion computes those ratios arithmetically — and on
 *    this page that is most of them, since every `.status-badge`, every `.chip`
 *    and the `.cancel-term.shared` fill is a `color-mix(…, transparent)` axe
 *    declines to resolve. Everything ELSE in the bucket is a real result axe
 *    simply could not finish, including `aria-prohibited-attr`: an `aria-label`
 *    or `aria-labelledby` on a role-less element is prohibited and lands there,
 *    never in `violations`.
 *  - arithmetic contrast: composite-aware WCAG 1.4.3 over every text node.
 *  - non-text contrast and generated content: SC 1.4.11, plus every `::before`
 *    and `::after`. axe has no rule for either and the text walk cannot reach
 *    either. See `nontext.ts`.
 *  - keyboard reachability of scrolling regions (WCAG 2.1.1) and a visible
 *    focus indicator on everything that reachability makes focusable (2.4.7).
 *  - reflow (WCAG 1.4.10), which axe has no rule for at all.
 */
/**
 * The focusable regions whose indicator has been measured under a real keyboard
 * Tab, filled in once per configuration by `driveAllStates`. Every scan asserts
 * that nothing outside this set has become focusable.
 */
let verifiedFocusRegions = new Set<string>();

export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  // NOT `.withTags(TAGS).withRules(EXTRA_RULES)`. `AxeBuilder` maps both onto
  // the single `runOnly` option, so the second call OVERWRITES the first — its
  // own docblock says "Cannot be used with AxeBuilder#withTags". Chained that
  // way the run executes ONLY the four landmark best-practice rules and the
  // entire WCAG A/AA rule set is silently switched off, which is a gate that
  // reports green because it checked almost nothing. That was live here until
  // it was caught by a probe running `aria-prohibited-attr` explicitly and
  // getting 15 nodes back that the "passing" gate had never mentioned.
  //
  // So: run axe's full default rule set with no `runOnly` at all, and filter the
  // RESULTS to the WCAG tags plus the four ids named above. Filtering after the
  // fact is what lets the two selections coexist; it is also strictly broader,
  // because a rule that gains a WCAG tag in a future axe release starts being
  // enforced without anyone editing a list.
  const results = await new AxeBuilder({ page }).analyze();
  const inScope = (v: { id: string; tags: string[] }): boolean =>
    EXTRA_RULES.includes(v.id) || v.tags.some((t) => TAGS.includes(t));

  const violations = results.violations.filter(inScope).map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`, []);

  const unexplainedIncomplete = results.incomplete
    .filter(inScope)
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, []);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`, []);

  const nonText = await auditNonText(page);
  expect(
    nonText.length + (await page.locator('button:not([disabled])').count()),
    `no controls found to measure in state: ${label}`
  ).toBeGreaterThan(0);
  softExpect(
    Array.from(new Set(formatNonTextFailures(nonText))),
    `non-text contrast / generated content failures (SC 1.4.11) in state: ${label}`,
    []
  );

  await soft(`scrollers in ${label}`, () => expectScrollersReachable(page, label));
  await soft(`focus regions in ${label}`, () =>
    expectNoUnverifiedFocusRegions(page, verifiedFocusRegions, label)
  );
  await soft(`reflow in ${label}`, async () => {
    await expectReflowFalsifiable(page);
    await expectNoHorizontalOverflow(page, label);
  });
}

// ── The drive ───────────────────────────────────────────────────────────────

/**
 * Flip the "Use same nonce (attack scenario)" switch, the way a reader can.
 *
 * `page.check('#same-nonce')` does not work and should not: the checkbox is
 * `opacity: 0; width: 0; height: 0`, which is how the custom switch is built, so
 * Playwright correctly refuses to click an element with no box. The visible
 * affordances are the `<label for="same-nonce">` caption and the switch itself;
 * this clicks the caption.
 *
 * The settle afterwards is load-bearing for the same reason it was for the
 * probe that found the knob defect: `.slider` carries
 * `transition: background 0.2s`, and reading `backgroundColor` immediately after
 * the click returns the interpolated START value — which made an unchecked
 * switch report the checked colour and briefly looked like a CSS bug that was
 * not there.
 */
async function setNonceReuse(page: Page, on: boolean): Promise<void> {
  const box = page.locator('#same-nonce');
  if ((await box.isChecked()) !== on) {
    await page.click('#nonce-toggle-label');
  }
  await expect(box).toBeChecked({ checked: on });
  await settle(page);
}

/**
 * Encrypt, then assert the outputs the run really produced.
 *
 * `#gcm-output` and `#siv-output` are replaced wholesale by one `innerHTML`
 * assignment each, so "the button was clicked" and "the panel was rebuilt" are
 * different claims. Waiting on the badge count is the completion signal the code
 * itself defines; there is no fixed timeout anywhere in this drive.
 */
async function encrypt(page: Page, sameNonce: boolean): Promise<void> {
  await expect(page.locator('#same-nonce')).toBeChecked({ checked: sameNonce });
  await page.click('#btn-encrypt');
  // Same nonce prints one shared nonce block; unique nonces print two.
  const hexBlocks = sameNonce ? 5 : 6;
  await expect(page.locator('#gcm-output > .hex-output')).toHaveCount(hexBlocks);
  await expect(page.locator('#siv-output > .hex-output')).toHaveCount(hexBlocks);
  await expect(page.locator('#btn-attack')).toBeEnabled();
  await expect(page.locator('#btn-attack')).toHaveAttribute('aria-disabled', 'false');
  await expect(page.locator('#demo-status')).toContainText(
    sameNonce ? 'using the same nonce' : 'using unique nonces'
  );
}

/**
 * Drive the lab through every state it renders, scanning each.
 *
 * Five things shape this drive, and each of them is a state the gate this
 * replaces never measured:
 *
 *  - THE ARRIVAL STATE IS SCANNED FIRST. Both output columns hold a
 *    `.placeholder-text`, Run Attack is `disabled`, and both Section C boards
 *    are uncancelled. The old gate cancelled both boards and ran the whole demo
 *    BEFORE its single scan, so the state every reader arrives in was never
 *    looked at.
 *
 *  - THE PREREQUISITE IS SCANNED BEFORE THE UNLOCK. `#btn-attack` ships
 *    `disabled` with `aria-disabled="true"`; it is asserted disabled, scanned,
 *    and only then unlocked by Encrypt.
 *
 *  - BOTH SIDES OF EVERY FORK. `#same-nonce` ships CHECKED, so the old gate
 *    only ever saw the attack path. Here it is driven checked (the broken
 *    badges) AND unchecked (the green UNIQUE NONCES pair and the "NO ATTACK"
 *    result). Section D's radio pair is driven both ways too, and Section C's
 *    two boards are cancelled and then REPLAYED back, because the replay is a
 *    distinct rendering with a different button label and a different caption.
 *
 *  - EVERY FAILURE BRANCH OF THE LEVEL 2 SOLVER, all four of which are reachable
 *    by typing and all four of which paint a badge nothing else paints:
 *    identical messages (`no-information`, the 0 = 0 degenerate equation), a
 *    message past the 512-byte root-search budget (`too-long`), an empty
 *    Message 1 (`no-keystream`, and simultaneously the Level 1 branch with no
 *    crib overlap), and a short Message 1 against a long Message 2 (partial
 *    recovery). The success branch — H recovered, forgery accepted, the
 *    `.threat-box` rendered — is driven first.
 *
 *  - THE EXTREMES, NOT THE DEFAULTS. The 512-byte message is what makes the
 *    output columns wide enough for reflow to have an answer, and an empty
 *    `#siv-input` is the edge `messageB()` special-cases.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${theme} / ${s}`);

  // Measure the focus indicator on every focusable region ONCE, by tab-walking
  // to it for real. See `verifyFocusIndicators` for why a scripted `.focus()`
  // cannot answer this question.
  verifiedFocusRegions = await verifyFocusIndicators(page);

  await scanAt('first paint: both columns empty, Run Attack locked, nonce toggle on');

  // Two skip links in tab order: the shared bar's, then the lab's own. Both
  // park off-screen and slide in on focus, so the focused rendering is the only
  // one that can be measured — and it is a real state a keyboard user lands in
  // on every load.
  //
  // The reset is load-bearing, and it caught a self-inflicted bug: the focus
  // walk above leaves the SEQUENTIAL FOCUS NAVIGATION STARTING POINT wherever
  // it stopped, and blurring an element does not move it back. A bare `Tab`
  // after that lands on whatever follows that element, not on the skip link, so
  // this assertion was failing against a page that is fine. Focusing `<body>`
  // through a temporary `tabindex="-1"` puts the starting point back at the top
  // of the document, which is where a fresh load leaves it.
  await page.evaluate(() => {
    const b = document.body;
    b.setAttribute('tabindex', '-1');
    b.focus();
    b.removeAttribute('tabindex');
  });
  await page.keyboard.press('Tab');
  await expect(page.locator('a.cl-skip-link')).toBeFocused();
  await scanAt('shared skip link focused');

  // The lab's own `.skip-link` is NOT second. It sits after the entire shared
  // header in source order, so it is the SIXTH stop — the tab order is asserted
  // rather than counted, because the number is the only thing that says where
  // the link actually is. 2.4.1 is satisfied by `.cl-skip-link`, which is first
  // and targets `#app`; this one is a redundant second route to `#main`, and
  // being reachable only after the sticky bar is what makes it redundant rather
  // than the bypass it looks like.
  for (const next of [
    page.locator('a.cl-brand'),
    page.locator('nav.cl-actions a.cl-btn').nth(0),
    page.locator('nav.cl-actions a.cl-btn').nth(1),
    page.locator("a.skip-link[href='#main']"),
  ]) {
    await page.keyboard.press('Tab');
    await expect(next).toBeFocused();
  }
  await scanAt("the lab's own skip link focused, six stops in");

  // ── Section C: both cancellation boards, cancelled and replayed ─────────
  for (const [btn, viz] of [
    ['#cancel-l1-btn', 'C1 keystream'],
    ['#cancel-l2-btn', 'C2 mask'],
  ] as const) {
    const board = page.locator(btn).locator('xpath=ancestor::div[@class="card"]').locator('.cancel-viz');
    await expect(board).not.toHaveClass(/is-cancelled/);
    await page.click(btn);
    await expect(board).toHaveClass(/is-cancelled/);
    await expect(page.locator(btn)).toHaveText('Replay ↺');
    await expect(board.locator('.cancel-term.gone')).toBeVisible();
    await scanAt(`${viz} board cancelled, the shared term faded out`);

    await page.click(btn);
    await expect(board).not.toHaveClass(/is-cancelled/);
    await expect(board.locator('.cancel-term.gone')).toBeHidden();
    await scanAt(`${viz} board replayed back to its uncancelled state`);
  }

  // ── Section D: the tag-as-IV comparison, both modes and both edges ──────
  await page.click('#siv-mode-diff');
  await expect(page.locator('#siv-mode-diff')).toHaveAttribute('aria-checked', 'true');
  await expect(page.locator('#siv-compare-output .status-badge.safe')).toBeVisible();
  await scanAt('SIV comparison: one byte changed, tag and IV diverge (safe verdict)');

  // An empty message is the edge `messageB()` special-cases: B becomes "A", so
  // the two are still different and the safe verdict holds with an empty A.
  await page.fill('#siv-input', '');
  await expect(page.locator('#siv-compare-output .status-badge.safe')).toBeVisible();
  await scanAt('SIV comparison with an empty Message A');

  await page.fill('#siv-input', 'Hello, world!');
  await page.click('#siv-mode-same');
  await expect(page.locator('#siv-mode-same')).toHaveAttribute('aria-checked', 'true');
  await expect(page.locator('#siv-compare-output .status-badge.warning')).toBeVisible();
  await scanAt('SIV comparison: same message twice, the one thing SIV leaks');

  // ── Section B: the attack path (the toggle's shipped default) ───────────
  await encrypt(page, true);
  await expect(page.locator('#gcm-output .status-badge.broken')).toHaveText(/SAME NONCE USED/);
  await scanAt('encrypted under a reused nonce, both columns populated');

  await page.click('#btn-attack');
  await expect(page.locator('#gcm-attack-output .status-badge').first()).toBeVisible();
  await expect(page.locator('#gcm-attack-output')).toContainText('H RECOVERED EXACTLY');
  await expect(page.locator('#gcm-attack-output')).toContainText('FORGERY ACCEPTED');
  await expect(page.locator('#gcm-attack-output .threat-box')).toBeVisible();
  await expect(page.locator('#siv-attack-output .status-badge.safe')).toBeVisible();
  await scanAt('attack run: H recovered, tag forged, threat box rendered');

  // ── Section B: the safe path, reached only by unchecking the default ────
  await setNonceReuse(page, false);
  // Scanned BEFORE encrypting. The switch in its OFF position is a rendering
  // nothing else on this page produces — the track drops from the amber
  // `--status-warning` to a neutral — and whether the knob is still findable
  // against that neutral is a 1.4.11 question with an answer only in this state.
  await scanAt('nonce reuse switched OFF, nothing encrypted yet');
  await encrypt(page, false);
  await expect(page.locator('#gcm-output .status-badge.safe')).toHaveText(/UNIQUE NONCES/);
  await expect(page.locator('#siv-output .status-badge.safe')).toHaveText(/UNIQUE NONCES/);
  await scanAt('encrypted under unique nonces, both columns green');

  await page.click('#btn-attack');
  await expect(page.locator('#gcm-attack-output .status-badge.safe')).toHaveText(/NO ATTACK/);
  await scanAt('attack declined: nonces are unique, nothing to break');

  // ── Every Level 2 failure branch ────────────────────────────────────────
  await setNonceReuse(page, true);

  // `no-information`: identical messages make C1 = C2 and T1 = T2, the key
  // equation degenerates to 0 = 0, and SIV's identical-plaintext leak fires in
  // the same run.
  await page.fill('#msg1', 'identical text');
  await page.fill('#msg2', 'identical text');
  await encrypt(page, true);
  await page.click('#btn-attack');
  await expect(page.locator('#gcm-attack-output')).toContainText('NO KEY RECOVERED');
  await expect(page.locator('#siv-attack-output')).toContainText('IDENTICAL PLAINTEXT DETECTED');
  await scanAt('identical messages: 0 = 0, nothing learned, SIV leaks only equality');

  // `no-keystream`, and Level 1 with no crib overlap: an empty Message 1.
  await page.fill('#msg1', '');
  await page.fill('#msg2', 'Wire $9000 to Mallory instead');
  await encrypt(page, true);
  await page.click('#btn-attack');
  await expect(page.locator('#gcm-attack-output')).toContainText('NO PLAINTEXT RECOVERED');
  await scanAt('empty Message 1: no crib, no keystream, no forgery attempted');

  // Partial recovery: a crib shorter than the message it is XORed against.
  await page.fill('#msg1', 'short');
  await page.fill('#msg2', 'a considerably longer second message than the first');
  await encrypt(page, true);
  await page.click('#btn-attack');
  await expect(page.locator('#gcm-attack-output')).toContainText('MESSAGE 2 PARTIALLY RECOVERED');
  await scanAt('partial recovery: the crib is shorter than Message 2');

  // `too-long`: past the 512-byte root-search budget. This is also the widest
  // the output columns ever get, which is what gives reflow something to say.
  const long = 'the quick brown fox jumps over the lazy dog. '.repeat(14);
  expect(long.length, 'the long message must exceed the 512-byte Level 2 cap').toBeGreaterThan(512);
  await page.fill('#msg1', long);
  await page.fill('#msg2', `${long}tail`);
  await encrypt(page, true);
  await page.click('#btn-attack');
  await expect(page.locator('#gcm-attack-output')).toContainText('NOT RUN');
  await expect(page.locator('#gcm-attack-output')).toContainText('MESSAGE 2 PARTIALLY RECOVERED');
  await scanAt('messages past the 512-byte cap: Level 2 declines rather than pretending');
}
