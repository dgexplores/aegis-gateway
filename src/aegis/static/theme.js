/* The theme cycle, shared by the landing page and the console.
 *
 * It lives apart from dashboard.js so that the pitch page can offer the same
 * dark mode without pulling in the console's twenty-odd element bindings —
 * those would all throw on a page that has no console. */
(() => {
  const ATTR = 'data-theme';
  const MODES = ['auto', 'light', 'dark'];

  const current = () => document.documentElement.getAttribute(ATTR) || 'auto';

  const apply = (mode) => {
    if (mode === 'auto') document.documentElement.removeAttribute(ATTR);
    else document.documentElement.setAttribute(ATTR, mode);
    const btn = document.getElementById('themeBtn');
    if (btn) btn.textContent = `Theme: ${mode}`;
  };

  const announce = (msg) => {
    const live = document.getElementById('toast');
    if (!live) return;
    live.textContent = msg;
    live.classList.add('show');
    clearTimeout(announce.t);
    announce.t = setTimeout(() => live.classList.remove('show'), 2400);
  };

  apply('auto');

  const btn = document.getElementById('themeBtn');
  if (btn) {
    btn.addEventListener('click', () => {
      const next = MODES[(MODES.indexOf(current()) + 1) % MODES.length];
      apply(next);
      announce(`Theme: ${next}`);
    });
  }
})();
