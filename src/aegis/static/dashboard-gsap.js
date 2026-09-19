/* AEGIS — GSAP Animations
 * Self-contained GSAP + ScrollTrigger bundle (minified locally)
 * Runs after dashboard.js initializes the DOM
 */

// ============================================================
// GSAP + ScrollTrigger (self-contained, minified)
// In production: copy from node_modules/gsap/dist/gsap.min.js
// and node_modules/gsap/dist/ScrollTrigger.min.js
// For this self-contained version, we'll use a lightweight implementation
// that mimics the core APIs we need. In real deploy, swap for real GSAP.
// ============================================================

/* Lightweight GSAP + ScrollTrigger shim for self-contained use */
/* In production: replace with real GSAP bundle */
const GSAP = (function() {
  const tweens = [];
  let rafId = null;

  function now() { return performance.now(); }

  function tick() {
    const t = now();
    for (let i = tweens.length - 1; i >= 0; i--) {
      const tw = tweens[i];
      const elapsed = t - tw.start;
      if (elapsed >= tw.duration) {
        tw.target[tw.prop] = tw.to;
        if (tw.onComplete) tw.onComplete();
        tweens.splice(i, 1);
      } else {
        const p = elapsed / tw.duration;
        const eased = tw.ease(p);
        tw.target[tw.prop] = tw.from + (tw.to - tw.from) * eased;
      }
    }
    if (tweens.length) rafId = requestAnimationFrame(tick);
    else rafId = null;
  }

  function to(target, vars) {
    const tw = {
      target: target,
      prop: vars.prop || 'opacity',
      from: vars.from !== undefined ? vars.from : (target[vars.prop] || 0),
      to: vars.to,
      duration: (vars.duration || 1) * 1000,
      ease: vars.ease || easeOut,
      start: performance.now(),
      onComplete: vars.onComplete
    };
    tweens.push(tw);
    if (!rafId) rafId = requestAnimationFrame(tick);
    return { kill: () => { const i = tweens.indexOf(tw); if (i > -1) tweens.splice(i, 1); } };
  }

  function fromTo(target, fromVars, toVars) {
    target[toVars.prop || 'opacity'] = fromVars[toVars.prop || 'opacity'] ?? 0;
    return to(target, toVars);
  }

  function set(target, vars) { Object.assign(target, vars); }

  function easeOut(t) { return 1 - Math.pow(1 - t, 3); }
  function easeInOut(t) { return t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2; }
  function easeSpring(t) { const c4 = (2 * Math.PI) / 3; return Math.pow(2, -10 * t) * Math.sin((t * 10 - 0.75) * c4) + 1; }

  function timeline() {
    const tweens = [];
    let totalDuration = 0;
    return {
      to(target, vars) { tweens.push({ target, vars, start: totalDuration }); totalDuration += (vars.duration || 1) * 1000; return this; },
      fromTo(target, from, to) { set(target, from); return this.to(target, to); },
      set(target, vars) { set(target, vars); return this; },
      play() { /* simplified */ }
    };
  }

  const ScrollTrigger = {
    triggers: [],
    create(config) {
      const trigger = {
        trigger: config.trigger,
        start: config.start || 'top bottom',
        end: config.end || 'bottom top',
        scrub: config.scrub || false,
        pin: config.pin || false,
        onUpdate: config.onUpdate,
        onEnter: config.onEnter,
        onLeave: config.onLeave,
        onEnterBack: config.onEnterBack,
        onLeaveBack: config.onLeaveBack,
      };
      this.triggers.push(trigger);
      this._check();
      return { kill: () => { const i = this.triggers.indexOf(trigger); if (i > -1) this.triggers.splice(i, 1); } };
    },
    _check() {
      const scrollY = window.scrollY || window.pageYOffset;
      const vh = window.innerHeight;
      for (const t of this.triggers) {
        const el = typeof t.trigger === 'string' ? document.querySelector(t.trigger) : t.trigger;
        if (!el) continue;
        const rect = el.getBoundingClientRect();
        const top = rect.top + scrollY;
        const bottom = top + el.offsetHeight;
        const start = this._parsePos(t.start, top, el.offsetHeight, vh);
        const end = this._parsePos(t.end, top, el.offsetHeight, vh);
        const progress = Math.max(0, Math.min(1, (scrollY - start) / (end - start)));
        if (t.onUpdate) t.onUpdate(progress, { progress, direction: scrollY > this._lastScrollY ? 1 : -1 });
        this._lastScrollY = scrollY;
      }
    },
    _parsePos(pos, top, height, vh) {
      if (typeof pos === 'number') return pos;
      if (pos.includes('top')) return top - vh * (pos.includes('bottom') ? 1 : 0);
      if (pos.includes('bottom')) return top + height - vh * (pos.includes('top') ? 1 : 0);
      return top;
    },
    refresh() { this._check(); }
  };

  window.addEventListener('scroll', () => ScrollTrigger.refresh(), { passive: true });
  window.addEventListener('resize', () => ScrollTrigger.refresh(), { passive: true });

  return { to, fromTo, set, timeline, ScrollTrigger, easeOut, easeInOut, easeSpring };
})();

// ============================================================
// ANIMATION CONTROLLER — Initializes all GSAP animations
// ============================================================

(function() {
  'use strict';

  const gsap = window.GSAP;
  const ScrollTrigger = gsap.ScrollTrigger;

  // ============================================================
  // UTILITIES
  // ============================================================
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  function prefersReduced() {
    return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  }

  // ============================================================
  // 1. HERO — Scrubbing text reveals on scroll
  // ============================================================
  function initHeroScrub() {
    if (prefersReduced()) return;

    const title = $('#hero-title');
    const sub = $('.hero-sub');
    const ctas = $('.hero-ctas');

    if (!title) return;

    // Split text into words for sequential reveal
    const splitText = (el) => {
      const text = el.textContent.trim();
      const words = text.split(/(\s+)/);
      el.innerHTML = words.map(w => w.trim() ? `<span class="word">${w}</span>` : w).join('');
      return $$('.word', el);
    };

    const titleWords = splitText(title);
    const subWords = splitText(sub);

    const allWords = [...titleWords, ...subWords, ...$$('.btn', '.hero-ctas')];

    // Initial state
    allWords.forEach(el => {
      el.style.opacity = '0';
      el.style.transform = 'translateY(30px)';
      el.style.display = 'inline-block';
    });

    ScrollTrigger.create({
      trigger: '.hero',
      start: 'top 80%',
      end: 'bottom 20%',
      scrub: 0.5,
      onUpdate: (self) => {
        const progress = self.progress;
        allWords.forEach((el, i) => {
          const delay = i * 0.03;
          const p = Math.max(0, Math.min(1, (progress - delay) / 0.8));
          el.style.opacity = p;
          el.style.transform = `translateY(${30 * (1 - p)}px)`;
        });
      }
    });
  }

  // ============================================================
  // 2. CARD STACKING — Capability cards stack on scroll
  // ============================================================
  function initCardStacking() {
    if (prefersReduced()) return;

    const cards = $$('.capability-card');
    if (!cards.length) return;

    ScrollTrigger.create({
      trigger: '.bento-grid',
      start: 'top 80%',
      end: 'bottom 20%',
      scrub: 0.8,
      onUpdate: (self) => {
        const progress = self.progress;
        cards.forEach((card, i) => {
          const delay = i * 0.1;
          const p = Math.max(0, Math.min(1, (progress - delay) / 0.6));
          const y = 60 * (1 - p);
          const scale = 0.95 + 0.05 * p;
          card.style.transform = `translateY(${y}px) scale(${scale})`;
          card.style.opacity = p;
        });
      }
    });
  }

  // ============================================================
  // 3. SCROLL PINNING — Section titles pin while content scrolls
  // ============================================================
  function initSectionPinning() {
    if (prefersReduced()) return;

    $$('.section-head').forEach(head => {
      const section = head.closest('section');
      if (!section) return;

      ScrollTrigger.create({
        trigger: section,
        start: 'top 20%',
        end: 'bottom 20%',
        pin: head,
        pinSpacing: false,
        pinType: 'transform',
      });
    });
  }

  // ============================================================
  // 4. IMAGE SCALE/FADE — Capability card images scale on scroll
  // ============================================================
  function initImageScaleFade() {
    if (prefersReduced()) return;

    $$('.card-visual').forEach(visual => {
      const img = visual.querySelector('.inline-img') || visual;
      ScrollTrigger.create({
        trigger: visual,
        start: 'top 90%',
        end: 'top 10%',
        scrub: 1,
        onUpdate: (self) => {
          const p = self.progress;
          const scale = 0.85 + 0.15 * p;
          const opacity = 0.3 + 0.7 * p;
          img.style.transform = `scale(${scale})`;
          img.style.opacity = opacity;
        }
      });
    });
  }

  // ============================================================
  // 5. HOVER PHYSICS — Card hover scale/lift
  // ============================================================
  function initHoverPhysics() {
    if (prefersReduced()) return;

    $$('.capability-card, .evidence, .tour-item').forEach(card => {
      let tween = null;
      card.addEventListener('mouseenter', () => {
        if (tween) tween.kill();
        tween = gsap.to(card, {
          prop: 'transform',
          to: 'translateY(-8px) scale(1.02)',
          duration: 0.4,
          ease: gsap.easeSpring
        });
      });
      card.addEventListener('mouseleave', () => {
        if (tween) tween.kill();
        tween = gsap.to(card, {
          prop: 'transform',
          to: 'translateY(0) scale(1)',
          duration: 0.4,
          ease: gsap.easeOut
        });
      });
    });
  }

  // ============================================================
  // 6. SCROLL REVEAL — Fade-in-up for sections
  // ============================================================
  function initScrollReveal() {
    if (prefersReduced()) return;

    $$('section:not(.hero) .card, .section-head, .marquee, .footer-copy').forEach(el => {
      el.style.opacity = '0';
      el.style.transform = 'translateY(40px)';

      ScrollTrigger.create({
        trigger: el,
        start: 'top 85%',
        once: true,
        onEnter: () => {
          gsap.to(el, {
            prop: 'opacity',
            to: 1,
            duration: 0.6,
            ease: gsap.easeOut,
            onStart: () => { el.style.transform = 'translateY(0)'; }
          });
        }
      });
    });
  }

  // ============================================================
  // 6b. CONSOLE THREAD — Staggered message animation
  // ============================================================
  function initThreadAnimation() {
    const observer = new MutationObserver((mutations) => {
      mutations.forEach(m => {
        m.addedNodes.forEach(node => {
          if (node.nodeType === 1 && node.classList.contains('turn')) {
            node.style.opacity = '0';
            node.style.transform = 'translateY(20px)';
            gsap.to(node, {
              prop: 'opacity',
              to: 1,
              duration: 0.4,
              ease: gsap.easeOut,
              onStart: () => { node.style.transform = 'translateY(0)'; }
            });
          }
        });
      });
    });

    const thread = $('#thread');
    if (thread) observer.observe(thread, { childList: true, subtree: true });
  }

  // ============================================================
  // 6c. EVIDENCE PANEL — Staggered detail reveal
  // ============================================================
  function initEvidenceAnimation() {
    const originalToggle = window.evidenceToggle;
    window.evidenceToggle = function(root) {
      const wasOpen = root.dataset.open === 'true';
      if (wasOpen) return; // Let original handle close

      const body = $('.evidence-body', root);
      if (!body) return;

      // Animate open
      body.style.display = 'block';
      body.style.opacity = '0';
      body.style.transform = 'translateY(-10px)';

      gsap.to(body, {
        prop: 'opacity',
        to: 1,
        duration: 0.3,
        ease: gsap.easeOut,
        onStart: () => { body.style.transform = 'translateY(0)'; }
      });
    };
  }

  // ============================================================
  // 7. MARQUEE PAUSE ON HOVER
  // ============================================================
  function initMarqueePause() {
    const track = $('.marquee-track');
    if (!track) return;

    track.addEventListener('mouseenter', () => {
      track.style.animationPlayState = 'paused';
    });
    track.addEventListener('mouseleave', () => {
      track.style.animationPlayState = 'running';
    });
  }

  // ============================================================
  // BOOT — Initialize all animations after DOM ready
  // ============================================================
  function init() {
    if (prefersReduced()) {
      // Still run non-animation inits
      initHoverPhysics();
      return;
    }

    // Initialize all GSAP animations
    initHeroScrub();
    initCardStacking();
    initSectionPinning();
    initImageScaleFade();
    initHoverPhysics();
    initScrollReveal();
    initThreadAnimation();
    initEvidenceAnimation();
    initMarqueePause();

    // Refresh ScrollTrigger on route changes / tab switches
    const originalShowView = window.showView;
    window.showView = function(name) {
      if (originalShowView) originalShowView(name);
      setTimeout(() => ScrollTrigger.refresh(), 50);
    };
  }

  // Initialize when DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  // Expose for debugging
  window.AEGIS_GSAP = { gsap, ScrollTrigger };
})();