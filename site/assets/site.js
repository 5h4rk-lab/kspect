/* kspect.dev — zero-dependency site behavior */
(() => {
  "use strict";
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* ---- scroll reveals ---- */
  const io = new IntersectionObserver(
    (es) => es.forEach((e) => e.isIntersecting && (e.target.classList.add("in"), io.unobserve(e.target))),
    { threshold: 0.12 }
  );
  $$(".reveal").forEach((el) => io.observe(el));

  /* ---- mobile nav ---- */
  const menuBtn = $(".menu-btn"), nav = $(".nav");
  menuBtn?.addEventListener("click", () => {
    const open = nav.classList.toggle("open");
    menuBtn.setAttribute("aria-expanded", String(open));
  });
  nav?.addEventListener("click", (e) => e.target.tagName === "A" && nav.classList.remove("open"));

  /* ---- hero terminal replay: genuine kspect output, typed ---- */
  const LINES = [
    ["c-p", "$ ", "c-cmd", "kspect scan --fail-on high"],
    ["c-dim", "kspect scan — kernel 6.8.0-generic (x86_64)"],
    ["", ""],
    ["c-fail", "FAIL", "c-sev", " HIGH    ", "", "KSPECT-SYSCTL-003    Unprivileged BPF disabled"],
    ["c-dim", "     observed: sysctl kernel.unprivileged_bpf_disabled = \"0\""],
    ["c-fix", "     fix:      sysctl -w kernel.unprivileged_bpf_disabled=1"],
    ["c-fail", "FAIL", "c-sev", " MEDIUM  ", "", "KSPECT-SYSCTL-006    ptrace restricted to descendants"],
    ["c-dim", "     observed: sysctl kernel.yama.ptrace_scope = \"0\""],
    ["c-fix", "     fix:      sysctl -w kernel.yama.ptrace_scope=1"],
    ["c-fail", "FAIL", "c-sev", " MEDIUM  ", "", "KSPECT-MODULE-001    DCCP protocol module not loaded"],
    ["c-dim", "     observed: module dccp loaded"],
    ["c-fix", "     fix:      echo 'install dccp /bin/false' > /etc/modprobe.d/dccp.conf"],
    ["c-pass", "PASS", "c-dim", " HIGH    KSPECT-MITIG-001     No unmitigated CPU vulnerabilities"],
    ["c-pass", "PASS", "c-dim", " HIGH    KSPECT-CMDLINE-002   KASLR not disabled at boot"],
    ["c-unk", "?   ", "c-dim", "  LOW     KSPECT-KCONFIG-006   Slab freelists randomized (no kconfig exposed)"],
    ["", ""],
    ["c-dim", "Summary: 48 checks — ", "c-fail", "18 fail", "c-dim", ", ", "c-pass", "19 pass", "c-dim", ", ", "c-unk", "11 unknown"],
    ["c-p", "$ ", "c-cmd", "echo $?", "", "   ", "c-dim", "# exit 1 → CI gate holds"],
  ];

  const body = $("#term-body");
  function renderLine(parts) {
    const frag = document.createDocumentFragment();
    for (let i = 0; i < parts.length; i += 2) {
      const span = document.createElement("span");
      if (parts[i]) span.className = parts[i];
      span.textContent = parts[i + 1];
      frag.appendChild(span);
    }
    frag.appendChild(document.createTextNode("\n"));
    return frag;
  }
  function finishPosture() {
    const bar = $("#posture-bar");
    if (!bar) return;
    // real self-scan of a stock cloud kernel: 18 fail / 19 pass / 11 unknown
    const total = 48, f = 18, p = 19, u = 11;
    $(".f", bar).style.width = (f / total) * 100 + "%";
    $(".p", bar).style.width = (p / total) * 100 + "%";
    $(".u", bar).style.width = (u / total) * 100 + "%";
  }
  if (body) {
    if (reduced) {
      LINES.forEach((l) => body.appendChild(renderLine(l)));
      finishPosture();
    } else {
      let i = 0;
      const caret = document.createElement("span");
      caret.className = "caret";
      body.appendChild(caret);
      (function tick() {
        if (i >= LINES.length) { caret.remove(); finishPosture(); return; }
        body.insertBefore(renderLine(LINES[i]), caret);
        const first = LINES[i][1] || "";
        i++;
        setTimeout(tick, first.startsWith("$") ? 600 : LINES[i - 1][0] === "" ? 90 : 170);
      })();
    }
  } else {
    finishPosture();
  }

  /* ---- tabs (accessible) ---- */
  $$("[role=tablist]").forEach((list) => {
    const tabs = $$("[role=tab]", list);
    const panels = tabs.map((t) => document.getElementById(t.getAttribute("aria-controls")));
    function select(idx, focus = true) {
      tabs.forEach((t, i) => {
        const on = i === idx;
        t.setAttribute("aria-selected", String(on));
        t.tabIndex = on ? 0 : -1;
        panels[i].hidden = !on;
      });
      if (focus) tabs[idx].focus();
    }
    tabs.forEach((t, i) => {
      t.addEventListener("click", () => select(i, false));
      t.addEventListener("keydown", (e) => {
        const n = tabs.length;
        if (e.key === "ArrowRight") select((i + 1) % n);
        else if (e.key === "ArrowLeft") select((i - 1 + n) % n);
        else if (e.key === "Home") select(0);
        else if (e.key === "End") select(n - 1);
        else return;
        e.preventDefault();
      });
    });
  });

  /* ---- copy buttons ---- */
  $$(".copy-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const src = document.getElementById(btn.dataset.copy);
      try {
        await navigator.clipboard.writeText(src.textContent.trim());
        const old = btn.textContent;
        btn.textContent = "copied";
        setTimeout(() => (btn.textContent = old), 1400);
      } catch { /* clipboard unavailable; no-op */ }
    });
  });

  /* ---- architecture diagram: hover/click updates the side panel ---- */
  const ARCH = {
    facts: {
      t: "internal/facts",
      d: "Root-relative, read-only collectors for /proc/sys, /proc/cmdline, kconfig, modules, CPU vulnerability files, and securityfs. Reads are size-capped; failures are recorded as data, never fatal.",
      k: "Collect(root) → *Facts",
    },
    rules: {
      t: "internal/rules",
      d: "48 KSPP/CIS-informed rules embedded as JSON, each with attacker-centric rationale, a copy-pasteable fix, and references. User rulesets layer over builtins by ID — override, downgrade, or disable.",
      k: "LoadBuiltin() · Merge(builtin, custom)",
    },
    engine: {
      t: "internal/engine",
      d: "Joins facts to rules with any/all combinators and three-state results. Missing keys and unavailable sources yield unknown — never a fabricated failure. Unknowns are reported but never gate.",
      k: "Evaluate(facts, rules) → *Report",
    },
    baseline: {
      t: "internal/baseline",
      d: "Snapshots the full fact set to disk (mode 0600) and diffs it against the current host. Sources that are empty on either side are skipped, so permission asymmetry never masquerades as drift.",
      k: "Save · Load · Diff → exit 2 on drift",
    },
    report: {
      t: "internal/report",
      d: "Formats reports as a color terminal table, stable JSON, or SARIF 2.1.0 for GitHub code scanning. Observed values are escaped — hostile kernel interfaces can't inject terminal sequences.",
      k: "table · json · sarif",
    },
  };
  const panel = $("#arch-panel");
  function setPanel(key) {
    const a = ARCH[key];
    if (!a || !panel) return;
    $("h3", panel).textContent = a.t;
    $("p", panel).textContent = a.d;
    $(".k", panel).textContent = a.k;
    $$(".arch-svg .node").forEach((n) => n.classList.toggle("on", n.dataset.k === key));
  }
  $$(".arch-svg .node").forEach((n) => {
    const go = () => setPanel(n.dataset.k);
    n.addEventListener("mouseenter", go);
    n.addEventListener("focus", go);
    n.addEventListener("click", go);
    n.addEventListener("keydown", (e) => (e.key === "Enter" || e.key === " ") && (e.preventDefault(), go()));
  });
  setPanel("engine");

  /* ---- surface map bars animate on reveal ---- */
  const sm = $("#surface");
  if (sm) {
    const grow = new IntersectionObserver((es) => {
      es.forEach((e) => {
        if (!e.isIntersecting) return;
        $$(".fillbar", sm).forEach((r) => (r.style.width = r.dataset.w + "px"));
        grow.disconnect();
      });
    }, { threshold: 0.3 });
    if (reduced) $$(".fillbar", sm).forEach((r) => (r.style.width = r.dataset.w + "px"));
    else grow.observe(sm);
  }
})();
