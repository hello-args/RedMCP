/* MCPAudit HTML Security Dashboard */
(function () {
  "use strict";

  function readJsonScript(id) {
    const el = document.getElementById(id);
    if (!el) return null;
    try {
      return JSON.parse(el.textContent || "{}");
    } catch (err) {
      console.error("MCPAudit: failed to parse", id, err);
      return null;
    }
  }

  const DATA = readJsonScript("mcpaudit-report-data");
  const ICONS = readJsonScript("mcpaudit-icons-data") || {};

  if (!DATA) {
    console.error("MCPAudit: report data missing");
    return;
  }

  const MIN_GAUGE_ARC = 8;

  const COLORS = {
    critical: "#ef4444",
    high: "#f97316",
    medium: "#facc15",
    low: "#22c55e",
    primary: "#2563eb",
    muted: "#64748b",
    grid: "rgba(255,255,255,0.06)",
    text: "#94a3b8",
  };

  function icon(name, className) {
    const svg = ICONS[name] || "";
    return `<span class="severity-icon ${className || ""}" aria-hidden="true">${svg}</span>`;
  }

  function scoreGaugeColor(score) {
    if (score <= 25) return COLORS.critical;
    if (score <= 50) return COLORS.high;
    if (score <= 75) return COLORS.yellow;
    return COLORS.low;
  }

  function fillScanMeta() {
    const m = DATA.meta;
    const map = {
      "meta-target": m.target,
      "meta-date": m.scan_date,
      "meta-time": m.scan_time,
      "meta-tools": String(m.tools_discovered),
      "meta-analyzers": String(m.analyzers_run),
    };
    Object.entries(map).forEach(([id, val]) => {
      const el = document.getElementById(id);
      if (el) el.textContent = val;
    });
    const pill = document.getElementById("risk-pill");
    const gaugeScore = document.getElementById("gauge-score-value");
    const gradeEl = document.getElementById("security-grade");
    const scoreText = String(DATA.score.overall);

    if (pill) {
      pill.textContent = DATA.risk.badge;
      pill.className = `risk-pill ${DATA.risk.level}`;
    }
    if (gaugeScore) gaugeScore.textContent = scoreText;

    const grade = DATA.score.grade || {};
    if (gradeEl) {
      gradeEl.textContent = grade.letter || "—";
      gradeEl.className = `grade-badge grade-${(grade.letter || "f").toLowerCase()}`;
    }
    const briefEl = document.getElementById("score-brief");
    if (briefEl) briefEl.textContent = DATA.risk.brief || DATA.risk.description || "—";
  }

  function categoryBarColor(pct) {
    if (pct >= 0.9) return COLORS.critical;
    if (pct >= 0.65) return COLORS.orange;
    if (pct >= 0.35) return COLORS.yellow;
    return COLORS.low;
  }

  function fillScoreTooltip() {
    const tooltip = document.getElementById("score-tooltip");
    const help = DATA.score_help;
    if (!tooltip || !help) return;
    const items = (help.items || [])
      .map((item) => `<li>${escapeHtml(item)}</li>`)
      .join("");
    tooltip.innerHTML = `<strong>${escapeHtml(help.title || "Score derived from:")}</strong><ul>${items}</ul>`;
  }

  function fillExecutiveSummary() {
    const summary = DATA.executive_summary || {};
    const paras = document.getElementById("exec-paragraphs");
    const actions = document.getElementById("exec-actions");
    if (paras) {
      paras.innerHTML = (summary.paragraphs || [])
        .map((p) => `<p>${escapeHtml(p)}</p>`)
        .join("");
    }
    if (actions) {
      const recs = (DATA.recommendations || []).slice(0, 3);
      if (!recs.length && summary.recommended) {
        actions.innerHTML = summary.recommended
          .map(
            (item, idx) => `
          <div class="exec-action-item">
            <span class="priority-badge p2">P2 Recommended</span>
            <p>${escapeHtml(item)}</p>
          </div>`
          )
          .join("");
      } else {
        actions.innerHTML = recs
          .map(
            (r) => `
          <div class="exec-action-item">
            <span class="priority-badge ${r.priority.toLowerCase()}">${r.priority} ${escapeHtml(r.impact)}</span>
            <p>${escapeHtml(r.recommendation)}</p>
          </div>`
          )
          .join("");
      }
    }
  }

  function fillSeverityCards() {
    const s = DATA.summary;
    const map = [
      ["critical", s.critical, "critical"],
      ["high", s.high, "high"],
      ["medium", s.medium, "medium"],
      ["low", s.low, "low"],
      ["tools", DATA.meta.tools_discovered, "tools"],
    ];
    map.forEach(([key, count, iconName]) => {
      const card = document.querySelector(`[data-severity="${key}"]`);
      if (!card) return;
      const iconEl = card.querySelector(".severity-icon-wrap");
      const countEl = card.querySelector(".count");
      if (iconEl) iconEl.innerHTML = icon(iconName === "tools" ? "tools" : iconName, iconName);
      if (countEl) countEl.textContent = String(count);
    });
  }

  function fillCategories() {
    const list = document.getElementById("category-list");
    if (!list) return;
    list.innerHTML = DATA.categories
      .map((c) => {
        const pct = c.maximum > 0 ? c.score / c.maximum : 0;
        const barColor = categoryBarColor(pct);
        const width = Math.round(pct * 100);
        return `
        <li class="category-item">
          <div class="category-item-header">
            <span class="name">${escapeHtml(c.label)}</span>
            <span class="score-val">${escapeHtml(c.display)}</span>
          </div>
          <div class="category-bar"><span style="width:${width}%;background:${barColor}"></span></div>
        </li>`;
      })
      .join("");
  }

  function initGaugeChart() {
    const canvas = document.getElementById("gauge-chart");
    if (!canvas || typeof Chart === "undefined") return;

    const score = DATA.score.overall;
    const color = scoreGaugeColor(score);
    const visualScore = Math.max(score, MIN_GAUGE_ARC);
    const remainder = Math.max(0, 100 - visualScore);

    const gradient = canvas.getContext("2d");
    let fillColor = color;
    if (gradient) {
      const g = gradient.createLinearGradient(0, 0, 0, canvas.height);
      g.addColorStop(0, color);
      g.addColorStop(1, "rgba(239,68,68,0.25)");
      fillColor = g;
    }

    new Chart(canvas, {
      type: "doughnut",
      data: {
        datasets: [
          {
            data: [visualScore, remainder],
            backgroundColor: [fillColor, "rgba(255,255,255,0.05)"],
            borderWidth: 0,
            borderRadius: 6,
            circumference: 180,
            rotation: 270,
            spacing: 2,
          },
        ],
      },
      options: {
        responsive: false,
        maintainAspectRatio: false,
        cutout: "58%",
        plugins: { legend: { display: false }, tooltip: { enabled: false } },
        animation: { duration: 600 },
      },
    });
  }

  function initRadarChart() {
    const canvas = document.getElementById("radar-chart");
    if (!canvas || typeof Chart === "undefined") return;

    const labels = DATA.categories.map((c) => c.label.replace(" Risk", "").replace(" Resistance", ""));
    const yourScores = DATA.categories.map((c) => (c.score / c.maximum) * 100);
    const industry = DATA.categories.map((c) => (c.benchmark / c.maximum) * 100);

    new Chart(canvas, {
      type: "radar",
      data: {
        labels,
        datasets: [
          {
            label: "Your Score",
            data: yourScores,
            borderColor: COLORS.critical,
            backgroundColor: "rgba(239,68,68,0.15)",
            borderWidth: 2,
            pointRadius: 3,
          },
          {
            label: "Industry Average",
            data: industry,
            borderColor: COLORS.muted,
            backgroundColor: "rgba(100,116,139,0.1)",
            borderWidth: 2,
            pointRadius: 3,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          r: {
            beginAtZero: true,
            max: 100,
            ticks: { display: false, stepSize: 25 },
            grid: { color: COLORS.grid },
            angleLines: { color: COLORS.grid },
            pointLabels: { color: COLORS.text, font: { size: 11 } },
          },
        },
        plugins: {
          legend: {
            position: "bottom",
            labels: { color: COLORS.text, boxWidth: 12, padding: 16 },
          },
        },
      },
    });
  }

  function initTrendChart() {
    const canvas = document.getElementById("trend-chart");
    const empty = document.getElementById("trend-empty");
    if (!canvas || typeof Chart === "undefined") return;

    if (!DATA.trend || DATA.trend.length < 2) {
      canvas.hidden = true;
      if (empty) {
        empty.hidden = false;
        empty.classList.add("visible");
      }
      return;
    }

    canvas.hidden = false;
    if (empty) {
      empty.hidden = true;
      empty.classList.remove("visible");
    }

    const labels = DATA.trend.map((t) => t.date);
    const values = DATA.trend.map((t) => t.score);

    new Chart(canvas, {
      type: "line",
      data: {
        labels,
        datasets: [
          {
            label: "Security Score",
            data: values,
            borderColor: COLORS.critical,
            backgroundColor: "rgba(239,68,68,0.08)",
            fill: true,
            tension: 0.4,
            pointRadius: 4,
            pointHoverRadius: 6,
            borderWidth: 2,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: { mode: "index", intersect: false },
        scales: {
          x: {
            grid: { color: COLORS.grid },
            ticks: { color: COLORS.text },
          },
          y: {
            min: 0,
            max: 100,
            grid: { color: COLORS.grid },
            ticks: { color: COLORS.text },
          },
        },
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: "#0f172a",
            borderColor: "rgba(255,255,255,0.1)",
            borderWidth: 1,
          },
        },
      },
    });
  }

  function fillRiskGuide() {
    const container = document.getElementById("risk-guide");
    if (!container) return;
    const score = DATA.score.overall;
    const iconMap = {
      critical: "critical",
      high: "high",
      medium: "medium",
      low: "low",
    };
    container.innerHTML = DATA.risk_guide
      .map((g) => {
        const parts = g.range.replace("–", "-").split("-").map(Number);
        const min = parts[0] ?? 0;
        const max = parts[1] ?? 100;
        const active = score >= min && score <= max;
        const fill = active ? 100 : Math.max(12, 40 - Math.abs(score - (min + max) / 2) * 0.5);
        const iconName = iconMap[g.key] || "shield";
        return `
        <div class="guide-card${active ? " active" : ""}">
          <div class="guide-card-top" style="background:${g.color}"></div>
          <div class="guide-card-icon">${icon(iconName, iconName)}</div>
          <h4>${escapeHtml(g.label)}</h4>
          <div class="range">${escapeHtml(g.range)}</div>
          <div class="guide-badge" style="color:${g.color}">${escapeHtml(g.badge)}</div>
          <p>${escapeHtml(g.description)}</p>
          <div class="guide-progress"><span style="width:${fill}%;background:${g.color}"></span></div>
        </div>`;
      })
      .join("");
  }

  function renderFindingsTable() {
    const tbody = document.getElementById("findings-body");
    if (!tbody) return;

    let rows = [...DATA.findings];
    const search = (document.getElementById("findings-search")?.value || "").toLowerCase();
    const filter = document.getElementById("findings-filter")?.value || "all";

    if (search) {
      rows = rows.filter(
        (f) =>
          f.title.toLowerCase().includes(search) ||
          f.category.toLowerCase().includes(search) ||
          f.tool.toLowerCase().includes(search)
      );
    }
    if (filter !== "all") {
      rows = rows.filter((f) => f.severity === filter);
    }

    tbody.innerHTML = rows
      .map(
        (f) => `
      <tr>
        <td><span class="sev-badge ${f.severity}">${f.severity}</span></td>
        <td><strong>${escapeHtml(f.title)}</strong><br><span style="color:var(--muted);font-size:12px">${escapeHtml(f.description)}</span></td>
        <td>${escapeHtml(f.category)}</td>
        <td>${escapeHtml(f.owasp)}</td>
        <td>${escapeHtml(f.tool)}</td>
        <td>${escapeHtml(f.recommendation)}</td>
      </tr>`
      )
      .join("");
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  let sortKey = "severity";
  let sortAsc = true;

  function sortFindings(key) {
    const order = { critical: 0, high: 1, medium: 2, low: 3 };
    if (sortKey === key) sortAsc = !sortAsc;
    else {
      sortKey = key;
      sortAsc = true;
    }
    DATA.findings.sort((a, b) => {
      let cmp = 0;
      if (key === "severity") cmp = (order[a.severity] ?? 9) - (order[b.severity] ?? 9);
      else cmp = String(a[key] || "").localeCompare(String(b[key] || ""));
      return sortAsc ? cmp : -cmp;
    });
    renderFindingsTable();
  }

  function renderOwasp() {
    const grid = document.getElementById("owasp-grid");
    if (!grid) return;
    if (!DATA.owasp.length) {
      grid.innerHTML = '<p style="color:var(--muted)">No OWASP mappings for this scan.</p>';
      return;
    }
    grid.innerHTML = DATA.owasp
      .map(
        (o) => `
      <div class="card owasp-card">
        <h4>${escapeHtml(o.id)} — ${escapeHtml(o.label)}</h4>
        <div class="meta-row">
          <span>Findings: <strong>${o.finding_count}</strong></span>
          <span>Risk: <span class="sev-badge ${o.risk_level}">${o.risk_level}</span></span>
        </div>
        <div class="owasp-tools">Affected tools: ${o.affected_tools.length ? escapeHtml(o.affected_tools.join(", ")) : "—"}</div>
      </div>`
      )
      .join("");
  }

  function renderRecommendations() {
    const list = document.getElementById("rec-list");
    if (!list) return;
    if (!DATA.recommendations.length) {
      list.innerHTML = '<p style="color:var(--muted)">No recommendations — scan passed cleanly.</p>';
      return;
    }
    list.innerHTML = DATA.recommendations
      .map(
        (r) => `
      <div class="card rec-card">
        <div class="rec-priority">Priority ${r.priority}</div>
        <h4>${escapeHtml(r.title)}</h4>
        <p style="color:var(--muted);margin:0 0 10px">${escapeHtml(r.recommendation)}</p>
        <div class="rec-meta">
          <span>Impact: <strong>${escapeHtml(r.impact)}</strong></span>
          <span>Effort: <strong>${escapeHtml(r.effort)}</strong></span>
        </div>
      </div>`
      )
      .join("");
  }

  function renderAnalyzers() {
    const grid = document.getElementById("analyzer-grid");
    if (!grid) return;
    grid.innerHTML = DATA.analyzers
      .map(
        (a) => `
      <div class="card analyzer-card">
        <h4>${escapeHtml(a.label)}</h4>
        <p style="color:var(--muted);margin:0 0 10px">${a.finding_count} finding(s)</p>
        <div class="analyzer-stats">
          ${Object.entries(a.severity_counts)
            .filter(([, n]) => n > 0)
            .map(([s, n]) => `<span class="sev-badge ${s}">${s}: ${n}</span>`)
            .join("")}
        </div>
      </div>`
      )
      .join("");
  }

  function renderAttackGraph() {
    const svg = document.getElementById("attack-graph");
    if (!svg) return;
    const { nodes, edges } = DATA.attack_graph;
    if (!nodes.length) {
      svg.innerHTML = '<text x="50%" y="50%" text-anchor="middle" fill="#94a3b8">No attack chain data</text>';
      return;
    }

    const width = svg.clientWidth || 800;
    const height = 400;
    const cx = width / 2;
    const cy = height / 2;
    const radius = Math.min(width, height) * 0.32;
    const positions = {};

    nodes.forEach((n, i) => {
      const angle = (i / nodes.length) * Math.PI * 2 - Math.PI / 2;
      positions[n.id] = {
        x: cx + radius * Math.cos(angle),
        y: cy + radius * Math.sin(angle),
      };
    });

    let markup = `<defs><marker id="arrowhead" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto"><polygon points="0 0, 8 3, 0 6" fill="rgba(59,130,246,0.7)"/></marker></defs>`;

    edges.forEach((e) => {
      const from = positions[e.from];
      const to = positions[e.to];
      if (!from || !to) return;
      markup += `<line class="graph-edge" x1="${from.x}" y1="${from.y}" x2="${to.x}" y2="${to.y}" marker-end="url(#arrowhead)"/>`;
    });

    nodes.forEach((n) => {
      const p = positions[n.id];
      if (!p) return;
      const label = n.label.length > 14 ? n.label.slice(0, 12) + "…" : n.label;
      markup += `
        <g class="graph-node" transform="translate(${p.x},${p.y})">
          <circle r="28"/>
          <text text-anchor="middle" dy="4">${escapeHtml(label)}</text>
        </g>`;
    });

    svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
    svg.innerHTML = markup;
  }

  function renderAppendix() {
    const pre = document.getElementById("appendix-json");
    if (pre) pre.textContent = JSON.stringify(DATA.raw_report, null, 2);
  }

  function setupNav() {
    const sections = document.querySelectorAll(".page-section");
    const navItems = document.querySelectorAll(".nav-item");

    function show(id) {
      sections.forEach((s) => s.classList.toggle("active", s.id === id));
      navItems.forEach((n) => n.classList.toggle("active", n.dataset.section === id));
    }

    navItems.forEach((btn) => {
      btn.addEventListener("click", () => show(btn.dataset.section));
    });
    show("overview");
  }

  function setupExport() {
    const menu = document.getElementById("export-menu");
    const toggle = document.getElementById("export-toggle");
    const downloadJson = document.getElementById("download-json");
    const downloadJsonSide = document.getElementById("download-json-side");

    function blobDownload(filename, content, type) {
      const blob = new Blob([content], { type });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
    }

    function exportJson() {
      blobDownload("mcpaudit-report.json", JSON.stringify(DATA.raw_report, null, 2), "application/json");
    }

    function exportHtml() {
      blobDownload("mcpaudit-report.html", document.documentElement.outerHTML, "text/html");
    }

    function exportPdf() {
      window.print();
    }

    if (toggle && menu) {
      toggle.addEventListener("click", (e) => {
        e.stopPropagation();
        menu.classList.toggle("open");
      });
      document.addEventListener("click", () => menu.classList.remove("open"));
    }

    document.getElementById("export-json")?.addEventListener("click", exportJson);
    document.getElementById("export-html")?.addEventListener("click", exportHtml);
    document.getElementById("export-pdf")?.addEventListener("click", exportPdf);
    downloadJson?.addEventListener("click", exportJson);
    downloadJsonSide?.addEventListener("click", exportJson);
  }

  function setupFindings() {
    document.getElementById("findings-search")?.addEventListener("input", renderFindingsTable);
    document.getElementById("findings-filter")?.addEventListener("change", renderFindingsTable);
    document.querySelectorAll("#findings-table th[data-sort]").forEach((th) => {
      th.addEventListener("click", () => sortFindings(th.dataset.sort));
    });
  }

  function init() {
    fillScanMeta();
    fillScoreTooltip();
    fillExecutiveSummary();
    fillSeverityCards();
    fillCategories();
    fillRiskGuide();
    renderFindingsTable();
    renderOwasp();
    renderRecommendations();
    renderAnalyzers();
    renderAttackGraph();
    renderAppendix();
    setupNav();
    setupExport();
    setupFindings();
    initGaugeChart();
    initRadarChart();
    initTrendChart();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
