/* ============================================================
   app.js
   ------------------------------------------------------------
   Phase 5.6 frontend logic. Talks only to mock-data.js's fake
   backend functions -- swapping these for real fetch() calls to a
   FastAPI backend (Phase 8) should only touch the functions marked
   "MOCK CALL" below, not the screen/state logic around them.
   ============================================================ */

const CONFIDENCE_THRESHOLD = 85;

// ---- App state ----
const state = {
  queue: [],          // [{ id, filename, sample, forcedVendor }]
  currentIndex: -1,   // which queue item is being processed
  currentStep: 1,
  parsed: null,       // ComplianceResult-shaped object for current item
  chosenVendor: null,
  unknownDecisions: {}, // raw_line -> confirmed category
  report: null,        // { device, framework, findings }
  currentFramework: "CIS",
  whatifOverrides: {},
};

let queueIdCounter = 0;

// ============================================================
// SCREEN NAVIGATION
// ============================================================
function goToStep(step) {
  state.currentStep = step;
  document.querySelectorAll(".screen").forEach(s => {
    s.hidden = Number(s.dataset.screen) !== step;
  });
  document.querySelectorAll(".step").forEach(s => {
    const n = Number(s.dataset.step);
    s.classList.toggle("active", n === step);
    s.classList.toggle("done", n < step);
  });
  window.scrollTo({ top: 0, behavior: "smooth" });
}

// ============================================================
// SCREEN 1 — UPLOAD
// ============================================================
function initUploadScreen() {
  const vendorSelect = document.getElementById("vendorOverride");
  VENDORS.forEach(v => {
    const opt = document.createElement("option");
    opt.value = v.id;
    opt.textContent = v.label;
    vendorSelect.appendChild(opt);
  });

  const sampleChips = document.getElementById("sampleChips");
  SAMPLE_CONFIGS.forEach(sample => {
    const chip = document.createElement("button");
    chip.type = "button";
    chip.className = "sample-chip";
    chip.textContent = `${sample.filename} (${VENDOR_LABEL[sample.vendor] || sample.vendor})`;
    chip.addEventListener("click", () => addToQueue(sample));
    sampleChips.appendChild(chip);
  });

  const dropzone = document.getElementById("dropzone");
  const fileInput = document.getElementById("fileInput");
  dropzone.addEventListener("click", () => fileInput.click());
  dropzone.addEventListener("keydown", e => {
    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); fileInput.click(); }
  });
  ["dragenter", "dragover"].forEach(evt =>
    dropzone.addEventListener(evt, e => { e.preventDefault(); dropzone.classList.add("dragover"); })
  );
  ["dragleave", "drop"].forEach(evt =>
    dropzone.addEventListener(evt, e => { e.preventDefault(); dropzone.classList.remove("dragover"); })
  );
  dropzone.addEventListener("drop", e => handleFiles(e.dataTransfer.files));
  fileInput.addEventListener("change", e => handleFiles(e.target.files));

  document.getElementById("btnProcessQueue").addEventListener("click", () => {
    state.currentIndex = 0;
    processQueueItem(0);
  });
}

function handleFiles(fileList) {
  // Real uploads: since there's no real parser wired in yet, read the
  // text and fall back to a low-confidence "couldn't confidently
  // detect" candidate set so the vendor-confirmation screen has
  // something honest to show, rather than pretending to detect vendor
  // syntax we don't actually have codecs for in this mock.
  Array.from(fileList).forEach(file => {
    const reader = new FileReader();
    reader.onload = () => {
      const text = String(reader.result || "");
      const guineaPig = {
        filename: file.name,
        vendor: "cisco_iosxe_cli",
        confidence: 38,
        reason: "Uploaded file text couldn't be matched with confidence in this mock demo -- real vendor probing happens in converter/schema_adapter.py once wired in.",
        text,
        parsed: {
          ssh_enabled: null, telnet_enabled: null, session_timeout_seconds: null,
          logging_enabled: null, password_encryption: null, banner_configured: null,
        },
        unrecognizedLines: text.split("\n").filter(l => l.trim()).slice(0, 5)
          .map(l => ({ line: l.trim(), aiGuess: "other / not a compliance field", confidence: 40 })),
        device: { hostname: file.name.replace(/\.[^.]+$/, ""), serial_number: null, os_version: null },
      };
      addToQueue(guineaPig);
    };
    reader.readAsText(file);
  });
}

function addToQueue(sample) {
  state.queue.push({ id: ++queueIdCounter, filename: sample.filename, sample, forcedVendor: null });
  renderQueue();
}

function renderQueue() {
  const queueEl = document.getElementById("queue");
  queueEl.innerHTML = "";
  state.queue.forEach(item => {
    const row = document.createElement("div");
    row.className = "queue-item";
    row.innerHTML = `
      <span class="queue-item-name">${escapeHtml(item.filename)}</span>
      <span class="queue-item-meta">${escapeHtml(VENDOR_LABEL[item.sample.vendor] || item.sample.vendor)} · ${item.sample.confidence}% confidence</span>
      <button class="queue-item-remove" aria-label="Remove ${escapeHtml(item.filename)}">&times;</button>
    `;
    row.querySelector(".queue-item-remove").addEventListener("click", () => {
      state.queue = state.queue.filter(q => q.id !== item.id);
      renderQueue();
    });
    queueEl.appendChild(row);
  });
  document.getElementById("btnProcessQueue").disabled = state.queue.length === 0;
}

// ============================================================
// PIPELINE — one queue item at a time
// ============================================================
function processQueueItem(index) {
  if (index >= state.queue.length) {
    // All done -- nothing left to process, stay on results of the last one.
    return;
  }
  state.currentIndex = index;
  const item = state.queue[index];
  const vendorOverride = document.getElementById("vendorOverride").value || item.forcedVendor;

  // MOCK CALL: converter.schema_adapter.detect_vendor()
  const candidates = mockDetectVendor(item.sample);
  const top = candidates[0];

  if (vendorOverride) {
    state.chosenVendor = vendorOverride;
    proceedToParse(item);
  } else if (top.confidence < CONFIDENCE_THRESHOLD) {
    renderVendorConfirmScreen(item, candidates);
    goToStep(2);
  } else {
    state.chosenVendor = top.vendor;
    proceedToParse(item);
  }
}

// ---------------------------------------------------------------
// SCREEN 2 — VENDOR CONFIRMATION
// ---------------------------------------------------------------
function renderVendorConfirmScreen(item, candidates) {
  const panel = document.getElementById("vendorConfirmPanel");
  panel.innerHTML = `<div class="field-label">File: <span class="mono">${escapeHtml(item.filename)}</span></div>`;

  const list = document.createElement("div");
  candidates.forEach((c, i) => {
    const row = document.createElement("label");
    row.className = "vendor-candidate" + (i === 0 ? " selected" : "");
    const confClass = c.confidence >= 85 ? "confidence-high" : c.confidence >= 50 ? "confidence-mid" : "confidence-low";
    row.innerHTML = `
      <input type="radio" name="vendorCandidate" value="${c.vendor}" ${i === 0 ? "checked" : ""}>
      <div class="vendor-candidate-info">
        <div class="vendor-candidate-name">${escapeHtml(VENDOR_LABEL[c.vendor] || c.vendor)}</div>
        <div class="vendor-candidate-reason">${escapeHtml(c.reason)}</div>
      </div>
      <span class="vendor-candidate-confidence ${confClass}">${c.confidence}%</span>
    `;
    row.addEventListener("click", () => {
      list.querySelectorAll(".vendor-candidate").forEach(el => el.classList.remove("selected"));
      row.classList.add("selected");
    });
    list.appendChild(row);
  });

  // Manual override, always available.
  const manualRow = document.createElement("label");
  manualRow.className = "vendor-candidate";
  manualRow.innerHTML = `
    <input type="radio" name="vendorCandidate" value="__manual__">
    <div class="vendor-candidate-info">
      <div class="vendor-candidate-name">Pick manually</div>
      <select class="select" id="manualVendorSelect" style="margin-top:8px;"></select>
    </div>
  `;
  list.appendChild(manualRow);
  panel.appendChild(list);

  const manualSelect = document.getElementById("manualVendorSelect");
  VENDORS.forEach(v => {
    const opt = document.createElement("option");
    opt.value = v.id;
    opt.textContent = v.label;
    manualSelect.appendChild(opt);
  });
  manualSelect.addEventListener("click", e => e.stopPropagation());
  manualSelect.addEventListener("change", () => {
    list.querySelectorAll(".vendor-candidate").forEach(el => el.classList.remove("selected"));
    manualRow.classList.add("selected");
    manualRow.querySelector("input").checked = true;
  });
}

document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("btnVendorBack").addEventListener("click", () => goToStep(1));
  document.getElementById("btnVendorConfirm").addEventListener("click", () => {
    const checked = document.querySelector('input[name="vendorCandidate"]:checked');
    if (!checked) return;
    let vendor = checked.value;
    if (vendor === "__manual__") {
      vendor = document.getElementById("manualVendorSelect").value;
    }
    state.chosenVendor = vendor;
    const item = state.queue[state.currentIndex];
    item.forcedVendor = vendor;
    proceedToParse(item);
  });
});

// ---------------------------------------------------------------
// PARSE + REVIEW UNKNOWN LINES (Screen 3)
// ---------------------------------------------------------------
function proceedToParse(item) {
  // MOCK CALL: converter.schema_adapter.parse_and_map()
  state.parsed = mockParseAndMap(item.sample, state.chosenVendor);
  state.unknownDecisions = {};

  const lines = item.sample.unrecognizedLines;
  if (lines.length === 0) {
    document.getElementById("unknownsEmptyPanel").hidden = false;
    document.getElementById("unknownsTablePanel").hidden = true;
  } else {
    document.getElementById("unknownsEmptyPanel").hidden = true;
    document.getElementById("unknownsTablePanel").hidden = false;
    renderUnknownsTable(item.sample);
  }
  goToStep(3);
}

function renderUnknownsTable(sample) {
  // MOCK CALL: ai_fallback.classify.classify_unrecognized_lines() -> LineClassification.to_review_dict()
  const classifications = mockClassifyLines(sample);
  const tbody = document.getElementById("unknownsTbody");
  tbody.innerHTML = "";

  classifications.forEach(c => {
    const tr = document.createElement("tr");
    const confClass = c.confidence >= 85 ? "confidence-high" : c.confidence >= 50 ? "confidence-mid" : "confidence-low";

    const selectId = `cat-${Math.random().toString(36).slice(2, 9)}`;
    tr.innerHTML = `
      <td class="mono">${escapeHtml(c.raw_line)}</td>
      <td>${escapeHtml(c.ai_guess)}</td>
      <td><span class="vendor-candidate-confidence ${confClass}">${c.confidence}%</span></td>
      <td><select class="unknown-select" id="${selectId}"></select></td>
    `;
    tbody.appendChild(tr);

    const select = tr.querySelector(`#${selectId}`);
    CATEGORY_OPTIONS.forEach(opt => {
      const o = document.createElement("option");
      o.value = opt;
      o.textContent = opt;
      if (opt === c.ai_guess) o.selected = true;
      select.appendChild(o);
    });
    select.addEventListener("change", () => {
      state.unknownDecisions[c.raw_line] = select.value;
    });
    state.unknownDecisions[c.raw_line] = c.ai_guess;
  });
}

document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("btnUnknownsBack").addEventListener("click", () => goToStep(2));
  document.getElementById("btnUnknownsSubmit").addEventListener("click", () => {
    // MOCK CALL: ai_fallback.classify.confirm_classification() per row
    // (internally calls MemoryStore.save_confirmed()). This mock just
    // logs the batch -- the real call is the only thing allowed to
    // persist a guess, per the handoff doc.
    console.log("[mock] confirm_classification batch:", state.unknownDecisions);
    runEvaluationAndShowResults();
  });
});

// ---------------------------------------------------------------
// SCREEN 4 — RESULTS + WHAT-IF
// ---------------------------------------------------------------
function runEvaluationAndShowResults() {
  const item = state.queue[state.currentIndex];
  const device = {
    vendor: state.chosenVendor,
    hostname: item.sample.device.hostname,
    serial_number: item.sample.device.serial_number,
    os_version: item.sample.device.os_version,
  };

  state.report = { device, config: state.parsed, framework: state.currentFramework };
  renderResults();
  goToStep(4);
}

function renderResults() {
  const item = state.queue[state.currentIndex];
  const device = state.report.device;
  document.getElementById("resultsDeviceTitle").textContent = device.hostname || "Results";
  document.getElementById("resultsDeviceSub").textContent =
    `${VENDOR_LABEL[device.vendor] || device.vendor}` +
    (device.os_version ? ` · OS ${device.os_version}` : "") +
    (device.serial_number ? ` · Serial ${device.serial_number}` : "");

  // MOCK CALL: compliance_engine.evaluate.evaluate_config()
  const findings = evaluateConfig(state.parsed, state.chosenVendor, state.currentFramework);
  state.report.findings = findings;

  renderSummaryChips(findings);
  renderFindingsTable(findings);
  renderWhatifControls();
  updateWhatif();
}

function renderSummaryChips(findings) {
  // MOCK CALL: compliance_engine.evaluate.summarize()
  const summary = summarizeFindings(findings);
  const chips = document.getElementById("summaryChips");
  chips.innerHTML = `
    <div class="summary-chip pass"><div class="summary-chip-value">${summary.PASS}</div><div class="summary-chip-label">Pass</div></div>
    <div class="summary-chip fail"><div class="summary-chip-value">${summary.FAIL}</div><div class="summary-chip-label">Fail</div></div>
    <div class="summary-chip unknown"><div class="summary-chip-value">${summary.UNKNOWN}</div><div class="summary-chip-label">Could not determine</div></div>
  `;
}

function renderFindingsTable(findings) {
  const tbody = document.getElementById("findingsTbody");
  tbody.innerHTML = "";
  findings.forEach(f => {
    const tr = document.createElement("tr");
    const label = f.status === "UNKNOWN" ? "COULD NOT DETERMINE" : f.status;
    tr.innerHTML = `
      <td class="mono">${escapeHtml(f.rule_id)}</td>
      <td><span class="status-pill status-${f.status}">${label}</span></td>
      <td>${escapeHtml(f.severity)}</td>
      <td class="mono">${escapeHtml(f.field_checked)}</td>
    `;
    tbody.appendChild(tr);
  });
}

document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".framework-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".framework-btn").forEach(b => {
        b.classList.remove("active");
        b.setAttribute("aria-selected", "false");
      });
      btn.classList.add("active");
      btn.setAttribute("aria-selected", "true");
      state.currentFramework = btn.dataset.framework;
      state.report.framework = state.currentFramework;
      const findings = evaluateConfig(state.parsed, state.chosenVendor, state.currentFramework);
      state.report.findings = findings;
      renderSummaryChips(findings);
      renderFindingsTable(findings);
      updateWhatif();
    });
  });

  document.getElementById("btnToggleWhatif").addEventListener("click", () => {
    const panel = document.getElementById("whatifPanel");
    panel.hidden = !panel.hidden;
    document.getElementById("btnToggleWhatif").textContent =
      panel.hidden ? "Open what-if panel" : "Close what-if panel";
  });

  document.getElementById("btnDownloadPdf").addEventListener("click", downloadPdfReport);
  document.getElementById("btnStartOver").addEventListener("click", () => location.reload());
});

// ---------------------------------------------------------------
// WHAT-IF PANEL
// ---------------------------------------------------------------
const WHATIF_FIELDS = [
  { key: "ssh_enabled", type: "bool", label: "ssh_enabled" },
  { key: "telnet_enabled", type: "bool", label: "telnet_enabled" },
  { key: "logging_enabled", type: "bool", label: "logging_enabled" },
  { key: "banner_configured", type: "bool", label: "banner_configured" },
  { key: "session_timeout_seconds", type: "number", label: "session_timeout_seconds" },
  { key: "password_encryption", type: "select", label: "password_encryption",
    options: ["none", "plaintext", "type7", "weak", "rc4", "type8", "type9", "sha512", "scrypt", "bcrypt"] },
];

function renderWhatifControls() {
  const container = document.getElementById("whatifControls");
  container.innerHTML = "";
  state.whatifOverrides = {};

  WHATIF_FIELDS.forEach(field => {
    const current = state.parsed[field.key];
    const row = document.createElement("div");
    row.className = "whatif-field";

    if (field.type === "bool") {
      const checked = current === true;
      row.innerHTML = `
        <div>
          <div class="whatif-field-name">${field.label}</div>
          <div class="whatif-field-current">current: ${current === null ? "unknown" : String(current)}</div>
        </div>
        <label class="switch">
          <input type="checkbox" ${checked ? "checked" : ""} ${current === null ? "" : ""}>
          <span class="switch-track"></span>
        </label>
      `;
      const input = row.querySelector("input");
      input.addEventListener("change", () => {
        state.whatifOverrides[field.key] = input.checked;
        updateWhatif();
      });
    } else if (field.type === "number") {
      row.innerHTML = `
        <div>
          <div class="whatif-field-name">${field.label}</div>
          <div class="whatif-field-current">current: ${current === null ? "unknown" : current}</div>
        </div>
        <input type="number" class="whatif-number" min="0" value="${current === null ? "" : current}" placeholder="seconds">
      `;
      const input = row.querySelector("input");
      input.addEventListener("input", () => {
        if (input.value === "") { delete state.whatifOverrides[field.key]; }
        else { state.whatifOverrides[field.key] = Number(input.value); }
        updateWhatif();
      });
    } else if (field.type === "select") {
      row.innerHTML = `
        <div>
          <div class="whatif-field-name">${field.label}</div>
          <div class="whatif-field-current">current: ${current === null ? "unknown" : current}</div>
        </div>
        <select class="whatif-select"></select>
      `;
      const select = row.querySelector("select");
      const blank = document.createElement("option");
      blank.value = ""; blank.textContent = "(no override)";
      select.appendChild(blank);
      field.options.forEach(opt => {
        const o = document.createElement("option");
        o.value = opt; o.textContent = opt;
        select.appendChild(o);
      });
      select.addEventListener("change", () => {
        if (select.value === "") delete state.whatifOverrides[field.key];
        else state.whatifOverrides[field.key] = select.value;
        updateWhatif();
      });
    }

    container.appendChild(row);
  });
}

function updateWhatif() {
  if (!state.parsed) return;
  // MOCK CALL: whatif.simulator.simulate_change()
  const result = simulateChange(state.parsed, state.whatifOverrides, state.chosenVendor, state.currentFramework);

  document.getElementById("scoreBefore").textContent = result.before_score.toFixed(2);
  const afterEl = document.getElementById("scoreAfter");
  afterEl.textContent = result.after_score.toFixed(2);
  afterEl.classList.remove("improved", "worsened", "unchanged");
  if (result.after_score < result.before_score) afterEl.classList.add("improved");
  else if (result.after_score > result.before_score) afterEl.classList.add("worsened");
  else afterEl.classList.add("unchanged");

  const diffEmpty = document.getElementById("whatifDiffEmpty");
  const diffTable = document.getElementById("whatifDiffTable");
  const diffTbody = document.getElementById("whatifDiffTbody");
  diffTbody.innerHTML = "";

  if (result.findings_diff.length === 0) {
    diffEmpty.hidden = false;
    diffTable.hidden = true;
  } else {
    diffEmpty.hidden = true;
    diffTable.hidden = false;
    result.findings_diff.forEach(d => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td class="mono">${escapeHtml(d.rule_id)}</td>
        <td><span class="status-pill status-${d.before_status}">${d.before_status === "UNKNOWN" ? "COULD NOT DETERMINE" : d.before_status}</span></td>
        <td class="diff-arrow">→</td>
        <td><span class="status-pill status-${d.after_status}">${d.after_status === "UNKNOWN" ? "COULD NOT DETERMINE" : d.after_status}</span></td>
      `;
      diffTbody.appendChild(tr);
    });
  }
}

// ---------------------------------------------------------------
// PDF DOWNLOAD (mock: opens a print-ready preview styled like the
// real report_generator.generator.generate_pdf() output; wire this
// button to a real download link once the FastAPI endpoint exists)
// ---------------------------------------------------------------
function downloadPdfReport() {
  const { device, findings, framework } = state.report;
  const failFindings = findings.filter(f => f.status === "FAIL");

  const statusStyle = {
    PASS: ["PASS", "#1e7e34", "#e6f4ea"],
    FAIL: ["FAIL", "#c62828", "#fdecea"],
    UNKNOWN: ["COULD NOT DETERMINE", "#8a6d00", "#fff8e1"],
  };

  const rows = findings.map(f => {
    const [label, fg, bg] = statusStyle[f.status];
    return `<tr style="background:${bg}">
      <td>${escapeHtml(f.rule_id)}</td>
      <td style="color:${fg};font-weight:700;">${label}</td>
      <td>${escapeHtml(f.severity)}</td>
      <td>${escapeHtml(f.field_checked)}</td>
    </tr>`;
  }).join("");

  const remediation = failFindings.map(f => `
    <div style="margin:14px 0;">
      <div style="font-weight:700;">${escapeHtml(f.rule_id)} — ${escapeHtml(f.field_checked)} (severity: ${escapeHtml(f.severity)})</div>
      <div style="margin:6px 0 3px;">Remediation (verbatim, deterministic):</div>
      <pre style="background:#f5f5f5;padding:10px;border-radius:4px;white-space:pre-wrap;font-family:monospace;font-size:12px;">${escapeHtml(f.remediation_cli || "")}</pre>
      <div style="font-style:italic;color:#333;">Why this matters: ${escapeHtml(f.explanation)}</div>
    </div>
  `).join("") || "<p>No FAIL findings — no remediation required.</p>";

  const printRoot = document.getElementById("printRoot");
  printRoot.innerHTML = `
    <div style="font-family:Helvetica,Arial,sans-serif;padding:24px;color:#111;">
      <h1>Network Compliance Report</h1>
      <p>Framework: ${escapeHtml(framework)} | Generated: ${new Date().toISOString().slice(0, 16).replace("T", " ")} UTC</p>
      <h2>Device Identification</h2>
      <table style="border-collapse:collapse;">
        <tr><td style="font-weight:700;padding:4px 12px 4px 0;">Vendor</td><td>${escapeHtml(VENDOR_LABEL[device.vendor] || device.vendor)}</td></tr>
        <tr><td style="font-weight:700;padding:4px 12px 4px 0;">Hostname</td><td>${escapeHtml(device.hostname || "—")}</td></tr>
        <tr><td style="font-weight:700;padding:4px 12px 4px 0;">Serial</td><td>${escapeHtml(device.serial_number || "—")}</td></tr>
        <tr><td style="font-weight:700;padding:4px 12px 4px 0;">OS Version</td><td>${escapeHtml(device.os_version || "—")}</td></tr>
      </table>
      <h2>Compliance Findings</h2>
      <table style="border-collapse:collapse;width:100%;">
        <thead><tr style="background:#333;color:#fff;"><th style="padding:6px;text-align:left;">Rule ID</th><th style="padding:6px;text-align:left;">Status</th><th style="padding:6px;text-align:left;">Severity</th><th style="padding:6px;text-align:left;">Field Checked</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
      <h2>Remediation Paths</h2>
      ${remediation}
    </div>
  `;
  window.print();
}

// ---------------------------------------------------------------
// UTIL
// ---------------------------------------------------------------
function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

document.addEventListener("DOMContentLoaded", () => {
  initUploadScreen();
  goToStep(1);
});
