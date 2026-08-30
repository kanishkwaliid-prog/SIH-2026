/*
 * Frontend wiring for the compliance checker.
 *
 * One shared file, loaded by all five screens with a single <script> tag each.
 * It picks the right screen controller from the URL, so the HTML/CSS itself is
 * untouched apart from that one added line.
 *
 * Where the screens had hardcoded demo rows (the vendor card, the unknown-lines
 * table, the findings list), this file clears them and rebuilds the same markup
 * with the same Tailwind classes from live API data -- so the design is
 * preserved without the HTML needing to change.
 *
 * Scan state moves between screens as a ?scan=<id> query param, mirrored into
 * sessionStorage as a fallback.
 */
(function () {
  "use strict";

  // ---------------------------------------------------------------------
  // Config & helpers
  // ---------------------------------------------------------------------

  // Same-origin when served by app.py; falls back to the default dev port if
  // someone opens the HTML directly from disk.
  var API_BASE =
    window.location.protocol === "file:"
      ? "http://127.0.0.1:8000"
      : window.location.origin;

  var SCREENS = {
    upload: "upload_configuration/code 4 uc.html",
    vendor: "vendor_detection_result/code 5 vdr.html",
    analyzing: "analyzing_configuration/code1 ac.html",
    review: "review_unknown_lines/code 3 rul.html",
    report: "compliance_report_dashboard/code 2 cr.html",
  };

  var VENDOR_LABELS = {
    cisco_ios: "Cisco IOS",
    juniper_junos: "Juniper Junos",
    palo_alto: "Palo Alto PAN-OS",
    fortinet: "Fortinet FortiOS",
  };

  var FIELD_LABELS = {
    ssh_enabled: "SSH enabled",
    telnet_enabled: "Telnet enabled",
    session_timeout_seconds: "Session timeout (seconds)",
    logging_enabled: "Logging enabled",
    password_encryption: "Password encryption",
    banner_configured: "Banner configured",
    snmp_default_community: "SNMP default community",
    unclear: "Not a tracked setting",
  };

  var BOOL_FIELDS = [
    "ssh_enabled",
    "telnet_enabled",
    "logging_enabled",
    "banner_configured",
  ];

  function vendorLabel(v) {
    if (!v) return "Unknown";
    return VENDOR_LABELS[v] || v;
  }

  function fieldLabel(f) {
    return FIELD_LABELS[f] || f;
  }

  /* Backend reason strings quote raw vendor keys ("cisco_ios"). Swap them for
     the display labels so user-facing copy doesn't leak internal identifiers. */
  function prettyReason(text) {
    if (!text) return text;
    var out = String(text);
    Object.keys(VENDOR_LABELS).forEach(function (key) {
      out = out.replace(new RegExp("'" + key + "'", "g"), VENDOR_LABELS[key]);
      out = out.replace(new RegExp("\\b" + key + "\\b", "g"), VENDOR_LABELS[key]);
    });
    return out;
  }

  function screenUrl(key, scanId) {
    // Screens live one directory below /ui, so "../" gets back to the root.
    var url = "../" + SCREENS[key].split("/").map(encodeURIComponent).join("/");
    return scanId ? url + "?scan=" + encodeURIComponent(scanId) : url;
  }

  function getScanId() {
    var fromQuery = new URLSearchParams(window.location.search).get("scan");
    if (fromQuery) {
      try {
        sessionStorage.setItem("scan_id", fromQuery);
      } catch (e) {
        /* private mode -- query param still works */
      }
      return fromQuery;
    }
    try {
      return sessionStorage.getItem("scan_id");
    } catch (e) {
      return null;
    }
  }

  function goTo(key, scanId) {
    window.location.href = screenUrl(key, scanId);
  }

  async function api(path, options) {
    var opts = options || {};
    var res = await fetch(API_BASE + path, opts);
    if (!res.ok) {
      var detail = res.status + " " + res.statusText;
      try {
        var body = await res.json();
        if (body && body.detail) detail = body.detail;
      } catch (e) {
        /* non-JSON error body */
      }
      throw new Error(detail);
    }
    if (res.status === 204) return null;
    return res.json();
  }

  function apiJson(path, method, payload) {
    return api(path, {
      method: method,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload || {}),
    });
  }

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  /* Floating error banner. Screens have no error slot in their markup, so
     rather than editing five HTML files we inject one consistent banner. */
  function showError(message) {
    var existing = document.getElementById("cg-error-banner");
    if (existing) existing.remove();

    var bar = el("div", "");
    bar.id = "cg-error-banner";
    bar.setAttribute(
      "style",
      "position:fixed;top:0;left:0;right:0;z-index:9999;padding:12px 16px;" +
        "background:#7f1d1d;color:#fee2e2;font-family:Inter,system-ui,sans-serif;" +
        "font-size:14px;display:flex;justify-content:space-between;align-items:center;gap:16px;"
    );
    bar.appendChild(el("span", "", message));

    var close = el("button", "", "Dismiss");
    close.setAttribute(
      "style",
      "background:transparent;border:1px solid #fecaca;color:#fee2e2;" +
        "padding:4px 10px;border-radius:6px;cursor:pointer;flex-shrink:0;"
    );
    close.onclick = function () {
      bar.remove();
    };
    bar.appendChild(close);
    document.body.appendChild(bar);
  }

  function requireScan() {
    var id = getScanId();
    if (!id) {
      showError("No scan in progress. Redirecting to the upload screen…");
      setTimeout(function () {
        goTo("upload", null);
      }, 1500);
      return null;
    }
    return id;
  }

  function findByText(selector, text) {
    var needle = text.toLowerCase();
    var nodes = Array.prototype.slice.call(document.querySelectorAll(selector));
    for (var i = 0; i < nodes.length; i++) {
      if ((nodes[i].textContent || "").toLowerCase().indexOf(needle) !== -1) {
        return nodes[i];
      }
    }
    return null;
  }

  // ---------------------------------------------------------------------
  // Screen 1: upload_configuration
  // ---------------------------------------------------------------------

  function initUpload() {
    var fileInput = document.querySelector('input[type="file"]');
    var vendorSelect = document.getElementById("vendor-select");
    var analyzeBtn = findByText("button", "Analyze Configuration");
    var dropzoneHeading = document.querySelector("#dropzone h3");
    var originalHeading = dropzoneHeading ? dropzoneHeading.innerHTML : "";

    if (!fileInput || !analyzeBtn) return;

    var selectedFile = null;

    function setFile(file) {
      selectedFile = file;
      if (dropzoneHeading) {
        if (file) {
          dropzoneHeading.textContent = file.name;
        } else {
          dropzoneHeading.innerHTML = originalHeading;
        }
      }
    }

    fileInput.addEventListener("change", function () {
      setFile(fileInput.files && fileInput.files[0] ? fileInput.files[0] : null);
    });

    // The screen's own cosmetic dropzone script calls preventDefault on drop
    // but never reads the file, so capture it here.
    var dropzone = document.getElementById("dropzone");
    if (dropzone) {
      dropzone.addEventListener("drop", function (event) {
        var dt = event.dataTransfer;
        if (dt && dt.files && dt.files.length) {
          setFile(dt.files[0]);
          try {
            fileInput.files = dt.files;
          } catch (e) {
            /* read-only in some browsers; selectedFile still holds it */
          }
        }
      });
    }

    analyzeBtn.addEventListener("click", async function () {
      var file =
        selectedFile ||
        (fileInput.files && fileInput.files[0] ? fileInput.files[0] : null);
      if (!file) {
        showError("Choose a configuration file first.");
        return;
      }

      var originalLabel = analyzeBtn.innerHTML;
      analyzeBtn.disabled = true;
      analyzeBtn.textContent = "Uploading…";

      try {
        var form = new FormData();
        form.append("file", file);
        form.append("vendor", vendorSelect ? vendorSelect.value : "auto");

        var data = await api("/api/scans", { method: "POST", body: form });
        try {
          sessionStorage.setItem("scan_id", data.scan_id);
        } catch (e) {
          /* ignore */
        }

        // Only stop at the vendor screen when the backend actually wants
        // confirmation; otherwise go straight to analysis.
        goTo(data.needs_confirmation ? "vendor" : "analyzing", data.scan_id);
      } catch (err) {
        showError("Upload failed: " + err.message);
        analyzeBtn.disabled = false;
        analyzeBtn.innerHTML = originalLabel;
      }
    });
  }

  // ---------------------------------------------------------------------
  // Screen 2: vendor_detection_result
  // ---------------------------------------------------------------------

  function initVendor() {
    var scanId = requireScan();
    if (!scanId) return;

    var heading = findByText("h2", "Detected Vendor");
    var subtitle = heading ? heading.parentElement.querySelector("p") : null;
    var confidencePill = document.querySelector(".bg-tertiary\\/10 span:last-child");
    var reasonWrap = document.querySelector("details .flex.flex-wrap");
    var mismatchCard = findByText("h3", "Configuration Mismatch");
    var mismatchBlock = mismatchCard
      ? mismatchCard.closest(".bg-surface-container-high")
      : null;
    var buttons = document.querySelectorAll("main button");
    var proceedBtn = buttons[0];
    var switchBtn = buttons[1];
    var backLink = findByText("div", "Back to Scan Setup");

    if (backLink) {
      backLink.addEventListener("click", function () {
        goTo("upload", null);
      });
    }

    api("/api/scans/" + scanId + "/vendor")
      .then(function (data) {
        var detected = vendorLabel(data.vendor);

        if (heading) heading.textContent = "Detected Vendor: " + detected;
        if (subtitle) {
          subtitle.textContent =
            "File: " + (data.filename || "config") +
            (data.hostname ? "  ·  Hostname: " + data.hostname : "");
        }
        if (confidencePill) {
          confidencePill.textContent =
            String(data.confidence || "unknown").replace("_", " ") + " confidence";
        }

        // "Why we think this" -- replace the demo chips with the detector's
        // real reason string, keeping the same chip markup.
        if (reasonWrap) {
          reasonWrap.innerHTML = "";
          var chip = el(
            "div",
            "bg-surface-variant border border-outline-variant text-on-surface-variant rounded px-3 py-1.5 font-code-md text-code-md flex items-center gap-2 shadow-sm"
          );
          var icon = el("span", "material-symbols-outlined text-xs text-primary", "data_object");
          chip.appendChild(icon);
          chip.appendChild(
            document.createTextNode(" " + (prettyReason(data.reason) || "No reason reported"))
          );
          reasonWrap.appendChild(chip);
        }

        var declared = data.declared_vendor;
        var isMismatch = declared && data.vendor && declared !== data.vendor;

        if (mismatchBlock) {
          if (isMismatch) {
            var body = mismatchBlock.querySelector("p");
            if (body) {
              // resolve_vendor() already phrases the mismatch as
              // "You selected 'x', but ...", so don't restate it.
              body.textContent = /^you selected/i.test(data.reason || "")
                ? prettyReason(data.reason)
                : "You selected " + vendorLabel(declared) +
                  ", but the detector found signatures consistent with " +
                  detected + ". " + (prettyReason(data.reason) || "");
            }
          } else if (!data.vendor) {
            var h3 = mismatchBlock.querySelector("h3");
            var p = mismatchBlock.querySelector("p");
            if (h3) h3.textContent = "Vendor Not Recognised";
            if (p) {
              p.textContent =
                (prettyReason(data.reason) || "No known vendor signature matched.") +
                " You can pick a vendor below, or continue and let the AI classifier attempt it.";
            }
          } else {
            mismatchBlock.style.display = "none";
          }
        }

        if (proceedBtn) {
          var known = data.vendor && String(data.vendor).toLowerCase() !== "unknown";
          if (declared) {
            proceedBtn.textContent = "Proceed with " + vendorLabel(declared);
          } else if (known) {
            proceedBtn.textContent = "Proceed with " + detected;
          } else {
            proceedBtn.textContent = "Continue without a vendor";
          }
          proceedBtn.addEventListener("click", async function () {
            try {
              await apiJson("/api/scans/" + scanId + "/vendor", "POST", {
                vendor: declared || data.vendor,
              });
              goTo("analyzing", scanId);
            } catch (err) {
              showError("Could not set vendor: " + err.message);
            }
          });
        }

        if (switchBtn) {
          if (isMismatch) {
            switchBtn.textContent = "Switch to " + detected;
          } else {
            switchBtn.textContent = "Continue to analysis";
          }
          switchBtn.addEventListener("click", async function () {
            try {
              await apiJson("/api/scans/" + scanId + "/vendor", "POST", {
                vendor: data.vendor,
              });
              goTo("analyzing", scanId);
            } catch (err) {
              showError("Could not set vendor: " + err.message);
            }
          });
        }
      })
      .catch(function (err) {
        showError("Could not load vendor detection: " + err.message);
      });
  }

  // ---------------------------------------------------------------------
  // Screen 3: analyzing_configuration
  // ---------------------------------------------------------------------

  function initAnalyzing() {
    var scanId = requireScan();
    if (!scanId) return;

    var statusLine = document.querySelector("main p.pulse-dot");
    var stepRows = document.querySelectorAll(
      "main .flex.flex-col.gap-md.pl-4 > .flex.items-start"
    );

    var ACTIVE_DOT =
      "absolute -left-[21px] top-1 w-2.5 h-2.5 rounded-full bg-primary shadow-[0_0_8px_rgba(107,216,203,0.6)] pulse-dot";
    var DONE_DOT =
      "absolute -left-[21px] top-1 w-2.5 h-2.5 rounded-full bg-tertiary";
    var PENDING_DOT =
      "absolute -left-[21px] top-1 w-2.5 h-2.5 rounded-full bg-surface-variant border border-outline-variant";

    function paintSteps(activeIndex) {
      for (var i = 0; i < stepRows.length; i++) {
        var dot = stepRows[i].querySelector("div");
        var label = stepRows[i].querySelector("span");
        if (!dot || !label) continue;
        if (i < activeIndex) {
          dot.className = DONE_DOT;
          label.className = "font-body-md text-body-md text-tertiary";
        } else if (i === activeIndex) {
          dot.className = ACTIVE_DOT;
          label.className = "font-body-md text-body-md text-on-surface font-medium";
        } else {
          dot.className = PENDING_DOT;
          label.className = "font-body-md text-body-md text-on-surface-variant";
        }
      }
    }

    var polling = null;

    async function poll() {
      try {
        var status = await api("/api/scans/" + scanId + "/status");
        paintSteps(status.step_index);
        if (statusLine) statusLine.textContent = status.current_step + "…";

        if (status.state === "error") {
          clearInterval(polling);
          if (statusLine) statusLine.textContent = "Analysis failed.";
          showError("Analysis failed: " + (status.error || "unknown error"));
          return;
        }

        if (status.state === "needs_review") {
          clearInterval(polling);
          paintSteps(2);
          if (statusLine) statusLine.textContent = "Waiting for your review…";
          goTo("review", scanId);
          return;
        }

        if (status.state === "analyzed" || status.state === "evaluated") {
          clearInterval(polling);
          paintSteps(3);
          if (statusLine) statusLine.textContent = "Generating report…";
          try {
            await apiJson("/api/scans/" + scanId + "/evaluate", "POST", {});
            goTo("report", scanId);
          } catch (err) {
            showError("Evaluation failed: " + err.message);
          }
        }
      } catch (err) {
        clearInterval(polling);
        showError("Lost contact with the API: " + err.message);
      }
    }

    apiJson("/api/scans/" + scanId + "/analyze", "POST", {})
      .then(function () {
        paintSteps(0);
        polling = setInterval(poll, 600);
        poll();
      })
      .catch(function (err) {
        showError("Could not start analysis: " + err.message);
      });
  }

  // ---------------------------------------------------------------------
  // Screen 4: review_unknown_lines
  // ---------------------------------------------------------------------

  function initReview() {
    var scanId = requireScan();
    if (!scanId) return;

    var tbody = document.querySelector("main table tbody");
    var confirmBtn = findByText("button", "Confirm All");
    if (!tbody) return;

    var CONFIRM_ENABLED =
      "bg-primary text-on-primary-fixed font-title-md text-title-md px-xl py-sm rounded-lg transition-colors w-full sm:w-auto hover:opacity-90";
    var CONFIRM_DISABLED =
      "bg-primary/50 text-on-primary-fixed/50 font-title-md text-title-md px-xl py-sm rounded-lg cursor-not-allowed transition-colors w-full sm:w-auto";

    var rows = [];

    function buildRow(item, fields) {
      var tr = el("tr", "hover:bg-surface-variant transition-colors group");

      // Raw config line
      var tdLine = el("td", "py-md px-lg");
      var box = el(
        "div",
        "bg-surface-container-lowest p-sm rounded border border-outline-variant inline-block"
      );
      box.appendChild(el("code", "font-code-md text-code-md text-tertiary", item.raw_line));
      tdLine.appendChild(box);
      tr.appendChild(tdLine);

      // Suggested field -- populated from the real NormalizedConfig schema
      // rather than the mockup's generic UI categories.
      var tdField = el("td", "py-md px-lg");
      var select = el(
        "select",
        "bg-surface-container-lowest border border-outline-variant text-on-surface text-sm rounded-lg focus:ring-primary focus:border-primary block w-full p-2.5"
      );
      var options = fields.concat(["unclear"]);
      options.forEach(function (field) {
        var opt = el("option", null, fieldLabel(field));
        opt.value = field;
        if (field === item.suggested_field) opt.selected = true;
        select.appendChild(opt);
      });
      if (!item.suggested_field || options.indexOf(item.suggested_field) === -1) {
        select.value = "unclear";
      }
      tdField.appendChild(select);

      // Value editor, shown for everything except "unclear".
      var valueWrap = el("div", "mt-2");
      var valueInput = el(
        "input",
        "bg-surface-container-lowest border border-outline-variant text-on-surface text-sm rounded-lg focus:ring-primary focus:border-primary block w-full p-2.5"
      );
      valueInput.type = "text";
      valueInput.placeholder = "Value";
      if (item.suggested_value !== null && item.suggested_value !== undefined) {
        valueInput.value = String(item.suggested_value);
      }
      valueWrap.appendChild(valueInput);
      tdField.appendChild(valueWrap);

      function syncValueEditor() {
        var field = select.value;
        if (field === "unclear") {
          valueWrap.style.display = "none";
          return;
        }
        valueWrap.style.display = "";
        if (BOOL_FIELDS.indexOf(field) !== -1) {
          valueInput.placeholder = "true or false";
        } else if (field === "session_timeout_seconds") {
          valueInput.placeholder = "seconds, e.g. 600";
        } else if (field === "snmp_default_community") {
          valueInput.placeholder = "comma-separated, e.g. public,private";
        } else {
          valueInput.placeholder = "e.g. type7";
        }
      }
      select.addEventListener("change", syncValueEditor);
      syncValueEditor();
      tr.appendChild(tdField);

      // Confidence -- shows the classifier's real number.
      var tdConf = el("td", "py-md px-lg");
      var pct = Math.round((item.confidence || 0) * 100);
      // memory.py returns confidence 1.0 for previously confirmed lines, so
      // labelling those "AI: 100%" would be wrong -- they came from the cache,
      // not the model.
      var fromMemory = /^from memory/i.test(item.reasoning || "");
      var label;
      if (fromMemory) label = "From memory";
      else if (pct > 0) label = "AI: " + pct + "%";
      else label = "Needs your input";
      var pillClass =
        pct >= 60 && !fromMemory
          ? "bg-primary/10 text-primary font-label-caps text-label-caps px-2 py-1 rounded-full border border-primary/20"
          : "bg-surface-variant text-on-surface-variant font-label-caps text-label-caps px-2 py-1 rounded-full border border-outline-variant";
      var pill = el("span", pillClass, label);
      if (item.reasoning) pill.title = item.reasoning;
      tdConf.appendChild(pill);
      tr.appendChild(tdConf);

      // Action -- per-row accept toggle.
      var tdAction = el("td", "py-md px-lg text-right");
      var actions = el("div", "flex justify-end gap-sm");
      var acceptBtn = el(
        "button",
        "text-on-surface-variant hover:text-tertiary transition-colors p-sm rounded-lg hover:bg-surface-container-highest"
      );
      acceptBtn.appendChild(
        el("span", "material-symbols-outlined text-[20px]", "check")
      );
      acceptBtn.title = "Mark this line reviewed";
      var accepted = false;
      acceptBtn.addEventListener("click", function () {
        accepted = !accepted;
        acceptBtn.className = accepted
          ? "text-tertiary transition-colors p-sm rounded-lg bg-surface-container-highest"
          : "text-on-surface-variant hover:text-tertiary transition-colors p-sm rounded-lg hover:bg-surface-container-highest";
      });
      actions.appendChild(acceptBtn);
      tdAction.appendChild(actions);
      tr.appendChild(tdAction);

      rows.push({
        raw_line: item.raw_line,
        getField: function () {
          return select.value;
        },
        getValue: function () {
          return valueInput.value;
        },
      });

      return tr;
    }

    api("/api/scans/" + scanId + "/pending")
      .then(function (data) {
        var pending = data.pending_confirmations || [];
        tbody.innerHTML = ""; // drop the mockup's three demo rows

        if (!pending.length) {
          var tr = el("tr");
          var td = el(
            "td",
            "py-md px-lg font-body-md text-on-surface-variant",
            "Nothing to review — every line was recognised. Continuing to the report…"
          );
          td.colSpan = 4;
          tr.appendChild(td);
          tbody.appendChild(tr);
          setTimeout(function () {
            goTo("report", scanId);
          }, 1200);
          return;
        }

        pending.forEach(function (item) {
          tbody.appendChild(buildRow(item, data.fields || []));
        });

        if (confirmBtn) {
          confirmBtn.disabled = false;
          confirmBtn.className = CONFIRM_ENABLED;
          confirmBtn.textContent =
            "Confirm All & Continue (" + pending.length + ")";
        }
      })
      .catch(function (err) {
        showError("Could not load unknown lines: " + err.message);
      });

    if (confirmBtn) {
      confirmBtn.addEventListener("click", async function () {
        if (confirmBtn.disabled) return;
        confirmBtn.disabled = true;
        confirmBtn.className = CONFIRM_DISABLED;
        confirmBtn.textContent = "Saving…";

        try {
          var payload = rows.map(function (row) {
            return {
              raw_line: row.raw_line,
              field: row.getField(),
              value: row.getField() === "unclear" ? null : row.getValue(),
            };
          });

          await apiJson("/api/scans/" + scanId + "/confirmations", "POST", {
            confirmations: payload,
          });
          await apiJson("/api/scans/" + scanId + "/evaluate", "POST", {});
          goTo("report", scanId);
        } catch (err) {
          showError("Could not save confirmations: " + err.message);
          confirmBtn.disabled = false;
          confirmBtn.className = CONFIRM_ENABLED;
          confirmBtn.textContent = "Confirm All & Continue";
        }
      });
    }
  }

  // ---------------------------------------------------------------------
  // Screen 5: compliance_report_dashboard
  // ---------------------------------------------------------------------

  function initReport() {
    var scanId = requireScan();
    if (!scanId) return;

    var SEVERITY_STYLES = {
      critical: { chip: "bg-error/20 text-error border-error/30", icon: "gpp_bad", border: "border-error/30" },
      high: { chip: "bg-error/20 text-error border-error/30", icon: "gpp_bad", border: "border-error/30" },
      medium: { chip: "bg-[#f59e0b]/20 text-[#fbbf24] border-[#f59e0b]/30", icon: "warning", border: "border-[#f59e0b]/30" },
      low: { chip: "bg-secondary/20 text-secondary border-secondary/30", icon: "info", border: "border-secondary/30" },
    };

    function severityStyle(sev) {
      return SEVERITY_STYLES[String(sev || "low").toLowerCase()] || SEVERITY_STYLES.low;
    }

    function buildFindingCard(finding) {
      var style = severityStyle(finding.severity);
      var card = el(
        "div",
        "bg-surface-container-low rounded-xl border " + style.border +
          " overflow-hidden shadow-sm transition-all"
      );

      var header = el(
        "div",
        "p-md bg-surface-container border-b border-outline-variant flex flex-wrap justify-between items-center gap-md cursor-pointer"
      );
      header.setAttribute("onclick", "toggleCard(this)");

      var left = el("div", "flex items-center gap-md");
      var sevChip = el(
        "div",
        "px-sm py-xs rounded font-label-caps text-label-caps border flex items-center gap-xs " + style.chip
      );
      sevChip.appendChild(el("span", "material-symbols-outlined text-[16px]", style.icon));
      sevChip.appendChild(
        document.createTextNode(" " + String(finding.severity || "low").toUpperCase())
      );
      left.appendChild(sevChip);
      left.appendChild(
        el(
          "span",
          "font-code-md text-code-md text-on-surface bg-surface-variant px-sm py-xs rounded border border-outline-variant",
          finding.rule_id
        )
      );
      left.appendChild(
        el("span", "font-title-md text-title-md text-on-surface", finding.field_checked || finding.rule_id)
      );
      header.appendChild(left);
      header.appendChild(
        el("span", "material-symbols-outlined text-on-surface-variant transition-transform transform", "expand_more")
      );
      card.appendChild(header);

      var body = el("div", "p-md space-y-md");

      // Simple view -- plain-English explanation from the rule pack.
      var simple = el("div", "view-simple");
      simple.appendChild(
        el(
          "p",
          "font-body-md text-body-md text-on-surface-variant",
          finding.risk_explanation || finding.explanation || "No explanation provided for this rule."
        )
      );
      body.appendChild(simple);

      // Technical view -- observed vs expected, plus remediation CLI.
      var tech = el("div", "view-technical hidden space-y-md");
      var grid = el("div", "grid grid-cols-1 md:grid-cols-2 gap-md");

      var foundBox = el("div", "bg-surface-container-highest rounded border border-outline-variant p-sm");
      foundBox.appendChild(el("span", "block font-label-caps text-label-caps text-error mb-xs", "FOUND CONFIGURATION"));
      foundBox.appendChild(
        el(
          "pre",
          "font-code-md text-code-md overflow-x-auto text-error",
          (finding.field_checked || "value") + " = " + JSON.stringify(finding.observed_value)
        )
      );
      grid.appendChild(foundBox);

      var expectBox = el("div", "bg-surface-container-highest rounded border border-outline-variant p-sm");
      expectBox.appendChild(el("span", "block font-label-caps text-label-caps text-tertiary mb-xs", "STATUS"));
      expectBox.appendChild(
        el("pre", "font-code-md text-code-md overflow-x-auto text-tertiary", finding.status)
      );
      grid.appendChild(expectBox);
      tech.appendChild(grid);

      if (finding.remediation_cli) {
        var remWrap = el("div");
        var remHead = el("div", "flex justify-between items-center mb-xs");
        remHead.appendChild(el("span", "font-label-caps text-label-caps text-on-surface-variant", "REMEDIATION CLI"));
        var copyBtn = el("button", "text-primary hover:text-primary-fixed-dim transition-colors flex items-center gap-xs text-sm");
        copyBtn.appendChild(el("span", "material-symbols-outlined text-[16px]", "content_copy"));
        copyBtn.appendChild(document.createTextNode(" Copy"));
        copyBtn.addEventListener("click", function (event) {
          event.stopPropagation();
          if (navigator.clipboard) {
            navigator.clipboard.writeText(finding.remediation_cli);
            copyBtn.lastChild.textContent = " Copied";
            setTimeout(function () {
              copyBtn.lastChild.textContent = " Copy";
            }, 1500);
          }
        });
        remHead.appendChild(copyBtn);
        remWrap.appendChild(remHead);

        var codeBlock = el("div", "code-block rounded-lg p-md overflow-x-auto relative group");
        codeBlock.appendChild(el("pre", "font-code-md text-code-md text-secondary", finding.remediation_cli));
        remWrap.appendChild(codeBlock);
        tech.appendChild(remWrap);
      }

      body.appendChild(tech);
      card.appendChild(body);
      return card;
    }

    api("/api/scans/" + scanId + "/report")
      .then(function (data) {
        var device = data.device || {};
        var summary = data.summary || {};

        // Header timestamp
        var scanLine = findByText("main p", "Scan completed");
        if (scanLine) {
          scanLine.textContent =
            "Scan completed: " + (data.meta ? data.meta.scan_date : "") +
            "  ·  " + (data.filename || "");
        }

        // Asset details card
        var assetCard = findByText("h2", "ASSET DETAILS");
        if (assetCard) {
          var values = assetCard.parentElement.querySelectorAll(".space-y-md > div > span:last-child");
          if (values[0]) values[0].textContent = device.hostname || "(not in config)";
          if (values[1]) values[1].textContent = vendorLabel(device.vendor);
          if (values[2]) values[2].textContent = device.serial_number || "(not in config)";
        }

        // Score ring. Anchor to the ring itself: the nav logo carries the same
        // "font-headline-lg text-headline-lg text-primary" classes and comes
        // first in the document, so a bare class selector overwrites the
        // ConfigGuard wordmark and leaves the real score stale.
        var score = typeof summary.score === "number" ? summary.score : 0;
        var ring = document.querySelector(".progress-ring__circle");
        var ringBox = ring ? ring.closest("div.relative") : null;
        var scoreText = ringBox ? ringBox.querySelector("span") : null;
        if (scoreText) scoreText.textContent = Math.round(score) + "%";
        if (ring) {
          var circumference = 2 * Math.PI * 50; // r=50 in the markup
          ring.setAttribute("stroke-dasharray", circumference.toFixed(3));
          ring.setAttribute(
            "stroke-dashoffset",
            (circumference * (1 - score / 100)).toFixed(3)
          );
        }

        // Stat pills. The count lives in the pill's own last child span --
        // NOT in a descendant query, because "span:last-child" would match the
        // label span inside the inner flex div first and rewrite the wrong node.
        function setPill(labelText, value, newLabel) {
          var labelEl = findByText("span", labelText);
          if (!labelEl) return;
          var pill = labelEl.closest("div").parentElement;
          var valueEl = pill.querySelector(":scope > span:last-child");
          if (valueEl && valueEl !== labelEl) valueEl.textContent = value;
          if (newLabel) labelEl.textContent = newLabel;
        }
        setPill("PASSED", summary.passed_count);
        setPill("FAILED", summary.failed_count);
        // The backend's third bucket is NOT_EVALUATED, not "warnings".
        setPill("WARNINGS", summary.not_evaluated_count, "NOT EVALUATED");

        // Findings list
        var findingsHeading = findByText("h2", "Findings");
        var listWrap = findingsHeading
          ? findingsHeading.parentElement.querySelector(".space-y-md")
          : null;
        if (listWrap) {
          listWrap.innerHTML = ""; // drop the mockup's single demo finding
          var failed = (data.findings || []).filter(function (f) {
            return f.status === "FAIL";
          });
          var others = (data.findings || []).filter(function (f) {
            return f.status !== "FAIL";
          });
          var ordered = failed.concat(others);

          if (findingsHeading) {
            findingsHeading.textContent =
              "Findings (" + failed.length + " failed of " + (data.findings || []).length + " checks)";
          }

          if (!ordered.length) {
            listWrap.appendChild(
              el("p", "font-body-md text-on-surface-variant", "No findings were produced for this configuration.")
            );
          } else {
            ordered.forEach(function (finding) {
              listWrap.appendChild(buildFindingCard(finding));
            });
          }
        }

        if (data.warning) {
          showError("Evaluator warning: " + data.warning);
        }

        // Download button -> the existing PDF generator
        var downloadBtn = findByText("button", "Download Full Report");
        if (downloadBtn) {
          downloadBtn.addEventListener("click", function () {
            window.location.href =
              API_BASE + "/api/scans/" + encodeURIComponent(scanId) + "/report.pdf";
          });
        }
      })
      .catch(function (err) {
        showError("Could not load the report: " + err.message);
      });
  }

  // ---------------------------------------------------------------------
  // Dispatch
  // ---------------------------------------------------------------------

  function currentScreen() {
    var path = decodeURIComponent(window.location.pathname);
    if (path.indexOf("upload_configuration") !== -1) return initUpload;
    if (path.indexOf("vendor_detection_result") !== -1) return initVendor;
    if (path.indexOf("analyzing_configuration") !== -1) return initAnalyzing;
    if (path.indexOf("review_unknown_lines") !== -1) return initReview;
    if (path.indexOf("compliance_report_dashboard") !== -1) return initReport;
    return null;
  }

  function boot() {
    var init = currentScreen();
    if (!init) return;
    try {
      init();
    } catch (err) {
      showError("Frontend error: " + err.message);
      throw err;
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
