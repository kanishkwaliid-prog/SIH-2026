/* ============================================================
   mock-data.js
   ------------------------------------------------------------
   Fake backend for Phase 5.6, per the handoff doc's instruction:
   "Mock the backend API with fake JSON shaped like ComplianceReport
   first; wire to a real FastAPI backend once confirmed stable."

   This is NOT calling any real Python. Everything here is a
   JavaScript port of small pieces of the real logic (condition
   matching from compliance_engine/evaluate.py's _condition_matches,
   risk_score's weights) plus real content lifted directly from
   rule_packs/*.yaml, so the demo reflects the actual project rather
   than generic placeholder data. When Phase 8 wires this to the real
   FastAPI backend, everything in this file gets deleted wholesale.
   ============================================================ */

// The 12 vendor codecs from converter/schema_adapter.py.
const VENDORS = [
  { id: "arista_eos",        label: "Arista EOS" },
  { id: "aruba_aoscx",       label: "Aruba AOS-CX" },
  { id: "aruba_aoss",        label: "Aruba AOS-Switch (AOS-S)" },
  { id: "cisco_iosxe",       label: "Cisco IOS-XE (NETCONF)" },
  { id: "cisco_iosxe_cli",   label: "Cisco IOS-XE (CLI)" },
  { id: "cisco_iosxr",       label: "Cisco IOS-XR" },
  { id: "cisco_nxos",        label: "Cisco NX-OS" },
  { id: "fortigate_cli",     label: "Fortinet FortiGate (CLI)" },
  { id: "juniper_junos",     label: "Juniper Junos" },
  { id: "mikrotik_routeros", label: "MikroTik RouterOS" },
  { id: "opnsense",          label: "OPNsense" },
  { id: "vyos",              label: "VyOS" },
];

const VENDOR_LABEL = Object.fromEntries(VENDORS.map(v => [v.id, v.label]));

// ------------------------------------------------------------
// Real rule packs, transcribed from rule_packs/cis_network_devices.yaml
// and rule_packs/nist_800_53_network_devices.yaml. Trimmed to the
// remediation entries needed for the sample vendors below, but every
// id / field / expected / severity / explanation is verbatim from the
// real YAML.
// ------------------------------------------------------------
const RULE_PACKS = {
  CIS: {
    framework: "CIS",
    rules: [
      { id: "CIS-4.1.1", field: "ssh_enabled", expected: true, severity: "high",
        explanation: "Remote administration should use SSH, which encrypts login credentials and session traffic.",
        remediation: {
          cisco_iosxe_cli: "line vty 0 4\n transport input ssh",
          juniper_junos: "set system services ssh",
          arista_eos: "management ssh\n no shutdown",
          vyos: "set service ssh port 22",
          fortigate_cli: "# NEEDS-VERIFICATION\nconfig system global\n  set admin-ssh-port 22\nend",
        } },
      { id: "CIS-4.1.2", field: "telnet_enabled", expected: false, severity: "critical",
        explanation: "Telnet transmits login credentials and all session data in plain text and should be disabled in favor of SSH.",
        remediation: {
          cisco_iosxe_cli: "line vty 0 4\n no transport input telnet",
          juniper_junos: "delete system services telnet",
          arista_eos: "management telnet\n shutdown",
          vyos: "delete service telnet",
          fortigate_cli: "# NEEDS-VERIFICATION\nconfig system interface\n  edit \"<interface>\"\n    unset allowaccess telnet\n  next\nend",
        } },
      { id: "CIS-4.2.1", field: "session_timeout_seconds", expected: "<= 300", severity: "medium",
        explanation: "Idle administrative sessions should time out within 5 minutes to reduce the risk of a hijacked or forgotten open session.",
        remediation: {
          cisco_iosxe_cli: "line vty 0 4\n exec-timeout 5 0",
          juniper_junos: "set system login idle-timeout 5",
          arista_eos: "management ssh\n idle-timeout 5",
          vyos: "set system login idle-timeout 300",
        } },
      { id: "CIS-4.2.2", field: "session_timeout_seconds", expected: "> 0", severity: "high",
        explanation: "A session timeout of 0 typically means idle sessions never expire -- this is materially worse than a generous-but-nonzero timeout and should be flagged as its own finding.",
        remediation: {
          cisco_iosxe_cli: "line vty 0 4\n exec-timeout 10 0\n! (any nonzero value; 0 0 means \"never times out\")",
        } },
      { id: "CIS-6.1.1", field: "logging_enabled", expected: true, severity: "high",
        explanation: "Administrative and system events should be logged to a remote syslog server for auditing and incident response.",
        remediation: {
          cisco_iosxe_cli: "logging host <syslog-server-ip>\nlogging trap informational",
          juniper_junos: "set system syslog host <syslog-server-ip> any any",
          arista_eos: "logging host <syslog-server-ip>",
          vyos: "set system syslog host <syslog-server-ip> facility all level info",
        } },
      { id: "CIS-4.3.1", field: "password_encryption", expected: "not in: none, plaintext, cleartext", severity: "critical",
        explanation: "Passwords stored in the running config must not be stored in plain, readable text -- at minimum a reversible encoding should be applied.",
        remediation: {
          cisco_iosxe_cli: "service password-encryption",
        } },
      { id: "CIS-4.3.2", field: "password_encryption", expected: "not in: type7, weak, rc4", severity: "high",
        explanation: "A password field being 'encrypted' is not sufficient if the scheme is a weak, trivially reversible cipher (e.g. Cisco type 7). A strong one-way hash (e.g. type 8/9, scrypt, sha512, bcrypt) should be used instead.",
        remediation: {
          cisco_iosxe_cli: "enable algorithm-type sha256 secret <new-secret>\nusername <user> algorithm-type sha256 secret <new-secret>",
        } },
      { id: "CIS-4.4.1", field: "banner_configured", expected: true, severity: "low",
        explanation: "A legal-notice login banner should be configured to establish authorized-use notice before granting access.",
        remediation: {
          cisco_iosxe_cli: "banner motd ^C\nAuthorized access only. All activity is monitored and logged.\n^C",
          juniper_junos: "set system login message \"Authorized access only. All activity is monitored and logged.\"",
          arista_eos: "banner motd\nAuthorized access only. All activity is monitored and logged.\nEOF",
          vyos: "set system login banner pre-login \"Authorized access only.\"",
        } },
    ],
  },
  NIST: {
    framework: "NIST",
    rules: [
      { id: "NIST-AC-17", field: "ssh_enabled", expected: true, severity: "high",
        explanation: "AC-17 (Remote Access): the organization must authorize, monitor, and control remote administrative access methods. Encrypted remote access (SSH) satisfies this; unencrypted access does not.",
        seeCisRule: "CIS-4.1.1" },
      { id: "NIST-AC-17-1", field: "telnet_enabled", expected: false, severity: "critical",
        explanation: "AC-17 (Remote Access): unencrypted remote access protocols like Telnet do not meet the confidentiality/integrity protections AC-17 requires for remote administrative sessions.",
        seeCisRule: "CIS-4.1.2" },
      { id: "NIST-AC-12", field: "session_timeout_seconds", expected: "<= 300", severity: "medium",
        explanation: "AC-12 (Session Termination): the system must automatically terminate a user session after a defined period of inactivity.",
        seeCisRule: "CIS-4.2.1" },
      { id: "NIST-AC-12-1", field: "session_timeout_seconds", expected: "> 0", severity: "high",
        explanation: "AC-12 (Session Termination): a timeout value of 0 (never expires) does not satisfy the control's requirement for automatic termination after inactivity.",
        seeCisRule: "CIS-4.2.2" },
      { id: "NIST-AU-2", field: "logging_enabled", expected: true, severity: "high",
        explanation: "AU-2 (Event Logging): the organization must identify and log the types of events the system is capable of logging, including administrative access, to a system capable of supporting audit and incident response.",
        seeCisRule: "CIS-6.1.1" },
      { id: "NIST-IA-5", field: "password_encryption", expected: "not in: none, plaintext, cleartext", severity: "critical",
        explanation: "IA-5 (Authenticator Management): the organization must protect authenticator content, including stored passwords/secrets, from unauthorized disclosure. Plaintext storage in a config file fails this requirement outright.",
        seeCisRule: "CIS-4.3.1" },
      { id: "NIST-IA-5-1", field: "password_encryption", expected: "not in: type7, weak, rc4", severity: "high",
        explanation: "IA-5 (Authenticator Management): protection of stored authenticators must use a scheme resistant to recovery, not merely an obfuscated/reversible encoding.",
        seeCisRule: "CIS-4.3.2" },
      { id: "NIST-AC-8", field: "banner_configured", expected: true, severity: "low",
        explanation: "AC-8 (System Use Notification): the system must display an approved system-use notification before granting access, informing users of monitoring and legal conditions of use.",
        seeCisRule: "CIS-4.4.1" },
    ],
  },
};

// ------------------------------------------------------------
// Sample configs -- illustrative text, not guaranteed byte-perfect
// vendor syntax, just enough to demo detection + parsing + the
// unrecognized-lines flow without a real file upload.
// ------------------------------------------------------------
const SAMPLE_CONFIGS = [
  {
    filename: "edge-sw-1.cfg",
    vendor: "cisco_iosxe_cli",
    confidence: 96,
    reason: "Matched Cisco IOS-XE CLI syntax markers (\"!\", \"line vty\", \"ip ssh version\").",
    text:
`!
hostname edge-sw-1
!
ip ssh version 2
line vty 0 4
 transport input ssh telnet
 exec-timeout 0 0
!
service password-encryption
!
logging host 10.0.0.5
!
snmp-server community public RO
radius-server deadtime 3
!
end`,
    parsed: {
      ssh_enabled: true, telnet_enabled: true, session_timeout_seconds: 0,
      logging_enabled: true, password_encryption: "type7", banner_configured: null,
    },
    unrecognizedLines: [
      { line: "snmp-server community public RO", aiGuess: "other / not a compliance field", confidence: 82 },
      { line: "radius-server deadtime 3", aiGuess: "other / not a compliance field", confidence: 74 },
    ],
    device: { hostname: "edge-sw-1", serial_number: "ABC123", os_version: "17.9" },
  },
  {
    filename: "core-router.junos",
    vendor: "juniper_junos",
    confidence: 91,
    reason: "Matched Junos \"set system\" / \"set interfaces\" configuration statement style.",
    text:
`set system host-name core-router
set system services ssh
set system login idle-timeout 15
set system syslog host 10.0.0.5 any any
set system login message "Authorized access only."
set policy-options prefix-list MGMT-ALLOWED 10.0.0.0/24
set forwarding-options sampling instance sample-1`,
    parsed: {
      ssh_enabled: true, telnet_enabled: false, session_timeout_seconds: 900,
      logging_enabled: true, password_encryption: "sha512", banner_configured: true,
    },
    unrecognizedLines: [
      { line: "set policy-options prefix-list MGMT-ALLOWED 10.0.0.0/24", aiGuess: "other / not a compliance field", confidence: 88 },
      { line: "set forwarding-options sampling instance sample-1", aiGuess: "other / not a compliance field", confidence: 69 },
    ],
    device: { hostname: "core-router", serial_number: "JX-99210", os_version: "21.4R3" },
  },
  {
    filename: "branch-fw.cfg",
    vendor: "fortigate_cli",
    confidence: 61,
    reason: "Weak match -- found \"config system\" blocks but no strong FortiGate-only markers in the probed prefix.",
    text:
`config system global
  set admin-ssh-port 22
  set hostname branch-fw
end
config system interface
  edit "port1"
    set allowaccess ping https ssh telnet
  next
end
config log syslogd setting
  set status disable
end`,
    parsed: {
      ssh_enabled: true, telnet_enabled: true, session_timeout_seconds: null,
      logging_enabled: false, password_encryption: null, banner_configured: null,
    },
    unrecognizedLines: [],
    device: { hostname: "branch-fw", serial_number: "FGT60F-77120", os_version: "7.2.5" },
    otherCandidates: [
      { vendor: "fortigate_cli", confidence: 61, reason: "\"config system\" block structure, generic across FortiOS versions." },
      { vendor: "opnsense", confidence: 22, reason: "XML-free config text ruled this mostly out, but low-confidence GUI-export keyword overlap." },
    ],
  },
];

// ------------------------------------------------------------
// Mock "backend" functions -- mirror the real module signatures
// described in the handoff doc closely enough that swapping in
// real fetch() calls later is a small diff, not a rewrite.
// ------------------------------------------------------------

function mockDetectVendor(sample) {
  // Mirrors converter.schema_adapter.detect_vendor()'s VendorCandidate shape.
  const candidates = sample.otherCandidates || [
    { vendor: sample.vendor, confidence: sample.confidence, reason: sample.reason },
  ];
  return candidates.sort((a, b) => b.confidence - a.confidence);
}

function mockParseAndMap(sample, vendorOverride) {
  // Mirrors converter.schema_adapter.parse_and_map()'s ComplianceResult shape.
  return {
    vendor: vendorOverride || sample.vendor,
    confidence: sample.confidence,
    ...sample.parsed,
    unrecognized_lines: sample.unrecognizedLines.map(u => u.line),
    device: sample.device,
  };
}

function mockClassifyLines(sample) {
  // Mirrors ai_fallback.classify.classify_unrecognized_lines() -> LineClassification.to_review_dict().
  return sample.unrecognizedLines.map(u => ({
    raw_line: u.line,
    ai_guess: u.aiGuess,
    confidence: u.confidence,
  }));
}

const CATEGORY_OPTIONS = [
  "ssh_enabled", "telnet_enabled", "session_timeout_seconds",
  "logging_enabled", "password_encryption", "banner_configured",
  "other / not a compliance field",
];

// ------------------------------------------------------------
// Condition matching -- ported from compliance_engine/evaluate.py's
// _condition_matches(). Same supported `expected` forms.
// ------------------------------------------------------------
function conditionMatches(actual, expected) {
  if (actual === null || actual === undefined) {
    throw new Error("conditionMatches should not be called with actual=null");
  }
  if (typeof expected === "boolean") {
    return Boolean(actual) === expected;
  }
  if (typeof expected === "number") {
    return actual === expected;
  }
  if (typeof expected === "string") {
    const e = expected.trim();
    if (e.toLowerCase() === "not none") {
      return actual !== null && String(actual).trim().toLowerCase() !== "none";
    }
    const numMatch = e.match(/^\s*(<=|>=|<|>|==|!=)\s*(-?\d+(?:\.\d+)?)\s*$/);
    if (numMatch) {
      const [, op, numStr] = numMatch;
      const num = parseFloat(numStr);
      const actualNum = parseFloat(actual);
      if (Number.isNaN(actualNum)) return false;
      switch (op) {
        case "<=": return actualNum <= num;
        case ">=": return actualNum >= num;
        case "<": return actualNum < num;
        case ">": return actualNum > num;
        case "==": return actualNum === num;
        case "!=": return actualNum !== num;
      }
    }
    if (e.toLowerCase().startsWith("not in:")) {
      const excluded = e.split(":").slice(1).join(":").split(",").map(x => x.trim().toLowerCase());
      return !excluded.includes(String(actual).trim().toLowerCase());
    }
    if (e.toLowerCase().startsWith("in:")) {
      const allowed = e.split(":").slice(1).join(":").split(",").map(x => x.trim().toLowerCase());
      return allowed.includes(String(actual).trim().toLowerCase());
    }
    return String(actual).trim().toLowerCase() === e.toLowerCase();
  }
  throw new Error(`Unsupported expected type: ${typeof expected}`);
}

const NO_REMEDIATION_TEXT =
  "No verified remediation command available for this vendor yet. Consult vendor documentation before making changes.";

function getRemediation(rule, vendor, rulePack) {
  let remediationMap = rule.remediation;
  if (!remediationMap && rule.seeCisRule) {
    const refRule = RULE_PACKS.CIS.rules.find(r => r.id === rule.seeCisRule);
    remediationMap = refRule ? refRule.remediation : null;
  }
  if (!remediationMap) return NO_REMEDIATION_TEXT;
  const text = remediationMap[vendor];
  return (text && text.trim()) ? text.trim() : NO_REMEDIATION_TEXT;
}

// Mirrors compliance_engine.evaluate.evaluate_config().
function evaluateConfig(config, vendor, framework) {
  const rulePack = RULE_PACKS[framework];
  const findings = [];
  for (const rule of rulePack.rules) {
    const actual = config[rule.field];
    if (actual === null || actual === undefined) {
      findings.push({
        rule_id: rule.id, status: "UNKNOWN", severity: rule.severity,
        field_checked: rule.field, expected: String(rule.expected),
        actual: "not present in config",
        explanation: `${rule.explanation} (This device's config did not contain enough information to check this rule.)`,
        remediation_cli: null,
      });
      continue;
    }
    const passed = conditionMatches(actual, rule.expected);
    const status = passed ? "PASS" : "FAIL";
    findings.push({
      rule_id: rule.id, status, severity: rule.severity,
      field_checked: rule.field, expected: String(rule.expected), actual: String(actual),
      explanation: rule.explanation,
      remediation_cli: passed ? null : getRemediation(rule, vendor, rulePack),
    });
  }
  return findings;
}

// Mirrors compliance_engine.evaluate.summarize().
function summarizeFindings(findings) {
  const summary = { PASS: 0, FAIL: 0, UNKNOWN: 0 };
  for (const f of findings) summary[f.status] = (summary[f.status] || 0) + 1;
  return summary;
}

// Mirrors compliance_engine.evaluate.risk_score(): critical=3, high=2, medium=1, low=0.5.
function riskScore(findings) {
  const weights = { critical: 3, high: 2, medium: 1, low: 0.5 };
  const total = findings
    .filter(f => f.status === "FAIL")
    .reduce((sum, f) => sum + (weights[f.severity] || 0), 0);
  return Math.round(total * 100) / 100;
}

// Mirrors whatif.simulator.simulate_change(): scratch-copy, diff by rule_id.
function simulateChange(baseConfig, overrides, vendor, framework) {
  const before = evaluateConfig(baseConfig, vendor, framework);
  const scratch = { ...baseConfig, ...overrides };
  const after = evaluateConfig(scratch, vendor, framework);

  const beforeById = Object.fromEntries(before.map(f => [f.rule_id, f]));
  const afterById = Object.fromEntries(after.map(f => [f.rule_id, f]));

  const findingsDiff = [];
  for (const [ruleId, b] of Object.entries(beforeById)) {
    const a = afterById[ruleId];
    if (a && a.status !== b.status) {
      findingsDiff.push({ rule_id: ruleId, before_status: b.status, after_status: a.status });
    }
  }

  return {
    before_score: riskScore(before),
    after_score: riskScore(after),
    findings_diff: findingsDiff,
  };
}
