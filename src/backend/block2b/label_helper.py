"""
Steps 2 and 3 helper: draft labels for labeling_sheet.csv, then split the
reviewed sheet into real_eval.csv and new training rows.

Save as block2b/label_helper.py. Run from src/backend/:

  python -m block2b.label_helper draft     # fills labels by rule, flags what needs YOU
  ... open block2b/labeling_sheet_drafted.csv in Excel, fix every row where
      auto == REVIEW (label is blank), skim the rest, save (keep it as CSV) ...
  python -m block2b.label_helper finish    # validates, writes real_eval.csv,
                                           # appends train rows to the training CSV

The drafted labels are MY reading of what each line means, following the
conventions already in your training CSV. You are the final judge: skim
them, especially anything with auto == rule.
"""
import csv
import os
import re
import shutil
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
SHEET = os.path.join(BASE, "labeling_sheet.csv")
DRAFT = os.path.join(BASE, "labeling_sheet_drafted.csv")
TRAIN = os.path.join(BASE, "prefilter_training_data.csv")
EVAL = os.path.join(BASE, "real_eval.csv")

# Timeout lines are always deferred to Groq (needs arithmetic), so they are
# not labeled here at all. Same idea as _TIMEOUT_PATTERN in prefilter.py.
TIMEOUT = re.compile(r"exec-timeout|session[-_ ]?timeout|idle-timeout|idle-limit|time-out", re.I)

# Lines that mention something we care about but no rule below settled them.
KEYWORDS = re.compile(r"ssh|telnet|logging|syslog|banner|password|secret|encrypt|hash|snmp|http", re.I)

# (regex, label). First match wins. Order matters.
RULES = [
    # --- password encryption ---
    (r"^no service password-encryption$", "password_encryption:none"),
    (r"^service password-encryption$", "password_encryption:type7"),
    (r"\b(secret|password)\s+5\s", "password_encryption:type5"),
    (r"\b(secret|password)\s+7\s", "password_encryption:type7"),
    (r"\b(secret|password)\s+0\s", "password_encryption:none"),
    (r"\bsecret\s+(8|9)\s", None),                         # type8/9: no such label -> REVIEW
    (r"^enable password\s+\S+$", "password_encryption:none"),
    (r"^enable secret\s+\S+$", "password_encryption:type5"),   # matches existing 'enable secret cisco123'
    (r"^username\s+\S+.*\bpassword\s+\S+$", "password_encryption:none"),
    (r"^username\s+\S+.*\bsecret\s+\S+$", "password_encryption:type5"),
    (r"^password\s+\S+$", "password_encryption:none"),          # plaintext line password
    (r"^hash-algo:\s*none", "password_encryption:none"),
    # --- new: PAN-OS syslog / log-forwarding config ---
    (r"^set (shared |panorama |template \S+ config (shared )?)?log-settings .*\bsend-syslog\b", "logging_enabled:true"),
    (r"^set (shared |panorama |template \S+ config (shared )?)?log-settings syslog \S+ server \S+ (transport|port|format|facility|server)\b", "logging_enabled:true"),
    (r"^set log-collector-group .*log-settings .*(send-syslog|filter|description)", "logging_enabled:true"),
    (r"\busers\s+\S+\s+phash\s+\$1\$", "password_encryption:type5"),
        # --- new: real telnet/ssh disable lines found in this batch ---
    (r"^no telnet-server$", "telnet_enabled:false"),
    (r"^set telnet disabled=yes$", "telnet_enabled:false"),
    (r"^set admin-telnet disable$", "telnet_enabled:false"),
    (r"^set system-execute-telnet enable$", "telnet_enabled:true"),
    (r"^ip ssh server enable$", "ssh_enabled:true"),
    (r"^set admin-ssh-password enable$", "ssh_enabled:true"),

    # --- new: comments / noise in other styles ---
    (r"^;", "SKIP"),
    (r"^//", "SKIP"),
    (r"^\*", "SKIP"),

    # --- new: HTML/JS junk embedded in FortiGate replacemsg buffers ---
    (r"<(script|html|head|body|style|input|label|img|a href|button|title|link|h1)\b", "unclear"),
    (r"^set buffer ", "unclear"),
    (r"^var \w+ = new XMLHttpRequest", "unclear"),

    # --- new: FortiGate address-book objects and system config noise ---
    (r'^edit "', "unclear"),
    (r"^config (system replacemsg|firewall ssh|firewall ssl-ssh-profile|switch-controller snmp|switch-controller|wireless-controller|log syslogd\d?)", "unclear"),
    (r"^config (https|http|ssh)$", "unclear"),
    (r"^set snmp-index \d+$", "unclear"),

    # --- new: encrypted secret blobs / hashes not in {none,type5,type7} ---
    (r"\bENC [A-Za-z0-9+/=]{10,}", "unclear"),
    (r"\bsecret (sha512|sha256|8|9)\b", "unclear"),
    (r"\bpassword (ciphertext|manager|operator)\b", "unclear"),
    (r"\b(radius-server|encrypted-password|private-key|BEGIN (RSA |ENCRYPTED |OPENSSH )?PRIVATE KEY|BEGIN CERTIFICATE|key-string|key-hash|keychain|psksecret|sae-password|priv-pwd|auth-pwd)\b", "unclear"),
    (r"^hash (sha256|sha512)$", "unclear"),

    # --- new: VPN/IPsec, not password/ssh/telnet/logging ---
    (r"\b(ipsec|ike proposal|encryption-algorithm|enc-algorithm|dpd-)\b", "unclear"),

    # --- new: XML tags (OPNsense) ---
    (r"^<[a-zA-Z_]+[ />]", "unclear"),
    (r"^</[a-zA-Z_]+>$", "SKIP"),

    # --- new: source/version comment lines ---
    (r"^// (Source|Snapshot|vyos-config-version)", "SKIP"),

    # --- new: RouterOS bare-path headers and false keyword hits ---
    (r"^/(system logging|snmp|ip ssh)\b", "unclear"),
    (r"connection-mark=HTTP|packet-mark=HTTP", "unclear"),
        # --- new: RouterOS multi-line command continuations (end with backslash) ---
    (r"\\\s*$", "unclear"),

    # --- new: password-hash lines with any $N$ hash format, regardless of prefix ---
    (r"\b(password|secret)\S*\$\d+\$", "unclear"),
    (r"^username \S+.*\bnopassword\b", "unclear"),
    (r"^username \S+ password <redacted>", "unclear"),

    # --- new: FortiGate policy/profile config headers, not on/off toggles ---
    (r"^config (user|system) password-policy", "unclear"),
    (r"^config (ssh-filter profile|firewall access-proxy-ssh-client-cert)$", "unclear"),
    (r"^set (encryption|encrypt-and-store-password|private-data-encryption|mac-event-logging|save-password) (disable|enable)$", "unclear"),
    (r"^set (password-renewal|pull-malware-hash) enable$", "unclear"),
    (r"^set password-encoding \w+$", "unclear"),
    (r"^set mac-password-delimiter \w+$", "unclear"),
    (r"^set admin-telnet-port \d+$", "unclear"),
    (r"^unset ssh-public-key\d+$", "unclear"),
    (r'^set ssl-ssh-profile\b', "unclear"),

    # --- new: SSH public keys, ACL/security-zone lines mentioning ssh/telnet as a service, not toggles ---
    (r'\bpublic-key "ssh-', "unclear"),
    (r"\b(permit|deny)\b.*\beq (ssh|telnet)\b", "unclear"),
    (r"^ssh (server|client)\b", "unclear"),
    (r"^set groups \S+ system (services (ssh|netconf ssh)|authentication-order)\b", "unclear"),
    (r"^set (security zones .* system-services (ssh|https)|access profile \S+ authentication-order|security remote-access client-config \S+ credentials password)\b", "unclear"),
    (r"^telnet vrf \S+ ipv4 server\b", "unclear"),
    (r"^no hardware multicast hw-hash$", "unclear"),

    # --- new: trailing/embedded XML comment closers ---
    (r"-->\s*$", "SKIP"),
    (r"^<!--", "SKIP"),

    # --- new: RouterOS user-add line ---
    (r"^/user add\b", "unclear"),

    # --- new: broad SNMP/HTTP catch-all (place LAST so specific rules above win first) ---
    
    (r"\bhttps?\b", "unclear"),
    # --- new: not in our schema, but keeps them from re-flagging as REVIEW ---
    (r"\bmgt-config password-complexity\b", "unclear"),
    (r"^key config-key password-encrypt", "unclear"),
    (r"^set mgt-config users \S+ password$", "unclear"),
    (r"^key\s+CHANGE_ME", "unclear"),
    (r"^set .*profiles decryption .*ssh-proxy", "unclear"),
    (r"^set deviceconfig system config-bundle-export-schedule", "unclear"),
    (r"^no ip http (secure-)?server", "unclear"),
    (r"snmp-setting", "unclear"),
    (r"^set .*profiles (url-filtering|virus)\b", "unclear"),
    (r"\bdeviceconfig setting (logging log-suppression|management hostname-type-in-syslog)\b", "unclear"),
    (r"^notify syslog$", "unclear"),
    # --- new: comment / section-header lines, always dropped ---
    (r"^!", "SKIP"),
    (r"^#", "SKIP"),
        # --- new: telnet/ssh explicit enable/disable (put before generic catch-alls) ---
    (r"^set admin-telnet enable$", "telnet_enabled:true"),
    (r"^set system services telnet$", "telnet_enabled:true"),
    (r"^set telnet .*\bdisabled=yes\b", "telnet_enabled:false"),
    (r"^set telnet .*\bdisabled=no\b", "telnet_enabled:true"),
    (r"^set ssh .*\bdisabled=yes\b", "ssh_enabled:false"),
    (r"^set ssh .*\bdisabled=no\b", "ssh_enabled:true"),

    # --- new: syslog detail lines (file/host/archive config, not on/off) ---
    (r"\bsystem syslog\b.*\b(archive|interactive-commands)\b", "unclear"),
    (r"\bsystem syslog\b", "logging_enabled:true"),
    (r"^(no )?logging (event|btrace)\b", "unclear"),
    (r"^clear logging\b", "unclear"),

    # --- new: SSH/telnet algorithm, cipher, vrf, port, key-management detail (not on/off) ---
    (r"^(ip )?ssh (server |client )?(algorithm|mac|cipher|rsa keypair-name|pubkey-chain|bulk-mode|maxstartups|key rsa|server (vrf|netconf|rate-limit))\b", "unclear"),
    (r"^set (ssh-\w+|admin-ssh-\w*|system-execute-(ssh|telnet)|hostkey-\w+|caname|untrusted-caname|event-type ssh-logs)\b", "unclear"),
    (r"^(ip |no ip )?access-(list|class) SSH-Allowed$", "unclear"),
    (r"\bssh server v2\b", "unclear"),
    (r"\btelnet,ssh\b|\bpolicy=.*telnet.*ssh\b|policy=\"local,telnet", "unclear"),

    # --- new: hashes, secrets, keys, hostnames containing a keyword substring ---
    (r"^password \d+ \S+$", "unclear"),
    (r"^key 7 \S+$", "unclear"),
    (r"\bsecret (10|9|8) \$", "unclear"),
    (r"PRIVATE KEY-----", "unclear"),
    (r"^hostname \S+$", "unclear"),
    (r"^input\[type=", "unclear"),
    (r"^(ssh|syslog) \{$", "SKIP"),

    # --- new: misc unrelated-but-keyword-matching config ---
    (r"^no password strength-check$", "unclear"),
    (r"\bencryption mode ciphers\b", "unclear"),
    (r"^crypto logging\b", "unclear"),
    (r"^privilege exec level \d+ show logging$", "unclear"),
    (r"^description .*LOGGING", "unclear"),
    (r"^set (auth-mode-l1|auth-mode-l2|type) password$", "unclear"),
    (r"^Password=", "unclear"),
    (r"^This is a test banner$", "unclear"),

    # --- fix: snmp catch-all was missing snmpv3 (no word boundary after 'snmp') ---
    (r"\bsnmp\w*", "unclear"),
    # --- telnet / ssh ---
    (r"^no transport input telnet", "telnet_enabled:false"),
    (r"^transport input none", "telnet_enabled:false"),
    (r"^transport input .*\b(telnet|all)\b", "telnet_enabled:true"),
    (r"^transport input .*\bssh\b", "ssh_enabled:true"),
    (r"^no telnet$", "telnet_enabled:false"),
    (r"^feature telnet", "telnet_enabled:true"),
    (r"disable-telnet\s+yes", "telnet_enabled:false"),
    (r"^protocol:\s*legacy-telnet", "telnet_enabled:true"),
    (r"^protocol:\s*secure-shell", "ssh_enabled:true"),
    (r"^(no ip ssh|ip ssh disable|no allow-service sshd)$", "ssh_enabled:false"),
    (r"^(ip ssh version \d|set system services ssh|allow-service sshd)", "ssh_enabled:true"),
    (r"^ip ssh authentication-retries", "unclear"),
    # --- logging ---
    (r"^logging synchronous", "unclear"),
    (r"^no logging console", "unclear"),
    (r"^no logging (on|trap)", "logging_enabled:false"),
    (r"^logging\b", "logging_enabled:true"),
    (r"^service timestamps (log|debug)", "logging_enabled:true"),  # follows existing convention
    (r"^set system syslog archive", "unclear"),
    (r"^set system syslog", "logging_enabled:true"),
    # --- banner ---
    (r"^banner\b|login-banner", "banner_configured:true"),
    # --- clearly not ours (would otherwise trip the keyword net) ---
    (r"^snmp-server", "unclear"),
    (r"^ip http (secure-)?server", "unclear"),
    (r"^set system services web-management", "unclear"),
    (r"^set deviceconfig system service disable-http", "unclear"),
    (r"^(aaa |login local|set system login|set system authentication-order)", "unclear"),
    (r"^set system services dhcp", "unclear"),
    (r"^enabled:\s*(true|false)$", "unclear"),                  # single line can't say what is enabled
]
RULES = [(re.compile(p, re.I), lab) for p, lab in RULES]


def draft_label(line):
    if TIMEOUT.search(line):
        return "SKIP", "SKIP"
    for rx, lab in RULES:
        if rx.search(line):
            return (lab, "rule") if lab else ("", "REVIEW")
    if KEYWORDS.search(line):
        return "", "REVIEW"
    return "unclear", "default"


def read_csv(path):
    with open(path, newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def cmd_draft():
    rows = read_csv(SHEET)
    counts = {}
    for r in rows:
        if r["label"].strip():                  # you already labeled it, keep it
            r["auto"] = "manual"
        else:
            r["label"], r["auto"] = draft_label(r["line"].strip())
        counts[r["auto"]] = counts.get(r["auto"], 0) + 1
    fields = list(rows[0].keys())
    with open(DRAFT, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    print(f"{len(rows)} rows -> {DRAFT}\n{counts}\n")
    print("Fix these (label is blank) before running `finish`:")
    for r in rows:
        if r["auto"] == "REVIEW":
            print(f"  [{r['source_file']}] {r['line']}")
    print("\nauto == SKIP rows are timeout lines; leave them, `finish` drops them.")


def cmd_finish():
    rows = read_csv(DRAFT)
    train_rows = read_csv(TRAIN)
    allowed = {r["label"].strip() for r in train_rows} | {"unclear"}
    train_lines = {r["line"].strip() for r in train_rows}

    errors, seen, keep = [], {}, []
    for r in rows:
        line, lab = r["line"].strip(), r["label"].strip()
        if lab == "SKIP":
            continue
        if not lab:
            errors.append(f"blank label: {line!r}")
        elif lab not in allowed:
            errors.append(f"unknown label {lab!r}: {line!r}")
        elif line in seen and seen[line] != lab:
            errors.append(f"conflicting labels for {line!r}: {seen[line]} vs {lab}")
        seen[line] = lab
        keep.append((r["split"].strip(), line, lab))
    if errors:
        print("Fix these in labeling_sheet_drafted.csv, then re-run:")
        for e in errors[:40]:
            print("  ", e)
        sys.exit(1)

    ev, new_train, already = [], [], 0
    for split, line, lab in keep:
        if line in train_lines:
            already += 1               # model already trained on it: useless as a test
            continue
        (ev if split == "eval" else new_train).append((line, lab))

    with open(EVAL, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["line", "label"])
        w.writerows(ev)

    shutil.copy(TRAIN, TRAIN + ".bak")
    with open(TRAIN, "rb") as f:
        needs_nl = not f.read().endswith((b"\n", b"\r"))
    with open(TRAIN, "a", newline="", encoding="utf-8") as f:
        if needs_nl:
            f.write("\r\n")
        w = csv.writer(f, lineterminator="\r\n")
        w.writerows(new_train)

    print(f"real_eval.csv: {len(ev)} rows  ->  {EVAL}")
    print(f"training CSV: appended {len(new_train)} rows (backup: {TRAIN}.bak)")
    print(f"skipped {already} lines that were already in the training CSV")


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ("draft", "finish"):
        sys.exit("usage: python -m block2b.label_helper draft|finish")
    {"draft": cmd_draft, "finish": cmd_finish}[sys.argv[1]]()
