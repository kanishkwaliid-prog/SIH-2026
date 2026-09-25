"""block2b/rules_prefilter.py — deterministic layer, runs before the model."""
import re

# Order matters: the first match wins, so negations precede positives.
RULES = [
    ("ssh_enabled:false",      r"^no\s+ip\s+ssh\b"),
    ("ssh_enabled:false",      r"^ip\s+ssh\s+disable\b"),
    ("ssh_enabled:true",       r"^ip\s+ssh\s+version\s+[12]\b"),
    # Confirmed in real_eval.csv (1x) -- no live rule existed for this phrasing.
    ("ssh_enabled:true",       r"^ip\s+ssh\s+server\s+enable$"),
    ("ssh_enabled:true",       r"^set\s+system\s+services\s+ssh\b"),
    # Ported from label_helper.py; no eval hit yet but same convention as
    # the confirmed rules around it.
    ("ssh_enabled:true",       r"^set\s+admin-ssh-password\s+enable$"),
    # Juniper/VyOS-style stanza removal.
    ("ssh_enabled:false",      r"^(delete|deactivate)\s+system\s+services\s+ssh\b"),
    ("ssh_enabled:false",      r"^delete\s+service\s+ssh\b"),
    # RouterOS-style key=value toggle -- ported from label_helper.py's
    # existing (never-live) rule, same convention as the telnet pair below.
    ("ssh_enabled:false",      r"^set\s+ssh\b.*\bdisabled=yes\b"),
    ("ssh_enabled:true",       r"^set\s+ssh\b.*\bdisabled=no\b"),
    # FortiGate admin-access removal.
    ("ssh_enabled:false",      r"^unset\s+allow-service\b.*\bsshd?\b"),
    # Ported from label_helper.py (the "no allow-service sshd" / bare
    # enable-form pair) -- no eval hit yet.
    ("ssh_enabled:false",      r"^no\s+allow-service\s+sshd$"),
    ("ssh_enabled:true",       r"^allow-service\s+sshd$"),
    ("ssh_enabled:false",      r"^disable\s+ssh$"),
    ("ssh_enabled:false",      r"^ssh\s+server\s+disable$"),
    # Ported from label_helper.py -- no eval hit yet.
    ("ssh_enabled:true",       r"^protocol:\s*secure-shell$"),

    ("telnet_enabled:false",   r"^no\s+(transport\s+input\s+)?telnet\b"),
    ("telnet_enabled:false",   r"disable-telnet\s+yes\b"),
    # Ported from label_helper.py (never made it into the live matcher).
    ("telnet_enabled:true",    r"^set\s+admin-telnet\s+enable$"),
    ("telnet_enabled:false",   r"^set\s+admin-telnet\s+disable$"),
    ("telnet_enabled:false",   r"^no\s+telnet-server$"),
    ("telnet_enabled:true",    r"^set\s+system\s+services\s+telnet$"),
    # Ported from label_helper.py -- distinct phrasing from the rule above
    # ("system-execute-telnet" vs "system services telnet"), no eval hit yet.
    ("telnet_enabled:true",    r"^set\s+system-execute-telnet\s+enable$"),
    ("telnet_enabled:false",   r"^set\s+telnet\b.*\bdisabled=yes\b"),
    ("telnet_enabled:true",    r"^set\s+telnet\b.*\bdisabled=no\b"),
    # Ported from label_helper.py -- no eval hit yet.
    ("telnet_enabled:true",    r"^feature\s+telnet\b"),
    ("telnet_enabled:true",    r"^protocol:\s*legacy-telnet$"),

    ("logging_enabled:false",  r"^no\s+logging\s+(on|trap)\b"),
    ("unclear",                r"^no\s+logging\s+(?!on\b|trap\b)\S+"),
    ("logging_enabled:true",   r"^logging\s+(on|enable|trap|buffered|host)\b"),
    # Ported from label_helper.py -- no eval hit yet.
    ("logging_enabled:true",   r"^service\s+timestamps\s+(log|debug)\b"),
    ("logging_enabled:true",   r"^set\s+system\s+syslog\s+(file|host)\b"),
    ("logging_enabled:false",  r"^(delete|deactivate)\s+system\s+syslog\b"),
    # PAN-OS log-forwarding -- confirmed 4x in real_eval.csv, ported from
    # label_helper.py's PAN-OS rules.
    ("logging_enabled:true",   r"^set\s+(shared\s+|panorama\s+|template\s+\S+\s+config\s+(shared\s+)?)?"
                                r"log-settings\b.*\bsend-syslog\b"),
    ("logging_enabled:true",   r"^set\s+log-collector-group\b.*log-settings\b.*\bsend-syslog\b"),

    ("banner_configured:true", r"^banner\s+(motd|login|exec)\b"),
    # Confirmed 3x in real_eval.csv (pre-login-banner / post-login-banner /
    # PAN-OS deviceconfig login-banner) -- the old rule required the exact
    # "banner motd|login|exec" prefix and missed all of these.
    ("banner_configured:true", r"\blogin-banner\b"),

    ("password_encryption:none",  r"^no\s+service\s+password-encryption\b"),
    ("password_encryption:type7", r"^service\s+password-encryption\b"),
    ("password_encryption:type7", r"\bpassword\s+7\s+\S+"),
    # Ported from label_helper.py's "(secret|password) 7" convention --
    # old rule only covered the "password 7" half.
    ("password_encryption:type7", r"\bsecret\s+7\s+\S+"),
    ("password_encryption:type5", r"\bsecret\s+5\s+\S+"),
    # Confirmed 2x in real_eval.csv -- old rule only covered "secret 5".
    ("password_encryption:type5", r"\bpassword\s+5\s+\S+"),
    # Ported from label_helper.py -- no eval hit yet.
    ("password_encryption:type5", r"\busers\s+\S+\s+phash\s+\$1\$"),
    ("password_encryption:type5", r"^enable\s+secret\s+(?!\d\b)\S+"),
    ("password_encryption:none",  r"\bpassword\s+0\s+\S+"),
    # Ported from label_helper.py -- no eval hit yet.
    ("password_encryption:none",  r"\bsecret\s+0\s+\S+"),
    ("password_encryption:none",  r"^enable\s+password\s+(?!7\b)\S+"),
    ("password_encryption:none",  r"^hash-algo:\s*none\b"),
    # Bare "password <token>" as the WHOLE line (no digit code, no other
    # tokens) -- e.g. a truncated RouterOS user-add fragment like
    # "password operator". Mirrors label_helper.py's line-49 convention.
    # Anchored to exactly two tokens so it can't shadow the type7/type5/
    # type0 rules above, which all require a digit as the second token.
    ("password_encryption:none",  r"^password\s+\S+$"),
]

_COMPILED = [(lbl, re.compile(p, re.IGNORECASE)) for lbl, p in RULES]


def rule_labels(line: str) -> set[str]:
    """Every label this line deterministically implies. Empty set = no rule fired."""
    text = line.strip()
    if not text or text.startswith(("!", "#")):
        return set()

    # `transport input` is genuinely multi-label — handle it before the table.
    m = re.match(r"^transport\s+input\s+(.+)$", text, re.IGNORECASE)
    if m:
        modes = m.group(1).lower().split()
        if "all" in modes:
            return {"ssh_enabled:true", "telnet_enabled:true"}
        if "none" in modes:
            return {"ssh_enabled:false", "telnet_enabled:false"}
        out = set()
        if "ssh" in modes:
            out.add("ssh_enabled:true")
        if "telnet" in modes:
            out.add("telnet_enabled:true")
        return out

    for label, pat in _COMPILED:
        if pat.search(text):
            return {label}
    return set()