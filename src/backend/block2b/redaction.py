"""
redaction.py -- scrub sensitive values from config text BEFORE it is sent
to the cloud LLM (Groq).

The classifier only needs COMMAND STRUCTURE ("is this an SSH command? what
password-encryption scheme?"). It never needs a real IP, hostname, username,
description, key, banner text, etc., so hiding them costs no accuracy.

WHAT IS COVERED (each category has tests in test_redaction.py)
  secrets      password / secret / passwd / passphrase / pre-shared-key /
               psksecret / authentication-key / key-string / "key <value>"
               (radius, tacacs, isakmp, ...) / SNMP communities and v3 auth+priv
  identities   hostname, username, domain names, e-mail addresses, URLs
  free text    interface/ACL descriptions, remarks, comments, SNMP
               location/contact, banner text (multi-line)
  names        ACL names (numeric ACL numbers are kept)
  addresses    IPv4, IPv6, MAC (colon, dash and Cisco dotted forms)

WHAT IS NOT GUARANTEED
  This is a pattern-based filter, not a full DLP system. A sensitive value in
  a syntax we have not seen can still get through. When you find one, add a
  pattern + a test. Do not describe this as "nothing sensitive is sent";
  describe it as "known sensitive categories are stripped before sending".
"""
import ipaddress
import re

_I = re.IGNORECASE
_M = re.MULTILINE
_S = re.DOTALL

# a value is either a "quoted string" or a bare token
_VAL = r'"[^"\r\n]*"|\S+'
# a value that has already been replaced by a placeholder like <REDACTED>
_NOT_PLACEHOLDER = r'(?!<[A-Z_]+>)'
# "secret 5 <REDACTED>": the 5 is a type number, not the value (keeps rules idempotent)
_NOT_TYPE_THEN_PLACEHOLDER = (r'(?!(?:(?:enc|encrypted|ascii-text|hex|local|remote|clear|md5|sha\d*|'
                              r'hmac-sha\d+|cmac-aes-128|level|\d+)[ \t]+)*<[A-Z_]+>)')

# ---------------------------------------------------------------------------
# 1. Banners (multi-line). Cisco:  banner motd ^C ... ^C   /  banner login # ... #
# ---------------------------------------------------------------------------
_BANNER_CLOSED = re.compile(
    r'(\bbanner\s+[\w-]+\s+)(\^C|\S)(.*?)\2', _I | _S)
_BANNER_UNCLOSED = re.compile(
    r'(\bbanner\s+[\w-]+\s+(?:\^C|(?!\^C)\S))(?!<BANNER_REDACTED>)(.*)\Z', _I | _S)
# other vendors: FortiGate pre/post-login-banner, Junos "message"/"announcement"
_BANNER_QUOTED = re.compile(
    r'(\b(?:pre-login-banner|post-login-banner|admin-console-banner|'
    r'message|announcement)\s+)("[^"]*"|\S+)', _I)

# ---------------------------------------------------------------------------
# 2. URLs and e-mail addresses
# ---------------------------------------------------------------------------
_URL = re.compile(r'\b(?:https?|ftp|tftp|scp|sftp)://\S+', _I)
_EMAIL = re.compile(r'[\w.+-]+@[\w-]+(?:\.[\w-]+)+')

# ---------------------------------------------------------------------------
# 3. Identities / names
# ---------------------------------------------------------------------------
_HOSTNAME = re.compile(
    r'\b(hostname|host-name|sysname|switchname)(\s+)' + _NOT_PLACEHOLDER +
    r'(' + _VAL + r')', _I)
_USERNAME = re.compile(
    r'\b(username|local-user|login\s+user)(\s+)' + _NOT_PLACEHOLDER + r'(\S+)', _I)
_SNMP_NAMES = re.compile(
    r'\b(snmp-server\s+(?:user|group)\s+)' + _NOT_PLACEHOLDER + r'(\S+)', _I)
_DOMAIN = re.compile(
    r'\b((?:ip\s+)?domain[-\s]name|domain-search|ip\s+domain-list|'
    r'ip\s+domain(?!\s*-?lookup))(\s+)' + _NOT_PLACEHOLDER + r'(\S+)', _I)

# ACL names (numeric ACL numbers are kept so the classifier can still tell
# "access-list 101 permit ..." apart)
_ACL_NAME_1 = re.compile(
    r'\b(ip(?:v6)?\s+access-list\s+(?:(?:extended|standard|role-based|logging)\s+)?)'
    r'(?!\d+\b)' + r'(?!(?:extended|standard|role-based|logging)\s+<[A-Z_]+>)' + _NOT_PLACEHOLDER + r'(\S+)', _I)
_ACL_NAME_2 = re.compile(
    r'\b((?:access-group|access-class|traffic-filter)\s+)'
    r'(?!\d+\b)' + _NOT_PLACEHOLDER + r'(\S+)', _I)
_ACL_NAME_3 = re.compile(
    r'\b(access-list\s+)(?!\d+\b)'
    r'(?!(?:extended|standard|resequence|role-based|logging|compiled|'
    r'log-update|deny-flow-max|alert-interval)\b)' + _NOT_PLACEHOLDER + r'(\S+)', _I)

# free-text fields: everything after the keyword to end of line
_FREE_TEXT = re.compile(
    r'(\b(?:description|remark|comment|alias|contact|location)\b)([ \t]+)'
    r'(?!<TEXT_REDACTED>)(.+)$', _I | _M)

# ---------------------------------------------------------------------------
# 4. Secrets
# ---------------------------------------------------------------------------
# Words that may sit between the keyword and the real value and are NOT the
# secret: type numbers (5, 7, 9), "ENC" (FortiGate), "ascii-text", "level 15",
# hash names used by NTP keys, etc. They are kept so the classifier can still
# tell type5 from type7.
_MODS = (r'(?:(?:enc|encrypted|ascii-text|hex|local|remote|clear|md5|sha1|sha256|'
         r'sha384|sha512|hmac-sha1|hmac-sha256|cmac-aes-128|level\s+\d+|[0-9](?=\s))\s+)*')

# Words that follow "password"/"secret" but are a policy keyword, not a value
# (e.g. Junos "password minimum-length 8").
_POLICY_WORDS = (r'(?!(?:minimum-length|minimum-changes|maximum-length|change-type|'
                 r'format|complexity|history|aging|lockout|encryption|policy|'
                 r'min-length|max-age|strength)\b)')

_SECRET_KEYWORDS = (r'(?:enable\s+)?(?:secret|password|passwd|passphrase|psksecret|'
                    r'pre-shared-key|preshared-key|shared-secret|encrypted-password|'
                    r'auth-password|priv-password|private-key|authentication-key|'
                    r'auth-key|md5-key|hmac-key|key-string)')

_SECRET = re.compile(
    r'(?<![\w-])(' + _SECRET_KEYWORDS + r')(\s+' + _MODS + r')'
    + _POLICY_WORDS + _NOT_PLACEHOLDER + _NOT_TYPE_THEN_PLACEHOLDER + r'(' + _VAL + r')', _I)

# "key <value>" as used by radius-server, tacacs-server, crypto isakmp, FortiGate...
# Excluded: "crypto key generate rsa", "key chain X", etc. (not secrets).
_KEY = re.compile(
    r'(?<![\w-])(key)(\s+(?:[0-7]\s+)?)'
    r'(?!(?:generate|chain|zeroize|config-key|pubkey-chain|export|import|'
    r'exchange|size|length|type|encrypt)\b)' + _NOT_PLACEHOLDER
    + _NOT_TYPE_THEN_PLACEHOLDER + r'(' + _VAL + r')', _I)

# SNMP
_SNMP_COMMUNITY = re.compile(r'((?:snmp-server|snmp)\s+community\s+)(\S+)', _I)
_SNMP_HOST_COMM = re.compile(r'(version\s+\d+c\s+)(\S+)', _I)
_SNMP_V3_AUTH = re.compile(r'(\bauth\s+(?:md5|sha\w*)\s+)' + _NOT_PLACEHOLDER + r'(\S+)', _I)
_SNMP_V3_PRIV = re.compile(
    r'(\bpriv\s+(?:des|3des|aes)(?:\s+\d+)?\s+)' + _NOT_PLACEHOLDER + r'(?!\d+\s+<[A-Z_]+>)' + r'(\S+)', _I)

# ---------------------------------------------------------------------------
# 5. Network addresses
# ---------------------------------------------------------------------------
_IPV4 = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b')
_MAC_COLON = re.compile(r'\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b', _I)
_MAC_DOTTED = re.compile(r'\b[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}\b', _I)
# candidate token for IPv6; validated with the ipaddress module below so that
# things like timestamps (12:30:45) and MACs are left alone by this rule.
_IPV6_CANDIDATE = re.compile(r'(?<![\w:.])([0-9A-Fa-f:.]{3,})(/\d{1,3})?(?![\w:])')

_TLDS = (r'com|net|org|edu|gov|mil|int|io|co|in|uk|de|fr|nl|se|no|ch|es|it|us|ca|'
         r'au|eu|ru|cn|jp|info|biz|local|lan|corp|internal|intranet|home|arpa')
_FQDN = re.compile(
    r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:' + _TLDS + r')\b', _I)


def _ipv6_cb(m):
    token = m.group(1)
    if token.count(':') < 2:
        return m.group(0)
    try:
        ipaddress.IPv6Address(token.split('%')[0])
    except ValueError:
        return m.group(0)
    return '<IPV6_ADDR>'


def _key_cb(m):
    # A bare "key 1" line inside a key chain is a key ID, not a secret.
    s = m.string
    start = s.rfind('\n', 0, m.start()) + 1
    end = s.find('\n', m.end())
    end = len(s) if end < 0 else end
    if re.fullmatch(r'\s*key\s+\d+\s*', s[start:end], _I):
        return m.group(0)
    return m.group(1) + m.group(2) + '<REDACTED>'


def redact_sensitive(text: str) -> str:
    """Return `text` with sensitive values replaced by placeholders.

    Keywords and structure are kept (so the LLM can still classify the
    command); only the values are replaced. Safe to call more than once on
    the same text (idempotent).
    """
    if not text:
        return text
    t = text

    # 1. banners first, so their contents are not half-processed by other rules
    t = _BANNER_CLOSED.sub(lambda m: f"{m.group(1)}{m.group(2)}<BANNER_REDACTED>{m.group(2)}", t)
    t = _BANNER_UNCLOSED.sub(lambda m: f"{m.group(1)}<BANNER_REDACTED>", t)
    t = _BANNER_QUOTED.sub(lambda m: f"{m.group(1)}<BANNER_REDACTED>", t)

    # 2. URLs / e-mail
    t = _URL.sub('<URL>', t)
    t = _EMAIL.sub('<EMAIL>', t)

    # 3. identities and free text
    t = _HOSTNAME.sub(lambda m: f"{m.group(1)}{m.group(2)}<HOSTNAME>", t)
    t = _USERNAME.sub(lambda m: f"{m.group(1)}{m.group(2)}<USERNAME>", t)
    t = _SNMP_NAMES.sub(lambda m: f"{m.group(1)}<USERNAME>", t)
    t = _DOMAIN.sub(lambda m: f"{m.group(1)}{m.group(2)}<DOMAIN>", t)
    t = _ACL_NAME_1.sub(lambda m: f"{m.group(1)}<ACL_NAME>", t)
    t = _ACL_NAME_2.sub(lambda m: f"{m.group(1)}<ACL_NAME>", t)
    t = _ACL_NAME_3.sub(lambda m: f"{m.group(1)}<ACL_NAME>", t)
    t = _FREE_TEXT.sub(lambda m: f"{m.group(1)}{m.group(2)}<TEXT_REDACTED>", t)

    # 4. secrets
    t = _SECRET.sub(lambda m: f"{m.group(1)}{m.group(2)}<REDACTED>", t)
    t = _KEY.sub(_key_cb, t)
    t = _SNMP_COMMUNITY.sub(lambda m: f"{m.group(1)}<REDACTED>", t)
    t = _SNMP_HOST_COMM.sub(lambda m: f"{m.group(1)}<REDACTED>", t)
    t = _SNMP_V3_AUTH.sub(lambda m: f"{m.group(1)}<REDACTED>", t)
    t = _SNMP_V3_PRIV.sub(lambda m: f"{m.group(1)}<REDACTED>", t)

    # 5. addresses (IPv4 last-but-one so IPv6 with embedded v4 is still caught)
    t = _MAC_COLON.sub('<MAC_ADDR>', t)
    t = _MAC_DOTTED.sub('<MAC_ADDR>', t)
    t = _IPV6_CANDIDATE.sub(_ipv6_cb, t)
    t = _IPV4.sub('<IP_ADDR>', t)
    t = _FQDN.sub('<DOMAIN>', t)

    return t


# ===========================================================================
# ---- extra rules (fix4): more secrets, names, key blocks + safety gate ----
# ===========================================================================
_redact_base = redact_sensitive

_PEM = re.compile(r'-----BEGIN [A-Z0-9 ]+-----.*?-----END [A-Z0-9 ]+-----', _S)
_PEM_OPEN = re.compile(r'-----BEGIN [A-Z0-9 ]+-----(?!<KEY_BLOCK_REDACTED>).*\Z', _S)
_HEX_BLOB = re.compile(r'^[ \t]*(?:[0-9a-fA-F]{8}[ \t]*){3,}$', _M)

_X_SECRETS = [
    # OSPF / RIP / HSRP style keys: "message-digest-key 1 md5 <secret>"
    re.compile(r'(\bmessage-digest-key\s+\d+\s+(?:md5|sha\w*)\s+(?:[0-9]\s+)?)(?!<)(?![0-9]\s+<[A-Z_]+>)(\S+)', _I),
    re.compile(r'(\bwpa-psk\s+(?:ascii|hex)\s+(?:[0-9]\s+)?)(?!<)(?![0-9]\s+<[A-Z_]+>)(\S+)', _I),
    re.compile(r'(\bwpa-passphrase\s+(?:[0-9]\s+)?)(?!<)(?![0-9]\s+<[A-Z_]+>)(\S+)', _I),
    re.compile(r'((?<![\w-])psk\s+(?:(?:ascii|hex)\s+)?(?:[0-9]\s+)?)(?!<)(?![0-9]\s+<[A-Z_]+>)(?!(?:ascii|hex)\b)(\S+)', _I),
    # license / API tokens
    re.compile(r'(?<![\w-])((?:api[-\s])?token\s+)(?!<)(?!(?:bucket|ring)\b)(\S+)', _I),
    # SNMP v1 / plain community on "snmp-server host": host [traps|informs] [version x] <community>
    re.compile(r'(\bsnmp-server\s+host\s+\S+\s+(?:(?:traps|informs)\s+)?'
               r'(?:version\s+(?:1|2c|3\s+(?:auth|noauth|priv))\s+|v1\s+|v2c\s+)?)'
               r'(?!<)(?!(?:version|traps|informs|vrf|udp-port|v1|v2c|v3)\b)(\S+)', _I),
]

_X_NAMES = [
    (re.compile(r'(\bvrf\s+(?:definition\s+|forwarding\s+|context\s+)?)(?!<)'
                r'(?!(?:definition|forwarding|context|upstream)\b)(\S+)', _I), '<VRF_NAME>'),
    (re.compile(r'(\broute-map\s+)(?!<)(\S+)', _I), '<NAME>'),
    (re.compile(r'(\bsnmp-server\s+view\s+)(?!<)(\S+)', _I), '<NAME>'),
    (re.compile(r'(\btrustpoint\s+)(?!<)(\S+)', _I), '<NAME>'),
    (re.compile(r'(\bneighbor\s+)(?!<)(?!(?:discovery|detection|advertisement)\b)(\S+)', _I), '<NEIGHBOR>'),
    (re.compile(r'(\bip\s+host\s+)(?!<)(\S+)', _I), '<HOSTNAME>'),
    (re.compile(r'(\bgroup\s+server\s+(?:radius|tacacs\+?|ldap)\s+)(?!<)(\S+)', _I), '<NAME>'),
    (re.compile(r'(\b(?:tacacs|radius)\s+server\s+)(?!<)(\S+)', _I), '<NAME>'),
]
# "name <text>" at the start of a line (VLAN / interface / object names): whole line
_X_NAME_LINE = re.compile(r'^([ \t]*(?:set[ \t]+)?name[ \t]+)(?!<)(.+)$', _I | _M)
# "... name <token>" mid-line (e.g. wtp-profile name X)
_X_NAME_INLINE = re.compile(r'(?<![\w-])(name\s+)(?!<)(\S+)', _I)

_X_FQDN = re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b', _I)
_FILE_EXT = {'cfg', 'txt', 'conf', 'bin', 'pkg', 'tar', 'log', 'json', 'xml', 'csv', 'img',
             'lic', 'dat', 'db', 'py', 'sh', 'yaml', 'yml', 'gz', 'zip', 'pdf', 'tcl', 'cer', 'crt', 'pem'}


def _fqdn_cb(m):
    tail = m.group(0).rsplit('.', 1)[-1].lower()
    return m.group(0) if tail in _FILE_EXT else '<DOMAIN>'


def redact_sensitive(text: str) -> str:
    """Base redaction + extra rules. Idempotent."""
    if not text:
        return text
    t = _PEM.sub('<KEY_BLOCK_REDACTED>', text)
    t = _PEM_OPEN.sub('<KEY_BLOCK_REDACTED>', t)
    t = _HEX_BLOB.sub('<CERT_DATA_REDACTED>', t)
    t = _redact_base(t)
    for rx in _X_SECRETS:
        t = rx.sub(lambda m: f"{m.group(1)}<REDACTED>", t)
    for rx, ph in _X_NAMES:
        t = rx.sub(lambda m, ph=ph: f"{m.group(1)}{ph}", t)
    t = _X_NAME_LINE.sub(lambda m: f"{m.group(1)}<TEXT_REDACTED>", t)
    t = _X_NAME_INLINE.sub(lambda m: f"{m.group(1)}<NAME>", t)
    t = _X_FQDN.sub(_fqdn_cb, t)
    return t


# ---- safety gate: last check on text that is ABOUT to be sent ----
_RISK_PATTERNS = [
    ('key/cert block', re.compile(r'BEGIN [A-Z0-9 ]*(?:KEY|CERTIFICATE)', _I)),
    ('long hex string', re.compile(r'\b[0-9a-fA-F]{32,}\b')),
    ('long token', re.compile(r'[A-Za-z0-9+/=_-]{40,}')),
    ('IPv4 address', _IPV4),
    ('MAC address', _MAC_COLON),
    ('MAC address', _MAC_DOTTED),
    ('e-mail', _EMAIL),
    ('URL', _URL),
    ('secret-like value', re.compile(
        r'(?<![\w-])(?:password|secret|passwd|passphrase|psk|token|community|key-string|key)\s+'
        r'(?:[0-9]\s+)*(?!<)(?=\S*\d)(?=\S*[A-Za-z])\S{6,}', _I)),
]


def residual_risk(text: str) -> list:
    """Reasons this (already redacted) text still looks unsafe to send. Empty = ok."""
    if not text:
        return []
    return sorted({name for name, rx in _RISK_PATTERNS if rx.search(text)})
