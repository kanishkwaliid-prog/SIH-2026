"""
Tests for block2b/redaction.py. No network, no API key needed.

Run from src/backend:
    python -m pytest block2b/test_redaction.py -v
or without pytest:
    python block2b/test_redaction.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from block2b.redaction import redact_sensitive  # noqa: E402

# (label, input, [must NOT appear in output], [must STILL appear in output])
LEAK_CASES = [
    # ---- secrets that leaked before the fix ----
    ("radius key",        "radius-server key MySharedSecret123",
     ["MySharedSecret123"], ["radius-server key"]),
    ("tacacs key 7",      "tacacs-server host 10.1.1.1 key 7 0822455D0A16",
     ["0822455D0A16", "10.1.1.1"], ["tacacs-server host", "key 7"]),
    ("isakmp key",        "crypto isakmp key VPNsecret address 1.2.3.4",
     ["VPNsecret", "1.2.3.4"], ["crypto isakmp key", "address"]),
    ("pre-shared-key",    'pre-shared-key ascii-text "abc123"',
     ["abc123"], ["pre-shared-key", "ascii-text"]),
    ("ntp auth key",      "ntp authentication-key 1 md5 NtpSecret99",
     ["NtpSecret99"], ["authentication-key", "md5"]),
    ("key-string",        "key-string 7 0822455D0A16",
     ["0822455D0A16"], ["key-string"]),
    # ---- other vendors ----
    ("fortigate password", "set password ENC SH2abcdefghijklmnop==",
     ["SH2abcdefghijklmnop"], ["set password"]),
    ("fortigate psk",      "set psksecret ENC abcXYZ123==",
     ["abcXYZ123"], ["psksecret"]),
    ("fortigate key",      "set key MyFortiKey42",
     ["MyFortiKey42"], ["set key"]),
    ("junos password",     'set system login user bob authentication encrypted-password "$6$abc$XYZ"',
     ["$6$abc$XYZ", "bob"], ["encrypted-password"]),
    # ---- existing behaviour must still work ----
    ("cisco secret 5",    "username admin secret 5 $1$abcd$efgh",
     ["$1$abcd$efgh", "admin"], ["secret 5"]),
    ("enable secret",     "enable secret 9 $9$abcdefg",
     ["$9$abcdefg"], ["enable secret 9"]),
    ("snmp community",    "snmp-server community S3cretComm RO",
     ["S3cretComm"], ["snmp-server community", "RO"]),
    ("snmp host comm",    "snmp-server host 10.0.0.5 version 2c HostComm",
     ["HostComm", "10.0.0.5"], ["version 2c"]),
    ("snmp v3",           "snmp-server user snmpadmin grp v3 auth sha AuthPass123 priv aes 128 PrivPass456",
     ["snmpadmin", "AuthPass123", "PrivPass456"], ["v3", "auth sha", "priv aes 128"]),
    # ---- identities the old filter did not hide ----
    ("hostname",          "hostname CORE-SW-01",
     ["CORE-SW-01"], ["hostname"]),
    ("junos host-name",   "set system host-name bank-fw-mumbai",
     ["bank-fw-mumbai"], ["host-name"]),
    ("domain name",       "ip domain-name corp.examplebank.com",
     ["examplebank"], ["ip domain-name"]),
    ("ntp fqdn",          "ntp server time.examplebank.com",
     ["examplebank"], ["ntp server"]),
    ("email",             "snmp-server contact netadmin@examplebank.com",
     ["netadmin", "examplebank"], ["snmp-server contact"]),
    ("url",               "archive path tftp://10.1.1.9/backups/core.cfg",
     ["10.1.1.9", "backups"], ["archive path"]),
    ("username only",     "username jsmith privilege 15",
     ["jsmith"], ["username", "privilege 15"]),
    ("acl name",          "ip access-list extended HR-FINANCE-MGMT",
     ["HR-FINANCE-MGMT"], ["ip access-list extended"]),
    ("access-group",      "ip access-group HR-FINANCE-MGMT in",
     ["HR-FINANCE-MGMT"], ["ip access-group", "in"]),
    # ---- free text ----
    ("description",       "description Uplink to HR Finance floor 3",
     ["HR Finance", "floor 3"], ["description"]),
    ("acl remark",        "access-list 101 remark Allow payroll server",
     ["payroll"], ["access-list 101"]),
    ("snmp location",     "snmp-server location Mumbai DC Rack 14",
     ["Mumbai", "Rack 14"], ["snmp-server location"]),
    # ---- addresses ----
    ("ipv6",              "ipv6 address 2001:db8:85a3::8a2e:370:7334/64",
     ["2001:db8", "8a2e"], ["ipv6 address"]),
    ("ipv6 short",        "ipv6 route ::/0 fe80::1",
     ["fe80::1"], ["ipv6 route"]),
    ("mac dotted",        "mac address-table static 0011.2233.4455 vlan 10",
     ["0011.2233.4455"], ["mac address-table static", "vlan 10"]),
    ("mac colon",         "arp 00:11:22:33:44:55",
     ["00:11:22:33:44:55"], ["arp"]),
    ("ipv4 (existing)",   "ip route 192.168.10.0 255.255.255.0 10.0.0.1",
     ["192.168.10.0", "10.0.0.1"], ["ip route"]),
]

# Lines with no sensitive content: must come back UNCHANGED, otherwise the
# classifier loses information it needs.
UNCHANGED_CASES = [
    "aaa new-model",
    "logging trap informational",
    "crypto key generate rsa",
    "crypto key generate rsa modulus 2048",
    "line vty 0 4",
    "exec-timeout 10 0",
    "no service pad",
    "service password-encryption",
    "no ip domain lookup",
    "ip ssh version 2",
    "key chain KEYS",          # 'chain' is not a secret value
    "key 1",                   # key ID, not a secret
    "access-list 101 permit tcp any any eq 22",
    "transport input ssh",
    "set system login idle-timeout 10",
    "set system login password minimum-length 8",
    '      "password_encryption": "type7",',
    "12:30:45 UTC Mon Jan 1 2024",
]


def _check_leak_case(label, text, gone, kept):
    out = redact_sensitive(text)
    for s in gone:
        assert s not in out, f"[{label}] leaked {s!r}: {out!r}"
    for s in kept:
        assert s in out, f"[{label}] lost structure {s!r}: {out!r}"


def test_sensitive_values_removed_and_structure_kept():
    for case in LEAK_CASES:
        _check_leak_case(*case)


def test_benign_lines_unchanged():
    for line in UNCHANGED_CASES:
        assert redact_sensitive(line) == line, f"changed benign line: {line!r} -> {redact_sensitive(line)!r}"


def test_banner_multiline_closed():
    text = "hostname R1\nbanner motd ^C\nAuthorized users only. Property of ExampleBank.\nCall +91-22-5550100\n^C\nline vty 0 4"
    out = redact_sensitive(text)
    assert "ExampleBank" not in out and "5550100" not in out
    assert "banner motd" in out and "line vty 0 4" in out


def test_banner_single_line_hash_delimiter():
    out = redact_sensitive("banner login #Restricted - ExampleBank IT#")
    assert "ExampleBank" not in out and "banner login" in out


def test_banner_cut_off_at_40_line_snippet():
    # the vendor-guess path sends only the first 40 lines, so a banner can be unclosed
    out = redact_sensitive("banner motd ^C\nSecret internal warning text\nmore text")
    assert "Secret internal" not in out and "more text" not in out


def test_fortigate_login_banner():
    out = redact_sensitive('set post-login-banner "Property of ExampleBank"')
    assert "ExampleBank" not in out and "post-login-banner" in out


def test_idempotent():
    for _, text, _, _ in LEAK_CASES:
        once = redact_sensitive(text)
        assert redact_sensitive(once) == once, f"not idempotent: {text!r}"


def test_realistic_snippet_has_no_leaks():
    """A realistic first-40-lines snippet, like what guess_vendor() sends."""
    snippet = """\
version 15.2
hostname MUM-CORE-01
!
enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0
username netops privilege 15 secret 9 $9$abcDEF
ip domain-name mum.examplebank.com
ip name-server 10.20.30.40
!
banner motd ^C
Authorized access only - ExampleBank Mumbai DC
^C
!
interface GigabitEthernet0/1
 description Uplink to Finance-Core (contact: r.sharma)
 ip address 10.1.2.1 255.255.255.0
 ipv6 address 2001:db8:10::1/64
!
snmp-server community BankPublic RO
snmp-server location Mumbai DC Rack 14
radius-server host 10.9.9.9 key 7 0822455D0A16
tacacs-server key TacacsKey!77
ip access-group MGMT-ONLY in
"""
    out = redact_sensitive(snippet)
    for bad in ["MUM-CORE-01", "hx5rVt7", "netops", "abcDEF", "examplebank", "ExampleBank",
                "10.20.30.40", "Finance-Core", "r.sharma", "10.1.2.1", "2001:db8", "BankPublic",
                "Mumbai", "0822455D0A16", "TacacsKey", "MGMT-ONLY", "10.9.9.9"]:
        assert bad not in out, f"leaked {bad!r} in:\n{out}"
    # structure the classifier needs is still there
    for good in ["enable secret 5", "snmp-server community", "radius-server host",
                 "interface GigabitEthernet0/1", "ip access-group"]:
        assert good in out, f"lost {good!r} in:\n{out}"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS  {fn.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL  {fn.__name__}: {e}")
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
