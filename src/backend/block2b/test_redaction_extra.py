"""
Extra tests (fix4). Run from src/backend:  python block2b/test_redaction_extra.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from block2b.redaction import redact_sensitive, residual_risk  # noqa: E402

# (input, secret/name that must NOT survive)
LEAKS = [
    ("neighbor CORE-SW-02 remote-as 65001", "CORE-SW-02"),
    ("neighbor 10.0.0.2 password BgpSecret9", "BgpSecret9"),
    ("ip vrf CUSTOMER-ACME", "ACME"),
    ("route-map TO-PAYROLL-DC permit 10", "PAYROLL"),
    ("snmp-server view PAYVIEW iso included", "PAYVIEW"),
    ("crypto pki trustpoint ACME-CA", "ACME"),
    ("-----BEGIN RSA PRIVATE KEY-----\nMIIEvQIBADANBgkq\n-----END RSA PRIVATE KEY-----", "MIIEvQ"),
    ("-----BEGIN CERTIFICATE-----\nMIIDdzCCAl+gAwIBAgIE\nabc", "MIIDdz"),
    ("ip host billing-db 10.5.5.5", "billing"),
    ("ntp server time.acme.xyz", "acme.xyz"),
    ("interface Vlan10\n name FINANCE-LAN", "FINANCE"),
    ("vlan 20\n name HR-Payroll Dept", "Payroll"),
    ("aaa group server tacacs+ ACME-TAC", "ACME"),
    ("wpa-psk ascii 0 MyWifiPass", "MyWifiPass"),
    ("set wireless-controller wtp-profile name ACME-AP", "ACME"),
    ("license smart token abc123TOKENxyz", "abc123TOKENxyz"),
    ("snmp-server host 10.1.1.1 traps v1 CommunityV1", "CommunityV1"),
    ("snmp-server host 10.1.1.1 CommPlain", "CommPlain"),
    ("ip ospf message-digest-key 1 md5 OspfSecret", "OspfSecret"),
    ("ip ospf authentication-key OspfPlain", "OspfPlain"),
    ("standby 1 authentication md5 key-string HsrpKey", "HsrpKey"),
    ("radius-server host 10.1.1.1 auth-port 1812 key RadKey1", "RadKey1"),
    ("tacacs server T1\n address ipv4 10.1.1.1\n key TacKey2", "TacKey2"),
    ("crypto isakmp key 6 abcdef address 0.0.0.0", "abcdef"),
    ("crypto pki certificate chain X\n 30820324 30820200 A0030201 02020401\n quit", "30820324"),
]

# lines that must come back unchanged and must not trip the safety gate
BENIGN = [
    "aaa new-model", "logging trap informational", "crypto key generate rsa",
    "line vty 0 4", "exec-timeout 10 0", "no service pad", "service password-encryption",
    "ip ssh version 2", "key chain KEYS", "key 1", "transport input ssh",
    "ip ssh time-out 60", "router ospf 1", "boot system flash:c2900-universalk9.bin",
    "archive path flash:backup.cfg", "ipv6 neighbor discovery", "snmp-server enable traps config",
    "token-ring speed 16", "crypto key zeroize rsa", "no logging console",
    "spanning-tree mode rapid-pvst", "12:30:45 UTC Mon Jan 1 2024",
]

# raw (unredacted) text the safety gate must flag
GATE_MUST_FLAG = [
    "password Abc12345xyz", "-----BEGIN RSA PRIVATE KEY-----", "tacacs-server key Tac123abc",
    "10.1.1.1", "a" * 45,
]


def test_extra_leaks_removed():
    for text, secret in LEAKS:
        out = redact_sensitive(text)
        assert secret not in out, f"leaked {secret!r}: {out!r}"


def test_extra_idempotent():
    for text, _ in LEAKS:
        once = redact_sensitive(text)
        assert redact_sensitive(once) == once, f"not idempotent: {text!r}"


def test_extra_benign_unchanged():
    for line in BENIGN:
        assert redact_sensitive(line) == line, f"changed: {line!r} -> {redact_sensitive(line)!r}"
        assert not residual_risk(line), f"gate false positive: {line!r} {residual_risk(line)}"


def test_gate_quiet_after_redaction():
    for text, _ in LEAKS:
        out = redact_sensitive(text)
        assert not residual_risk(out), f"gate flags redacted text {out!r}: {residual_risk(out)}"


def test_gate_flags_raw_secrets():
    for raw in GATE_MUST_FLAG:
        assert residual_risk(raw), f"gate missed {raw[:30]!r}"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn(); print(f"PASS  {fn.__name__}")
        except AssertionError as e:
            failed += 1; print(f"FAIL  {fn.__name__}: {e}")
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
