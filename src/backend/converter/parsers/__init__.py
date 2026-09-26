"""
Block 2a - Parser dispatch.

Maps a vendor name to its parser function. To support a new vendor,
add one line here and create the corresponding parser file -- nothing
else in the pipeline needs to change.
"""

from .cisco import parse_cisco
from .juniper import parse_juniper
from .paloalto import parse_paloalto
from .fortinet import parse_fortinet
from .arista import parse_arista
from .huawei import parse_huawei
from .mikrotik import parse_mikrotik
from .checkpoint import parse_checkpoint
from .netgate_pfsense import parse_netgate_pfsense
from .sonic import parse_sonic

PARSER_DISPATCH = {
    "cisco_ios": parse_cisco,
    "juniper_junos": parse_juniper,
    "palo_alto": parse_paloalto,
    "fortinet_fortios": parse_fortinet,
    "arista_eos": parse_arista,
    "huawei_vrp": parse_huawei,
    "mikrotik_routeros": parse_mikrotik,
    "checkpoint_gaia": parse_checkpoint,
    "netgate_pfsense": parse_netgate_pfsense,
    "sonic": parse_sonic,
}