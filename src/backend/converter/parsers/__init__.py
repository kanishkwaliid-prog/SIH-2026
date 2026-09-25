"""
Block 2a - Parser dispatch.

Maps a vendor name to its parser function. To support a new vendor,
add one line here and create the corresponding parser file -- nothing
else in the pipeline needs to change.
"""

from .cisco import parse_cisco
from .juniper import parse_juniper
from .paloalto import parse_paloalto

PARSER_DISPATCH = {
    "cisco_ios": parse_cisco,
    "juniper_junos": parse_juniper,
    "palo_alto": parse_paloalto,
}
