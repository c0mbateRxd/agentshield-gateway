import re

from rapidfuzz import fuzz

_NOISE = {"PVT", "PRIVATE", "LTD", "LIMITED"}


def normalise(name: str) -> str:
    s = name.upper().replace("&", " ")
    s = re.sub(r"[^A-Z0-9 ]", " ", s)
    return " ".join(t for t in s.split() if t not in _NOISE)


def bank_name_score(holder: str, legal: str, trade: str) -> float:
    h = normalise(holder)
    return max(fuzz.token_set_ratio(h, normalise(legal)), fuzz.token_set_ratio(h, normalise(trade)))
