from decimal import Decimal


def format_inr(amount) -> str:
    """format_inr(980000) -> '₹9,80,000' (Indian digit grouping)."""
    d = Decimal(str(amount))
    sign = "-" if d < 0 else ""
    whole, _, frac = f"{abs(d):f}".partition(".")
    frac = frac.rstrip("0")
    head, tail = whole[:-3], whole[-3:]
    groups = []
    while len(head) > 2:
        groups.insert(0, head[-2:])
        head = head[:-2]
    if head:
        groups.insert(0, head)
    out = ",".join(groups + [tail])
    return f"{sign}₹{out}" + (f".{frac}" if frac else "")
