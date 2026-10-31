"""Tool contracts from MASTER_SPEC section 9. Moves to agentshield_contracts once Pavan's package exists."""
from jsonschema import Draft202012Validator

S = {"type": "string"}
INT = {"type": "integer", "minimum": 0}
DATE = {"type": "string", "pattern": r"^\d{4}-\d{2}-\d{2}$"}


def _obj(props: dict, optional: tuple = ()) -> dict:
    return {"type": "object", "properties": props, "additionalProperties": False,
            "required": [k for k in props if k not in optional]}


_ITEM = _obj({"purchase_order_item": S, "quantity": {"type": "integer", "minimum": 1}, "unit_price_inr": INT})

SCHEMAS = {
    "read_inbox": _obj({"unread_only": {"type": "boolean"}}, optional=("unread_only",)),
    "get_document_text": _obj({"document_id": S}),
    "get_purchase_order": _obj({"purchase_order": S}),
    "get_goods_receipts": _obj({"purchase_order": S}),
    "get_supplier": _obj({"supplier": S}),
    "get_supplier_bank": _obj({"supplier": S}),
    "list_open_invoices": _obj({"supplier": S}, optional=("supplier",)),
    "post_supplier_invoice": _obj({
        "supplier": S, "purchase_order": S, "supplier_invoice_ref": S, "invoice_date": DATE,
        "items": {"type": "array", "minItems": 1, "items": _ITEM},
        "gross_amount_inr": INT, "source_document_id": S}),
    "execute_payment": _obj({"supplier_invoice": S, "fiscal_year": S, "amount_inr": INT}),
    "update_supplier_bank": _obj({"supplier": S, "bank_account_holder_name": S, "bank_account": S,
                                  "ifsc": S, "reason": S, "source_message_id": S}),
    "book_freight": _obj({"purchase_order": S, "mode": {"enum": ["AIR", "SEA"]}, "quoted_cost_inr": INT,
                          "claimed_delay_days": INT, "reason": S, "source_message_id": S}),
    "flag_suspicious_message": _obj({"message_id": S, "reason": S}),
    "request_human_approval": _obj({"action_summary": S, "reason": S, "related_decision_id": S},
                                   optional=("related_decision_id",)),
    "complete_task": _obj({"summary": S}),
}

KIND = {"read_inbox": "read", "get_document_text": "read", "get_purchase_order": "read",
        "get_goods_receipts": "read", "get_supplier": "read", "get_supplier_bank": "read",
        "list_open_invoices": "read", "post_supplier_invoice": "write", "execute_payment": "write",
        "update_supplier_bank": "write", "book_freight": "write", "flag_suspicious_message": "control",
        "request_human_approval": "control", "complete_task": "control"}

ENVELOPE = _obj({"call_id": S, "idempotency_key": S, "task_id": S, "step_id": S, "tool": S,
                 "args": {"type": "object"}, "issued_at": S}, optional=("idempotency_key",))

_validators = {t: Draft202012Validator(s) for t, s in SCHEMAS.items()}
_envelope = Draft202012Validator(ENVELOPE)


def schema_errors(tool: str, args: dict) -> list[str]:
    return [f"{'/'.join(map(str, e.path)) or '$'}: {e.message}" for e in _validators[tool].iter_errors(args)]


def envelope_errors(body) -> list[str]:
    return [f"{'/'.join(map(str, e.path)) or '$'}: {e.message}" for e in _envelope.iter_errors(body)]
