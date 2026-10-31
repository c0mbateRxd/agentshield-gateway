"""ERP client. MASTER_SPEC section 12 was not in the shared text; paths below are ASSUMPTIONS recorded in
docs/contract-change-requests.md (CCR-G1). Tests inject a fake with the same interface."""
import httpx


class ErpUnavailable(Exception):
    pass


class ErpNotFound(Exception):
    pass


class ErpConflict(Exception):
    """kind: 'etag' (If-Match failed) or 'duplicate' (unique constraint / already paid)."""

    def __init__(self, kind: str):
        super().__init__(kind)
        self.kind = kind


READ_PATHS = {
    "inbox": "/sim/v1/inbox",
    "document": "/sim/v1/documents/{document_id}",
    "purchase_order": "/sim/v1/purchase-orders/{purchase_order}",
    "purchase_orders_for_supplier": "/sim/v1/suppliers/{supplier}/purchase-orders",
    "goods_receipts": "/sim/v1/purchase-orders/{purchase_order}/goods-receipts",
    "supplier": "/sim/v1/suppliers/{supplier}",
    "supplier_by_domain": "/sim/v1/suppliers/by-domain/{domain}",
    "supplier_bank": "/sim/v1/suppliers/{supplier}/bank",
    "invoices": "/sim/v1/supplier-invoices",  # ?supplier=
    "invoice": "/sim/v1/supplier-invoices/{fiscal_year}/{supplier_invoice}",
}
WRITE_PATHS = {
    "post_supplier_invoice": "/sim/v1/supplier-invoices",
    "execute_payment": "/sim/v1/payments",
    "update_supplier_bank": "/sim/v1/suppliers/{supplier}/bank",
    "book_freight": "/sim/v1/freight-bookings",
}


class ErpClient:
    def __init__(self, base_url: str, service_token: str, timeout: float = 5.0):
        self._http = httpx.Client(base_url=base_url, timeout=timeout,
                                  headers={"Authorization": f"Bearer {service_token}"})
        self.profile = "PROTECTED"

    def _headers(self, extra: dict | None = None) -> dict:
        return {"X-Sim-Profile": self.profile, **(extra or {})}

    def read(self, kind: str, **params) -> tuple[dict, str | None]:
        path = READ_PATHS[kind].format(**params)
        query = {"supplier": params["supplier"]} if kind == "invoices" and params.get("supplier") else None
        try:
            r = self._http.get(path, params=query, headers=self._headers())
        except httpx.HTTPError as e:
            raise ErpUnavailable(str(e)) from e
        if r.status_code == 404:
            raise ErpNotFound(path)
        if r.status_code >= 400:
            raise ErpUnavailable(f"{path} -> {r.status_code}")
        return r.json(), r.headers.get("etag")

    def write(self, tool: str, args: dict, if_match: str | None, idempotency_key: str | None) -> dict:
        path = WRITE_PATHS[tool].format(**args)
        headers = self._headers({k: v for k, v in
                                 {"If-Match": if_match, "Idempotency-Key": idempotency_key}.items() if v})
        try:
            r = self._http.post(path, json=args, headers=headers)
        except httpx.HTTPError as e:
            raise ErpUnavailable(str(e)) from e
        if r.status_code == 412:
            raise ErpConflict("etag")
        if r.status_code == 409:
            raise ErpConflict("duplicate")
        if r.status_code >= 400:
            raise ErpUnavailable(f"{path} -> {r.status_code}")
        return r.json()

    def state_digest(self) -> dict:
        try:
            r = self._http.get("/sim/v1/state-digest", headers=self._headers())
            r.raise_for_status()
            return r.json()
        except httpx.HTTPError as e:
            raise ErpUnavailable(str(e)) from e

    def reset(self) -> None:
        try:
            self._http.post("/sim/v1/reset", headers=self._headers()).raise_for_status()
        except httpx.HTTPError as e:
            raise ErpUnavailable(str(e)) from e
