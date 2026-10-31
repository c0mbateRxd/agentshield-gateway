"""Oracle client: 2 s timeout, no retries, fails closed (callers map OracleError -> HOLD_ORACLE_UNAVAILABLE).
Endpoint paths are ASSUMPTIONS pending Kirti (CCR-G1)."""
import httpx


class OracleError(Exception):
    pass


class OracleClient:
    def __init__(self, base_url: str, timeout: float = 2.0):
        self._http = httpx.Client(base_url=base_url, timeout=timeout)

    def _call(self, method: str, path: str, **kw) -> dict:
        try:
            r = self._http.request(method, path, **kw)
            r.raise_for_status()
            return r.json()
        except (httpx.HTTPError, ValueError) as e:
            raise OracleError(f"{path}: {e}") from e

    def penny_drop(self, account: str, ifsc: str) -> dict:  # -> {"holder_name": str}
        return self._call("POST", "/v1/penny-drop", json={"account": account, "ifsc": ifsc})

    def gstin(self, gstin: str) -> dict:  # -> {"legal_name": str, "trade_name": str}
        return self._call("GET", f"/v1/gstin/{gstin}")

    def ais(self, port: str) -> dict:  # -> {"port": str, "berthed_today": int, "threshold": int}
        return self._call("GET", f"/v1/ais/{port}")

    def health(self) -> dict:
        return self._call("GET", "/v1/health")
