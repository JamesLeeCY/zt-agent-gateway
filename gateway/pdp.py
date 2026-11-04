"""Client for the Policy Decision Point (OPA). Any failure is a deny (fail closed, rule R1)."""
import httpx

VALID_RESULTS = {"allow", "deny", "require_approval"}


class PdpClient:
    def __init__(self, opa_url: str, package_path: str = "agent/authz", timeout: float = 2.0):
        self._url = f"{opa_url.rstrip('/')}/v1/data/{package_path}"
        self._client = httpx.AsyncClient(timeout=timeout)

    async def decide(self, decision_input: dict) -> dict:
        try:
            resp = await self._client.post(self._url, json={"input": decision_input})
            resp.raise_for_status()
            doc = resp.json().get("result") or {}
            decision = doc.get("decision") or {}
            result = decision.get("result")
            if result not in VALID_RESULTS:
                raise ValueError("PDP returned no usable decision")
            return {
                "result": result,
                "reasons": sorted(decision.get("reasons", [])),
                "policy_version": doc.get("policy_version", "unknown"),
            }
        except Exception as exc:  # noqa: BLE001 - fail closed on anything
            return {
                "result": "deny",
                "reasons": [f"R1: no decision from PDP, fail closed ({type(exc).__name__})"],
                "policy_version": "unavailable",
            }

    async def aclose(self):
        await self._client.aclose()
