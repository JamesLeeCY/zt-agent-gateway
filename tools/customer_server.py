"""Mock MCP server: internal customer database (TRUSTED source, returns PII)."""
import json

from mcp.server.fastmcp import FastMCP

from tools.paths import DATA_DIR

mcp = FastMCP("customer", log_level="WARNING")


@mcp.tool()
def query_customer(customer_id: str) -> str:
    """Look up a customer's profile and account summary by customer ID (e.g. C-1001)."""
    db = json.loads((DATA_DIR / "customers.json").read_text(encoding="utf-8"))["customers"]
    record = db.get(customer_id.strip().upper())
    if record is None:
        return json.dumps({"error": f"customer {customer_id!r} not found"})
    return json.dumps(record, ensure_ascii=False)


if __name__ == "__main__":
    mcp.run()
