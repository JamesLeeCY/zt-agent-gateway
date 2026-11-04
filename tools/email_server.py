"""Mock MCP server: outbound email. Nothing leaves the machine; mail is appended to var/outbox.jsonl."""
import json
from datetime import datetime, timezone

from mcp.server.fastmcp import FastMCP

from tools.paths import OUTBOX

mcp = FastMCP("email", log_level="WARNING")


@mcp.tool()
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email to the given address."""
    OUTBOX.parent.mkdir(parents=True, exist_ok=True)
    msg = {"ts": datetime.now(timezone.utc).isoformat(), "to": to, "subject": subject, "body": body}
    with OUTBOX.open("a", encoding="utf-8") as f:
        f.write(json.dumps(msg, ensure_ascii=False) + "\n")
    return json.dumps({"status": "sent", "to": to})


if __name__ == "__main__":
    mcp.run()
