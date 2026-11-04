"""Mock MCP server: the relationship manager's mailbox (UNTRUSTED external content)."""
import json

from mcp.server.fastmcp import FastMCP

from tools.paths import DATA_DIR

mcp = FastMCP("inbox", log_level="WARNING")


def render(m: dict) -> str:
    """Render like a mail client's raw view: headers, then the body as received (HTML included)."""
    return (f"Message-ID: {m['message_id']}\nDate: {m['date']}\nFrom: {m['from']}\nTo: {m['to']}\n"
            f"Subject: {m['subject']}\nContent-Type: {m['content_type']}\n\n{m['body']}")


@mcp.tool()
def read_inbox(mailbox: str, limit: int = 1) -> str:
    """Read the most recent customer emails in the mailbox, newest first."""
    folder = DATA_DIR / "inbox" / mailbox
    if not folder.is_dir():
        return f"(mailbox {mailbox} is empty)"
    files = sorted(folder.glob("*.json"), reverse=True)[: max(1, min(limit, 10))]
    return "\n\n".join(render(json.loads(f.read_text(encoding="utf-8"))) for f in files)


if __name__ == "__main__":
    mcp.run()
