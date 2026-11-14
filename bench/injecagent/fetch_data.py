"""Download the InjecAgent data files (MIT, github.com/uiuc-kang-lab/InjecAgent) at a pinned commit.

  bench/.venv/Scripts/python -m bench.injecagent.fetch_data
"""
from pathlib import Path

import httpx

COMMIT = "f19c9f2c79a41046eb13c03c51a24c567a8ffa07"
FILES = ["attacker_cases_dh.jsonl", "attacker_cases_ds.jsonl", "user_cases.jsonl", "tools.json",
         "test_cases_dh_base.json", "test_cases_ds_base.json", "test_cases_dh_enhanced.json",
         "test_cases_ds_enhanced.json"]
DATA = Path(__file__).parent / "data"


def main():
    DATA.mkdir(exist_ok=True)
    for f in FILES:
        url = f"https://raw.githubusercontent.com/uiuc-kang-lab/InjecAgent/{COMMIT}/data/{f}"
        body = httpx.get(url, timeout=60, follow_redirects=True).raise_for_status().content
        (DATA / f).write_bytes(body)
        print(f"{f}: {len(body):,} bytes")


if __name__ == "__main__":
    main()
