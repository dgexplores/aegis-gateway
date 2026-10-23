"""Server-side AEGIS example. Supply the deployment URL and key through environment variables."""

import argparse
import json
import os

import httpx


def ask(question: str) -> dict:
    response = httpx.post(
        os.environ["AEGIS_BASE_URL"].rstrip("/") + "/v1/chat",
        headers={"Authorization": "Bearer " + os.environ["AEGIS_API_KEY"]},
        json={"messages": [{"role": "user", "content": question}]},
        timeout=40,
    )
    response.raise_for_status()
    return response.json()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("question", help="Use fictional input for public-demo requests")
    args = parser.parse_args()
    try:
        result = ask(args.question)
    except KeyError:
        parser.error("Set AEGIS_BASE_URL and AEGIS_API_KEY in the server environment.")
    except httpx.HTTPError as exc:
        print(f"Gateway request failed ({type(exc).__name__}). Check status and retry policy server-side.")
        return 1
    state = "refused" if result["blocked"] else "test-output" if result["provider"] == "echo" else "response"
    print(json.dumps({"state": state, "answer": result["answer"], "provider": result["provider"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
