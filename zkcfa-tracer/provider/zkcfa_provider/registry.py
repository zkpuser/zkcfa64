"""HTTP registry for fresh raw24 challenges and one-time report verification."""

from __future__ import annotations

import argparse
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from .protocol import RawRegistryService, _regular_json, _write_json_new
from .persistent_registry import PersistentRawRegistryService


class RawRegistryHandler(BaseHTTPRequestHandler):
    server: "RawRegistryHTTPServer"

    def _json_body(self) -> object:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > 2 * 1024 * 1024:
            raise ValueError("invalid JSON body length")
        return json.loads(self.rfile.read(length))

    def _reply(self, status: HTTPStatus, value: object) -> None:
        body = (json.dumps(value, sort_keys=True) + "\n").encode("ascii")
        self.send_response(status.value)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        wanted = (
            "/raw/registry/"
            f"{self.server.service.registry['raw_registry_id']}"
        )
        if urlparse(self.path).path != wanted:
            self._reply(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        self._reply(HTTPStatus.OK, self.server.service.envelope)

    def do_POST(self) -> None:  # noqa: N802
        try:
            body = self._json_body()
            path = urlparse(self.path).path
            if path == "/raw/challenges":
                if not isinstance(body, dict):
                    raise ValueError("raw challenge request must be an object")
                result = self.server.service.issue_challenge(
                    str(body.get("device_id", "")),
                    str(body.get("raw_registry_id", "")),
                )
            elif path == "/raw/reports/verify":
                result = self.server.service.verify_report(body)
            else:
                self._reply(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return
            self._reply(HTTPStatus.OK, result)
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            self._reply(HTTPStatus.BAD_REQUEST, {"error": str(error)})

    def log_message(self, message: str, *args: object) -> None:
        print(f"[raw-registry] {self.address_string()} {message % args}")


class RawRegistryHTTPServer(ThreadingHTTPServer):
    def __init__(self, address: tuple[str, int], service: RawRegistryService) -> None:
        self.service = service
        super().__init__(address, RawRegistryHandler)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, required=True)
    parser.add_argument("--authority-public", type=Path, required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8081)
    parser.add_argument("--ready-file", type=Path)
    parser.add_argument("--state-db", type=Path,
                        help="persist challenge issuance/consumption across restarts")
    args = parser.parse_args()
    registry = _regular_json(args.registry, "raw authority registry")
    service = (
        PersistentRawRegistryService(registry, args.authority_public, state_path=args.state_db)
        if args.state_db else RawRegistryService(registry, args.authority_public)
    )
    server = RawRegistryHTTPServer((args.host, args.port), service)
    if args.ready_file:
        _write_json_new(
            args.ready_file,
            {
                "host": server.server_address[0],
                "port": server.server_address[1],
                "raw_registry_id": service.registry["raw_registry_id"],
            },
        )
    print(
        "raw registry listening on "
        f"http://{server.server_address[0]}:{server.server_address[1]}"
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
