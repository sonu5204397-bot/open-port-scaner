"""A bounded TCP port scanner for authorized testing."""

from __future__ import annotations

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from flask import Flask, jsonify, render_template, request

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

MAX_HOST_LENGTH = 1000
MAX_PORTS_PER_SCAN = 5000
CONNECT_TIMEOUT = 0.4
MAX_WORKERS = 32


class ScanError(Exception):
    """An expected, user-displayable scan error."""


@dataclass(frozen=True)
class TargetAddress:
    family: int
    address: tuple


def _validate_input(
    raw_host: object,
    raw_start: object,
    raw_end: object,
    authorized: object,
) -> tuple[str, int, int]:
    if authorized is not True:
        raise ScanError(
            "Confirm that you own this system or have explicit authorization to test it."
        )

    if not isinstance(raw_host, str) or not raw_host.strip():
        raise ScanError("Enter an IP address or hostname.")

    host = raw_host.strip()

    if len(host) > MAX_HOST_LENGTH or any(
        character.isspace() for character in host
    ):
        raise ScanError("Enter a valid IP address or hostname.")

    try:
        ipaddress.ip_address(host)
    except ValueError:
        try:
            ascii_host = host.encode("idna").decode("ascii")
        except UnicodeError as error:
            raise ScanError(
                "Enter a valid IP address or hostname."
            ) from error

        labels = ascii_host.rstrip(".").split(".")

        if (
            not ascii_host
            or len(ascii_host) > MAX_HOST_LENGTH
            or any(
                not label
                or len(label) > 63
                or label.startswith("-")
                or label.endswith("-")
                or not all(
                    character.isalnum() or character == "-"
                    for character in label
                )
                for label in labels
            )
        ):
            raise ScanError("Enter a valid IP address or hostname.")

    def parse_port(value: object) -> int:
        if isinstance(value, int) and not isinstance(value, bool):
            return value

        if isinstance(value, str) and value.isdecimal():
            return int(value)

        raise ValueError("Port must be a whole number.")

    try:
        start_port = parse_port(raw_start)
        end_port = parse_port(raw_end)
    except ValueError as error:
        raise ScanError(
            "Enter a valid starting and ending port."
        ) from error

    if not (1 <= start_port <= end_port <= 65535):
        raise ScanError(
            "Ports must be between 1 and 65535, "
            "with the start no greater than the end."
        )

    if end_port - start_port + 1 > MAX_PORTS_PER_SCAN:
        raise ScanError(
            f"Scan no more than {MAX_PORTS_PER_SCAN} ports at a time."
        )

    return host, start_port, end_port


def _resolve_target(host: str) -> TargetAddress:
    try:
        addresses = socket.getaddrinfo(
            host, None, type=socket.SOCK_STREAM
        )
    except socket.gaierror as error:
        raise ScanError(
            "The hostname could not be resolved. Check it and try again."
        ) from error

    if not addresses:
        raise ScanError(
            "The hostname did not resolve to an IP address."
        )

    family, _, _, _, address = addresses[0]
    return TargetAddress(family, address)


def _check_port(target: TargetAddress, port: int) -> dict | None:
    if target.family == socket.AF_INET6:
        address = (
            target.address[0],
            port,
            *target.address[2:],
        )
    else:
        address = (target.address[0], port)

    try:
        with socket.socket(
            target.family, socket.SOCK_STREAM
        ) as connection:
            connection.settimeout(CONNECT_TIMEOUT)

            if connection.connect_ex(address) != 0:
                return None
    except OSError:
        return None

    try:
        service = socket.getservbyport(port, "tcp")
    except OSError:
        service = "Unknown"

    return {
        "port": port,
        "service": service,
    }


def scan_ports(
    host: str,
    start_port: int,
    end_port: int,
) -> list[dict]:
    """Check the requested TCP ports on one resolved address."""

    target = _resolve_target(host)
    ports = range(start_port, end_port + 1)

    with ThreadPoolExecutor(
        max_workers=min(MAX_WORKERS, len(ports))
    ) as executor:
        results = executor.map(
            lambda port: _check_port(target, port),
            ports,
        )
        return [
            result for result in results
            if result is not None
        ]


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/scan")
def scan():
    payload = request.get_json(silent=True)

    if not isinstance(payload, dict):
        return jsonify({
            "error": "Send scan details as a JSON object."
        }), 400

    try:
        host, start_port, end_port = _validate_input(
            payload.get("host"),
            payload.get("start_port"),
            payload.get("end_port"),
            payload.get("authorized"),
        )

        open_ports = scan_ports(
            host, start_port, end_port
        )

    except ScanError as error:
        return jsonify({"error": str(error)}), 400

    except Exception:
        app.logger.exception(
            "Unexpected error while scanning target"
        )
        return jsonify({
            "error": (
                "An unexpected error interrupted the scan. "
                "Check the server log."
            )
        }), 500

    return jsonify({
        "host": host,
        "start_port": start_port,
        "end_port": end_port,
        "ports_checked": end_port - start_port + 1,
        "open_ports": open_ports,
        "summary": (
            f"Found {len(open_ports)} open TCP port(s) "
            f"in the range {start_port}–{end_port}."
        ),
    })


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
    )
```
