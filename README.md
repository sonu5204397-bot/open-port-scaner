# PORT SCANNER (PYTHON)

A beginner-friendly web tool for checking a bounded range of TCP ports on one IP address or hostname. It uses Python's built-in `socket` library and shows open ports with their registered service names when available.

> **Authorization required:** Scan only systems you own or have explicit authorization to test. Unauthorized port scanning may violate laws, contracts, or network policies. The confirmation checkbox is an acknowledgement, not technical verification of permission.

## Requirements

- Python 3.9 or newer
- pip

Flask is the only external dependency. Install it from `requirements.txt`.

## Installation

1. Clone this repository and move into the project directory:

   ```bash
   git clone https://github.com/sonu5204397-bot/open-port-scaner.git
   cd open-port-scaner
   ```

2. Create a virtual environment:

   ```bash
   python3 -m venv .venv
   ```

3. Activate the virtual environment.

   macOS/Linux:

   ```bash
   source .venv/bin/activate
   ```

   Windows PowerShell:

   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```

4. Install the required package:

   ```bash
   python -m pip install -r requirements.txt
   ```

## Run and scan

1. Start the application from the project directory:

   ```bash
   python app.py
   ```

2. Open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser.
3. Enter the IP address or hostname you are authorized to test.
4. Enter a starting port and ending port. You can scan up to 256 ports per scan. For a single port, enter the same port number in both fields.
5. Confirm that you are authorized to test the target, then select **Start scan**.
6. Review the results. Open TCP ports appear with their port number and registered service name where available. If none are detected, the page reports that no open ports were found in the range.
7. Stop the application with **Ctrl+C** in the terminal when finished.

### Local example

To check port 8000 on your own computer, enter:

| Field | Value |
| --- | --- |
| Target IP or hostname | `127.0.0.1` |
| Start port | `8000` |
| End port | `8000` |

Confirm authorization and start the scan. This works when you have a service listening on that port locally.

## API example

With the application running, you can check your own local port using the JSON API:

```bash
curl -X POST http://127.0.0.1:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"host":"127.0.0.1","start_port":8000,"end_port":8000,"authorized":true}'
```

The JSON response includes the target, port range, number of ports checked, and an `open_ports` list. Invalid inputs return an error message.

## Tests

Run the included tests from the project directory:

```bash
python -m unittest discover -s tests -v
```

## Scope and safety

- The scanner checks TCP ports on one resolved IP address per scan.
- The allowed range is limited to 256 ports.
- A service name is a standard port mapping, not confirmation of the software actually running.
- The app binds to `127.0.0.1` by default. Do not expose it publicly without appropriate security controls.
- Scan only systems you own or have explicit authorization to test.
