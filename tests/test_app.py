import socket
import unittest

import app


class PortScannerTests(unittest.TestCase):
    def setUp(self):
        self.client = app.app.test_client()

    def test_homepage_uses_the_requested_project_heading(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"<h1>PORT SCANNER (PYTHON)</h1>", response.data)

    def post_scan(self, **overrides):
        payload = {
            "host": "127.0.0.1",
            "start_port": 1,
            "end_port": 1,
            "authorized": True,
        }
        payload.update(overrides)
        return self.client.post("/api/scan", json=payload)

    def test_requires_authorization_confirmation(self):
        response = self.post_scan(authorized=False)

        self.assertEqual(response.status_code, 400)
        self.assertIn("authorization", response.get_json()["error"])

    def test_rejects_invalid_or_oversized_ranges(self):
        cases = (
            {"start_port": 0},
            {"start_port": 9000, "end_port": 8000},
            {"start_port": 1, "end_port": 257},
            {"start_port": 1.5},
        )
        for values in cases:
            with self.subTest(values=values):
                response = self.post_scan(**values)
                self.assertEqual(response.status_code, 400)

    def test_scans_a_localhost_listener(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            port = listener.getsockname()[1]

            response = self.post_scan(start_port=port, end_port=port)

        self.assertEqual(response.status_code, 200)
        result = response.get_json()
        self.assertEqual(result["ports_checked"], 1)
        self.assertEqual(result["open_ports"][0]["port"], port)
        self.assertTrue(result["open_ports"][0]["service"])


if __name__ == "__main__":
    unittest.main()
