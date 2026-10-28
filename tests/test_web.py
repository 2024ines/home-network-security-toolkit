import json
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from hnst import classify, config
from hnst.web import WebApp, make_handler


class ClassifyTests(unittest.TestCase):
    def test_types(self):
        g = classify.guess_type
        self.assertEqual(g("192.168.1.45", "", "Hikvision", "", [554])[0], "Camera")
        self.assertEqual(g("192.168.1.52", "office-printer", "HP", "", [9100])[0], "Printer")
        self.assertEqual(g("192.168.1.1", "", "TP-Link", "", [53, 80])[0], "Router")
        self.assertEqual(g("192.168.1.10", "DESKTOP-95DHCA5", "", "", [445])[0], "Computer")
        self.assertEqual(g("192.168.1.23", "", "Samsung", "Android", [])[0], "Phone / Tablet")
        self.assertEqual(g("192.168.1.99", "", "", "", [])[0], "Unknown")

    def test_private_mac_and_brand(self):
        self.assertTrue(classify.is_private_mac("36:6f:70:e9:0d:75"))
        self.assertFalse(classify.is_private_mac("3C:10:00:00:00:01"))
        self.assertEqual(classify.brand_of("LG Electronics"), "LG")
        self.assertEqual(classify.brand_of(""), "Unrecognised")


class WebTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.patch = mock.patch.object(config, "REPORT_DIR", Path(self.tmp.name) / "reports")
        self.patch.start()
        self.app = WebApp(demo=True, db_path=Path(self.tmp.name) / "web.db")
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.app))
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.patch.stop()
        self.tmp.cleanup()

    def req(self, path, body=None, token=True, host=None):
        data = json.dumps(body).encode() if body is not None else None
        r = urllib.request.Request(self.base + path, data=data, method="POST" if body is not None else "GET")
        if body is not None:
            r.add_header("Content-Type", "application/json")
            if token:
                r.add_header("X-HNST-Token", self.app.token)
        if host:
            r.add_header("Host", host)
        try:
            with urllib.request.urlopen(r) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def wait_job(self):
        for _ in range(100):
            time.sleep(0.1)
            if not self.app.snapshot()["running"]:
                return
        self.fail("job did not finish")

    def state(self):
        return json.loads(self.req("/api/state")[1])

    def test_page_has_token_and_no_placeholder(self):
        code, body = self.req("/")
        self.assertEqual(code, 200)
        self.assertIn(self.app.token.encode(), body)
        self.assertNotIn(b"__TOKEN__", body)

    def test_security_checks(self):
        self.assertEqual(self.req("/api/scan", {"network": "192.168.1.0/24", "authorised": True}, token=False)[0], 403)
        self.assertEqual(self.req("/api/state", host="evil.example.com")[0], 403)
        code, body = self.req("/api/scan", {"network": "8.8.8.0/24", "authorised": True})
        self.assertEqual(code, 400)
        self.assertIn("not a private", json.loads(body)["error"])
        code, body = self.req("/api/scan", {"network": "192.168.1.0/24", "authorised": False})
        self.assertEqual(code, 400)

    def test_scan_flow_and_actions(self):
        self.assertEqual(self.req("/api/scan", {"network": "192.168.1.0/24", "authorised": True, "deep": True})[0], 200)
        self.wait_job()
        st = self.state()
        self.assertEqual(st["counts"]["online"], 6)
        self.assertGreater(st["counts"]["open_ports"], 0)
        types = {d["type"] for d in st["devices"]}
        self.assertTrue({"Router", "Camera", "Printer"} <= types)
        cam = next(d for d in st["devices"] if d["type"] == "Camera")
        self.assertEqual(cam["risk"], "risk")                        # Telnet open
        before = st["scan"]["score"]
        # trust everything, then rename one device
        code, _ = self.req("/api/trust-all", {})
        self.assertEqual(code, 200)
        self.assertEqual(self.state()["counts"]["new"], 0)
        self.assertEqual(self.req(f"/api/device/{cam['id']}/rename", {"label": "<b>Garage cam</b>"})[0], 200)
        st = self.state()
        self.assertEqual(next(d for d in st["devices"] if d["id"] == cam["id"])["label"], "<b>Garage cam</b>")
        self.assertGreaterEqual(st["scan"]["score"], before)
        self.assertEqual(self.req("/api/device/9999/trust", {"trusted": True})[0], 404)
        # second scan: unknown device appears, phone sleeps
        self.req("/api/scan", {"network": "192.168.1.0/24", "authorised": True})
        self.wait_job()
        st = self.state()
        self.assertEqual(st["counts"]["new"], 1)
        self.assertEqual(st["counts"]["offline"], 1)
        self.assertEqual(len(st["history"]), 2)

    def test_traffic_and_report(self):
        code, body = self.req("/api/report")
        self.assertEqual(code, 400)                                  # nothing scanned yet
        self.req("/api/scan", {"network": "192.168.1.0/24", "authorised": True})
        self.wait_job()
        self.assertEqual(self.req("/api/traffic", {"interface": "Wi-Fi", "seconds": 5, "authorised": True})[0], 200)
        self.wait_job()
        tf = self.state()["traffic"]["summary"]["findings"]
        self.assertGreater(self.state()["traffic"]["summary"]["packets"], 0)
        keys = [(f["rule_id"], f["title"]) for f in tf]
        self.assertEqual(len(keys), len(set(keys)))                    # one alert per kind of problem
        self.assertTrue(all("steps" in f for f in tf))
        code, body = self.req("/api/report")
        self.assertEqual(code, 200)
        self.assertIn(b"Security score", body)

    def test_findings_carry_plain_language_help(self):
        self.req("/api/scan", {"network": "192.168.1.0/24", "authorised": True})
        self.wait_job()
        st = self.state()
        telnet = next(f for f in st["findings"] if f["rule_id"] == "PORT_TELNET")
        self.assertEqual(telnet["priority"], "Fix today")
        self.assertGreaterEqual(len(telnet["steps"]), 3)
        cam = next(d for d in st["devices"] if d["type"] == "Camera")
        self.assertTrue(all("simple" in f for f in cam["findings"]))

    def test_setup_check_endpoint(self):
        code, body = self.req("/api/check")
        data = json.loads(body)
        self.assertEqual(code, 200)
        self.assertTrue(data["checks"])
        self.assertIn("interfaces", data)

    def test_stored_data_page_endpoint(self):
        empty = json.loads(self.req("/api/data")[1])
        self.assertEqual([t["name"] for t in empty["tables"]],
                         ["devices", "scans", "ports", "findings", "traffic_sessions"])
        self.assertTrue(all(t["count"] == 0 for t in empty["tables"]))
        self.req("/api/scan", {"network": "192.168.1.0/24", "authorised": True})
        self.wait_job()
        data = json.loads(self.req("/api/data")[1])
        by = {t["name"]: t for t in data["tables"]}
        self.assertEqual(by["devices"]["count"], 6)
        self.assertEqual(by["scans"]["count"], 1)
        self.assertGreater(by["ports"]["count"], 0)
        self.assertGreater(by["findings"]["count"], 0)
        self.assertIn("mac", by["devices"]["columns"])
        self.assertLessEqual(len(by["devices"]["rows"]), data["limit"])
        self.assertEqual(self.req("/api/data", {})[0], 404)            # read-only: POST is not allowed here
     
    def test_busy_returns_409(self):
        self.app._job["running"] = True
        code, _ = self.req("/api/scan", {"network": "192.168.1.0/24", "authorised": True})
        self.assertEqual(code, 409)
        self.app._job["running"] = False


if __name__ == "__main__":
    unittest.main()