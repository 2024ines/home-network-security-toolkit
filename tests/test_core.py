import json
import os
import tempfile
import unittest

from hnst import config, risk, traffic
from hnst.database import Database
from hnst.demo import DemoMonitor, DemoScanner, DEMO_NETWORK
from hnst.models import Device, HostResult, PortInfo
from hnst.report import build_report
from hnst.scanner import parse_discovery, parse_ports
from hnst.service import SecurityService


class NetworkValidation(unittest.TestCase):
    def test_private_ok(self):
        self.assertEqual(config.validate_network("192.168.1.15/24"), "192.168.1.0/24")

    def test_public_rejected(self):
        for bad in ("8.8.8.8/32", "1.1.1.0/24", "127.0.0.1/32", "abc", "2001:db8::/64"):
            with self.assertRaises(config.NetworkNotAllowed, msg=bad):
                config.validate_network(bad)

    def test_too_large_rejected(self):
        with self.assertRaises(config.NetworkNotAllowed):
            config.validate_network("10.0.0.0/16")


class ParserTests(unittest.TestCase):
    def test_parse_discovery(self):
        raw = {
            "192.168.1.1": {"status": {"state": "up"}, "addresses": {"ipv4": "192.168.1.1", "mac": "aa:bb:cc:00:00:01"},
                            "vendor": {"aa:bb:cc:00:00:01": "TP-Link"}, "hostnames": [{"name": "router", "type": "PTR"}]},
            "192.168.1.9": {"status": {"state": "down"}, "addresses": {"ipv4": "192.168.1.9"}},
            "192.168.1.20": {"status": {"state": "up"}, "addresses": {"ipv4": "192.168.1.20"}, "hostnames": [{"name": ""}]},
        }
        hosts = parse_discovery(raw, own_ip="192.168.1.20", arp={"192.168.1.20": "11:22:33:44:55:66"})
        self.assertEqual([h.ip for h in hosts], ["192.168.1.1", "192.168.1.20"])
        self.assertEqual(hosts[0].vendor, "TP-Link")
        self.assertEqual(hosts[0].hostname, "router")
        self.assertTrue(hosts[1].is_self)
        self.assertEqual(hosts[1].mac, "11:22:33:44:55:66")      # ARP fallback

    def test_parse_ports(self):
        data = {"tcp": {23: {"state": "open", "name": "telnet", "product": "BusyBox", "version": ""},
                        80: {"state": "closed", "name": "http"}}}
        ports = parse_ports(data)
        self.assertEqual([p.port for p in ports], [23, 80])
        self.assertEqual(ports[0].banner, "BusyBox")


def dev(i=1, trusted=True, online=True, ip="192.168.1.5"):
    return Device(i, f"k{i}", ip, "", "host", "", "", "", trusted, online, "", "")


class RiskTests(unittest.TestCase):
    def test_telnet_is_critical(self):
        f = risk.analyse([dev()], {1: [PortInfo(23, service="telnet")]})
        self.assertEqual(f[0].severity, "critical")
        self.assertIn("does not prove", f[0].description)

    def test_unrecognised_device_flagged_cautiously(self):
        f = risk.analyse([dev(trusted=False)], {})
        self.assertEqual(f[0].rule_id, "NEW_DEVICE")
        self.assertNotIn("intruder", f[0].description.lower())

    def test_offline_devices_ignored(self):
        self.assertEqual(risk.analyse([dev(trusted=False, online=False)], {}), [])

    def test_closed_ports_ignored(self):
        self.assertEqual(risk.analyse([dev()], {1: [PortInfo(23, state="closed")]}), [])

    def test_many_ports(self):
        ports = [PortInfo(9000 + i) for i in range(12)]
        self.assertIn("MANY_PORTS", [f.rule_id for f in risk.analyse([dev()], {1: ports})])

    def test_score(self):
        self.assertEqual(risk.security_score([])[0], 100)
        f = risk.analyse([dev()], {1: [PortInfo(23), PortInfo(3389), PortInfo(5900)]})
        score, label = risk.security_score(f)
        self.assertLess(score, 70)
        self.assertGreaterEqual(score, 0)


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.db = Database(":memory:")

    def test_onboarding_and_offboarding(self):
        a = HostResult("192.168.1.2", "AA:AA:AA:AA:AA:01")
        b = HostResult("192.168.1.3", "AA:AA:AA:AA:AA:02")
        _, new, missing = self.db.reconcile_devices([a, b])
        self.assertEqual(len(new), 2)
        self.assertEqual(missing, [])
        # second scan: b disappears, c appears, a changes IP
        a2 = HostResult("192.168.1.9", "aa:aa:aa:aa:aa:01")
        c = HostResult("192.168.1.4", "AA:AA:AA:AA:AA:03")
        _, new, missing = self.db.reconcile_devices([a2, c])
        self.assertEqual(len(new), 1)
        self.assertEqual(len(missing), 1)
        devs = {d.mac: d for d in self.db.list_devices()}
        self.assertEqual(devs["AA:AA:AA:AA:AA:01"].ip, "192.168.1.9")          # same device, new IP
        self.assertEqual(devs["AA:AA:AA:AA:AA:02"].status, "Not Currently Detected")   # kept, not deleted
        self.assertEqual(devs["AA:AA:AA:AA:AA:03"].status, "New/Unrecognised")

    def test_self_is_trusted_and_trust_actions(self):
        self.db.reconcile_devices([HostResult("192.168.1.2", "AA:AA:AA:AA:AA:01", is_self=True),
                                   HostResult("192.168.1.3", "AA:AA:AA:AA:AA:02")])
        d = {x.ip: x for x in self.db.list_devices()}
        self.assertTrue(d["192.168.1.2"].trusted)
        self.assertFalse(d["192.168.1.3"].trusted)
        self.assertEqual(self.db.trust_all_online(), 1)
        self.db.rename_device(d["192.168.1.3"].id, "Guest phone")
        self.assertEqual(self.db.get_device(d["192.168.1.3"].id).display_name, "Guest phone")

    def test_devices_without_mac_keyed_by_ip(self):
        self.db.reconcile_devices([HostResult("192.168.1.8")])
        _, new, _ = self.db.reconcile_devices([HostResult("192.168.1.8")])
        self.assertEqual(new, [])
        self.assertEqual(len(self.db.list_devices()), 1)


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.db = Database(":memory:")
        self.svc = SecurityService(self.db, DemoScanner(), DemoMonitor())

    def test_full_demo_flow(self):
        first = self.svc.run_scan(DEMO_NETWORK, deep=True)
        self.assertEqual(first.hosts_found, 6)
        self.assertTrue(any(f.rule_id == "PORT_TELNET" for f in first.findings))
        self.assertLess(first.score, 100)
        self.db.trust_all_online()
        second = self.svc.run_scan(DEMO_NETWORK, deep=True)     # unknown device appears, phone sleeps
        self.assertEqual(second.not_detected, 1)
        self.assertEqual(second.new_devices, 1)
        self.assertTrue(any(f.rule_id == "NEW_DEVICE" for f in second.findings))
        self.assertEqual(len(self.db.scan_history()), 2)

    def test_quick_scan_warns(self):
        res = self.svc.run_scan(DEMO_NETWORK, deep=False)
        self.assertTrue(any("Quick scan" in w for w in res.warnings))
        self.assertEqual(res.open_ports, 0)

    def test_public_network_blocked(self):
        with self.assertRaises(config.NetworkNotAllowed):
            self.svc.run_scan("8.8.8.0/24")
        self.assertEqual(len(self.db.scan_history()), 0)

    def test_stop_flag(self):
        res = self.svc.run_scan(DEMO_NETWORK, deep=True, should_stop=lambda: True)
        self.assertTrue(any("stopped early" in w for w in res.warnings))

    def test_traffic_and_report(self):
        self.svc.run_scan(DEMO_NETWORK, deep=True)
        summary, findings = self.svc.run_traffic("eth0", 5)
        self.assertGreater(summary["packets"], 0)
        self.assertTrue(any(f.rule_id == "TRAFFIC_CLEARTEXT" for f in findings))
        with tempfile.TemporaryDirectory() as d:
            out = build_report(self.db, os.path.join(d, "r.html"))
            text = out.read_text(encoding="utf-8")
            self.assertIn("Security score", text)
            self.assertIn("Telnet", text)
            self.assertIn("data:image/png;base64", text)

    def test_report_requires_scan(self):
        with self.assertRaises(RuntimeError):
            build_report(self.db, "x.html")


class TrafficTests(unittest.TestCase):
    def test_aggregator_and_rules(self):
        agg = traffic.TrafficAggregator()
        for i in range(300):
            agg.add("192.168.1.50", f"10.0.0.{i % 40}", "TCP", 100, i)
        agg.add("192.168.1.51", "192.168.1.1", "TELNET", 60, 1)
        s = agg.summary()
        ids = {f.rule_id for f in traffic.analyse_traffic(s, known_ips={"192.168.1.1"})}
        self.assertIn("TRAFFIC_CLEARTEXT", ids)
        self.assertIn("TRAFFIC_DOMINANT", ids)
        self.assertIn("TRAFFIC_FANOUT", ids)
        self.assertIn("TRAFFIC_UNKNOWN_SOURCE", ids)
        json.dumps(s)    # must be JSON-serialisable for storage

    def test_quiet_traffic_has_no_findings(self):
        agg = traffic.TrafficAggregator()
        for i in range(50):
            agg.add("192.168.1.2", "8.8.8.8", "TLS", 100, i)
        self.assertEqual(traffic.analyse_traffic(agg.summary(), {"192.168.1.2"}), [])


if __name__ == "__main__":
    unittest.main()