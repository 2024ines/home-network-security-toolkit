import io
import unittest
from types import SimpleNamespace
from unittest import mock

from hnst import advice, risk, traffic

WIN_D = ("1. \\Device\\NPF_{AAA} (Ethernet 2)\n2. \\Device\\NPF_Loopback (Adapter for loopback traffic capture)\n"
         "3. \\Device\\NPF_{BBB} (VirtualBox Host-Only Network)\n4. \\Device\\NPF_{CCC} (Wi-Fi)\n")


class FakeProc:
    def __init__(self, lines=(), err="", rc=0):
        self.stdout, self.stderr, self.returncode = io.StringIO("".join(lines)), io.StringIO(err), rc

    def terminate(self):
        pass

    def kill(self):
        pass

    def wait(self, timeout=None):
        return self.returncode


def line(src, dst, chain, length=100, ts=1700000000.5):
    return f"{ts}\t{src}\t{dst}\t\t\t\t\t{length}\t{chain}\n"


class ParsingTests(unittest.TestCase):
    def test_protocol_label(self):
        self.assertEqual(traffic.protocol_label("eth:ethertype:ip:tcp:tls"), "TLS")
        self.assertEqual(traffic.protocol_label("eth:ethertype:ip:tcp:telnet"), "TELNET")
        self.assertEqual(traffic.protocol_label("eth:ethertype:ip:udp:dns"), "DNS")
        self.assertEqual(traffic.protocol_label("eth:ethertype:arp"), "ARP")
        self.assertEqual(traffic.protocol_label("eth:ethertype:ip:tcp:http2"), "TCP")
        self.assertEqual(traffic.protocol_label("eth:foo"), "FOO")

    def test_parse_line(self):
        self.assertEqual(traffic.parse_line(line("192.168.1.45", "192.168.1.1", "eth:ethertype:ip:tcp:telnet", 120)),
                         ("192.168.1.45", "192.168.1.1", "TELNET", 120, 1700000000.5))
        arp = "1700000001.0\t\t\t\t\t192.168.1.7\t192.168.1.1\t60\teth:ethertype:arp\n"
        self.assertEqual(traffic.parse_line(arp)[:3], ("192.168.1.7", "192.168.1.1", "ARP"))
        tunnel = "1700000002.0\t10.0.0.1,10.0.0.9\t8.8.8.8,1.1.1.1\t\t\t\t\t90,60\teth:ip:udp:dns\n"
        self.assertEqual(traffic.parse_line(tunnel)[:4], ("10.0.0.1", "8.8.8.8", "DNS", 90))
        self.assertIsNone(traffic.parse_line("Capturing on 'Wi-Fi'\n"))

    def test_interfaces(self):
        ifs = traffic.parse_interfaces(WIN_D)
        self.assertEqual([i["name"] for i in ifs][0::3], ["Ethernet 2", "Wi-Fi"])
        linux = traffic.parse_interfaces("1. eth0\n2. any\n3. lo (Loopback)\n")
        self.assertEqual(linux[0], {"index": "1", "device": "eth0", "name": "eth0"})
        self.assertEqual(linux[2]["name"], "Loopback")

    def test_resolve_interface(self):
        ifs = traffic.parse_interfaces(WIN_D)
        self.assertEqual(traffic.resolve_interface("", ifs)["name"], "Wi-Fi")      # skips loopback and VirtualBox
        self.assertEqual(traffic.resolve_interface("1", ifs)["name"], "Ethernet 2")
        self.assertEqual(traffic.resolve_interface("wi-fi", ifs)["index"], "4")
        with self.assertRaises(RuntimeError) as ctx:
            traffic.resolve_interface("nonsense", ifs)
        self.assertIn("Wi-Fi", str(ctx.exception))
        with self.assertRaises(RuntimeError):
            traffic.resolve_interface("", [])

    def test_explain_error(self):
        self.assertIn("administrator", traffic.explain_error("tshark: Couldn't run dumpcap: permission denied"))
        self.assertIn("not found", traffic.explain_error("There is no interface"))
        self.assertIn("Wireshark reported", traffic.explain_error("something odd"))
        self.assertIn("No packets", traffic.explain_error(""))


class CaptureTests(unittest.TestCase):
    def patches(self, proc):
        return (mock.patch.object(traffic, "find_tshark", return_value="tshark"),
                mock.patch.object(traffic.subprocess, "run", return_value=SimpleNamespace(stdout=WIN_D, stderr="", returncode=0)),
                mock.patch.object(traffic.subprocess, "Popen", return_value=proc))

    def test_live_capture_counts_and_flags(self):
        proc = FakeProc([line("192.168.1.45", "192.168.1.1", "eth:ethertype:ip:tcp:telnet")] * 3
                        + [line("192.168.1.10", "8.8.8.8", "eth:ethertype:ip:udp:dns")] * 2, "Capturing on 'Wi-Fi'\n")
        p1, p2, p3 = self.patches(proc)
        with p1, p2, p3:
            agg = traffic.TrafficMonitor().capture_live("", 5)
        self.assertEqual(agg.packets, 5)
        ids = {f.rule_id for f in traffic.analyse_traffic(agg.summary(), {"192.168.1.1"})}
        self.assertIn("TRAFFIC_CLEARTEXT", ids)

    def test_permission_error_is_explained(self):
        p1, p2, p3 = self.patches(FakeProc([], "tshark: Couldn't run dumpcap in child process: Permission denied\n", 2))
        with p1, p2, p3, self.assertRaises(RuntimeError) as ctx:
            traffic.TrafficMonitor().capture_live("Wi-Fi", 5)
        self.assertIn("administrator", str(ctx.exception))

    def test_missing_wireshark(self):
        with mock.patch.object(traffic, "find_tshark", return_value=None), self.assertRaises(RuntimeError) as ctx:
            traffic.TrafficMonitor().capture_live("", 5)
        self.assertIn("Install Wireshark", str(ctx.exception))

    def test_pcap_file(self):
        p1, p2, p3 = self.patches(FakeProc([line("10.0.0.2", "10.0.0.3", "eth:ip:tcp:tls")] * 4))
        with p1, p2, p3:
            self.assertEqual(traffic.TrafficMonitor().analyse_file("x.pcapng").packets, 4)

    def test_diagnose_never_crashes(self):
        with mock.patch.object(traffic, "find_tshark", return_value=None):
            titles = " ".join(c["title"] for c in traffic.diagnose())
        self.assertIn("Wireshark (tshark) not found", titles)


class AdviceTests(unittest.TestCase):
    def test_every_rule_has_plain_advice(self):
        ids = [r.rule_id for r in risk.PORT_RULES.values()] + ["NEW_DEVICE", "MANY_PORTS", "TRAFFIC_CLEARTEXT",
                                                                 "TRAFFIC_DOMINANT", "TRAFFIC_FANOUT", "TRAFFIC_UNKNOWN_SOURCE"]
        for rid in ids:
            a = advice.advice_for(rid, "medium")
            self.assertIn(rid, advice.ADVICE, rid)
            self.assertGreaterEqual(len(a["steps"]), 2, rid)
            self.assertTrue(a["simple"] and a["time"] and a["skill"])

    def test_priority_and_fallback(self):
        self.assertEqual(advice.advice_for("PORT_TELNET", "critical")["priority"], "Fix today")
        self.assertEqual(advice.advice_for("UNKNOWN_RULE", "low")["priority"], "When you have time")
        self.assertTrue(advice.advice_for("UNKNOWN_RULE", "low")["steps"])


if __name__ == "__main__":
    unittest.main()