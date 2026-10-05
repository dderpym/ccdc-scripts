"""Host-side parsers exercised offline; only the listener check opens sockets."""
import contextlib
import io
import ipaddress
import socket
import unittest
from unittest.mock import patch

from test_controller import load

listeners = load('discover-listeners')


class ListenerTests(unittest.TestCase):
    def test_command_parsers(self):
        with contextlib.redirect_stdout(io.StringIO()):
            listeners.self_check()

    def test_proc_fallback_ipv4_tcp_udp(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp, \
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            tcp.bind(('127.0.0.1', 0))
            tcp.listen()
            udp.bind(('0.0.0.0', 0))
            with patch.object(listeners.subprocess, 'run', side_effect=FileNotFoundError):
                rows = listeners.discover()
            tcp_rows = [row for row in rows if row['protocol'] == 'tcp' and row['port'] == tcp.getsockname()[1]]
            udp_rows = [row for row in rows if row['protocol'] == 'udp' and row['port'] == udp.getsockname()[1]]
            self.assertTrue(tcp_rows)
            self.assertTrue(udp_rows)
            self.assertTrue(all(row['loopback_only'] and not row['external'] for row in tcp_rows))
            self.assertTrue(all(row['external'] and not row['loopback_only'] for row in udp_rows))

    def test_ipv6_and_mapped_loopback_endpoints(self):
        address, port, family = listeners.endpoint('[::ffff:127.0.0.1]:22')
        self.assertEqual(str(ipaddress.ip_address(address).ipv4_mapped), '127.0.0.1')
        self.assertEqual((port, family), (22, 'IPv6'))
        self.assertEqual(listeners.endpoint('[fe80::1%eth0]:53'), ('fe80::1%eth0', 53, 'IPv6'))


if __name__ == '__main__':
    unittest.main()
