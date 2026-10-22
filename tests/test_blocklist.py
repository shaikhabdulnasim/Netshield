"""Basic unit tests; run after installing project requirements."""
import os
import tempfile
import unittest
from pathlib import Path

from dnslib import DNSRecord

with tempfile.TemporaryDirectory() as t:
    os.environ['DB_PATH'] = str(Path(t) / 'test.db')
    os.environ['BLOCKLIST_PATH'] = str(Path(__file__).resolve().parents[1] / 'data' / 'blocklist.txt')
    from app.main import Resolver, load_blocklist


class FakeHandler:
    client_address = ('127.0.0.1', 1234)
    protocol = 'udp'


class FilteringTests(unittest.TestCase):
    def test_list_loaded(self):
        self.assertIn('doubleclick.net', load_blocklist())

    def test_subdomain_is_blocked(self):
        from app.main import initialize
        initialize()
        response = Resolver().resolve(DNSRecord.question('ads.doubleclick.net'), FakeHandler())
        self.assertEqual(response.header.rcode, 3)


if __name__ == '__main__':
    unittest.main()
