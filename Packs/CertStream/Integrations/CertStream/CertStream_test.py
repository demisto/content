import unittest
from CertStream import websocket_connections


class TestCertStream(unittest.TestCase):

    def test_websocket_connections_success(self):
        host = "wss://certstream.calidog.io"
        with websocket_connections(host) as ws:
            assert ws is not None

    def test_websocket_connections_invalid_host(self):
        host = "invalidhost"
        with self.assertRaises(ConnectionError), websocket_connections(host):
            pass
