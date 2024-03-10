import unittest
from CertStream import websocket_connections

class TestCertStream(unittest.TestCase):

    def test_websocket_connections_success(self):
        host = "wss://certstream.calidog.io"
        with websocket_connections(host) as ws:
            self.assertIsNotNone(ws)

    def test_websocket_connections_invalid_host(self):
        host = "invalidhost" 
        with self.assertRaises(ConnectionError):
            with websocket_connections(host) as ws:
                pass

