"""DNS rebinding regressions; fake DNS/HTTP transport, no network connections."""
import contextlib
import io
import os
from pathlib import Path
import socket
import sys
import threading
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import netshield_common as nc


class DnsPinningSecurityTests(unittest.TestCase):
    def setUp(self):
        # Isolate the process-wide DNS hook and thread-local state from other tests.
        for target, value in [('_patched', False), ('_original_getaddrinfo', None),
                              ('_pin_state', threading.local())]:
            patcher = patch.object(nc, target, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.dns_calls = []
        self.connections = []
        self.public_ip = '93.184.216.34'

        def resolver(host, port, *args, **kwargs):
            self.dns_calls.append(host)
            # A second resolver lookup is the attacker-controlled response.
            ip = self.public_ip if len(self.dns_calls) == 1 else '127.0.0.1'
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, int(port or 0)))]

        patcher = patch('socket.getaddrinfo', side_effect=resolver)
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = patch.dict(os.environ, {k: '' for k in (
            'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy')})
        patcher.start()
        self.addCleanup(patcher.stop)

    def probe_download(self, function, host):
        def blocked_connect(address, *args, **kwargs):
            self.connections.extend(socket.getaddrinfo(*address))
            raise OSError('Test stops before opening a network socket')

        with patch('socket.create_connection', side_effect=blocked_connect), \
             contextlib.redirect_stdout(io.StringIO()):
            if function == 'fetch_url':
                self.assertIsNone(nc.fetch_url('http://' + host + '/feed', retries=1))
            else:
                with self.assertRaises(urllib.error.URLError):
                    with nc.safe_urlopen('http://' + host + '/feed'):
                        self.fail('Connection must be intercepted')
        self.assertEqual(len(self.dns_calls), 1, self.dns_calls)
        self.assertEqual([row[4][0] for row in self.connections], [self.public_ip])
        self.assertEqual(nc._pin_state.pin_map, {})

    def test_fetch_url_mixed_case_cannot_rebind(self):
        self.probe_download('fetch_url', 'PrObE.ExAmPlE')

    def test_safe_urlopen_mixed_case_cannot_rebind(self):
        self.probe_download('safe_urlopen', 'PrObE.ExAmPlE')

    def test_lowercase_transport_retains_pin(self):
        self.probe_download('fetch_url', 'probe.example')

    def test_bytes_idna_root_dot_and_nested_restore(self):
        outer = nc._pin_host('BÜCHER.example.', [self.public_ip])
        inner = nc._pin_host(b'XN--BCHER-KVA.EXAMPLE', ['93.184.216.35'])
        self.assertEqual(inner, [self.public_ip])
        for host in ('bücher.example', 'BÜCHER.EXAMPLE.', b'xn--bcher-kva.example.'):
            self.assertEqual(socket.getaddrinfo(host, 80)[0][4][0], '93.184.216.35')
        nc._restore_pin('xn--bcher-kva.example.', inner)
        self.assertEqual(socket.getaddrinfo('BÜCHER.example', 80)[0][4][0], self.public_ip)
        nc._restore_pin(b'XN--BCHER-KVA.EXAMPLE', outer)
        self.assertEqual(nc._pin_state.pin_map, {})
        self.assertEqual(self.dns_calls, [])

    def test_redirects_in_both_fetchers_keep_validated_address(self):
        class Response(io.BytesIO):
            headers = {}

        for function in ('fetch_url', 'safe_urlopen'):
            with self.subTest(function=function):
                self.dns_calls.clear()
                self.connections.clear()
                # This exercises each fetcher's actual redirect validation handler.
                def open_response(req, timeout):
                    redirected = self.handler.redirect_request(
                        req, None, 302, 'Found', {}, 'http://ReDiReCt.ExAmPlE/feed')
                    self.connections.extend(socket.getaddrinfo('ReDiReCt.ExAmPlE', 80))
                    self.assertIsNotNone(redirected)
                    return Response(b'45.1.0.1\n')

                def opener(handler):
                    self.handler = handler
                    obj = unittest.mock.Mock()
                    obj.open.side_effect = open_response
                    return obj

                # First host's validation is represented by an existing outer pin;
                # only the new redirect hostname may query DNS once.
                previous = nc._pin_host('start.example', [self.public_ip])
                try:
                    with patch('urllib.request.build_opener', side_effect=opener):
                        if function == 'fetch_url':
                            self.assertEqual(nc.fetch_url('http://start.example/feed', retries=1), '45.1.0.1\n')
                        else:
                            with nc.safe_urlopen('http://start.example/feed') as response:
                                self.assertEqual(response.read(), b'45.1.0.1\n')
                    self.assertEqual(self.dns_calls, ['redirect.example'])
                    self.assertEqual([row[4][0] for row in self.connections], [self.public_ip])
                    self.assertEqual(nc._pin_state.pin_map, {'start.example': [self.public_ip]})
                finally:
                    nc._restore_pin('START.EXAMPLE', previous)


if __name__ == '__main__':
    unittest.main()
