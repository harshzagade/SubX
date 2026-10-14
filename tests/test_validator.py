import unittest
from unittest.mock import patch, MagicMock
from subx.validator import Validator
import dns.resolver

RESOLVE_TARGET = 'dns.resolver.Resolver.resolve'


def _resolve_router(cname_target=None, a_ips=('1.2.3.4',)):
    """Build a resolve() side effect that answers per record type.

    CNAME queries raise NoAnswer when ``cname_target`` is None (like a
    real resolver for a name with no CNAME record); A queries return
    the given IPs.
    """
    def side_effect(name, rdtype, *args, **kwargs):
        if str(rdtype).upper() == 'CNAME':
            if cname_target is None:
                raise dns.resolver.NoAnswer
            answer = MagicMock()
            rdata = MagicMock()
            rdata.target = cname_target
            answer.__iter__.return_value = [rdata]
            return answer
        answer = MagicMock()
        answer.__iter__.return_value = list(a_ips)
        return answer
    return side_effect


class TestValidator(unittest.TestCase):
    def setUp(self):
        self.validator = Validator()

    @patch(RESOLVE_TARGET)
    def test_detect_wildcard_found(self, mock_resolve):
        # Mocking a wildcard DNS that returns an IP
        mock_answer = MagicMock()
        mock_answer.__iter__.return_value = ['1.2.3.4']
        mock_resolve.return_value = mock_answer

        ips = self.validator.detect_wildcard("example.com")
        self.assertIn('1.2.3.4', ips)

    @patch(RESOLVE_TARGET)
    def test_detect_wildcard_not_found(self, mock_resolve):
        # Mocking NXDOMAIN
        mock_resolve.side_effect = dns.resolver.NXDOMAIN

        ips = self.validator.detect_wildcard("example.com")
        self.assertEqual(len(ips), 0)

    @patch(RESOLVE_TARGET)
    @patch('requests.get')
    def test_validate_success(self, mock_get, mock_resolve):
        # Mock DNS (no CNAME record on the name)
        mock_resolve.side_effect = _resolve_router()

        # Mock HTTP
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        ips, status, alias = self.validator.validate("sub.example.com")
        self.assertEqual(ips, ['1.2.3.4'])
        self.assertEqual(status, 200)
        self.assertIsNone(alias)

    @patch(RESOLVE_TARGET)
    def test_validate_follows_cname(self, mock_resolve):
        # A CNAME-only name must resolve through to the target's A records
        # and report the alias.
        mock_resolve.side_effect = _resolve_router(
            cname_target='cdn.provider.net', a_ips=('203.0.113.9',))

        ips, status, alias = self.validator.validate("cdn.example.com", check_http=False)
        self.assertEqual(ips, ['203.0.113.9'])
        self.assertEqual(status, "N/A")
        self.assertEqual(alias, 'cdn.provider.net')

    @patch(RESOLVE_TARGET)
    def test_validate_no_dns(self, mock_resolve):
        mock_resolve.side_effect = dns.resolver.NXDOMAIN

        result = self.validator.validate("nonexistent.example.com")
        self.assertIsNone(result)

    def test_dns_timeout_default(self):
        v = Validator()
        self.assertEqual(v.dns_timeout, Validator.DEFAULT_DNS_TIMEOUT)
        self.assertEqual(v.resolver.timeout, Validator.DEFAULT_DNS_TIMEOUT)
        self.assertEqual(v.resolver.lifetime, Validator.DEFAULT_DNS_TIMEOUT)

    def test_dns_timeout_custom(self):
        v = Validator(dns_timeout=9.5)
        self.assertEqual(v.dns_timeout, 9.5)
        self.assertEqual(v.resolver.timeout, 9.5)
        self.assertEqual(v.resolver.lifetime, 9.5)

    def test_dns_timeout_rejects_non_positive(self):
        with self.assertRaises(ValueError):
            Validator(dns_timeout=0)
        with self.assertRaises(ValueError):
            Validator(dns_timeout=-1)

    def test_http_timeout_default(self):
        v = Validator()
        self.assertEqual(v.http_timeout, Validator.DEFAULT_HTTP_TIMEOUT)
        self.assertEqual(v.http_timeout, 3.0)

    def test_http_timeout_custom(self):
        v = Validator(http_timeout=9.5)
        self.assertEqual(v.http_timeout, 9.5)

    def test_http_timeout_rejects_non_positive(self):
        with self.assertRaises(ValueError):
            Validator(http_timeout=0)
        with self.assertRaises(ValueError):
            Validator(http_timeout=-1)

    @patch(RESOLVE_TARGET)
    @patch('subx.validator.requests')
    def test_validate_passes_http_timeout_to_requests(self, mock_requests, mock_resolve):
        mock_resolve.side_effect = _resolve_router()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_requests.get.return_value = mock_response

        v = Validator(http_timeout=7.5)
        v.validate("sub.example.com")
        mock_requests.get.assert_called_once()
        _, kwargs = mock_requests.get.call_args
        self.assertEqual(kwargs["timeout"], 7.5)

    @patch(RESOLVE_TARGET)
    def test_validate_uses_configured_resolver(self, mock_resolve):
        mock_resolve.side_effect = _resolve_router()

        v = Validator(dns_timeout=7)
        v.validate("sub.example.com", check_http=False)
        # Resolution went through the instance's resolver, whose
        # timeout the caller configured.
        self.assertEqual(v.resolver.timeout, 7)
        mock_resolve.assert_called()

if __name__ == '__main__':
    unittest.main()
