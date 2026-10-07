import unittest
from unittest.mock import patch, MagicMock
from subx.validator import Validator
import dns.resolver

RESOLVE_TARGET = 'dns.resolver.Resolver.resolve'


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
        # Mock DNS
        mock_answer = MagicMock()
        mock_answer.__iter__.return_value = ['1.2.3.4']
        mock_resolve.return_value = mock_answer

        # Mock HTTP
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        ips, status = self.validator.validate("sub.example.com")
        self.assertEqual(ips, ['1.2.3.4'])
        self.assertEqual(status, 200)

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

    @patch(RESOLVE_TARGET)
    def test_validate_uses_configured_resolver(self, mock_resolve):
        mock_answer = MagicMock()
        mock_answer.__iter__.return_value = ['1.2.3.4']
        mock_resolve.return_value = mock_answer

        v = Validator(dns_timeout=7)
        v.validate("sub.example.com", check_http=False)
        # Resolution went through the instance's resolver, whose
        # timeout the caller configured.
        self.assertEqual(v.resolver.timeout, 7)
        mock_resolve.assert_called()

if __name__ == '__main__':
    unittest.main()
