import unittest
from unittest.mock import patch, MagicMock
from subx.validator import Validator
import dns.resolver

class TestValidator(unittest.TestCase):
    def setUp(self):
        self.validator = Validator()

    @patch('dns.resolver.resolve')
    def test_detect_wildcard_found(self, mock_resolve):
        # Mocking a wildcard DNS that returns an IP
        mock_answer = MagicMock()
        mock_answer.__iter__.return_value = ['1.2.3.4']
        mock_resolve.return_value = mock_answer
        
        ips = Validator.detect_wildcard("example.com")
        self.assertIn('1.2.3.4', ips)

    @patch('dns.resolver.resolve')
    def test_detect_wildcard_not_found(self, mock_resolve):
        # Mocking NXDOMAIN
        mock_resolve.side_effect = dns.resolver.NXDOMAIN
        
        ips = Validator.detect_wildcard("example.com")
        self.assertEqual(len(ips), 0)

    @patch('dns.resolver.resolve')
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

    @patch('dns.resolver.resolve')
    def test_validate_no_dns(self, mock_resolve):
        mock_resolve.side_effect = dns.resolver.NXDOMAIN
        
        result = self.validator.validate("nonexistent.example.com")
        self.assertIsNone(result)

if __name__ == '__main__':
    unittest.main()
