import unittest
from unittest.mock import patch, MagicMock
from subx.enumerator import Enumerator

class TestEnumerator(unittest.TestCase):
    def setUp(self):
        self.enumerator = Enumerator("example.com")

    @patch('requests.get')
    def test_alienvault(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'passive_dns': [
                {'hostname': 'sub1.example.com'},
                {'hostname': 'sub2.example.com'}
            ]
        }
        mock_get.return_value = mock_response
        
        subs = self.enumerator._alienvault()
        self.assertIn('sub1.example.com', subs)
        self.assertIn('sub2.example.com', subs)

    @patch('requests.get')
    def test_hackertarget(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "sub1.example.com,1.2.3.4\nsub2.example.com,5.6.7.8"
        mock_get.return_value = mock_response
        
        subs = self.enumerator._hackertarget()
        self.assertIn('sub1.example.com', subs)
        self.assertIn('sub2.example.com', subs)

    def test_default_source_timeout_is_15(self):
        self.assertEqual(self.enumerator.source_timeout, 15.0)

    @patch('requests.get')
    def test_custom_source_timeout_reaches_requests(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'passive_dns': []}
        mock_get.return_value = mock_response

        enumerator = Enumerator("example.com", source_timeout=2.5)
        enumerator._alienvault()
        mock_get.assert_called_once()
        self.assertEqual(mock_get.call_args.kwargs['timeout'], 2.5)

    def test_nonpositive_source_timeout_rejected(self):
        with self.assertRaises(ValueError):
            Enumerator("example.com", source_timeout=0)


if __name__ == '__main__':
    unittest.main()
