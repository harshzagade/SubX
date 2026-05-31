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

if __name__ == '__main__':
    unittest.main()
