import unittest
from unittest.mock import patch, MagicMock
import dns.resolver
import requests
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))
from main import (
    is_suspicious_url,
    check_ssl_certificate,
    check_url_virustotal,
    get_urls_from_file,
    generate_report,
    check_email_spoofing,
    analyze_email_header
)

class TestPhishingDetectionTool(unittest.TestCase):

    # Test suspicious URL detection
    def test_is_suspicious_url(self):
        self.assertTrue(is_suspicious_url("http://phishingsite.com"))
        self.assertFalse(is_suspicious_url("https://example.com"))

    # Test SSL certificate check for a valid site
    @patch('main.requests.get')
    def test_check_ssl_certificate_valid(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        cert = check_ssl_certificate("https://example.com")
        self.assertTrue(cert)

    # Test SSL certificate check for an invalid site
    @patch('main.requests.get', side_effect=requests.exceptions.SSLError("SSL Error"))
    def test_check_ssl_certificate_invalid(self, mock_get):
        cert = check_ssl_certificate("https://invalid-site.com")
        self.assertFalse(cert)

    # Test VirusTotal API integration
    @patch('main.requests.get')
    def test_check_url_virustotal_safe(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'response_code': 1, 'positives': 0}
        mock_get.return_value = mock_response
        is_blacklisted, positives = check_url_virustotal("http://example.com")
        self.assertFalse(is_blacklisted)
        self.assertEqual(positives, 0)

    # Test VirusTotal API for a blacklisted URL
    @patch('main.requests.get')
    def test_check_url_virustotal_blacklisted(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'response_code': 1, 'positives': 5}
        mock_get.return_value = mock_response
        is_blacklisted, positives = check_url_virustotal("http://phishing-site.com")
        self.assertTrue(is_blacklisted)
        self.assertEqual(positives, 5)

    # Test email spoofing detection
    def test_check_email_spoofing(self):
        email_header = {'From': 'user@example.com', 'Reply-To': 'spoof@example.com'}
        self.assertTrue(check_email_spoofing(email_header))

        email_header = {'From': 'user@example.com', 'Reply-To': 'user@example.com'}
        self.assertFalse(check_email_spoofing(email_header))

    # Test get_urls_from_file for batch processing
    def test_get_urls_from_file(self):
        with patch('builtins.open', unittest.mock.mock_open(read_data='http://example.com\nhttp://phishingsite.com\n')):
            urls = get_urls_from_file("urls.txt")
            self.assertEqual(urls, ["http://example.com", "http://phishingsite.com"])

    # Test report generation for a safe URL
    def test_generate_report_safe(self):
        report = generate_report("http://example.com", False, True, False)
        expected_report = (
            "Phishing Detection Report for http://example.com:\n"
            "- URL not blacklisted.\n"
            "- SSL certificate is valid.\n"
        )
        self.assertEqual(report, expected_report)

    # Test report generation for a blacklisted URL
    def test_generate_report_blacklisted(self):
        report = generate_report("http://phishing-site.com", True, False, True)
        expected_report = (
            "Phishing Detection Report for http://phishing-site.com:\n"
            "- Blacklisted: True\n"
            "- SSL certificate is invalid or expired.\n"
            "- Email header has inconsistencies (potential spoofing).\n"
        )
        self.assertEqual(report, expected_report)


if __name__ == '__main__':
    unittest.main()
