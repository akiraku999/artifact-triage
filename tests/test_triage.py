import unittest
import tempfile
import os
import sys
import hashlib
from core.analyzer import calculate_hashes, analyze_file_entropy, calculate_entropy
from core.extractors import IOCExtractor, defang_url, defang_ip, defang_email
from core.pe_analyzer import PEAnalyzer


class TestArtifactTriage(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory()
        
    def tearDown(self):
        self.test_dir.cleanup()
        
    def test_calculate_hashes(self):
        test_data = b"Hello Sentinel Triage!"
        test_file = os.path.join(self.test_dir.name, "test_hash.txt")
        with open(test_file, "wb") as f:
            f.write(test_data)
            
        hashes = calculate_hashes(test_file)
        self.assertEqual(hashes['md5'], hashlib.md5(test_data).hexdigest())
        self.assertEqual(hashes['sha1'], hashlib.sha1(test_data).hexdigest())
        self.assertEqual(hashes['sha256'], hashlib.sha256(test_data).hexdigest())

    def test_entropy_streaming(self):
        # 1. Zero data
        empty_file = os.path.join(self.test_dir.name, "empty.bin")
        with open(empty_file, "wb") as f:
            pass
        entropy, is_susp = analyze_file_entropy(empty_file)
        self.assertEqual(entropy, 0.0)
        self.assertFalse(is_susp)
        
        # 2. Consistent data
        sample_data = b"A" * 1000 + b"B" * 500 + bytes(range(256)) * 4
        sample_file = os.path.join(self.test_dir.name, "sample.bin")
        with open(sample_file, "wb") as f:
            f.write(sample_data)
            
        stream_entropy, _ = analyze_file_entropy(sample_file, chunk_size=64)
        direct_entropy = calculate_entropy(sample_data)
        self.assertAlmostEqual(stream_entropy, direct_entropy, places=5)

    def test_extract_ipv4_classification(self):
        content = (
            "Private IP: 192.168.1.50 and 10.0.0.1 and 127.0.0.1\n"
            "Public IP: 93.184.216.34 and 1.1.1.1\n"
            "Invalid: 999.999.999.999 and 0.0.0.0\n"
        )
        test_file = os.path.join(self.test_dir.name, "ips.txt")
        with open(test_file, "w", encoding="utf-8") as f:
            f.write(content)
            
        extractor = IOCExtractor(test_file)
        details = extractor.extract_ipv4_details()
        
        self.assertIn("192.168.1.50", details['private'])
        self.assertIn("10.0.0.1", details['private'])
        self.assertIn("127.0.0.1", details['private'])
        self.assertIn("93.184.216.34", details['public'])
        self.assertIn("1.1.1.1", details['public'])
        self.assertNotIn("0.0.0.0", details['all'])
        self.assertNotIn("999.999.999.999", details['all'])

    def test_extract_utf16le_strings(self):
        # Simulate Windows PE binary with UTF-16LE strings
        ascii_part = b"Regular ASCII text header\x00\x00\x00"
        wide_url = "http://malicious-c2-domain.com/gate.php".encode('utf-16le')
        wide_ip = "185.220.101.5".encode('utf-16le')
        raw_binary = ascii_part + b"\x90\x90\x00\x00" + wide_url + b"\x00\x00" + wide_ip
        
        test_file = os.path.join(self.test_dir.name, "binary_sample.bin")
        with open(test_file, "wb") as f:
            f.write(raw_binary)
            
        extractor = IOCExtractor(test_file)
        urls = extractor.extract_urls()
        ips = extractor.extract_ipv4()
        
        self.assertIn("http://malicious-c2-domain.com/gate.php", urls)
        self.assertIn("185.220.101.5", ips)

    def test_base64_decoding(self):
        # Base64 string longer than 20 chars:
        # "VGhpcyBpcyBhIHNlY3JldCBtZXNzYWdl" -> "This is a secret message"
        content = "Config: VGhpcyBpcyBhIHNlY3JldCBtZXNzYWdl\n"
        test_file = os.path.join(self.test_dir.name, "b64.txt")
        with open(test_file, "w", encoding="utf-8") as f:
            f.write(content)
            
        extractor = IOCExtractor(test_file)
        b64_results = extractor.extract_base64_strings()
        
        self.assertEqual(len(b64_results), 1)
        self.assertTrue(b64_results[0]['is_printable'])
        self.assertEqual(b64_results[0]['decoded'], "This is a secret message")

    def test_defanging(self):
        # URL defanging
        self.assertEqual(defang_url("http://evil-c2.com/payload"), "hxxp://evil-c2[.]com/payload")
        self.assertEqual(defang_url("https://secure-gate.org/login"), "hxxps://secure-gate[.]org/login")
        
        # IP defanging
        self.assertEqual(defang_ip("192.168.1.100"), "192.168.1[.]100")
        
        # Email defanging
        self.assertEqual(defang_email("attacker@badguys.net"), "attacker[@]badguys[.]net")
        
        # Extractor integration
        content = "Server: http://evil.com/gate and IP: 185.220.101.5\n"
        test_file = os.path.join(self.test_dir.name, "defang_test.txt")
        with open(test_file, "w", encoding="utf-8") as f:
            f.write(content)
            
        extractor = IOCExtractor(test_file)
        iocs = extractor.extract_all_iocs(defang=True)
        self.assertIn("hxxp://evil[.]com/gate", iocs['urls'])
        self.assertIn("185.220.101[.]5", iocs['ipv4'])

    def test_pe_analyzer_non_pe(self):
        non_pe_file = os.path.join(self.test_dir.name, "script.py")
        with open(non_pe_file, "w") as f:
            f.write("print('hello world')")
            
        pe_analyzer = PEAnalyzer(non_pe_file)
        self.assertFalse(pe_analyzer.is_pe_file())
        res = pe_analyzer.analyze()
        self.assertFalse(res['is_pe'])

    def test_pe_analyzer_real_pe(self):
        # sys.executable is python.exe, a real PE binary
        if sys.platform == 'win32' and os.path.exists(sys.executable):
            pe_analyzer = PEAnalyzer(sys.executable)
            self.assertTrue(pe_analyzer.is_pe_file())
            res = pe_analyzer.analyze()
            self.assertTrue(res['is_pe'])
            self.assertIn('x64', res['architecture'].lower())
            self.assertGreater(len(res['sections']), 0)
            self.assertIn('compile_time', res)


if __name__ == '__main__':
    unittest.main()

