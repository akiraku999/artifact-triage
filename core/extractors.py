import re
import base64
from typing import List, Dict, Any


class IOCExtractor:
    """Extract Indicators of Compromise from file content."""
    
    # IPv4 regex pattern
    IPV4_PATTERN = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    
    # URL regex pattern
    URL_PATTERN = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w .-]*/?'
    
    # Email regex pattern
    EMAIL_PATTERN = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    
    # Base64 pattern (strings longer than 20 chars)
    BASE64_PATTERN = r'[A-Za-z0-9+/]{20,}={0,2}'
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.content = self._read_file_content()
    
    def _read_file_content(self) -> str:
        """Read file content as text, fallback to partial binary read."""
        try:
            with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception:
            try:
                with open(self.file_path, 'r', encoding='latin-1', errors='ignore') as f:
                    return f.read()
            except Exception:
                with open(self.file_path, 'rb') as f:
                    return f.read().decode('utf-8', errors='ignore')
    
    def extract_ipv4(self) -> List[str]:
        """Extract IPv4 addresses from content."""
        matches = re.findall(self.IPV4_PATTERN, self.content)
        return list(set(matches))
    
    def extract_urls(self) -> List[str]:
        """Extract URLs from content."""
        matches = re.findall(self.URL_PATTERN, self.content, re.IGNORECASE)
        return list(set(matches))
    
    def extract_emails(self) -> List[str]:
        """Extract email addresses from content."""
        matches = re.findall(self.EMAIL_PATTERN, self.content)
        return list(set(matches))
    
    def extract_base64_strings(self) -> List[Dict[str, Any]]:
        """Extract suspicious base64 strings and attempt to decode them."""
        matches = re.findall(self.BASE64_PATTERN, self.content)
        unique_matches = list(set(matches))
        
        results = []
        for match in unique_matches:
            try:
                decoded = base64.b64decode(match, validate=True).decode('utf-8', errors='ignore')
                results.append({
                    'encoded': match,
                    'decoded': decoded,
                    'is_printable': decoded.isprintable()
                })
            except Exception:
                results.append({
                    'encoded': match,
                    'decoded': None,
                    'is_printable': False
                })
        
        return results
    
    def extract_all_iocs(self) -> Dict[str, Any]:
        """Extract all IOCs from the file."""
        return {
            'ipv4': self.extract_ipv4(),
            'urls': self.extract_urls(),
            'emails': self.extract_emails(),
            'base64_strings': self.extract_base64_strings()
        }
