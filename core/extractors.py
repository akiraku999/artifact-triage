import re
import base64
import ipaddress
from typing import List, Dict, Any


def defang_url(url: str) -> str:
    """Defang a URL to prevent accidental clicks (e.g. http://evil.com -> hxxp://evil[.]com)."""
    defanged = re.sub(r'^http://', 'hxxp://', url, flags=re.IGNORECASE)
    defanged = re.sub(r'^https://', 'hxxps://', defanged, flags=re.IGNORECASE)
    parts = defanged.split('/', 3)
    if len(parts) >= 3:
        parts[2] = parts[2].replace('.', '[.]')
        return '/'.join(parts)
    return defanged.replace('.', '[.]')


def defang_ip(ip: str) -> str:
    """Defang an IP address (e.g. 192.168.1.1 -> 192.168.1[.]1)."""
    if '.' in ip:
        last_dot_idx = ip.rfind('.')
        return ip[:last_dot_idx] + '[.]' + ip[last_dot_idx + 1:]
    return ip


def defang_email(email: str) -> str:
    """Defang an email address (e.g. attacker@evil.com -> attacker[@]evil[.]com)."""
    if '@' in email:
        user, domain = email.split('@', 1)
        return f"{user}[@]{domain.replace('.', '[.]')}"
    return email.replace('.', '[.]')


class IOCExtractor:
    """Extract Indicators of Compromise from file content."""
    
    # IPv4 regex pattern
    IPV4_PATTERN = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    
    # URL regex pattern
    URL_PATTERN = r'https?://[a-zA-Z0-9_\-\.]+(?::\d+)?(?:/[a-zA-Z0-9_\-\.\?%&=#~:@!$,;+]*)?'
    
    # Email regex pattern
    EMAIL_PATTERN = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    
    # Base64 pattern (strings of 20+ base64 chars with optional padding)
    BASE64_PATTERN = r'\b[A-Za-z0-9+/]{20,}={0,2}\b'
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.content = self._read_file_content()
    
    def _read_file_content(self) -> str:
        """Read file content with extraction of ASCII and UTF-16LE (wide) strings for binaries."""
        try:
            with open(self.file_path, 'rb') as f:
                raw_bytes = f.read()
        except Exception:
            return ""
        
        extracted_strings = []
        
        # 1. Try decoding as regular UTF-8/text
        try:
            decoded_text = raw_bytes.decode('utf-8')
            extracted_strings.append(decoded_text)
        except UnicodeDecodeError:
            pass
        
        # 2. Extract ASCII strings (min length 4)
        ascii_matches = re.findall(b'[\x20-\x7E]{4,}', raw_bytes)
        if ascii_matches:
            extracted_strings.extend(m.decode('latin-1', errors='ignore') for m in ascii_matches)
        
        # 3. Extract UTF-16LE strings (Wide strings, min length 4 chars) - common in Windows binaries
        utf16_matches = re.findall(b'(?:[\x20-\x7E]\x00){4,}', raw_bytes)
        if utf16_matches:
            extracted_strings.extend(m.decode('utf-16le', errors='ignore') for m in utf16_matches)
        
        if not extracted_strings:
            return raw_bytes.decode('utf-8', errors='ignore')
        
        return "\n".join(extracted_strings)
    
    def extract_ipv4(self) -> List[str]:
        """Extract valid IPv4 addresses from content."""
        details = self.extract_ipv4_details()
        return details['all']
    
    def extract_ipv4_details(self) -> Dict[str, List[str]]:
        """Extract and categorize IPv4 addresses into public and private/local."""
        matches = re.findall(self.IPV4_PATTERN, self.content)
        unique_matches = set(matches)
        
        public_ips = set()
        private_ips = set()
        
        for ip_str in unique_matches:
            # Skip invalid, wildcard, broadcast, or software version numbers (e.g. 1.0.0.0, 6.0.0.0)
            if ip_str in ('0.0.0.0', '255.255.255.255') or ip_str.endswith('.0.0.0'):
                continue
            try:
                ip = ipaddress.IPv4Address(ip_str)
                if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                    private_ips.add(ip_str)
                elif ip.is_global:
                    public_ips.add(ip_str)
                else:
                    private_ips.add(ip_str)
            except ValueError:
                continue
        
        return {
            'all': sorted(list(public_ips | private_ips)),
            'public': sorted(list(public_ips)),
            'private': sorted(list(private_ips))
        }
    
    def extract_urls(self) -> List[str]:
        """Extract URLs from content, trimming trailing punctuation."""
        matches = re.findall(self.URL_PATTERN, self.content, re.IGNORECASE)
        cleaned_urls = set()
        for url in matches:
            cleaned = url.rstrip('.,;:)>\'"`')
            if len(cleaned) > 10 and '://' in cleaned:
                cleaned_urls.add(cleaned)
        return sorted(list(cleaned_urls))
    
    def extract_emails(self) -> List[str]:
        """Extract email addresses from content."""
        matches = re.findall(self.EMAIL_PATTERN, self.content)
        cleaned_emails = set()
        for email in matches:
            cleaned = email.rstrip('.,;:)>\'"`')
            cleaned_emails.add(cleaned)
        return sorted(list(cleaned_emails))
    
    def extract_base64_strings(self) -> List[Dict[str, Any]]:
        """Extract suspicious base64 strings and attempt to decode them."""
        matches = re.findall(self.BASE64_PATTERN, self.content)
        unique_matches = sorted(list(set(matches)))
        
        results = []
        for match in unique_matches:
            # Add padding if needed
            pad_len = len(match) % 4
            padded_match = match if pad_len == 0 else match + ('=' * (4 - pad_len))
            
            try:
                decoded_bytes = base64.b64decode(padded_match, validate=True)
                decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
                is_printable = len(decoded_str) > 0 and all(c.isprintable() or c in '\r\n\t' for c in decoded_str)
                results.append({
                    'encoded': match,
                    'decoded': decoded_str if is_printable else None,
                    'is_printable': is_printable
                })
            except Exception:
                results.append({
                    'encoded': match,
                    'decoded': None,
                    'is_printable': False
                })
        
        return results
    
    def extract_all_iocs(self, defang: bool = False) -> Dict[str, Any]:
        """Extract all IOCs from the file, with optional defanging."""
        ipv4_details = self.extract_ipv4_details()
        urls = self.extract_urls()
        emails = self.extract_emails()
        base64_strings = self.extract_base64_strings()

        if defang:
            all_ips = [defang_ip(ip) for ip in ipv4_details['all']]
            pub_ips = [defang_ip(ip) for ip in ipv4_details['public']]
            priv_ips = [defang_ip(ip) for ip in ipv4_details['private']]
            urls = [defang_url(u) for u in urls]
            emails = [defang_email(e) for e in emails]
            ipv4_details = {
                'all': all_ips,
                'public': pub_ips,
                'private': priv_ips
            }
        else:
            all_ips = ipv4_details['all']

        return {
            'ipv4': all_ips,
            'ipv4_details': ipv4_details,
            'urls': urls,
            'emails': emails,
            'base64_strings': base64_strings
        }
