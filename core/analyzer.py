import hashlib
import math
from typing import Dict, Tuple


def calculate_hashes(file_path: str) -> Dict[str, str]:
    """Calculate MD5, SHA1, and SHA256 hashes of a file."""
    hashes = {
        'md5': hashlib.md5(),
        'sha1': hashlib.sha1(),
        'sha256': hashlib.sha256()
    }
    
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            for hash_obj in hashes.values():
                hash_obj.update(chunk)
    
    return {name: hash_obj.hexdigest() for name, hash_obj in hashes.items()}


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte data."""
    if not data:
        return 0.0
    
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1
    
    entropy = 0.0
    data_len = len(data)
    
    for count in byte_counts:
        if count > 0:
            probability = count / data_len
            entropy -= probability * math.log2(probability)
    
    return entropy


def analyze_file_entropy(file_path: str, chunk_size: int = 65536) -> Tuple[float, bool]:
    """Calculate file entropy via streaming and determine if it's suspicious (> 7.0)."""
    byte_counts = [0] * 256
    total_bytes = 0
    
    with open(file_path, 'rb') as f:
        while chunk := f.read(chunk_size):
            total_bytes += len(chunk)
            for b in chunk:
                byte_counts[b] += 1
    
    if total_bytes == 0:
        return 0.0, False
    
    entropy = 0.0
    for count in byte_counts:
        if count > 0:
            probability = count / total_bytes
            entropy -= probability * math.log2(probability)
    
    is_suspicious = entropy > 7.0
    return entropy, is_suspicious


def get_file_size(file_path: str) -> int:
    """Get file size in bytes."""
    import os
    return os.path.getsize(file_path)
