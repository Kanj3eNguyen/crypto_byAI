"""
Byte statistics and frequency analysis
"""

from typing import List, Dict


def calculate_byte_frequencies(data: bytes) -> Dict[int, float]:
    """
    Calculate frequency of each byte value (0-255)
    
    Args:
        data: Bytes to analyze
    
    Returns:
        Dictionary mapping byte value to frequency (0.0-1.0)
    """
    frequencies = {}
    data_len = len(data)
    
    if data_len == 0:
        return {i: 0.0 for i in range(256)}
    
    # Count occurrences
    byte_counts = {}
    for byte in data:
        byte_counts[byte] = byte_counts.get(byte, 0) + 1
    
    # Convert to frequencies
    for i in range(256):
        frequencies[i] = byte_counts.get(i, 0) / data_len
    
    return frequencies


def calculate_byte_statistics(data: bytes) -> Dict[str, float]:
    """
    Calculate byte-level statistics
    
    Args:
        data: Bytes to analyze
    
    Returns:
        Dictionary of byte statistics
    """
    if len(data) == 0:
        return {
            'unique_bytes': 0,
            'printable_ratio': 0.0,
            'null_byte_ratio': 0.0,
            'byte_mean': 0.0,
            'byte_std': 0.0,
            'byte_min': 0,
            'byte_max': 0,
            'byte_median': 0
        }
    
    # Count unique bytes
    unique_bytes = len(set(data))
    
    # Count printable bytes (ASCII 32-126)
    printable_count = sum(1 for b in data if 32 <= b <= 126)
    printable_ratio = printable_count / len(data)
    
    # Count null bytes (0x00)
    null_count = sum(1 for b in data if b == 0)
    null_ratio = null_count / len(data)
    
    # Calculate byte value statistics
    byte_values = list(data)
    byte_mean = sum(byte_values) / len(byte_values)
    
    variance = sum((b - byte_mean) ** 2 for b in byte_values) / len(byte_values)
    byte_std = variance ** 0.5
    
    sorted_bytes = sorted(byte_values)
    n = len(sorted_bytes)
    byte_median = (sorted_bytes[n // 2] + sorted_bytes[(n - 1) // 2]) / 2
    
    return {
        'unique_bytes': unique_bytes,
        'printable_ratio': printable_ratio,
        'null_byte_ratio': null_ratio,
        'byte_mean': byte_mean,
        'byte_std': byte_std,
        'byte_min': min(byte_values),
        'byte_max': max(byte_values),
        'byte_median': byte_median
    }


def get_file_magic_bytes(data: bytes, n_bytes: int = 16) -> str:
    """
    Get first N bytes as hex string (file magic/header)
    
    Args:
        data: File data
        n_bytes: Number of bytes to get
    
    Returns:
        Hex string representation
    """
    return data[:n_bytes].hex().upper()


def get_footer_bytes(data: bytes, n_bytes: int = 16) -> str:
    """
    Get last N bytes as hex string (file footer)
    
    Args:
        data: File data
        n_bytes: Number of bytes to get
    
    Returns:
        Hex string representation
    """
    return data[-n_bytes:].hex().upper() if len(data) >= n_bytes else data.hex().upper()
