"""
Shannon entropy calculation utilities
"""

import math
from typing import List, Tuple


def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of data
    
    Args:
        data: Bytes to analyze
    
    Returns:
        Shannon entropy value (0-8 for bytes)
    """
    if len(data) == 0:
        return 0.0
    
    # Count byte frequencies
    frequencies = {}
    for byte in data:
        frequencies[byte] = frequencies.get(byte, 0) + 1
    
    # Calculate entropy
    entropy = 0.0
    data_len = len(data)
    
    for freq in frequencies.values():
        if freq > 0:
            probability = freq / data_len
            entropy -= probability * math.log2(probability)
    
    return entropy


def calculate_block_entropy(data: bytes, block_size: int = 4096) -> Tuple[List[float], dict]:
    """
    Calculate entropy for each block of data
    
    Args:
        data: Bytes to analyze
        block_size: Size of each block in bytes
    
    Returns:
        Tuple of (block_entropies, entropy_stats)
    """
    block_entropies = []
    
    # Calculate entropy for each block
    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        if len(block) > 0:
            entropy = calculate_entropy(block)
            block_entropies.append(entropy)
    
    # Calculate statistics
    if not block_entropies:
        stats = {
            'mean': 0.0,
            'std': 0.0,
            'min': 0.0,
            'max': 0.0,
            'median': 0.0,
            'high_entropy_count': 0,
            'very_high_entropy_count': 0
        }
    else:
        entropies = sorted(block_entropies)
        n = len(entropies)
        median = (entropies[n // 2] + entropies[(n - 1) // 2]) / 2
        
        mean = sum(block_entropies) / len(block_entropies)
        variance = sum((e - mean) ** 2 for e in block_entropies) / len(block_entropies)
        std = math.sqrt(variance)
        
        high_entropy_count = sum(1 for e in block_entropies if e > 7.5)
        very_high_entropy_count = sum(1 for e in block_entropies if e > 7.8)
        
        stats = {
            'mean': mean,
            'std': std,
            'min': min(block_entropies),
            'max': max(block_entropies),
            'median': median,
            'high_entropy_count': high_entropy_count,
            'very_high_entropy_count': very_high_entropy_count,
            'high_entropy_ratio': high_entropy_count / len(block_entropies) if block_entropies else 0,
            'very_high_entropy_ratio': very_high_entropy_count / len(block_entropies) if block_entropies else 0
        }
    
    return block_entropies, stats
