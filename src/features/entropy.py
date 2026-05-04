"""
Shannon entropy calculation utilities
"""

from typing import List, Tuple

import numpy as np


def calculate_entropy_from_counts(counts, data_len: int) -> float:
    """Calculate Shannon entropy from precomputed byte counts."""
    if data_len == 0:
        return 0.0

    counts_array = np.asarray(counts, dtype=np.float64)
    nonzero_counts = counts_array[counts_array > 0]
    probabilities = nonzero_counts / data_len
    return float(-np.sum(probabilities * np.log2(probabilities)))


def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of data
    
    Args:
        data: Bytes to analyze
    
    Returns:
        Shannon entropy value (0-8 for bytes)
    """
    data_len = len(data)
    if data_len == 0:
        return 0.0

    byte_values = np.frombuffer(data, dtype=np.uint8)
    counts = np.bincount(byte_values, minlength=256)
    return calculate_entropy_from_counts(counts, data_len)


def calculate_block_entropy(data: bytes, block_size: int = 4096) -> Tuple[List[float], dict]:
    """
    Calculate entropy for each block of data
    
    Args:
        data: Bytes to analyze
        block_size: Size of each block in bytes
    
    Returns:
        Tuple of (block_entropies, entropy_stats)
    """
    if block_size <= 0:
        raise ValueError("block_size must be greater than 0")

    block_entropies = []
    data_view = memoryview(data)
    
    # Calculate entropy for each block
    for i in range(0, len(data), block_size):
        block = data_view[i:i + block_size]
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
            'very_high_entropy_count': 0,
            'high_entropy_ratio': 0.0,
            'very_high_entropy_ratio': 0.0,
            'percentage_above_7_5': 0.0,
            'percentage_above_7_8': 0.0,
        }
    else:
        entropy_array = np.asarray(block_entropies, dtype=np.float64)
        high_entropy_count = int(np.count_nonzero(entropy_array > 7.5))
        very_high_entropy_count = int(np.count_nonzero(entropy_array > 7.8))
        block_count = len(block_entropies)
        
        stats = {
            'mean': float(np.mean(entropy_array)),
            'std': float(np.std(entropy_array)),
            'min': float(np.min(entropy_array)),
            'max': float(np.max(entropy_array)),
            'median': float(np.median(entropy_array)),
            'high_entropy_count': high_entropy_count,
            'very_high_entropy_count': very_high_entropy_count,
            'high_entropy_ratio': high_entropy_count / block_count,
            'very_high_entropy_ratio': very_high_entropy_count / block_count,
            'percentage_above_7_5': high_entropy_count / block_count,
            'percentage_above_7_8': very_high_entropy_count / block_count,
        }
    
    return block_entropies, stats
