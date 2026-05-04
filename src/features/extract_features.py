"""
Extract features from encrypted files
"""

import os
import pandas as pd
from typing import Dict, Any, List
from tqdm import tqdm

from src.features.entropy import calculate_entropy, calculate_block_entropy
from src.features.byte_stats import (
    calculate_byte_frequencies, 
    calculate_byte_statistics,
    get_file_magic_bytes,
    get_footer_bytes
)
from src.features.file_structure import analyze_file_structure


def extract_features_from_file(file_path: str, block_size: int = 4096) -> Dict[str, Any]:
    """
    Extract all features from a single file
    
    Args:
        file_path: Path to file
        block_size: Block size for entropy calculation
    
    Returns:
        Dictionary of extracted features
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    with open(file_path, 'rb') as f:
        data = f.read()
    
    features = {}
    features['path'] = file_path
    
    # File size features
    file_size = len(data)
    features['file_size'] = file_size
    features['file_size_mod_8'] = file_size % 8
    features['file_size_mod_16'] = file_size % 16
    features['file_size_mod_256'] = file_size % 256
    
    # Full entropy
    full_entropy = calculate_entropy(data)
    features['shannon_entropy_full'] = full_entropy
    
    # Block entropy
    block_entropies, entropy_stats = calculate_block_entropy(data, block_size)
    features['entropy_mean'] = entropy_stats['mean']
    features['entropy_std'] = entropy_stats['std']
    features['entropy_min'] = entropy_stats['min']
    features['entropy_max'] = entropy_stats['max']
    features['entropy_median'] = entropy_stats['median']
    features['entropy_first_block'] = block_entropies[0] if block_entropies else 0.0
    features['entropy_last_block'] = block_entropies[-1] if block_entropies else 0.0
    features['high_entropy_block_ratio'] = entropy_stats.get('high_entropy_ratio', 0.0)
    features['very_high_entropy_block_ratio'] = entropy_stats.get('very_high_entropy_ratio', 0.0)
    
    # Byte statistics
    byte_freqs = calculate_byte_frequencies(data)
    byte_stats = calculate_byte_statistics(data)
    
    features['unique_byte_count'] = byte_stats['unique_bytes']
    features['printable_byte_ratio'] = byte_stats['printable_ratio']
    features['null_byte_ratio'] = byte_stats['null_byte_ratio']
    features['byte_mean'] = byte_stats['byte_mean']
    features['byte_std'] = byte_stats['byte_std']
    features['byte_min'] = byte_stats['byte_min']
    features['byte_max'] = byte_stats['byte_max']
    features['byte_median'] = byte_stats['byte_median']
    
    # Byte histogram (256 features)
    for byte_val in range(256):
        features[f'byte_{byte_val}_freq'] = byte_freqs[byte_val]
    
    # File structure
    structure = analyze_file_structure(data, file_path)
    features['file_size'] = structure['file_size']
    features['has_known_signature'] = structure['has_known_signature']
    
    # Magic bytes (first 16 bytes)
    magic_bytes_str = get_file_magic_bytes(data, 16)
    features['magic_bytes_hex'] = magic_bytes_str
    
    # Footer bytes (last 16 bytes)
    footer_bytes_str = get_footer_bytes(data, 16)
    features['footer_bytes_hex'] = footer_bytes_str
    
    return features


def extract_features_batch(
    file_paths: List[str],
    output_file: str = None,
    block_size: int = 4096,
    verbose: bool = True
) -> pd.DataFrame:
    """
    Extract features from multiple files
    
    Args:
        file_paths: List of file paths
        output_file: Optional output parquet file
        block_size: Block size for entropy calculation
        verbose: Show progress bar
    
    Returns:
        DataFrame with extracted features
    """
    all_features = []
    
    iterator = tqdm(file_paths, desc="Extracting features") if verbose else file_paths
    
    for file_path in iterator:
        try:
            features = extract_features_from_file(file_path, block_size)
            all_features.append(features)
        except Exception as e:
            if verbose:
                print(f"Error processing {file_path}: {e}")
            continue
    
    df = pd.DataFrame(all_features)
    
    if output_file:
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        df.to_parquet(output_file, index=False)
    
    return df
