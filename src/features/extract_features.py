"""
Extract features from encrypted files
"""

import os
from pathlib import Path
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


COMMON_ORIGINAL_EXTENSIONS = {
    '.csv',
    '.doc',
    '.docx',
    '.exe',
    '.jpg',
    '.jpeg',
    '.pdf',
    '.ppt',
    '.pptx',
    '.txt',
    '.xls',
    '.xlsx',
    '.zip',
}


def _ratio(count: int, total: int) -> float:
    return count / total if total else 0.0


def calculate_advanced_byte_features(data: bytes) -> Dict[str, float]:
    """Calculate statistical byte features useful for encrypted-family fingerprints."""
    data_len = len(data)
    if data_len == 0:
        return {
            'byte_chi_square_uniformity': 0.0,
            'byte_serial_correlation': 0.0,
            'adjacent_equal_byte_ratio': 0.0,
            'adjacent_abs_diff_mean': 0.0,
            'adjacent_abs_diff_std': 0.0,
            'adjacent_xor_mean': 0.0,
            'unique_bigram_ratio': 0.0,
            'run_count_ratio': 0.0,
            'longest_byte_run': 0.0,
            'mean_byte_run_length': 0.0,
        }

    expected = data_len / 256
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    chi_square = sum(((count - expected) ** 2) / expected for count in counts) if expected else 0.0

    sample = data[: min(data_len, 1_000_000)]
    if len(sample) < 2:
        return {
            'byte_chi_square_uniformity': chi_square,
            'byte_serial_correlation': 0.0,
            'adjacent_equal_byte_ratio': 0.0,
            'adjacent_abs_diff_mean': 0.0,
            'adjacent_abs_diff_std': 0.0,
            'adjacent_xor_mean': 0.0,
            'unique_bigram_ratio': 0.0,
            'run_count_ratio': 1.0,
            'longest_byte_run': float(data_len),
            'mean_byte_run_length': float(data_len),
        }

    n_pairs = len(sample) - 1
    equal_pairs = 0
    abs_diffs = []
    xor_values = []
    bigrams = set()

    for left, right in zip(sample, sample[1:]):
        if left == right:
            equal_pairs += 1
        abs_diffs.append(abs(left - right))
        xor_values.append(left ^ right)
        bigrams.add((left, right))

    diff_mean = sum(abs_diffs) / n_pairs
    diff_var = sum((value - diff_mean) ** 2 for value in abs_diffs) / n_pairs
    xor_mean = sum(xor_values) / n_pairs

    x_values = sample[:-1]
    y_values = sample[1:]
    x_mean = sum(x_values) / n_pairs
    y_mean = sum(y_values) / n_pairs
    covariance = sum((x - x_mean) * (y - y_mean) for x, y in zip(x_values, y_values)) / n_pairs
    x_var = sum((x - x_mean) ** 2 for x in x_values) / n_pairs
    y_var = sum((y - y_mean) ** 2 for y in y_values) / n_pairs
    serial_correlation = covariance / ((x_var * y_var) ** 0.5) if x_var and y_var else 0.0

    run_count = 1
    current_run = 1
    longest_run = 1
    for left, right in zip(sample, sample[1:]):
        if left == right:
            current_run += 1
            longest_run = max(longest_run, current_run)
        else:
            run_count += 1
            current_run = 1

    return {
        'byte_chi_square_uniformity': chi_square,
        'byte_serial_correlation': serial_correlation,
        'adjacent_equal_byte_ratio': equal_pairs / n_pairs,
        'adjacent_abs_diff_mean': diff_mean,
        'adjacent_abs_diff_std': diff_var ** 0.5,
        'adjacent_xor_mean': xor_mean,
        'unique_bigram_ratio': len(bigrams) / min(n_pairs, 65536),
        'run_count_ratio': run_count / len(sample),
        'longest_byte_run': float(longest_run),
        'mean_byte_run_length': len(sample) / run_count,
    }


def calculate_segment_features(data: bytes) -> Dict[str, float]:
    """Calculate entropy and byte-distribution features for file regions."""
    segments = {
        'first_256': data[:256],
        'first_1024': data[:1024],
        'last_256': data[-256:] if data else b'',
        'last_1024': data[-1024:] if data else b'',
    }

    if len(data) > 1024:
        middle_start = max((len(data) // 2) - 512, 0)
        segments['middle_1024'] = data[middle_start:middle_start + 1024]
    else:
        segments['middle_1024'] = data

    features = {}
    for name, segment in segments.items():
        stats = calculate_byte_statistics(segment)
        features[f'{name}_entropy'] = calculate_entropy(segment)
        features[f'{name}_printable_ratio'] = stats['printable_ratio']
        features[f'{name}_null_byte_ratio'] = stats['null_byte_ratio']
        features[f'{name}_unique_byte_count'] = stats['unique_bytes']

    if data:
        features['first_byte_value'] = data[0]
        features['last_byte_value'] = data[-1]
    else:
        features['first_byte_value'] = 0
        features['last_byte_value'] = 0

    return features


def calculate_filename_features(file_path: str) -> Dict[str, float]:
    """Calculate numeric filename/extension features often exposed by ransomware outputs."""
    path = Path(file_path)
    name = path.name
    suffixes = path.suffixes
    final_suffix = suffixes[-1].lower() if suffixes else ''
    prior_suffix = suffixes[-2].lower() if len(suffixes) >= 2 else ''
    final_suffix_text = final_suffix.lstrip('.')

    final_len = len(final_suffix_text)
    alpha_count = sum(1 for char in final_suffix_text if char.isalpha())
    digit_count = sum(1 for char in final_suffix_text if char.isdigit())
    hex_count = sum(1 for char in final_suffix_text.lower() if char in '0123456789abcdef')
    vowel_count = sum(1 for char in final_suffix_text.lower() if char in 'aeiou')
    ascii_values = [ord(char) for char in final_suffix_text]

    return {
        'filename_length': len(name),
        'filename_digit_ratio': _ratio(sum(1 for char in name if char.isdigit()), len(name)),
        'filename_alpha_ratio': _ratio(sum(1 for char in name if char.isalpha()), len(name)),
        'suffix_count': len(suffixes),
        'has_double_extension': float(len(suffixes) >= 2),
        'final_extension_length': final_len,
        'final_extension_entropy': calculate_entropy(final_suffix_text.encode('utf-8')),
        'final_extension_alpha_ratio': _ratio(alpha_count, final_len),
        'final_extension_digit_ratio': _ratio(digit_count, final_len),
        'final_extension_hex_ratio': _ratio(hex_count, final_len),
        'final_extension_vowel_ratio': _ratio(vowel_count, final_len),
        'final_extension_ascii_mean': sum(ascii_values) / final_len if final_len else 0.0,
        'prior_extension_is_common_original': float(prior_suffix in COMMON_ORIGINAL_EXTENSIONS),
        'final_extension_is_common_original': float(final_suffix in COMMON_ORIGINAL_EXTENSIONS),
    }


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

    # Advanced encrypted-file statistics
    features.update(calculate_advanced_byte_features(data))
    features.update(calculate_segment_features(data))
    features.update(calculate_filename_features(file_path))
    
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
