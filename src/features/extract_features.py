"""
Extract features from encrypted files
"""

import os
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Dict, Any, List

import numpy as np
import pandas as pd
from tqdm import tqdm

from src.features.entropy import (
    calculate_entropy,
    calculate_entropy_from_counts,
    calculate_block_entropy,
)
from src.features.byte_stats import (
    calculate_byte_counts,
    calculate_byte_frequencies_from_counts,
    calculate_byte_statistics,
    calculate_byte_statistics_from_counts,
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


def calculate_advanced_byte_features(data: bytes, byte_counts=None) -> Dict[str, float]:
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

    counts = (
        np.asarray(byte_counts, dtype=np.float64)
        if byte_counts is not None
        else calculate_byte_counts(data).astype(np.float64)
    )
    expected = data_len / 256
    chi_square = float(np.sum(((counts - expected) ** 2) / expected)) if expected else 0.0

    byte_values = np.frombuffer(data, dtype=np.uint8)
    sample = byte_values[: min(data_len, 1_000_000)]
    sample_size = len(sample)
    if sample_size < 2:
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

    n_pairs = sample_size - 1
    left_values = sample[:-1]
    right_values = sample[1:]
    left_int = left_values.astype(np.int16)
    right_int = right_values.astype(np.int16)

    equal_pairs = int(np.count_nonzero(left_values == right_values))
    abs_diffs = np.abs(left_int - right_int)
    xor_values = np.bitwise_xor(left_values, right_values)
    diff_mean = float(np.mean(abs_diffs))
    diff_std = float(np.std(abs_diffs))
    xor_mean = float(np.mean(xor_values))

    x_values = left_values.astype(np.float64)
    y_values = right_values.astype(np.float64)
    x_mean = float(np.mean(x_values))
    y_mean = float(np.mean(y_values))
    covariance = float(np.mean((x_values - x_mean) * (y_values - y_mean)))
    x_var = float(np.mean((x_values - x_mean) ** 2))
    y_var = float(np.mean((y_values - y_mean) ** 2))
    serial_correlation = covariance / ((x_var * y_var) ** 0.5) if x_var and y_var else 0.0

    bigram_codes = left_values.astype(np.uint16) * 256 + right_values.astype(np.uint16)
    unique_bigram_count = int(np.unique(bigram_codes).size)

    run_breaks = np.flatnonzero(left_values != right_values) + 1
    run_count = int(len(run_breaks) + 1)
    run_boundaries = np.concatenate(([0], run_breaks, [sample_size]))
    longest_run = int(np.max(np.diff(run_boundaries)))

    return {
        'byte_chi_square_uniformity': chi_square,
        'byte_serial_correlation': serial_correlation,
        'adjacent_equal_byte_ratio': equal_pairs / n_pairs,
        'adjacent_abs_diff_mean': diff_mean,
        'adjacent_abs_diff_std': diff_std,
        'adjacent_xor_mean': xor_mean,
        'unique_bigram_ratio': unique_bigram_count / min(n_pairs, 65536),
        'run_count_ratio': run_count / sample_size,
        'longest_byte_run': float(longest_run),
        'mean_byte_run_length': sample_size / run_count,
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
    
    byte_counts = calculate_byte_counts(data)

    # Full entropy
    full_entropy = calculate_entropy_from_counts(byte_counts, file_size)
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
    byte_freqs = calculate_byte_frequencies_from_counts(byte_counts, file_size)
    byte_stats = calculate_byte_statistics_from_counts(byte_counts, file_size)
    
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
    features.update(calculate_advanced_byte_features(data, byte_counts=byte_counts))
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


def _extract_features_worker(args):
    file_path, block_size = args
    try:
        return extract_features_from_file(file_path, block_size), None
    except Exception as exc:
        return None, f"Error processing {file_path}: {exc}"


def extract_features_batch(
    file_paths: List[str],
    output_file: str = None,
    block_size: int = 4096,
    workers: int = 1,
    verbose: bool = True
) -> pd.DataFrame:
    """
    Extract features from multiple files
    
    Args:
        file_paths: List of file paths
        output_file: Optional output parquet file
        block_size: Block size for entropy calculation
        workers: Number of worker processes. Use 0 to auto-select CPU count.
        verbose: Show progress bar
    
    Returns:
        DataFrame with extracted features
    """
    if workers == 0:
        workers = max((os.cpu_count() or 2) - 1, 1)

    all_features = []

    if workers <= 1 or len(file_paths) <= 1:
        iterator = tqdm(file_paths, desc="Extracting features") if verbose else file_paths
        for file_path in iterator:
            features, error = _extract_features_worker((file_path, block_size))
            if error:
                if verbose:
                    print(error)
                continue
            all_features.append(features)
    else:
        worker_args = ((file_path, block_size) for file_path in file_paths)
        chunk_size = max(1, len(file_paths) // (workers * 4))
        with ProcessPoolExecutor(max_workers=workers) as executor:
            results = executor.map(_extract_features_worker, worker_args, chunksize=chunk_size)
            iterator = (
                tqdm(results, total=len(file_paths), desc=f"Extracting features ({workers} workers)")
                if verbose
                else results
            )
            for features, error in iterator:
                if error:
                    if verbose:
                        print(error)
                    continue
                all_features.append(features)
    
    df = pd.DataFrame(all_features)
    
    if output_file:
        os.makedirs(os.path.dirname(output_file) or '.', exist_ok=True)
        df.to_parquet(output_file, index=False)
    
    return df
