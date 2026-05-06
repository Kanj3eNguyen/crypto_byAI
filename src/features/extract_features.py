"""
Trích xuất đặc trưng từ tệp cần phân tích.
"""

import os
from concurrent.futures import ProcessPoolExecutor
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


def calculate_advanced_byte_features(data: bytes, byte_counts=None) -> Dict[str, float]:
    """Tính các đặc trưng byte dùng để phân biệt nhóm mã hóa."""
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
    """Tính entropy và phân bố byte cho các vùng trong tệp."""
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


def _normalized_entropy(data: bytes) -> float:
    """Tính entropy đã chuẩn hóa theo độ dài đoạn dữ liệu."""
    data_len = len(data)
    if data_len <= 1:
        return 0.0

    max_entropy = float(np.log2(min(data_len, 256)))
    if max_entropy == 0:
        return 0.0

    return calculate_entropy(data) / max_entropy


def _random_like_segment(data: bytes, min_len: int = 8) -> float:
    """Trả về 1.0 nếu đoạn ngắn giống nonce, tag hoặc khóa."""
    data_len = len(data)
    if data_len < min_len:
        return 0.0

    counts = calculate_byte_counts(data)
    unique_ratio = float(np.count_nonzero(counts) / data_len)
    max_frequency = float(np.max(counts) / data_len)
    normalized_entropy = _normalized_entropy(data)

    min_unique_ratio = 0.50 if data_len >= 128 else 0.70
    if unique_ratio >= min_unique_ratio and normalized_entropy >= 0.75 and max_frequency <= 0.30:
        return 1.0

    return 0.0


def _plausible_footer_length_values(data_len: int, value: int) -> bool:
    """Kiểm tra giá trị độ dài footer sau khi giải mã marker."""
    max_footer_size = min(data_len - 4, 4096)
    common_footer_sizes = {
        8,
        12,
        16,
        24,
        28,
        32,
        40,
        264,
        268,
        272,
        276,
        280,
        296,
        512,
        528,
        536,
        552,
    }
    return (
        8 <= value <= max_footer_size
        and (value in common_footer_sizes or value % 8 == 0 or value % 16 == 0)
    )


def _find_footer_marker(data: bytes):
    """Tìm marker footer hợp lý ở cuối tệp hoặc trước phần footer."""
    if len(data) < 12:
        return 0, ''

    marker_candidates = [
        ('suffix_length', len(data) - 4),
    ]
    for footer_size in (8, 12, 16, 24, 28, 32, 40, 264, 268, 272, 276, 280, 296):
        marker_start = len(data) - footer_size - 4
        if marker_start >= 0:
            marker_candidates.append(('prefix_length', marker_start))

    for layout, marker_start in marker_candidates:
        marker = data[marker_start:marker_start + 4]
        values = [
            int.from_bytes(marker, byteorder='big', signed=False),
            int.from_bytes(marker, byteorder='little', signed=False),
        ]
        for value in values:
            if _plausible_footer_length_values(len(data), value):
                return value, layout

    return 0, ''


def calculate_footer_features(data: bytes) -> Dict[str, float]:
    """Tính các đặc trưng footer gợi ý metadata kiểu ransomware."""
    features = {}
    data_len = len(data)
    footer_sizes = (8, 12, 16, 24, 28, 32, 40, 64, 128, 256, 512)

    body = data[:-512] if data_len > 512 else data[: data_len // 2]
    body_entropy = calculate_entropy(body) if body else 0.0

    for size in footer_sizes:
        segment = data[-size:] if data_len >= size else b''
        stats = calculate_byte_statistics(segment)
        features[f'footer_{size}_present'] = 1.0 if segment else 0.0
        features[f'footer_{size}_entropy'] = calculate_entropy(segment)
        features[f'footer_{size}_normalized_entropy'] = _normalized_entropy(segment)
        features[f'footer_{size}_unique_ratio'] = (
            stats['unique_bytes'] / len(segment) if segment else 0.0
        )
        features[f'footer_{size}_printable_ratio'] = stats['printable_ratio']

    footer_length, footer_layout = _find_footer_marker(data)
    if footer_length and footer_layout == 'suffix_length':
        footer_body = data[-4 - footer_length:-4]
    elif footer_length and footer_layout == 'prefix_length':
        footer_body = data[-footer_length:]
    else:
        footer_body = b''

    features['footer_has_length_marker'] = 1.0 if footer_length else 0.0
    features['footer_marker_layout_suffix'] = 1.0 if footer_layout == 'suffix_length' else 0.0
    features['footer_marker_layout_prefix'] = 1.0 if footer_layout == 'prefix_length' else 0.0
    features['footer_length_marker_value'] = float(footer_length)
    features['footer_length_marker_ratio'] = footer_length / data_len if data_len else 0.0
    features['footer_marker_body_entropy'] = calculate_entropy(footer_body)
    features['footer_marker_body_normalized_entropy'] = _normalized_entropy(footer_body)

    features['footer_iv8_like'] = 0.0
    features['footer_nonce12_like'] = 0.0
    features['footer_iv16_or_tag16_like'] = 0.0
    features['footer_nonce24_like'] = 0.0

    if footer_body:
        if len(footer_body) == 8:
            features['footer_iv8_like'] = _random_like_segment(footer_body, min_len=8)
        elif len(footer_body) == 12:
            features['footer_nonce12_like'] = _random_like_segment(footer_body, min_len=8)
        elif 16 <= len(footer_body) < 24:
            features['footer_iv16_or_tag16_like'] = _random_like_segment(
                footer_body,
                min_len=12,
            )
        elif 24 <= len(footer_body) < 28:
            features['footer_nonce24_like'] = _random_like_segment(
                footer_body[:24],
                min_len=16,
            )
        elif 264 <= len(footer_body) < 268:
            features['footer_iv8_like'] = _random_like_segment(footer_body[:8], min_len=8)
        elif 268 <= len(footer_body) < 272:
            features['footer_nonce12_like'] = _random_like_segment(footer_body[:12], min_len=8)
        elif 272 <= len(footer_body) < 280:
            features['footer_iv16_or_tag16_like'] = _random_like_segment(
                footer_body[:16],
                min_len=12,
            )

    if 28 <= len(footer_body) < 40:
        nonce_12 = footer_body[:12]
        tag_16 = footer_body[12:28]
        features['footer_nonce12_tag16_like'] = min(
            _random_like_segment(nonce_12, min_len=8),
            _random_like_segment(tag_16, min_len=12),
        )
    else:
        features['footer_nonce12_tag16_like'] = 0.0

    if 40 <= len(footer_body) < 56:
        nonce_24 = footer_body[:24]
        tag_16 = footer_body[24:40]
        features['footer_nonce24_tag16_like'] = min(
            _random_like_segment(nonce_24, min_len=16),
            _random_like_segment(tag_16, min_len=12),
        )
    else:
        features['footer_nonce24_tag16_like'] = 0.0

    rsa2048_candidates = []
    rsa4096_candidates = []
    if len(footer_body) >= 256:
        rsa2048_candidates.append(footer_body[-256:])
        for offset in (0, 8, 12, 16, 24):
            candidate = footer_body[offset:offset + 256]
            if len(candidate) == 256:
                rsa2048_candidates.append(candidate)
    if len(footer_body) >= 512:
        rsa4096_candidates.append(footer_body[-512:])
        for offset in (0, 8, 12, 16, 24):
            candidate = footer_body[offset:offset + 512]
            if len(candidate) == 512:
                rsa4096_candidates.append(candidate)
    features['footer_rsa2048_wrapped_key_like'] = (
        features['footer_has_length_marker'] *
        max(
            (
                _random_like_segment(candidate, min_len=128)
                for candidate in rsa2048_candidates
            ),
            default=0.0,
        )
    )
    features['footer_rsa4096_wrapped_key_like'] = (
        features['footer_has_length_marker'] *
        max(
            (
                _random_like_segment(candidate, min_len=256)
                for candidate in rsa4096_candidates
            ),
            default=0.0,
        )
    )
    features['footer_entropy_delta_vs_body'] = features['footer_256_entropy'] - body_entropy
    features['footer_metadata_score'] = float(
        features['footer_has_length_marker']
        + features['footer_nonce12_tag16_like']
        + features['footer_nonce24_tag16_like']
        + features['footer_rsa2048_wrapped_key_like']
        + features['footer_rsa4096_wrapped_key_like']
    )

    return features


def extract_features_from_file(file_path: str, block_size: int = 4096) -> Dict[str, Any]:
    """
    Trích xuất toàn bộ đặc trưng từ một tệp.

    Args:
        file_path: Đường dẫn tệp.
        block_size: Kích thước block dùng khi tính entropy.

    Returns:
        Dictionary chứa các đặc trưng đã trích xuất.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    with open(file_path, 'rb') as f:
        data = f.read()
    
    features = {}
    features['path'] = file_path
    
    # Đặc trưng kích thước tệp.
    file_size = len(data)
    features['file_size'] = file_size
    features['file_size_mod_8'] = file_size % 8
    features['file_size_mod_16'] = file_size % 16
    features['file_size_mod_256'] = file_size % 256
    
    byte_counts = calculate_byte_counts(data)

    # Entropy toàn tệp.
    full_entropy = calculate_entropy_from_counts(byte_counts, file_size)
    features['shannon_entropy_full'] = full_entropy
    
    # Entropy theo block.
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
    
    # Thống kê byte.
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
    
    # Histogram byte gồm 256 đặc trưng.
    for byte_val in range(256):
        features[f'byte_{byte_val}_freq'] = byte_freqs[byte_val]

    # Các thống kê nâng cao cho dữ liệu mã hóa.
    features.update(calculate_advanced_byte_features(data, byte_counts=byte_counts))
    features.update(calculate_segment_features(data))
    features.update(calculate_footer_features(data))
    
    # Cấu trúc tệp.
    structure = analyze_file_structure(data, file_path)
    features['file_size'] = structure['file_size']
    features['has_known_signature'] = structure['has_known_signature']
    
    # Magic bytes: 16 byte đầu tệp.
    magic_bytes_str = get_file_magic_bytes(data, 16)
    features['magic_bytes_hex'] = magic_bytes_str
    
    # Footer bytes: 16 byte cuối tệp.
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
    Trích xuất đặc trưng từ nhiều tệp.

    Args:
        file_paths: Danh sách đường dẫn tệp.
        output_file: File parquet đầu ra nếu cần lưu.
        block_size: Kích thước block dùng khi tính entropy.
        workers: Số tiến trình xử lý. Dùng 0 để tự chọn theo CPU.
        verbose: Có hiển thị thanh tiến trình hay không.

    Returns:
        DataFrame chứa đặc trưng đã trích xuất.
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
