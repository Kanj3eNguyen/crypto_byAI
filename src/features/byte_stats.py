"""
Thống kê byte và tần suất xuất hiện.
"""

from typing import Dict

import numpy as np


def calculate_byte_counts(data: bytes) -> np.ndarray:
    """Đếm số lần xuất hiện của các giá trị byte 0-255."""
    if len(data) == 0:
        return np.zeros(256, dtype=np.int64)

    byte_values = np.frombuffer(data, dtype=np.uint8)
    return np.bincount(byte_values, minlength=256)


def calculate_byte_frequencies_from_counts(counts, data_len: int) -> Dict[int, float]:
    """Tính tần suất byte từ mảng số lần xuất hiện đã có."""
    if data_len == 0:
        return {i: 0.0 for i in range(256)}

    counts_array = np.asarray(counts, dtype=np.float64)
    frequencies = counts_array / data_len
    return {i: float(frequencies[i]) for i in range(256)}


def _median_from_counts(counts, data_len: int) -> float:
    lower_index = (data_len - 1) // 2
    upper_index = data_len // 2
    cumulative_counts = np.cumsum(counts)
    lower = int(np.searchsorted(cumulative_counts, lower_index + 1, side='left'))
    upper = int(np.searchsorted(cumulative_counts, upper_index + 1, side='left'))
    return (lower + upper) / 2


def calculate_byte_statistics_from_counts(counts, data_len: int) -> Dict[str, float]:
    """Tính các thống kê mức byte từ mảng số lần xuất hiện đã có."""
    if data_len == 0:
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

    counts_array = np.asarray(counts, dtype=np.float64)
    byte_values = np.arange(256, dtype=np.float64)
    nonzero_values = np.flatnonzero(counts_array)

    byte_mean = float(np.dot(byte_values, counts_array) / data_len)
    variance = float(np.dot((byte_values - byte_mean) ** 2, counts_array) / data_len)

    return {
        'unique_bytes': int(np.count_nonzero(counts_array)),
        'printable_ratio': float(np.sum(counts_array[32:127]) / data_len),
        'null_byte_ratio': float(counts_array[0] / data_len),
        'byte_mean': byte_mean,
        'byte_std': variance ** 0.5,
        'byte_min': int(nonzero_values[0]),
        'byte_max': int(nonzero_values[-1]),
        'byte_median': _median_from_counts(counts_array, data_len)
    }


def calculate_byte_frequencies(data: bytes) -> Dict[int, float]:
    """
    Tính tần suất của từng giá trị byte 0-255.

    Args:
        data: Dữ liệu byte cần phân tích.

    Returns:
        Dictionary ánh xạ giá trị byte sang tần suất 0.0-1.0.
    """
    data_len = len(data)
    counts = calculate_byte_counts(data)
    return calculate_byte_frequencies_from_counts(counts, data_len)


def calculate_byte_statistics(data: bytes) -> Dict[str, float]:
    """
    Tính các thống kê mức byte.

    Args:
        data: Dữ liệu byte cần phân tích.

    Returns:
        Dictionary chứa các thống kê byte.
    """
    data_len = len(data)
    counts = calculate_byte_counts(data)
    return calculate_byte_statistics_from_counts(counts, data_len)


def get_file_magic_bytes(data: bytes, n_bytes: int = 16) -> str:
    """
    Lấy N byte đầu dưới dạng chuỗi hex.

    Args:
        data: Dữ liệu tệp.
        n_bytes: Số byte cần lấy.

    Returns:
        Chuỗi hex biểu diễn các byte đầu tệp.
    """
    return data[:n_bytes].hex().upper()


def get_footer_bytes(data: bytes, n_bytes: int = 16) -> str:
    """
    Lấy N byte cuối dưới dạng chuỗi hex.

    Args:
        data: Dữ liệu tệp.
        n_bytes: Số byte cần lấy.

    Returns:
        Chuỗi hex biểu diễn các byte cuối tệp.
    """
    return data[-n_bytes:].hex().upper() if len(data) >= n_bytes else data.hex().upper()
