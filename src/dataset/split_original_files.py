"""
Chia tệp gốc thành các tập train, val và test.
"""

import os
from typing import Tuple, List
import random


def split_original_files(
    input_dir: str, 
    train_ratio: float = 0.7,
    val_ratio: float = 0.15,
    test_ratio: float = 0.15,
    random_state: int = 42
) -> Tuple[List[str], List[str], List[str]]:
    """
    Chia các tệp trong thư mục đầu vào thành train/val/test.

    Args:
        input_dir: Thư mục chứa tệp gốc.
        train_ratio: Tỷ lệ tập train.
        val_ratio: Tỷ lệ tập validation.
        test_ratio: Tỷ lệ tập test.
        random_state: Seed để kết quả chia ổn định.

    Returns:
        Bộ ba danh sách gồm train_files, val_files và test_files.
    """
    if not os.path.exists(input_dir):
        raise FileNotFoundError(f"Input directory not found: {input_dir}")
    
    if abs(train_ratio + val_ratio + test_ratio - 1.0) > 0.01:
        raise ValueError(f"Ratios must sum to 1.0, got {train_ratio + val_ratio + test_ratio}")
    
    # Lấy danh sách toàn bộ tệp.
    all_files = [f for f in os.listdir(input_dir) if os.path.isfile(os.path.join(input_dir, f))]
    all_files.sort()
    
    # Đặt seed trước khi xáo trộn.
    random.seed(random_state)
    random.shuffle(all_files)
    
    # Tính vị trí chia tập dữ liệu.
    n_files = len(all_files)
    train_count = int(n_files * train_ratio)
    val_count = int(n_files * val_ratio)
    
    train_files = all_files[:train_count]
    val_files = all_files[train_count:train_count + val_count]
    test_files = all_files[train_count + val_count:]
    
    return train_files, val_files, test_files


def get_split_info(files: List[str]) -> dict:
    """Lấy thông tin tóm tắt về một split."""
    return {
        'count': len(files),
        'files': files[:5] + (['...'] if len(files) > 5 else [])
    }
