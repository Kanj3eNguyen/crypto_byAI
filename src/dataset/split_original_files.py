"""
Split original files into train/val/test sets
"""

import os
import shutil
from pathlib import Path
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
    Split files in input directory into train/val/test sets
    
    Args:
        input_dir: Directory containing original files
        train_ratio: Ratio for training set
        val_ratio: Ratio for validation set
        test_ratio: Ratio for test set
        random_state: Random seed for reproducibility
    
    Returns:
        Tuple of (train_files, val_files, test_files)
    """
    if not os.path.exists(input_dir):
        raise FileNotFoundError(f"Input directory not found: {input_dir}")
    
    if abs(train_ratio + val_ratio + test_ratio - 1.0) > 0.01:
        raise ValueError(f"Ratios must sum to 1.0, got {train_ratio + val_ratio + test_ratio}")
    
    # Get all files
    all_files = [f for f in os.listdir(input_dir) if os.path.isfile(os.path.join(input_dir, f))]
    all_files.sort()
    
    # Set random seed
    random.seed(random_state)
    random.shuffle(all_files)
    
    # Calculate split indices
    n_files = len(all_files)
    train_count = int(n_files * train_ratio)
    val_count = int(n_files * val_ratio)
    
    train_files = all_files[:train_count]
    val_files = all_files[train_count:train_count + val_count]
    test_files = all_files[train_count + val_count:]
    
    return train_files, val_files, test_files


def get_split_info(files: List[str]) -> dict:
    """Get information about a file split"""
    return {
        'count': len(files),
        'files': files[:5] + (['...'] if len(files) > 5 else [])
    }
