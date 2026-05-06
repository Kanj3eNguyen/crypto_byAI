"""
Tạo file metadata CSV từ các mẫu đã sinh.
"""

import os
import csv
from pathlib import Path


def build_metadata_csv(
    samples_dir: str,
    output_file: str
) -> None:
    """
    Tạo metadata CSV từ cấu trúc thư mục.

    Args:
        samples_dir: Thư mục chứa các mẫu đã sinh.
        output_file: Đường dẫn file CSV đầu ra.
    """
    Path(os.path.dirname(output_file)).mkdir(parents=True, exist_ok=True)
    
    rows = []
    sample_counter = 0
    
    # Duyệt các thư mục nhãn.
    for label_group in os.listdir(samples_dir):
        label_path = os.path.join(samples_dir, label_group)
        
        if not os.path.isdir(label_path):
            continue
        
        # Xử lý từng tệp trong thư mục nhãn.
        for filename in os.listdir(label_path):
            if filename.startswith('.'):
                continue
            
            file_path = os.path.join(label_path, filename)
            
            if os.path.isfile(file_path):
                sample_counter += 1
                file_size = os.path.getsize(file_path)
                
                row = {
                    'sample_id': f"{sample_counter:06d}",
                    'path': file_path,
                    'label_group': label_group,
                    'algorithm': '',
                    'mode': '',
                    'key_size': '',
                    'original_file_id': '',
                    'original_type': '',
                    'tool': '',
                    'split': '',
                    'file_size': file_size
                }
                
                rows.append(row)
    
    # Ghi file CSV.
    if rows:
        fieldnames = rows[0].keys()
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
