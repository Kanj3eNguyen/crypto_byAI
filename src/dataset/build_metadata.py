"""
Build metadata CSV from generated samples
"""

import os
import csv
from pathlib import Path
from typing import Dict, Any, List


def build_metadata_csv(
    samples_dir: str,
    output_file: str
) -> None:
    """
    Build metadata CSV from directory structure
    
    Args:
        samples_dir: Directory containing generated samples
        output_file: Output CSV file path
    """
    Path(os.path.dirname(output_file)).mkdir(parents=True, exist_ok=True)
    
    rows = []
    sample_counter = 0
    
    # Walk through label directories
    for label_group in os.listdir(samples_dir):
        label_path = os.path.join(samples_dir, label_group)
        
        if not os.path.isdir(label_path):
            continue
        
        # Process each file in label directory
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
    
    # Write CSV
    if rows:
        fieldnames = rows[0].keys()
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
