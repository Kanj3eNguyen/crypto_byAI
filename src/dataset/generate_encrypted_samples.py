"""
Tạo mẫu mã hóa từ các tệp gốc.
"""

import os
from pathlib import Path
from typing import Dict, Any
import csv


class EncryptedSampleGenerator:
    """Sinh mẫu mã hóa và ghi metadata đi kèm."""
    
    def __init__(self, output_dir: str, metadata_file: str = None):
        """
        Khởi tạo bộ sinh mẫu.

        Args:
            output_dir: Thư mục gốc để lưu mẫu mã hóa.
            metadata_file: Đường dẫn file metadata CSV.
        """
        self.output_dir = output_dir
        self.metadata_file = metadata_file
        self.samples = []
        self.sample_counter = 0
        
        # Tạo thư mục đầu ra nếu chưa có.
        Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    def add_sample(
        self,
        original_file_path: str,
        original_file_id: str,
        original_type: str,
        label_group: str,
        algorithm: str,
        mode: str = "",
        key_size: int = 0,
        tool: str = "custom",
        split: str = "train",
        ciphertext: bytes = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Thêm một mẫu mã hóa vào tập dữ liệu.

        Args:
            original_file_path: Đường dẫn tệp gốc.
            original_file_id: Mã định danh của tệp gốc.
            original_type: Loại tệp gốc.
            label_group: Nhãn phân loại.
            algorithm: Thuật toán mã hóa đã dùng.
            mode: Chế độ mã hóa.
            key_size: Độ dài khóa, tính theo bit.
            tool: Công cụ dùng để mã hóa.
            split: Phần chia dữ liệu train/val/test.
            ciphertext: Nội dung tệp sau mã hóa.
            **kwargs: Metadata bổ sung.

        Returns:
            Dictionary chứa metadata của mẫu.
        """
        self.sample_counter += 1
        sample_id = f"{self.sample_counter:06d}"
        
        # Tạo đường dẫn tệp mã hóa.
        encrypted_path = os.path.join(
            self.output_dir,
            label_group,
            f"{sample_id}.enc"
        )
        
        # Tạo thư mục nhãn nếu chưa có.
        Path(os.path.dirname(encrypted_path)).mkdir(parents=True, exist_ok=True)
        
        # Ghi ciphertext ra tệp.
        if ciphertext is not None:
            with open(encrypted_path, 'wb') as f:
                f.write(ciphertext)
        
        # Tạo bản ghi metadata.
        file_size = os.path.getsize(encrypted_path) if os.path.exists(encrypted_path) else 0
        
        metadata = {
            'sample_id': sample_id,
            'path': encrypted_path,
            'label_group': label_group,
            'algorithm': algorithm,
            'mode': mode,
            'key_size': key_size,
            'original_file_id': original_file_id,
            'original_type': original_type,
            'tool': tool,
            'split': split,
            'file_size': file_size
        }
        
        # Gắn metadata bổ sung nếu có.
        metadata.update(kwargs)
        
        self.samples.append(metadata)
        
        return metadata
    
    def save_metadata(self):
        """Lưu metadata của toàn bộ mẫu ra file CSV."""
        if not self.metadata_file:
            return
        
        if not self.samples:
            return
        
        # Tạo thư mục metadata nếu chưa có.
        Path(os.path.dirname(self.metadata_file)).mkdir(parents=True, exist_ok=True)
        
        # Lấy toàn bộ tên cột từ các mẫu.
        fieldnames = set()
        for sample in self.samples:
            fieldnames.update(sample.keys())
        
        # Sắp xếp tên cột để file đầu ra ổn định.
        fieldnames = sorted(list(fieldnames))
        
        # Ghi file CSV.
        with open(self.metadata_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(self.samples)
    
    def get_samples_count(self) -> int:
        """Trả về số mẫu đã sinh."""
        return len(self.samples)
