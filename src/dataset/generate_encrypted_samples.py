"""
Generate encrypted samples from original files
"""

import os
from pathlib import Path
from typing import List, Dict, Any
import csv


class EncryptedSampleGenerator:
    """Generate encrypted samples with metadata tracking"""
    
    def __init__(self, output_dir: str, metadata_file: str = None):
        """
        Initialize generator
        
        Args:
            output_dir: Base directory for encrypted samples
            metadata_file: Path to metadata CSV file
        """
        self.output_dir = output_dir
        self.metadata_file = metadata_file
        self.samples = []
        self.sample_counter = 0
        
        # Create output directory if needed
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
        Add an encrypted sample to the dataset
        
        Args:
            original_file_path: Path to original file
            original_file_id: ID of original file
            original_type: Type of original file (pdf, txt, etc.)
            label_group: Classification label
            algorithm: Encryption algorithm used
            mode: Encryption mode (CBC, GCM, etc.)
            key_size: Key size in bits
            tool: Tool used for encryption
            split: Dataset split (train/val/test)
            ciphertext: Encrypted file content (bytes)
            **kwargs: Additional metadata
        
        Returns:
            Dictionary with sample metadata
        """
        self.sample_counter += 1
        sample_id = f"{self.sample_counter:06d}"
        
        # Create encrypted file path
        encrypted_path = os.path.join(
            self.output_dir,
            label_group,
            f"{sample_id}.enc"
        )
        
        # Create label directory if needed
        Path(os.path.dirname(encrypted_path)).mkdir(parents=True, exist_ok=True)
        
        # Write ciphertext
        if ciphertext is not None:
            with open(encrypted_path, 'wb') as f:
                f.write(ciphertext)
        
        # Create metadata entry
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
        
        # Add any additional metadata
        metadata.update(kwargs)
        
        self.samples.append(metadata)
        
        return metadata
    
    def save_metadata(self):
        """Save all samples metadata to CSV file"""
        if not self.metadata_file:
            return
        
        if not self.samples:
            return
        
        # Create metadata directory
        Path(os.path.dirname(self.metadata_file)).mkdir(parents=True, exist_ok=True)
        
        # Get all keys from samples
        fieldnames = set()
        for sample in self.samples:
            fieldnames.update(sample.keys())
        
        # Sort field names for consistent output
        fieldnames = sorted(list(fieldnames))
        
        # Write CSV
        with open(self.metadata_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(self.samples)
    
    def get_samples_count(self) -> int:
        """Get number of samples generated"""
        return len(self.samples)
