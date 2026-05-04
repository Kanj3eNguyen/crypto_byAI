"""
Generate compressed samples (not_encrypted and compressed_only groups)
"""

import os
import zipfile
import gzip
import shutil
from pathlib import Path
from typing import List, Dict, Any


class CompressedSampleGenerator:
    """Generate compressed/uncompressed samples"""
    
    def __init__(self, output_dir: str):
        """Initialize generator"""
        self.output_dir = output_dir
        Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    def copy_unencrypted_sample(
        self,
        source_file: str,
        label_group: str,
        sample_id: str
    ) -> str:
        """Copy file as-is to not_encrypted group"""
        output_dir = os.path.join(self.output_dir, label_group)
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        output_path = os.path.join(output_dir, f"{sample_id}.bin")
        shutil.copy2(source_file, output_path)
        
        return output_path
    
    def create_zip_compressed(
        self,
        source_file: str,
        sample_id: str
    ) -> str:
        """Create ZIP compressed version"""
        output_dir = os.path.join(self.output_dir, "compressed_only")
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        output_path = os.path.join(output_dir, f"{sample_id}.zip")
        
        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(source_file, arcname=os.path.basename(source_file))
        
        return output_path
    
    def create_gzip_compressed(
        self,
        source_file: str,
        sample_id: str
    ) -> str:
        """Create GZIP compressed version"""
        output_dir = os.path.join(self.output_dir, "compressed_only")
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        output_path = os.path.join(output_dir, f"{sample_id}.gz")
        
        with open(source_file, 'rb') as f_in:
            with gzip.open(output_path, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        
        return output_path
