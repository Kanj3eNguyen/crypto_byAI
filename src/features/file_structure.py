"""
File structure and format analysis
"""

from typing import Dict, Any


def analyze_file_structure(data: bytes, file_path: str = None) -> Dict[str, Any]:
    """
    Analyze file structure characteristics
    
    Args:
        data: File data
        file_path: Optional file path for extension analysis
    
    Returns:
        Dictionary of structural features
    """
    file_size = len(data)
    
    structure = {
        'file_size': file_size,
        'file_size_mod_8': file_size % 8,
        'file_size_mod_16': file_size % 16,
        'file_size_mod_256': file_size % 256,
        'file_size_mod_4096': file_size % 4096,
        'is_power_of_two': (file_size & (file_size - 1)) == 0 and file_size > 0
    }
    
    # File extension analysis
    if file_path:
        import os
        _, ext = os.path.splitext(file_path)
        structure['file_extension'] = ext.lower()
    
    # Check for common file signatures (magic bytes)
    magic_signatures = {
        'PDF': b'%PDF',
        'ZIP': b'PK\x03\x04',
        'GZIP': b'\x1f\x8b\x08',
        'PNG': b'\x89PNG',
        'JPEG': b'\xff\xd8\xff',
        'GIF': b'GIF8',
        'TIFF': b'II\x2a\x00',
        'EXECUTABLE': b'MZ',
        'ELF': b'\x7fELF',
        'DOCX': b'PK\x03\x04',
        'MP4': b'\x00\x00\x00\x20ftypmp42',
    }
    
    detected_signatures = []
    for sig_name, sig_bytes in magic_signatures.items():
        if data.startswith(sig_bytes):
            detected_signatures.append(sig_name)
    
    structure['detected_signatures'] = detected_signatures
    structure['has_known_signature'] = len(detected_signatures) > 0
    
    return structure
