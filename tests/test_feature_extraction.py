"""
Kiểm thử phần trích xuất đặc trưng.
"""

import pytest
import tempfile
import os
from src.features.extract_features import extract_features_from_file


class TestFeatureExtraction:
    """Kiểm thử trích xuất đặc trưng từ tệp."""
    
    def test_extract_features_from_random_file(self):
        """Kiểm thử trích xuất đặc trưng từ dữ liệu ngẫu nhiên."""
        # Tạo file tạm chứa dữ liệu ngẫu nhiên.
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(os.urandom(4096))
            tmp_path = tmp.name
        
        try:
            features = extract_features_from_file(tmp_path)
            
            assert 'shannon_entropy_full' in features, "Should have full entropy"
            assert 'entropy_mean' in features, "Should have entropy mean"
            assert 'file_size' in features, "Should have file size"
            assert 'footer_256_entropy' in features, "Should have footer entropy"
            assert 'footer_metadata_score' in features, "Should have footer metadata score"
            assert features['file_size'] == 4096, "File size should be 4096"
            
            # Dữ liệu ngẫu nhiên phải có entropy cao.
            assert features['shannon_entropy_full'] > 7.0, "Random data should have high entropy"
        
        finally:
            os.unlink(tmp_path)
    
    def test_extract_features_consistency(self):
        """Kiểm thử cùng một tệp cho ra cùng bộ đặc trưng."""
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b'test' * 1024)
            tmp_path = tmp.name
        
        try:
            features1 = extract_features_from_file(tmp_path)
            features2 = extract_features_from_file(tmp_path)
            
            assert features1['shannon_entropy_full'] == features2['shannon_entropy_full']
            assert features1['file_size'] == features2['file_size']
            assert (
                features1['footer_40_normalized_entropy'] ==
                features2['footer_40_normalized_entropy']
            )
        
        finally:
            os.unlink(tmp_path)

    def test_footer_length_marker_features(self):
        """Kiểm thử nhận diện marker độ dài footer kiểu ransomware."""
        footer_body = os.urandom(16 + 256)
        footer = footer_body + len(footer_body).to_bytes(4, byteorder='big')

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(os.urandom(2048) + footer)
            tmp_path = tmp.name

        try:
            features = extract_features_from_file(tmp_path)

            assert features['footer_has_length_marker'] == 1.0
            assert features['footer_length_marker_value'] == len(footer_body)
            assert features['footer_marker_layout_suffix'] == 1.0
            assert features['footer_rsa2048_wrapped_key_like'] == 1.0

        finally:
            os.unlink(tmp_path)
    
    def test_byte_histogram_sum(self):
        """Kiểm thử tổng tần suất histogram byte bằng 1."""
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(os.urandom(1024))
            tmp_path = tmp.name
        
        try:
            features = extract_features_from_file(tmp_path)
            
            # Cộng toàn bộ tần suất byte.
            histogram_sum = sum(features.get(f'byte_{i}_freq', 0) for i in range(256))
            
            # Tổng phải rất gần 1.0.
            assert abs(histogram_sum - 1.0) < 0.0001, "Byte histogram should sum to 1"
        
        finally:
            os.unlink(tmp_path)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
