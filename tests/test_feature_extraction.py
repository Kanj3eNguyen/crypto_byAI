"""
Test suite for feature extraction
"""

import pytest
import tempfile
import os
from src.features.extract_features import extract_features_from_file
from src.features.entropy import calculate_entropy


class TestFeatureExtraction:
    """Test feature extraction from files"""
    
    def test_extract_features_from_random_file(self):
        """Test feature extraction from random data"""
        # Create temporary file with random data
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(os.urandom(4096))
            tmp_path = tmp.name
        
        try:
            features = extract_features_from_file(tmp_path)
            
            assert 'shannon_entropy_full' in features, "Should have full entropy"
            assert 'entropy_mean' in features, "Should have entropy mean"
            assert 'file_size' in features, "Should have file size"
            assert features['file_size'] == 4096, "File size should be 4096"
            
            # Random data should have high entropy
            assert features['shannon_entropy_full'] > 7.0, "Random data should have high entropy"
        
        finally:
            os.unlink(tmp_path)
    
    def test_extract_features_consistency(self):
        """Test that same file produces same features"""
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b'test' * 1024)
            tmp_path = tmp.name
        
        try:
            features1 = extract_features_from_file(tmp_path)
            features2 = extract_features_from_file(tmp_path)
            
            assert features1['shannon_entropy_full'] == features2['shannon_entropy_full']
            assert features1['file_size'] == features2['file_size']
        
        finally:
            os.unlink(tmp_path)
    
    def test_byte_histogram_sum(self):
        """Test that byte histogram frequencies sum to 1"""
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(os.urandom(1024))
            tmp_path = tmp.name
        
        try:
            features = extract_features_from_file(tmp_path)
            
            # Sum all byte frequencies
            histogram_sum = sum(features.get(f'byte_{i:03d}_freq', 0) for i in range(256))
            
            # Should be very close to 1.0
            assert abs(histogram_sum - 1.0) < 0.0001, "Byte histogram should sum to 1"
        
        finally:
            os.unlink(tmp_path)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
