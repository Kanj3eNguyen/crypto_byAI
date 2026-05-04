"""
Test suite for entropy module
"""

import pytest
from src.features.entropy import calculate_entropy, calculate_block_entropy


class TestEntropyCalculation:
    """Test entropy calculation functions"""
    
    def test_entropy_uniform_distribution(self):
        """Test entropy with uniform byte distribution"""
        # All bytes are the same
        data = b'\x00' * 256
        entropy = calculate_entropy(data)
        assert entropy == 0.0, "Entropy of all zeros should be 0"
    
    def test_entropy_random_data(self):
        """Test entropy with random-like data"""
        # Data with high entropy should score high
        data = bytes(range(256)) * 4  # Uniform distribution
        entropy = calculate_entropy(data)
        assert entropy > 7.9, "Uniform distribution should have high entropy"
    
    def test_block_entropy(self):
        """Test block entropy calculation"""
        data = bytes(range(256)) * 20  # 5120 bytes
        block_entropies, stats = calculate_block_entropy(data, block_size=256)
        
        assert len(block_entropies) == 20, "Should have 20 blocks"
        assert 'mean' in stats, "Stats should have mean"
        assert stats['mean'] > 0, "Mean entropy should be positive"


class TestEntropyThresholds:
    """Test entropy threshold features"""
    
    def test_high_entropy_ratio(self):
        """Test calculation of high entropy block ratio"""
        # Create data with mostly high entropy blocks
        high_entropy_data = bytes(range(256)) * 16  # 4096 bytes, very high entropy
        block_entropies, stats = calculate_block_entropy(high_entropy_data, block_size=256)
        
        assert stats['percentage_above_7_5'] > 0.9, "Most blocks should be above 7.5"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
