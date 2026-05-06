"""
Kiểm thử module entropy.
"""

import pytest
from src.features.entropy import calculate_entropy, calculate_block_entropy


class TestEntropyCalculation:
    """Kiểm thử các hàm tính entropy."""
    
    def test_entropy_uniform_distribution(self):
        """Kiểm thử entropy khi toàn bộ byte giống nhau."""
        # Tất cả byte đều giống nhau.
        data = b'\x00' * 256
        entropy = calculate_entropy(data)
        assert entropy == 0.0, "Entropy of all zeros should be 0"
    
    def test_entropy_random_data(self):
        """Kiểm thử entropy với dữ liệu có phân bố gần đều."""
        # Dữ liệu entropy cao phải cho điểm entropy cao.
        data = bytes(range(256)) * 4  # Phân bố đều.
        entropy = calculate_entropy(data)
        assert entropy > 7.9, "Uniform distribution should have high entropy"
    
    def test_block_entropy(self):
        """Kiểm thử tính entropy theo block."""
        data = bytes(range(256)) * 20  # 5120 bytes
        block_entropies, stats = calculate_block_entropy(data, block_size=256)
        
        assert len(block_entropies) == 20, "Should have 20 blocks"
        assert 'mean' in stats, "Stats should have mean"
        assert stats['mean'] > 0, "Mean entropy should be positive"


class TestEntropyThresholds:
    """Kiểm thử các đặc trưng theo ngưỡng entropy."""
    
    def test_high_entropy_ratio(self):
        """Kiểm thử tỷ lệ block có entropy cao."""
        # Tạo dữ liệu mà phần lớn block có entropy cao.
        high_entropy_data = bytes(range(256)) * 16  # 4096 bytes, entropy rất cao.
        block_entropies, stats = calculate_block_entropy(high_entropy_data, block_size=256)
        
        assert stats['percentage_above_7_5'] > 0.9, "Most blocks should be above 7.5"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
