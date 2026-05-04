"""
Test suite for prediction schema validation
"""

import pytest
import json
from src.models.predict import format_prediction_json


class TestPredictionSchema:
    """Test prediction output schema"""
    
    def test_prediction_schema_structure(self):
        """Test that prediction output has correct structure"""
        prediction = format_prediction_json(
            file_path="test.enc",
            file_size=1024,
            is_encrypted=True,
            predicted_class="AES_like",
            confidence=0.85,
            top_predictions=[
                {"label": "AES_like", "confidence": 0.85},
                {"label": "ChaCha20_Salsa20_like", "confidence": 0.10},
                {"label": "unknown_encrypted", "confidence": 0.05}
            ],
            features_summary={
                "shannon_entropy_full": 7.91,
                "entropy_mean": 7.88
            },
            evidence=["entropy trung bình cao"]
        )
        
        # Check top-level keys
        assert 'file' in prediction
        assert 'classification' in prediction
        assert 'features_summary' in prediction
        assert 'evidence' in prediction
        assert 'warning' in prediction
        
        # Check file object
        assert prediction['file']['path'] == "test.enc"
        assert prediction['file']['size_bytes'] == 1024
        
        # Check classification
        assert prediction['classification']['is_encrypted'] is True
        assert prediction['classification']['predicted_crypto_group'] == "AES_like"
        assert prediction['classification']['confidence'] == 0.85
        
        # Check top predictions
        assert len(prediction['classification']['top_predictions']) == 3
        assert prediction['classification']['top_predictions'][0]['label'] == "AES_like"
    
    def test_prediction_json_serializable(self):
        """Test that prediction output is JSON serializable"""
        prediction = format_prediction_json(
            file_path="test.enc",
            file_size=1024,
            is_encrypted=True,
            predicted_class="AES_like",
            confidence=0.85,
            top_predictions=[{"label": "AES_like", "confidence": 0.85}],
            features_summary={"entropy": 7.5},
            evidence=["test evidence"]
        )
        
        # Should not raise an exception
        json_str = json.dumps(prediction)
        
        # Should be able to load it back
        loaded = json.loads(json_str)
        assert loaded['classification']['predicted_crypto_group'] == "AES_like"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
