"""
Test suite for prediction schema validation.
"""

import json

import pytest

from src.models.predict import format_prediction_json


class TestPredictionSchema:
    """Test prediction output schema."""

    def test_prediction_schema_structure(self):
        """Test that prediction output has the group-first structure."""
        prediction = format_prediction_json(
            file_path="test.enc",
            file_size=1024,
            is_encrypted=True,
            predicted_class="AES_like",
            confidence=0.85,
            top_predictions=[
                {"label": "AES_like", "confidence": 0.85},
                {"label": "ChaCha20_Salsa20_like", "confidence": 0.10},
                {"label": "unknown_encrypted", "confidence": 0.05},
            ],
            features_summary={
                "shannon_entropy_full": 7.91,
                "entropy_mean": 7.88,
                "footer_metadata_score": 1.0,
            },
            evidence=["entropy trung binh cao"],
            top_groups=[
                {"crypto_group": "block_cipher_like", "confidence": 0.85},
                {"crypto_group": "stream_cipher_like", "confidence": 0.10},
            ],
            basis=["file_statistics", "footer_heuristics"],
            certainty="probable_from_file_statistics_and_footer_heuristics",
        )

        assert "file" in prediction
        assert "is_encrypted" in prediction
        assert "crypto_group" in prediction
        assert "algorithm_guess" in prediction
        assert "confidence" in prediction
        assert "certainty" in prediction
        assert "basis" in prediction
        assert "top_groups" in prediction
        assert "top_predictions" in prediction
        assert "features_summary" in prediction
        assert "evidence" in prediction
        assert "warning" in prediction

        assert prediction["file"]["path"] == "test.enc"
        assert prediction["file"]["size_bytes"] == 1024

        assert prediction["is_encrypted"] is True
        assert prediction["crypto_group"] == "block_cipher_like"
        assert prediction["algorithm_guess"] == "aes_family"
        assert prediction["confidence"] == 0.85
        assert prediction["certainty"] == "probable_from_file_statistics_and_footer_heuristics"
        assert prediction["basis"] == ["file_statistics", "footer_heuristics"]

        assert len(prediction["top_predictions"]) == 3
        assert prediction["top_predictions"][0]["label"] == "AES_like"
        assert prediction["top_groups"][0]["crypto_group"] == "block_cipher_like"

    def test_prediction_json_serializable(self):
        """Test that prediction output is JSON serializable."""
        prediction = format_prediction_json(
            file_path="test.enc",
            file_size=1024,
            is_encrypted=True,
            predicted_class="AES_like",
            confidence=0.85,
            top_predictions=[{"label": "AES_like", "confidence": 0.85}],
            features_summary={"entropy": 7.5},
            evidence=["test evidence"],
        )

        json_str = json.dumps(prediction)
        loaded = json.loads(json_str)

        assert loaded["crypto_group"] == "block_cipher_like"
        assert loaded["algorithm_guess"] == "aes_family"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
