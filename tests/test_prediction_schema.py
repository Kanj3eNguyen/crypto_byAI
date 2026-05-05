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
        assert "predicted_label" in prediction
        assert "predicted_class" in prediction
        assert "crypto_group" in prediction
        assert "algorithm_guess" in prediction
        assert "possible_encryption_types" in prediction
        assert "possible_encryption_summary" in prediction
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
        assert prediction["predicted_label"] == "AES_like"
        assert prediction["predicted_class"] == "AES_like"
        assert prediction["crypto_group"] == "block_padded_mode_like"
        assert prediction["crypto_subgroup"] == "block_padded_mode_like"
        assert prediction["algorithm_guess"] == "aes_family"
        assert prediction["possible_encryption_types"] == [
            "AES-CBC",
            "AES-ECB",
            "AES-CTR",
            "AES-CFB",
            "AES-OFB",
            "AES-GCM",
        ]
        assert prediction["possible_encryption_summary"] == "block_cipher_like: AES"
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

        assert loaded["crypto_group"] == "block_padded_mode_like"
        assert loaded["algorithm_guess"] == "aes_family"
        assert loaded["possible_encryption_types"] == [
            "AES-CBC",
            "AES-ECB",
            "AES-CTR",
            "AES-CFB",
            "AES-OFB",
            "AES-GCM",
        ]
        assert loaded["possible_encryption_summary"] == "block_cipher_like: AES"

    def test_legacy_unknown_high_entropy_label_is_renamed(self):
        """Test that legacy unknown_high_entropy output is not exposed."""
        prediction = format_prediction_json(
            file_path="test.enc",
            file_size=1024,
            is_encrypted=True,
            predicted_class="unknown_high_entropy",
            confidence=0.51,
            top_predictions=[{"label": "unknown_high_entropy", "confidence": 0.51}],
            features_summary={},
            evidence=[],
        )

        assert prediction["predicted_label"] == "unknown_encrypted"
        assert prediction["predicted_class"] == "unknown_encrypted"
        assert prediction["crypto_group"] == "unknown_encrypted"
        assert prediction["possible_encryption_types"] == ["unknown encryption"]
        assert prediction["possible_encryption_summary"] == "unknown_encrypted: unknown"
        assert prediction["top_predictions"][0]["label"] == "unknown_encrypted"
        assert prediction["top_predictions"][0]["possible_encryption_types"] == [
            "unknown encryption"
        ]
        assert (
            prediction["top_predictions"][0]["possible_encryption_summary"]
            == "unknown_encrypted: unknown"
        )

    def test_broad_group_lists_member_encryption_types(self):
        """Test that a broad label expands to its possible encryption types."""
        prediction = format_prediction_json(
            file_path="test.enc",
            file_size=1024,
            is_encrypted=True,
            predicted_class="block_padded_mode_like",
            confidence=0.72,
            top_predictions=[{"label": "block_padded_mode_like", "confidence": 0.72}],
            features_summary={},
            evidence=[],
        )

        assert prediction["predicted_label"] == "block_padded_mode_like"
        assert prediction["possible_encryption_types"] == [
            "AES-CBC",
            "AES-ECB",
            "AES-CTR",
            "AES-CFB",
            "AES-OFB",
            "AES-GCM",
            "3DES-CBC",
            "Blowfish-CBC",
            "DES-CBC",
            "RC2-CBC",
            "CAST5-CBC",
        ]
        assert prediction["possible_encryption_summary"] == (
            "block_cipher_like: AES/3DES/Blowfish/DES/RC2/CAST5"
        )

    def test_stream_group_summary_lists_compact_algorithms(self):
        """Test stream labels render as stream_cipher_like: algorithms."""
        prediction = format_prediction_json(
            file_path="test.enc",
            file_size=1024,
            is_encrypted=True,
            predicted_class="stream_or_counter_mode_like",
            confidence=0.72,
            top_predictions=[
                {"label": "stream_or_counter_mode_like", "confidence": 0.72}
            ],
            features_summary={},
            evidence=[],
        )

        assert prediction["predicted_label"] == "stream_or_counter_mode_like"
        assert prediction["possible_encryption_summary"] == (
            "stream_cipher_like: ChaCha20/Salsa20/RC4"
        )

    def test_legacy_stream_group_summary_lists_compact_algorithms(self):
        """Test legacy stream_cipher_like model labels expand correctly."""
        prediction = format_prediction_json(
            file_path="test.enc",
            file_size=1024,
            is_encrypted=True,
            predicted_class="stream_cipher_like",
            confidence=0.82,
            top_predictions=[{"label": "stream_cipher_like", "confidence": 0.82}],
            features_summary={},
            evidence=[],
        )

        assert prediction["predicted_label"] == "stream_cipher_like"
        assert prediction["algorithm_guess"] == "stream_cipher_family"
        assert prediction["possible_encryption_types"] == [
            "ChaCha20",
            "Salsa20",
            "RC4",
        ]
        assert prediction["possible_encryption_summary"] == (
            "stream_cipher_like: ChaCha20/Salsa20/RC4"
        )
        assert prediction["top_predictions"][0]["possible_encryption_summary"] == (
            "stream_cipher_like: ChaCha20/Salsa20/RC4"
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
