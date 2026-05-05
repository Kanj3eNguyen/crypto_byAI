"""
Model prediction utilities.
"""

from typing import Any, Dict, List

import numpy as np


LABEL_TO_CRYPTO_GROUP = {
    'AES_like': 'block_cipher_like',
    '3DES_like': 'block_cipher_like',
    'Blowfish_like': 'block_cipher_like',
    'DES_like': 'block_cipher_like',
    'RC2_like': 'block_cipher_like',
    'CAST5_like': 'block_cipher_like',
    'ChaCha20_Salsa20_like': 'stream_cipher_like',
    'RC4_like': 'stream_cipher_like',
    'XOR_like': 'weak_obfuscation_like',
    'hybrid_AES_RSA_like': 'hybrid_cipher_like',
    'hybrid_ChaCha20_RSA_like': 'hybrid_cipher_like',
    'hybrid_Salsa20_RSA_like': 'hybrid_cipher_like',
    'compressed_only': 'compressed_only',
    'not_encrypted': 'not_encrypted',
    'unknown_encrypted': 'unknown_encrypted',
}


BROAD_CRYPTO_GROUPS = {
    'block_cipher_like',
    'stream_cipher_like',
    'hybrid_cipher_like',
    'weak_obfuscation_like',
    'compressed_only',
    'not_encrypted',
    'unknown_encrypted',
}


ALGORITHM_GUESS_MAP = {
    'AES_like': 'aes_family',
    '3DES_like': 'triple_des_family',
    'Blowfish_like': 'blowfish_family',
    'DES_like': 'des_family',
    'RC2_like': 'rc2_family',
    'CAST5_like': 'cast5_family',
    'ChaCha20_Salsa20_like': 'chacha20_salsa20_family',
    'RC4_like': 'rc4_family',
    'XOR_like': 'repeating_xor_or_simple_custom_cipher',
    'hybrid_AES_RSA_like': 'hybrid_block_cipher_rsa_like',
    'hybrid_ChaCha20_RSA_like': 'hybrid_stream_cipher_rsa_like',
    'hybrid_Salsa20_RSA_like': 'hybrid_stream_cipher_rsa_like',
    'block_cipher_like': 'block_cipher_family',
    'stream_cipher_like': 'stream_cipher_family',
    'hybrid_cipher_like': 'hybrid_symmetric_asymmetric_family',
    'weak_obfuscation_like': 'weak_obfuscation_or_custom_cipher',
    'compressed_only': 'compressed_or_high_entropy_format',
    'not_encrypted': 'not_encrypted',
    'unknown_encrypted': 'unknown_encrypted',
}


def normalize_crypto_group(label: str) -> str:
    """Map a detailed label to the broad group used as the main prediction."""
    if label in BROAD_CRYPTO_GROUPS:
        return label
    return LABEL_TO_CRYPTO_GROUP.get(label, 'unknown_encrypted')


def algorithm_guess_for_label(label: str) -> str:
    """Return a deliberately broad algorithm-family guess."""
    return ALGORITHM_GUESS_MAP.get(label, normalize_crypto_group(label))


def is_encrypted_label(label: str) -> bool:
    """Return whether a predicted label/group should be treated as encrypted."""
    return normalize_crypto_group(label) not in {'not_encrypted', 'compressed_only'}


def aggregate_top_groups(top_predictions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Aggregate detailed label probabilities into broad crypto groups."""
    grouped: Dict[str, float] = {}
    for item in top_predictions:
        group = normalize_crypto_group(item.get('label', 'unknown_encrypted'))
        grouped[group] = grouped.get(group, 0.0) + float(item.get('confidence', 0.0))

    return [
        {'crypto_group': group, 'confidence': confidence}
        for group, confidence in sorted(grouped.items(), key=lambda item: item[1], reverse=True)
    ]


def infer_prediction_basis(features: Dict[str, Any]) -> List[str]:
    """Infer which evidence sources support the prediction."""
    basis = ['file_statistics']
    footer_score = float(features.get('footer_metadata_score', 0.0) or 0.0)
    footer_signals = [
        features.get('footer_has_length_marker', 0),
        features.get('footer_nonce12_tag16_like', 0),
        features.get('footer_nonce24_tag16_like', 0),
        features.get('footer_rsa2048_wrapped_key_like', 0),
        features.get('footer_rsa4096_wrapped_key_like', 0),
    ]

    if footer_score > 0 or any(float(value or 0) > 0 for value in footer_signals):
        basis.append('footer_heuristics')

    return basis


def certainty_from_prediction(is_encrypted: bool, confidence: float, basis: List[str]) -> str:
    """Convert model confidence and evidence sources into a calibrated label."""
    if not is_encrypted:
        return 'not_encrypted_or_compressed_candidate'
    if confidence >= 0.85 and 'footer_heuristics' in basis:
        return 'probable_from_file_statistics_and_footer_heuristics'
    if confidence >= 0.70:
        return 'probable_group_prediction'
    if confidence >= 0.50:
        return 'possible_group_prediction'
    return 'low_confidence_group_candidate'


class Predictor:
    """Make predictions on new data with evidence generation."""

    def __init__(self, model_trainer, feature_columns: list = None):
        self.model_trainer = model_trainer
        self.feature_columns = feature_columns or model_trainer.feature_columns

    def predict_with_confidence(self, X: np.ndarray, top_k: int = 3) -> Dict[str, Any]:
        """Make predictions with confidence scores."""
        predictions, probabilities = self.model_trainer.predict(X)
        class_names = self.model_trainer.label_encoder.classes_

        top_indices = np.argsort(probabilities[0])[-top_k:][::-1]
        top_predictions = [
            {
                'label': class_names[idx],
                'confidence': float(probabilities[0][idx]),
            }
            for idx in top_indices
        ]
        all_predictions = [
            {
                'label': class_names[idx],
                'confidence': float(probabilities[0][idx]),
            }
            for idx in range(len(class_names))
        ]

        predicted_class = class_names[predictions[0]]

        return {
            'predicted_class': predicted_class,
            'crypto_group': normalize_crypto_group(predicted_class),
            'algorithm_guess': algorithm_guess_for_label(predicted_class),
            'confidence': float(probabilities[0][predictions[0]]),
            'all_probabilities': {
                class_names[idx]: float(probabilities[0][idx])
                for idx in range(len(class_names))
            },
            'top_predictions': top_predictions,
            'top_groups': aggregate_top_groups(all_predictions)[:top_k],
        }

    def generate_evidence(
        self,
        features: Dict[str, Any],
        prediction: str,
        confidence: float,
    ) -> List[str]:
        """Generate human-readable evidence for a group-first prediction."""
        evidence = []
        crypto_group = normalize_crypto_group(prediction)

        full_entropy = features.get('shannon_entropy_full', 0)
        if full_entropy > 7.5:
            evidence.append('entropy toan file cao, gan du lieu ngau nhien')

        entropy_mean = features.get('entropy_mean', 0)
        if entropy_mean > 7.5:
            evidence.append('entropy trung binh cac block cao (> 7.5)')
        elif entropy_mean > 7.0:
            evidence.append('entropy trung binh cac block cao (> 7.0)')

        high_entropy_ratio = features.get(
            'high_entropy_block_ratio',
            features.get('high_entropy_block_ratio_75', 0),
        )
        if high_entropy_ratio > 0.8:
            evidence.append(f'{high_entropy_ratio*100:.1f}% block co entropy cao')

        file_size_mod_16 = features.get('file_size_mod_16', 0)
        file_size_mod_8 = features.get('file_size_mod_8', 0)
        legacy_8_byte_block_labels = [
            '3DES_like',
            'Blowfish_like',
            'DES_like',
            'RC2_like',
            'CAST5_like',
        ]

        if prediction in ['AES_like'] and file_size_mod_16 == 0:
            evidence.append('kich thuoc file la boi so cua 16, phu hop block cipher AES-like')
        elif prediction in legacy_8_byte_block_labels and file_size_mod_8 == 0:
            evidence.append('kich thuoc file la boi so cua 8, phu hop legacy block cipher')
        elif crypto_group == 'stream_cipher_like' and file_size_mod_8 and file_size_mod_16:
            evidence.append('khong thay tin hieu padding/block-size ro cua block cipher')

        if features.get('footer_nonce24_tag16_like', 0) > 0:
            evidence.append('footer co candidate nonce 24 bytes va authentication tag 16 bytes')
        elif features.get('footer_nonce12_tag16_like', 0) > 0:
            evidence.append('footer co candidate nonce 12 bytes va authentication tag 16 bytes')

        if features.get('footer_rsa4096_wrapped_key_like', 0) > 0:
            evidence.append('footer co candidate RSA-4096 wrapped symmetric key')
        elif features.get('footer_rsa2048_wrapped_key_like', 0) > 0:
            evidence.append('footer co candidate RSA-2048 wrapped symmetric key')
        elif features.get('footer_has_length_marker', 0) > 0:
            evidence.append('footer co length marker cho metadata ma hoa')

        if (
            crypto_group == 'block_cipher_like'
            and features.get('footer_iv16_or_tag16_like', 0) > 0
        ):
            evidence.append('footer co candidate IV/tag 16 bytes')

        printable_ratio = features.get('printable_byte_ratio', 0)
        if printable_ratio < 0.05:
            evidence.append('printable byte ratio rat thap')

        null_ratio = features.get('null_byte_ratio', 0)
        if null_ratio > 0.05:
            evidence.append(f'{null_ratio*100:.2f}% byte null (0x00)')

        unique_bytes = features.get('unique_byte_count', 0)
        if unique_bytes > 250:
            evidence.append(f'unique byte count cao ({unique_bytes}/256)')

        if not evidence:
            evidence.append('du lieu phu hop voi phan bo thong ke cua nhom du doan')

        return evidence


def format_prediction_json(
    file_path: str,
    file_size: int,
    is_encrypted: bool,
    predicted_class: str,
    confidence: float,
    top_predictions: List[Dict],
    features_summary: Dict[str, Any],
    evidence: List[str],
    top_groups: List[Dict] = None,
    basis: List[str] = None,
    certainty: str = None,
) -> Dict[str, Any]:
    """Format prediction output as a group-first JSON object."""
    crypto_group = normalize_crypto_group(predicted_class)
    algorithm_guess = algorithm_guess_for_label(predicted_class)
    basis = basis or infer_prediction_basis(features_summary)
    certainty = certainty or certainty_from_prediction(is_encrypted, confidence, basis)

    return {
        'file': {
            'path': file_path,
            'size_bytes': file_size,
        },
        'is_encrypted': is_encrypted,
        'crypto_group': crypto_group,
        'algorithm_guess': algorithm_guess,
        'confidence': confidence,
        'certainty': certainty,
        'basis': basis,
        'top_groups': top_groups or aggregate_top_groups(top_predictions),
        'top_predictions': top_predictions,
        'features_summary': features_summary,
        'evidence': evidence,
        'warning': (
            'Ket qua la du doan theo nhom thuat toan, '
            'khong khang dinh chinh xac thuat toan cu the.'
        ),
    }
