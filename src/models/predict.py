"""
Model prediction utilities.
"""

from typing import Any, Dict, List

import numpy as np
import os
import pandas as pd


LABEL_TO_CRYPTO_GROUP = {
    'AES_like': 'block_padded_mode_like',
    '3DES_like': 'block_padded_mode_like',
    'Blowfish_like': 'block_padded_mode_like',
    'DES_like': 'block_padded_mode_like',
    'RC2_like': 'block_padded_mode_like',
    'CAST5_like': 'block_padded_mode_like',
    'ChaCha20_Salsa20_like': 'stream_or_counter_mode_like',
    'RC4_like': 'stream_or_counter_mode_like',
    'XOR_like': 'weak_obfuscation_like',
    'hybrid_AES_RSA_like': 'hybrid_encryption_like',
    'hybrid_ChaCha20_RSA_like': 'hybrid_encryption_like',
    'hybrid_Salsa20_RSA_like': 'hybrid_encryption_like',
    'compressed_only': 'compressed_only',
    'not_encrypted': 'not_encrypted',
    'unknown_encrypted': 'unknown_encrypted',
}


BROAD_CRYPTO_GROUPS = {
    'not_encrypted',
    'compressed_only',
    'weak_obfuscation_like',
    'block_cipher_like',
    'stream_cipher_like',
    'hybrid_cipher_like',
    'block_padded_mode_like',
    'stream_or_counter_mode_like',
    'aead_mode_like',
    'hybrid_encryption_like',
    'unknown_encrypted',
    'ambiguous',
}


AEAD_HINTS = (
    'footer_nonce12_tag16_like',
    'footer_nonce24_tag16_like',
    'footer_iv16_or_tag16_like',
)


PREDICTION_FEATURE_SUMMARY_KEYS = (
    'shannon_entropy_full',
    'entropy_mean',
    'high_entropy_block_ratio',
    'unique_byte_count',
    'printable_byte_ratio',
    'footer_metadata_score',
    'footer_nonce12_tag16_like',
    'footer_nonce24_tag16_like',
    'footer_rsa2048_wrapped_key_like',
)


LEGACY_LABEL_ALIASES = {
    'unknown_high_entropy': 'unknown_encrypted',
}


CRYPTO_GROUP_LABELS = {
    'block_cipher_like': [
        'AES_like',
        '3DES_like',
        'Blowfish_like',
        'DES_like',
        'RC2_like',
        'CAST5_like',
    ],
    'block_padded_mode_like': [
        'AES_like',
        '3DES_like',
        'Blowfish_like',
        'DES_like',
        'RC2_like',
        'CAST5_like',
    ],
    'stream_cipher_like': ['ChaCha20_Salsa20_like', 'RC4_like'],
    'stream_or_counter_mode_like': ['ChaCha20_Salsa20_like', 'RC4_like'],
    'aead_mode_like': ['AES_like'],
    'hybrid_cipher_like': [
        'hybrid_AES_RSA_like',
        'hybrid_ChaCha20_RSA_like',
        'hybrid_Salsa20_RSA_like',
    ],
    'hybrid_encryption_like': [
        'hybrid_AES_RSA_like',
        'hybrid_ChaCha20_RSA_like',
        'hybrid_Salsa20_RSA_like',
    ],
    'weak_obfuscation_like': ['XOR_like'],
}


DISPLAY_CRYPTO_GROUP_NAMES = {
    'block_padded_mode_like': 'block_cipher_like',
    'stream_or_counter_mode_like': 'stream_cipher_like',
    'aead_mode_like': 'aead_cipher_like',
    'hybrid_encryption_like': 'hybrid_cipher_like',
}


LABEL_TO_ALGORITHM_NAMES = {
    'AES_like': ['AES'],
    '3DES_like': ['3DES'],
    'Blowfish_like': ['Blowfish'],
    'DES_like': ['DES'],
    'RC2_like': ['RC2'],
    'CAST5_like': ['CAST5'],
    'ChaCha20_Salsa20_like': ['ChaCha20', 'Salsa20'],
    'RC4_like': ['RC4'],
    'XOR_like': ['XOR'],
    'hybrid_AES_RSA_like': ['AES+RSA'],
    'hybrid_ChaCha20_RSA_like': ['ChaCha20+RSA'],
    'hybrid_Salsa20_RSA_like': ['Salsa20+RSA'],
    'unknown_encrypted': ['unknown'],
}


LABEL_TO_ENCRYPTION_TYPES = {
    'AES_like': ['AES-CBC', 'AES-ECB', 'AES-CTR', 'AES-CFB', 'AES-OFB', 'AES-GCM'],
    '3DES_like': ['3DES-CBC'],
    'Blowfish_like': ['Blowfish-CBC'],
    'DES_like': ['DES-CBC'],
    'RC2_like': ['RC2-CBC'],
    'CAST5_like': ['CAST5-CBC'],
    'ChaCha20_Salsa20_like': ['ChaCha20', 'Salsa20'],
    'RC4_like': ['RC4'],
    'XOR_like': ['repeating XOR', 'simple custom XOR'],
    'hybrid_AES_RSA_like': ['AES + RSA wrapped key'],
    'hybrid_ChaCha20_RSA_like': ['ChaCha20 + RSA wrapped key'],
    'hybrid_Salsa20_RSA_like': ['Salsa20 + RSA wrapped key'],
    'unknown_encrypted': ['unknown encryption'],
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
    'hybrid_cipher_like': 'hybrid_cipher_family',
    'block_padded_mode_like': 'block_padded_mode_family',
    'stream_or_counter_mode_like': 'stream_or_counter_mode_family',
    'aead_mode_like': 'aead_mode_family',
    'hybrid_encryption_like': 'hybrid_encryption_family',
    'weak_obfuscation_like': 'weak_obfuscation_or_custom_cipher',
    'compressed_only': 'compressed_or_high_entropy_format',
    'not_encrypted': 'not_encrypted',
    'unknown_encrypted': 'unknown_encrypted',
    'ambiguous': 'ambiguous',
}


def canonicalize_prediction_label(label: str) -> str:
    """Return the current output name for a model label."""
    return LEGACY_LABEL_ALIASES.get(str(label), str(label))


def normalize_crypto_group(label: str, features: Dict[str, Any] = None) -> str:
    """Map a detailed label to the broad crypto_group used as the main prediction."""
    label = canonicalize_prediction_label(label)

    if label in BROAD_CRYPTO_GROUPS:
        return label

    mapped = LABEL_TO_CRYPTO_GROUP.get(label)
    if mapped is None:
        return label

    if mapped == 'block_padded_mode_like' and features:
        if any(float(features.get(key, 0) or 0) > 0 for key in AEAD_HINTS):
            return 'aead_mode_like'
    return mapped


def normalize_crypto_subgroup(label: str, features: Dict[str, Any] = None) -> str:
    """Return the most specific leaf label for the prediction."""
    return normalize_crypto_group(label, features)


def algorithm_guess_for_label(label: str) -> str:
    """Return a deliberately broad algorithm-family guess."""
    label = canonicalize_prediction_label(label)
    return ALGORITHM_GUESS_MAP.get(label, normalize_crypto_group(label))


def possible_encryption_types_for_label(label: str) -> List[str]:
    """Return encryption algorithms/modes that can appear under a model label."""
    label = canonicalize_prediction_label(label)

    if label in {'not_encrypted', 'compressed_only'}:
        return []

    member_labels = CRYPTO_GROUP_LABELS.get(label)
    if member_labels:
        possible_types = []
        for member_label in member_labels:
            possible_types.extend(LABEL_TO_ENCRYPTION_TYPES.get(member_label, [member_label]))
        return possible_types

    return LABEL_TO_ENCRYPTION_TYPES.get(label, [label])


def possible_algorithm_names_for_label(label: str) -> List[str]:
    """Return compact algorithm names that can appear under a model label."""
    label = canonicalize_prediction_label(label)

    if label in {'not_encrypted', 'compressed_only'}:
        return []

    member_labels = CRYPTO_GROUP_LABELS.get(label)
    if member_labels:
        possible_names = []
        for member_label in member_labels:
            possible_names.extend(LABEL_TO_ALGORITHM_NAMES.get(member_label, [member_label]))
        return possible_names

    return LABEL_TO_ALGORITHM_NAMES.get(label, [label])


def display_crypto_group_for_label(label: str) -> str:
    """Return the display group name used in compact prediction summaries."""
    group = normalize_crypto_group(label)
    return DISPLAY_CRYPTO_GROUP_NAMES.get(group, group)


def possible_encryption_summary_for_label(label: str) -> str:
    """Return a compact summary like block_cipher_like: AES/3DES/DES."""
    group = display_crypto_group_for_label(label)
    algorithm_names = possible_algorithm_names_for_label(label)

    if not algorithm_names:
        return f'{group}: none'

    return f'{group}: {"/".join(algorithm_names)}'


def summarize_prediction_features(features: Dict[str, Any]) -> Dict[str, Any]:
    """Return the compact feature subset exposed in prediction responses."""
    return {
        key: features.get(key, 0)
        for key in PREDICTION_FEATURE_SUMMARY_KEYS
    }


def is_encrypted_label(label: str) -> bool:
    """Return whether a predicted label/group should be treated as encrypted."""
    return normalize_crypto_group(label) not in {'not_encrypted', 'compressed_only'}


def aggregate_top_groups(
    top_predictions: List[Dict[str, Any]],
    features: Dict[str, Any] = None,
) -> List[Dict[str, Any]]:
    """Aggregate detailed label probabilities into crypto groups."""
    grouped: Dict[str, float] = {}
    for item in top_predictions:
        group = normalize_crypto_group(item.get('label', 'unknown_encrypted'), features)
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
        class_names = [
            canonicalize_prediction_label(label)
            for label in self.model_trainer.label_encoder.classes_
        ]

        top_indices = np.argsort(probabilities[0])[-top_k:][::-1]
        top_predictions = [
            {
                'label': class_names[idx],
                'confidence': float(probabilities[0][idx]),
                'possible_encryption_types': possible_encryption_types_for_label(
                    class_names[idx],
                ),
                'possible_encryption_summary': possible_encryption_summary_for_label(
                    class_names[idx],
                ),
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
            'predicted_label': predicted_class,
            'predicted_class': predicted_class,
            'crypto_group': normalize_crypto_group(predicted_class),
            'algorithm_guess': algorithm_guess_for_label(predicted_class),
            'possible_encryption_types': possible_encryption_types_for_label(predicted_class),
            'possible_encryption_summary': possible_encryption_summary_for_label(
                predicted_class,
            ),
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
    predicted_class = canonicalize_prediction_label(predicted_class)
    top_predictions = [
        {
            **item,
            'label': canonicalize_prediction_label(item.get('label', 'unknown_encrypted')),
            'possible_encryption_types': possible_encryption_types_for_label(
                item.get('label', 'unknown_encrypted'),
            ),
            'possible_encryption_summary': possible_encryption_summary_for_label(
                item.get('label', 'unknown_encrypted'),
            ),
        }
        for item in top_predictions
    ]

    crypto_group = normalize_crypto_group(predicted_class, features_summary)
    crypto_subgroup = normalize_crypto_subgroup(predicted_class, features_summary)
    algorithm_guess = algorithm_guess_for_label(predicted_class)
    possible_encryption_types = possible_encryption_types_for_label(predicted_class)
    possible_encryption_summary = possible_encryption_summary_for_label(predicted_class)
    basis = basis or infer_prediction_basis(features_summary)
    certainty = certainty or certainty_from_prediction(is_encrypted, confidence, basis)

    return {
        'file': {
            'path': file_path,
            'size_bytes': file_size,
        },
        'is_encrypted': is_encrypted,
        'predicted_label': predicted_class,
        'predicted_class': predicted_class,
        'crypto_group': crypto_group,
        'crypto_subgroup': crypto_subgroup,
        'algorithm_guess': algorithm_guess,
        'possible_encryption_types': possible_encryption_types,
        'possible_encryption_summary': possible_encryption_summary,
        'confidence': confidence,
        'certainty': certainty,
        'basis': basis,
        'top_groups': top_groups or aggregate_top_groups(top_predictions, features_summary),
        'top_predictions': top_predictions,
        'features_summary': features_summary,
        'evidence': evidence,
        'warning': (
            'Ket qua la du doan theo nhom thuat toan, '
            'khong khang dinh chinh xac thuat toan cu the.'
        ),
    }


def predict_all(
    file_path: str,
    crypto_model_path: str = 'models/crypto_family_predictor.pkl',
    ransomware_model_path: str = 'models/ransomware_family_predictor.pkl',
    top_k: int = 3,
) -> Dict[str, Any]:
    """Run both crypto-family and optional ransomware-family predictions for a file.

    Returns a dictionary with keys `crypto` (group-first formatted output) and
    `ransomware_family` (simple prediction dict) when a ransomware model path is
    provided.
    """
    from src.models.train import ModelTrainer
    from src.features.extract_features import extract_features_from_file

    # Extract features from file
    features = extract_features_from_file(file_path)

    # Prepare crypto predictor
    crypto_trainer = ModelTrainer()
    crypto_trainer.load_model(crypto_model_path)
    crypto_predictor = Predictor(crypto_trainer)

    feature_array = pd.DataFrame([
        {name: features.get(name, 0) for name in crypto_trainer.feature_columns}
    ])

    crypto_result = crypto_predictor.predict_with_confidence(feature_array, top_k=top_k)

    predicted_class = crypto_result['predicted_class']
    confidence = crypto_result['confidence']
    is_encrypted = is_encrypted_label(predicted_class)
    basis = infer_prediction_basis(features)

    evidence = crypto_predictor.generate_evidence(features, predicted_class, confidence)

    file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0

    crypto_output = format_prediction_json(
        file_path=file_path,
        file_size=file_size,
        is_encrypted=is_encrypted,
        predicted_class=predicted_class,
        confidence=confidence,
        top_predictions=crypto_result['top_predictions'],
        features_summary=summarize_prediction_features(features),
        evidence=evidence,
        top_groups=crypto_result.get('top_groups'),
        basis=basis,
        certainty=certainty_from_prediction(is_encrypted, confidence, basis),
    )

    ransomware_output = None
    if ransomware_model_path:
        # Load ransomware-family model and predict
        ransomware_trainer = ModelTrainer()
        ransomware_trainer.load_model(ransomware_model_path)
        ransomware_predictor = Predictor(ransomware_trainer)

        feature_array_r = pd.DataFrame([
            {name: features.get(name, 0) for name in ransomware_trainer.feature_columns}
        ])

        r_result = ransomware_predictor.predict_with_confidence(feature_array_r, top_k=top_k)

        ransomware_output = {
            'predicted_family': r_result['predicted_class'],
            'confidence': r_result['confidence'],
            'top_predictions': [
                {
                    'label': item.get('label'),
                    'confidence': item.get('confidence'),
                }
                for item in r_result['top_predictions']
            ],
        }

    return {
        'crypto': crypto_output,
        'ransomware_family': ransomware_output,
        'features': features,
    }
