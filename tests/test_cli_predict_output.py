"""
Kiểm thử cấu trúc output của lệnh predict.
"""

from src.cli import build_predict_output


def test_build_predict_output_merges_crypto_and_ransomware():
    combined = {
        'crypto': {
            'file': {'path': 'sample.enc', 'size_bytes': 123},
            'crypto_group': 'stream_or_counter_mode_like',
            'crypto_subgroup': 'stream_or_counter_mode_like',
            'algorithm_guess': 'stream_or_counter_mode_family',
            'possible_encryption_types': ['ChaCha20', 'Salsa20', 'RC4'],
            'possible_encryption_summary': 'stream_cipher_like: ChaCha20/Salsa20/RC4',
            'confidence': 0.82,
            'certainty': 'probable_group_prediction',
            'basis': ['file_statistics'],
            'top_predictions': [
                {'label': 'stream_or_counter_mode_like', 'confidence': 0.82},
                {'label': 'compressed_only', 'confidence': 0.12},
            ],
            'top_groups': [
                {'crypto_group': 'stream_or_counter_mode_like', 'confidence': 0.82},
                {'crypto_group': 'compressed_only', 'confidence': 0.12},
            ],
            'evidence': ['entropy cao'],
            'features_summary': {'shannon_entropy_full': 7.99},
        },
        'ransomware_family': {
            'predicted_family': 'LOCKBIT',
            'confidence': 0.94,
            'top_predictions': [
                {'label': 'LOCKBIT', 'confidence': 0.94},
                {'label': 'WANNACRY', 'confidence': 0.03},
            ],
        },
        'features': {'shannon_entropy_full': 7.99},
    }

    output = build_predict_output(
        file_path='sample.enc',
        crypto_model_path='models/crypto_family_predictor.pkl',
        ransomware_model_path='models/ransomware_family_predictor.pkl',
        combined=combined,
    )

    assert output['file']['path'] == 'sample.enc'
    assert output['models']['crypto_model'] == 'models/crypto_family_predictor.pkl'
    assert output['models']['ransomware_model'] == 'models/ransomware_family_predictor.pkl'
    assert output['crypto_prediction']['predicted_label'] == 'stream_or_counter_mode_like'
    assert output['crypto_prediction']['predicted_class'] == 'stream_or_counter_mode_like'
    assert output['crypto_prediction']['crypto_group'] == 'stream_or_counter_mode_like'
    assert output['crypto_prediction']['possible_encryption_types'] == [
        'ChaCha20',
        'Salsa20',
        'RC4',
    ]
    assert output['crypto_prediction']['possible_encryption_summary'] == (
        'stream_cipher_like: ChaCha20/Salsa20/RC4'
    )
    assert output['ransomware_prediction']['predicted_family'] == 'LOCKBIT'
    assert output['features_summary']['shannon_entropy_full'] == 7.99


def test_build_predict_output_without_ransomware_prediction():
    combined = {
        'crypto': {
            'file': {'path': 'sample.enc', 'size_bytes': 123},
            'crypto_group': 'block_padded_mode_like',
            'crypto_subgroup': 'block_padded_mode_like',
            'algorithm_guess': 'aes_family',
            'confidence': 0.91,
            'certainty': 'probable_group_prediction',
            'basis': ['file_statistics'],
            'top_predictions': [{'label': 'AES_like', 'confidence': 0.91}],
            'top_groups': [{'crypto_group': 'block_padded_mode_like', 'confidence': 0.91}],
            'evidence': ['entropy cao'],
        },
        'ransomware_family': None,
        'features': {'entropy_mean': 7.8},
    }

    output = build_predict_output(
        file_path='sample.enc',
        crypto_model_path='models/crypto_family_predictor.pkl',
        ransomware_model_path=None,
        combined=combined,
    )

    assert output['models']['ransomware_model'] is None
    assert 'ransomware_prediction' not in output
    assert output['crypto_prediction']['predicted_label'] == 'AES_like'
    assert output['crypto_prediction']['predicted_class'] == 'AES_like'
    assert output['crypto_prediction']['possible_encryption_types'] == [
        'AES-CBC',
        'AES-ECB',
        'AES-CTR',
        'AES-CFB',
        'AES-OFB',
        'AES-GCM',
    ]
    assert output['crypto_prediction']['possible_encryption_summary'] == 'block_cipher_like: AES'
    assert output['features_summary']['entropy_mean'] == 7.8
