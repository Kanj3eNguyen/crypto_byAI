"""
Kiểm thử phần sinh mẫu mã hóa tổng hợp.
"""

import csv

from click.testing import CliRunner

from src.cli import cli
from src.crypto.encrypt_aes import (
    encrypt_aes_cbc,
    encrypt_aes_cfb,
    encrypt_aes_ctr,
    encrypt_aes_ecb,
    encrypt_aes_gcm,
    encrypt_aes_ofb,
)
from src.crypto.encrypt_arc2 import encrypt_rc2_cbc
from src.crypto.encrypt_blowfish import encrypt_blowfish_cbc
from src.crypto.encrypt_cast import encrypt_cast5_cbc
from src.crypto.encrypt_des import encrypt_des_cbc
from src.crypto.encrypt_xor import encrypt_repeating_xor
from src.features.extract_features import extract_features_from_file


def test_common_ransomware_encryptors_return_metadata():
    data = b"ransomware crypto detector sample" * 8
    encryptors = [
        encrypt_aes_cbc,
        encrypt_aes_ecb,
        encrypt_aes_ctr,
        encrypt_aes_cfb,
        encrypt_aes_ofb,
        encrypt_aes_gcm,
        encrypt_blowfish_cbc,
        encrypt_des_cbc,
        encrypt_rc2_cbc,
        encrypt_cast5_cbc,
        encrypt_repeating_xor,
    ]

    for encryptor in encryptors:
        ciphertext, metadata = encryptor(data)

        assert ciphertext
        assert ciphertext != data
        assert metadata["algorithm"]
        assert metadata["key_size"] > 0


def test_generate_samples_includes_added_algorithm_groups(tmp_path):
    input_dir = tmp_path / "raw"
    output_dir = tmp_path / "generated"
    metadata_path = tmp_path / "metadata" / "dataset.csv"
    input_dir.mkdir()
    (input_dir / "sample.txt").write_bytes(b"hello from a harmless test file" * 16)

    result = CliRunner().invoke(
        cli,
        [
            "generate-samples",
            "--input",
            str(input_dir),
            "--output",
            str(output_dir),
            "--metadata",
            str(metadata_path),
            "--limit",
            "1",
            "--profile",
            "all-variants",
            "--skip-hybrid",
        ],
    )

    assert result.exit_code == 0, result.output

    with metadata_path.open(newline="", encoding="utf-8") as csv_file:
        rows = list(csv.DictReader(csv_file))

    labels = {row["label_group"] for row in rows}
    algorithms = {row["algorithm"] for row in rows}

    assert {
        "Blowfish_like",
        "DES_like",
        "RC2_like",
        "CAST5_like",
        "XOR_like",
    }.issubset(labels)
    assert {"Blowfish", "DES", "RC2", "CAST5", "XOR"}.issubset(algorithms)
    assert "crypto_family" in rows[0]


def test_generated_aes_gcm_footer_survives_padding(tmp_path):
    input_dir = tmp_path / "raw"
    output_dir = tmp_path / "generated"
    metadata_path = tmp_path / "metadata" / "dataset.csv"
    input_dir.mkdir()
    (input_dir / "sample.txt").write_bytes(b"hello from a harmless test file" * 16)

    result = CliRunner().invoke(
        cli,
        [
            "generate-samples",
            "--input",
            str(input_dir),
            "--output",
            str(output_dir),
            "--metadata",
            str(metadata_path),
            "--limit",
            "1",
            "--profile",
            "all-variants",
            "--skip-hybrid",
        ],
    )

    assert result.exit_code == 0, result.output

    with metadata_path.open(newline="", encoding="utf-8") as csv_file:
        rows = list(csv.DictReader(csv_file))

    aes_gcm_row = next(row for row in rows if row["algorithm"] == "AES" and row["mode"] == "GCM")
    features = extract_features_from_file(aes_gcm_row["path"])

    assert features["footer_has_length_marker"] == 1.0
    assert features["footer_nonce12_tag16_like"] == 1.0
