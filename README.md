# Ransomware Crypto AI

AI/ML pipeline for predicting the crypto-family pattern of ransomware-affected
files from statistical file features. The project also supports a separate
ransomware-family classifier when samples are organized by family.

This tool does not break encryption, recover keys, or prove the exact algorithm.
It returns probabilistic labels, confidence scores, top alternatives, and
human-readable evidence.

## Current Scope

The repo currently has two separate prediction tasks:

- `crypto_family`: predicts a crypto group or detailed crypto-like label.
- `ransomware_family`: predicts a ransomware family such as `LOCKBIT`,
  `BLACKCAT`, `RYUK`, etc. when a separate family model is available.

Do not merge these into one label column. They answer different questions.

## Important Scientific Limit

Modern ciphertext often looks random. AES, ChaCha20, Salsa20, compressed data,
and high-entropy formats can be difficult to distinguish from statistics alone.

Read outputs as:

```text
The file looks most similar to stream_cipher_like with confidence 0.49.
Possible algorithms in that label: ChaCha20/Salsa20/RC4.
This is a low-confidence candidate, not proof.
```

## Repository Layout

```text
crypto_detect_byAI/
  configs/
    default.yaml
  data/
    raw/
      original/
      .gitkeep
    metadata/
      dataset.csv
      ransomware_family_dataset.csv
    ransomware_family/
      .gitkeep
  models/
    crypto_family_predictor.pkl
    crypto_predictor.pkl
    ransomware_family_predictor.pkl
  reports/
    .gitkeep
  src/
    api/
      app.py
    crypto/
      encrypt_aes.py
      encrypt_3des.py
      encrypt_arc2.py
      encrypt_blowfish.py
      encrypt_cast.py
      encrypt_chacha20.py
      encrypt_des.py
      encrypt_hybrid.py
      encrypt_rc4.py
      encrypt_salsa20.py
      encrypt_xor.py
      footer.py
    dataset/
      build_metadata.py
      generate_compressed_samples.py
      generate_encrypted_samples.py
      split_original_files.py
    features/
      byte_stats.py
      entropy.py
      extract_features.py
      file_structure.py
    models/
      evaluate.py
      predict.py
      train.py
    cli.py
    config.py
  tests/
    test_cli_predict_output.py
    test_crypto_generation.py
    test_entropy.py
    test_feature_extraction.py
    test_prediction_schema.py
  main.py
  requirements.txt
  pyproject.toml
```

## Installation

From the repo root:

```powershell
py -3.11 -m pip install -r requirements.txt
```

For tests, install pytest and pytest-cov:

```powershell
py -3.11 -m pip install pytest pytest-cov
```

or install the dev extras:

```powershell
py -3.11 -m pip install -e ".[dev]"
```

## CLI Commands

Show available commands:

```powershell
py -3.11 -m src.cli --help
```

Current commands:

```text
generate-samples
build-ransomware-metadata
extract-features
train
predict
examples
```

## Recommended Workflow

### 1. Generate synthetic crypto samples

Put clean source files in `data/raw/original/`, then run:

```powershell
py -3.11 -m src.cli generate-samples `
  --input data/raw/original `
  --output data/generated `
  --metadata data/metadata/dataset.csv `
  --workers 0 `
  --profile group-balanced
```

Use `--profile all-variants` if you want detailed `label_group` training with
all available algorithm variants.

### 2. Extract crypto features

```powershell
py -3.11 -m src.cli extract-features `
  --input data/generated `
  --output data/features/features.parquet `
  --metadata data/metadata/dataset.csv
```

### 3. Train crypto-family model

```powershell
py -3.11 -m src.cli train `
  --features data/features/features.parquet `
  --metadata data/metadata/dataset.csv `
  --label-column crypto_family `
  --model-output models/crypto_family_predictor.pkl `
  --report-dir reports/crypto_family
```

Reports are written to:

```text
reports/crypto_family/metrics.json
reports/crypto_family/classification_report.txt
reports/crypto_family/confusion_matrix.png
reports/crypto_family/top_features.json
```

### 4. Prepare ransomware-family data

For family classification, organize files like this:

```text
data/ransomware_family/
  BLACKCAT/
  LOCKBIT/
  NOTPETYA/
  RYUK/
  SODINOKIBI/
  WANNACRY/
```

Then build metadata:

```powershell
py -3.11 -m src.cli build-ransomware-metadata `
  --input data/ransomware_family `
  --output data/metadata/ransomware_family_dataset.csv `
  --limit-per-family 1000
```

Extract features:

```powershell
py -3.11 -m src.cli extract-features `
  --input data/ransomware_family `
  --output data/features/ransomware_family_features.parquet `
  --metadata data/metadata/ransomware_family_dataset.csv
```

Train ransomware-family model:

```powershell
py -3.11 -m src.cli train `
  --features data/features/ransomware_family_features.parquet `
  --metadata data/metadata/ransomware_family_dataset.csv `
  --label-column ransomware_family `
  --model-output models/ransomware_family_predictor.pkl `
  --report-dir reports/ransomware_family
```

### 5. Predict a file

CLI prediction uses both models by default if both paths exist:

```powershell
py -3.11 -m src.cli predict `
  --file .\data\ransomware_family\LOCKBIT\0001-docx.docx
```

Explicit paths:

```powershell
py -3.11 -m src.cli predict `
  --file suspicious.enc `
  --model models/crypto_family_predictor.pkl `
  --ransomware-model models/ransomware_family_predictor.pkl
```

Skip ransomware-family prediction:

```powershell
py -3.11 -m src.cli predict `
  --file suspicious.enc `
  --ransomware-model ""
```

## Supported Synthetic Labels

Detailed labels generated by `generate-samples`:

```text
not_encrypted
compressed_only
AES_like
3DES_like
Blowfish_like
DES_like
RC2_like
CAST5_like
ChaCha20_Salsa20_like
RC4_like
XOR_like
hybrid_AES_RSA_like
hybrid_ChaCha20_RSA_like
hybrid_Salsa20_RSA_like
unknown_encrypted
```

Current crypto-family mapping:

```text
block_padded_mode_like       = AES_like + 3DES_like + Blowfish_like + DES_like + RC2_like + CAST5_like
stream_or_counter_mode_like  = ChaCha20_Salsa20_like + RC4_like
weak_obfuscation_like        = XOR_like
aead_mode_like               = AES_like with AEAD-like footer hints
hybrid_encryption_like       = hybrid_AES_RSA_like + hybrid_ChaCha20_RSA_like + hybrid_Salsa20_RSA_like
compressed_only              = compressed_only
not_encrypted                = not_encrypted
unknown_encrypted            = unknown_encrypted
```

Older model artifacts may still output legacy group names such as
`block_cipher_like`, `stream_cipher_like`, or `hybrid_cipher_like`. Prediction
formatting supports those names and expands them correctly in summaries.

## Prediction Output

CLI output is wrapped into three main sections:

- `features_summary`: compact feature subset shown to users.
- `crypto_prediction`: crypto model result.
- `ransomware_prediction`: optional ransomware-family result.

Example:

```json
{
  "file": {
    "path": ".\\data\\ransomware_family\\0001-doc.doc.uhwuvzu",
    "size_bytes": 87820
  },
  "models": {
    "crypto_model": "models/crypto_family_predictor.pkl",
    "ransomware_model": "models/ransomware_family_predictor.pkl"
  },
  "features_summary": {
    "shannon_entropy_full": 7.9977,
    "entropy_mean": 7.9511,
    "high_entropy_block_ratio": 1.0,
    "unique_byte_count": 256,
    "printable_byte_ratio": 0.3722,
    "footer_metadata_score": 0.0,
    "footer_nonce12_tag16_like": 0.0,
    "footer_nonce24_tag16_like": 0.0,
    "footer_rsa2048_wrapped_key_like": 0.0
  },
  "crypto_prediction": {
    "predicted_label": "stream_cipher_like",
    "predicted_class": "stream_cipher_like",
    "crypto_group": "stream_cipher_like",
    "crypto_subgroup": "stream_cipher_like",
    "algorithm_guess": "stream_cipher_family",
    "possible_encryption_types": [
      "ChaCha20",
      "Salsa20",
      "RC4"
    ],
    "possible_encryption_summary": "stream_cipher_like: ChaCha20/Salsa20/RC4",
    "confidence": 0.4908,
    "certainty": "low_confidence_group_candidate",
    "basis": [
      "file_statistics"
    ],
    "top_predictions": [
      {
        "label": "stream_cipher_like",
        "confidence": 0.4908,
        "possible_encryption_types": [
          "ChaCha20",
          "Salsa20",
          "RC4"
        ],
        "possible_encryption_summary": "stream_cipher_like: ChaCha20/Salsa20/RC4"
      },
      {
        "label": "compressed_only",
        "confidence": 0.3515,
        "possible_encryption_types": [],
        "possible_encryption_summary": "compressed_only: none"
      }
    ],
    "top_groups": [
      {
        "crypto_group": "stream_cipher_like",
        "confidence": 0.4908
      },
      {
        "crypto_group": "compressed_only",
        "confidence": 0.3515
      }
    ],
    "evidence": [
      "entropy toan file cao, gan du lieu ngau nhien",
      "entropy trung binh cac block cao (> 7.5)"
    ]
  },
  "is_encrypted": true,
  "ransomware_prediction": {
    "predicted_family": "BLACKCAT",
    "confidence": 0.7572,
    "top_predictions": [
      {
        "label": "BLACKCAT",
        "confidence": 0.7572
      }
    ]
  }
}
```

### Meaning of key fields

- `predicted_label`: raw label chosen by the trained model, after legacy label
  alias cleanup.
- `confidence`: probability returned by the model for `predicted_label`.
- `certainty`: human-readable confidence bucket derived from confidence and
  evidence basis. It is not a separate model.
- `possible_encryption_summary`: compact explanation of what algorithms may be
  inside the predicted label, for example
  `stream_cipher_like: ChaCha20/Salsa20/RC4`.
- `top_predictions`: alternatives from the model. Always inspect these when
  confidence is low.

## Feature Extraction

The feature extractor currently includes:

- full-file entropy;
- block entropy statistics;
- byte histogram `byte_0_freq` through `byte_255_freq`;
- byte statistics such as printable ratio, null-byte ratio, mean, std, median;
- advanced byte-distribution features;
- first/middle/last segment features;
- file signature and file-size features;
- ransomware-like footer heuristics.

During model training, metadata columns and known leaky synthetic artifact
features are removed by `ModelTrainer.prepare_data()`.

## API

The API also serves a small web app for batch prediction, model selection, and
JSON output inspection.

Install API dependencies if they are not already available in your global
Python:

```powershell
python -m pip install fastapi uvicorn python-multipart
```

Run with global Python:

```powershell
python -m uvicorn src.api.app:app --reload --host 127.0.0.1 --port 8000
```

Open:

```text
http://127.0.0.1:8000/
```

Health:

```powershell
curl http://localhost:8000/health
```

List available model artifacts:

```powershell
curl http://localhost:8000/models
```

Predict one file with the default loaded crypto model:

```powershell
curl -X POST -F "file=@suspicious.enc" http://localhost:8000/predict
```

Predict multiple files with selected models:

```powershell
curl -X POST `
  -F "crypto_model=crypto_family_predictor.pkl" `
  -F "ransomware_model=ransomware_family_predictor.pkl" `
  -F "files=@sample1.enc" `
  -F "files=@sample2.enc" `
  http://localhost:8000/predict/batch
```

Model info:

```powershell
curl http://localhost:8000/model/info
```

The web app and `/predict/batch` endpoint use the same combined output wrapper
as the CLI. Default artifacts are:

```text
models/crypto_family_predictor.pkl
models/ransomware_family_predictor.pkl
```

## Tests

Install test dependencies first:

```powershell
py -3.11 -m pip install pytest pytest-cov
```

Run:

```powershell
py -3.11 -m pytest
```

Current test files:

```text
tests/test_cli_predict_output.py
tests/test_crypto_generation.py
tests/test_entropy.py
tests/test_feature_extraction.py
tests/test_prediction_schema.py
```

## Safety Notes

- Do not execute real malware.
- This repo only analyzes bytes and generates synthetic encrypted samples.
- It does not recover plaintext or keys.
- Treat predictions as probabilistic research signals, not forensic proof.

## Project Status

The repo currently has working CLI prediction using:

```text
models/crypto_family_predictor.pkl
models/ransomware_family_predictor.pkl
```

The docs are aligned with the current code paths and output schema as of the
latest local refactor.
