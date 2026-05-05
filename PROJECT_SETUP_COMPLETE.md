# Project State Summary

This file records the current state of the repository after the local cleanup
and documentation refresh. It replaces the older initialization-only summary.

## Project

```text
Name: ransomware-crypto-ai
Location: D:\crypto_detect_byAI
Version: 0.1.0
Primary interface: python -m src.cli
```

## What Is Implemented

### CLI

`src/cli.py` provides:

```text
generate-samples
build-ransomware-metadata
extract-features
train
predict
examples
```

The current `predict` command can combine:

- crypto prediction from `models/crypto_family_predictor.pkl`;
- optional ransomware-family prediction from
  `models/ransomware_family_predictor.pkl`.

### Models

Current model utilities live in:

```text
src/models/train.py
src/models/evaluate.py
src/models/predict.py
```

The baseline classifier is `RandomForestClassifier`.

Prediction output includes:

- `predicted_label`
- `confidence`
- `certainty`
- `possible_encryption_types`
- `possible_encryption_summary`
- `top_predictions`
- `top_groups`
- evidence strings

### Feature Extraction

Feature extraction is implemented in:

```text
src/features/extract_features.py
src/features/entropy.py
src/features/byte_stats.py
src/features/file_structure.py
```

Feature families include:

- full-file entropy;
- block entropy;
- byte histogram;
- byte-level statistics;
- segment statistics;
- file structure and magic bytes;
- ransomware-like footer heuristics.

### Crypto Sample Generation

Synthetic encryption helpers include:

```text
AES CBC/ECB/CTR/CFB/OFB/GCM
3DES CBC
Blowfish CBC
DES CBC
RC2 CBC
CAST5 CBC
ChaCha20
Salsa20
RC4
repeating XOR
AES + RSA hybrid
ChaCha20 + RSA hybrid
Salsa20 + RSA hybrid
```

### API

`src/api/app.py` exposes:

```text
GET  /health
POST /predict
GET  /model/info
```

The API currently loads `models/crypto_predictor.pkl` and serves crypto
prediction. The dual crypto+ransomware wrapper is currently available through
the CLI.

### Tests

Current test files:

```text
tests/test_cli_predict_output.py
tests/test_crypto_generation.py
tests/test_entropy.py
tests/test_feature_extraction.py
tests/test_prediction_schema.py
```

`pytest` and `pytest-cov` are not bundled inside the checked `.venv` at the
time of this update; install them before running tests.

## Recommended Commands

Install dependencies:

```powershell
py -3.11 -m pip install -r requirements.txt
```

Run a compile check:

```powershell
py -3.11 -m compileall src tests main.py
```

Run tests:

```powershell
py -3.11 -m pip install pytest pytest-cov
py -3.11 -m pytest
```

Predict:

```powershell
py -3.11 -m src.cli predict `
  --file suspicious.enc `
  --model models/crypto_family_predictor.pkl `
  --ransomware-model models/ransomware_family_predictor.pkl
```

## Notes For Future Work

- Keep crypto label mappings centralized in `src/models/predict.py`.
- Keep README examples aligned with actual CLI defaults.
- If API should match CLI behavior, update `src/api/app.py` to use
  `predict_all()` or add a separate ransomware-family model loader.
- Retrain model artifacts after changing label mappings or generated sample
  distributions.

## Safety Status

The project is prediction-only. It does not execute malware, recover encryption
keys, or decrypt files.
