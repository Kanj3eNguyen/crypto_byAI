# Development Guide

This guide is for maintaining and extending the current repo. It mirrors the
current CLI/API code paths rather than the older project scaffold.

## Environment

Recommended on Windows:

```powershell
cd D:\crypto_detect_byAI
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

For tests:

```powershell
.\.venv\Scripts\python.exe -m pip install pytest pytest-cov
```

## Main Commands

```powershell
py -3.11 -m src.cli --help
py -3.11 -m src.cli examples
```

Available CLI commands:

```text
generate-samples
build-ransomware-metadata
extract-features
train
predict
examples
```

## Current Training Workflows

### Crypto-family model

Generate synthetic samples from clean files:

```powershell
py -3.11 -m src.cli generate-samples `
  --input data/raw/original `
  --output data/generated `
  --metadata data/metadata/dataset.csv `
  --workers 0 `
  --profile group-balanced
```

Extract features:

```powershell
py -3.11 -m src.cli extract-features `
  --input data/generated `
  --output data/features/features.parquet `
  --metadata data/metadata/dataset.csv
```

Train:

```powershell
py -3.11 -m src.cli train `
  --features data/features/features.parquet `
  --metadata data/metadata/dataset.csv `
  --label-column crypto_family `
  --model-output models/crypto_family_predictor.pkl `
  --report-dir reports/crypto_family
```

### Ransomware-family model

Expected directory shape:

```text
data/ransomware_family/
  BLACKCAT/
  LOCKBIT/
  RYUK/
  WANNACRY/
```

Build metadata:

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

Train:

```powershell
py -3.11 -m src.cli train `
  --features data/features/ransomware_family_features.parquet `
  --metadata data/metadata/ransomware_family_dataset.csv `
  --label-column ransomware_family `
  --model-output models/ransomware_family_predictor.pkl `
  --report-dir reports/ransomware_family
```

## Prediction Development Notes

The CLI prediction flow is:

```text
src.cli.predict
  -> src.models.predict.predict_all
     -> extract_features_from_file
     -> ModelTrainer.load_model
     -> Predictor.predict_with_confidence
     -> format_prediction_json
  -> build_predict_output
```

Important fields:

- `predicted_label`: model label after legacy alias cleanup.
- `confidence`: model probability.
- `certainty`: derived confidence bucket.
- `possible_encryption_types`: detailed algorithms/modes possible under the
  label.
- `possible_encryption_summary`: compact label explanation, for example
  `stream_cipher_like: ChaCha20/Salsa20/RC4`.

The ransomware-family output deliberately does not include crypto metadata.

## API Development Notes

The FastAPI app currently loads:

```text
models/crypto_predictor.pkl
```

in `src/api/app.py`. It serves crypto prediction only. The CLI path is the
current dual-model path for crypto + ransomware-family prediction.

Endpoints:

```text
GET  /health
POST /predict
GET  /model/info
```

## Adding a New Synthetic Crypto Variant

1. Add or update an encryptor in `src/crypto/`.
2. Add it to the relevant spec list inside `generate_samples()` in `src/cli.py`.
3. Add the label mapping in `src/models/predict.py`:
   - `LABEL_TO_CRYPTO_GROUP`
   - `CRYPTO_GROUP_LABELS`
   - `LABEL_TO_ALGORITHM_NAMES`
   - `LABEL_TO_ENCRYPTION_TYPES`
   - `ALGORITHM_GUESS_MAP` if a display family is needed.
4. Add or update tests in `tests/test_crypto_generation.py` and
   `tests/test_prediction_schema.py`.
5. Regenerate data and retrain the model.

## Feature Extraction Notes

Main entry points:

```text
src.features.extract_features.extract_features_from_file
src.features.extract_features.extract_features_batch
```

Training removes metadata and known leaky synthetic artifacts in
`ModelTrainer.prepare_data()`. Do not add filename, extension, or footer marker
layout features to training unless you explicitly want artifact leakage.

## Testing

Compile check:

```powershell
py -3.11 -m compileall src tests main.py
```

Run tests:

```powershell
py -3.11 -m pytest
```

If this fails with `No module named pytest` or an unrecognized `--cov`
argument, install `pytest pytest-cov` first.

## Troubleshooting

### `ModuleNotFoundError: No module named 'src'`

Run commands from repo root:

```powershell
cd D:\crypto_detect_byAI
py -3.11 -m src.cli predict --file suspicious.enc
```

### `Model not found`

Check that these files exist or pass explicit paths:

```text
models/crypto_family_predictor.pkl
models/ransomware_family_predictor.pkl
```

### Low crypto confidence

Inspect `top_predictions`. A top-1 label with confidence below 0.50 should be
treated as a candidate, not a conclusion.

### Ransomware metadata builder finds no family directories

`build-ransomware-metadata` expects one subdirectory per family. Standalone
files directly under `data/ransomware_family/` are ignored by that command.

## Safety

Do not execute real ransomware samples. The project only reads files as bytes
and generates synthetic encryption samples using legal crypto libraries.
