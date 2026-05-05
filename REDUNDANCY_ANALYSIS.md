# Redundancy Analysis

This file tracks cleanup opportunities in the current repository. It replaces
the older generated analysis that had stale paths and broken encoding.

## Summary

Recent cleanup has already removed several safe redundancies:

- unused imports in CLI, API-adjacent modules, dataset helpers, and tests;
- one unused private footer helper in feature extraction;
- duplicate prediction feature-summary dictionaries;
- duplicate crypto-family mapping in CLI;
- redundant `Predictor` construction in the API prediction path.

The repo now keeps the most important crypto prediction labels and display
metadata in `src/models/predict.py`.

## Resolved Or Partially Resolved

### 1. Duplicate crypto-family mapping

Status: partially resolved.

Current source of truth:

```text
src/models/predict.py
  LABEL_TO_CRYPTO_GROUP
  CRYPTO_GROUP_LABELS
  LABEL_TO_ALGORITHM_NAMES
  LABEL_TO_ENCRYPTION_TYPES
```

`src/cli.py` imports those constants instead of maintaining a second full copy.

Remaining possible cleanup:

- Move constants to a dedicated module only if the mapping grows further, for
  example `src/constants/crypto_labels.py`.

### 2. Duplicate feature summary formatting

Status: resolved.

Current helper:

```text
src/models/predict.py::summarize_prediction_features
```

It is used by:

```text
src/models/predict.py::predict_all
src/api/app.py
```

### 3. API recreated Predictor during request handling

Status: resolved.

`src/api/app.py` now reuses `_predictor.generate_evidence(...)`.

### 4. Unused imports and unused private helper

Status: resolved for obvious cases.

Files cleaned:

```text
src/cli.py
src/config.py
src/crypto/encrypt_aes.py
src/dataset/build_metadata.py
src/dataset/generate_compressed_samples.py
src/dataset/generate_encrypted_samples.py
src/dataset/split_original_files.py
src/features/extract_features.py
src/models/evaluate.py
tests/test_feature_extraction.py
```

## Remaining Opportunities

### 1. CLI command size

Status: still present.

`src/cli.py` still contains generation, extraction, training, prediction, and
metadata commands in one file. This is acceptable for the current repo size, but
could be split later:

```text
src/cli/
  __init__.py
  main.py
  commands/
    generate.py
    extract.py
    train.py
    predict.py
```

Risk: medium. Splitting Click commands can create import and packaging churn.
Only do this when CLI grows further.

### 2. API and CLI prediction behavior differ

Status: still present by design.

CLI:

```text
models/crypto_family_predictor.pkl
models/ransomware_family_predictor.pkl
```

API:

```text
models/crypto_predictor.pkl
```

Potential cleanup:

- update API to call `predict_all()` for the same crypto+ransomware response as
  CLI; or
- document API as crypto-only and keep it intentionally smaller.

Current README documents this difference.

### 3. Crypto encryptor modules have repeated structure

Status: still present.

The encryptors share common patterns:

- create key/nonce/IV;
- create cipher;
- encrypt data;
- append footer metadata;
- return `(ciphertext, metadata)`.

Potential cleanup:

- add helper functions for metadata formatting;
- keep one file per algorithm to preserve readability.

Avoid a large factory refactor unless tests are expanded first.

### 4. Feature extraction still recalculates small segment statistics

Status: still present but acceptable.

`calculate_segment_features()` calculates stats per segment. This is simple and
safe. Optimizing it may improve speed, but should be benchmarked first.

### 5. Public helper modules with low usage

Status: intentionally kept.

Examples:

```text
src/dataset/build_metadata.py
src/dataset/generate_compressed_samples.py
src/dataset/split_original_files.py::get_split_info
src/features/byte_stats.py::calculate_byte_frequencies
```

They may be useful for scripts outside the repo, so they were not removed.

### 6. Test environment dependency

Status: still present.

The repo has tests, but the checked local environment may not have `pytest` and
`pytest-cov` installed. The docs now explicitly include:

```powershell
py -3.11 -m pip install pytest pytest-cov
py -3.11 -m pytest
```

## Current Verification Commands

Compile check:

```powershell
py -3.11 -m compileall src tests main.py
```

Predict smoke test:

```powershell
py -3.11 -m src.cli predict `
  --file .\data\ransomware_family\0001-doc.doc.uhwuvzu
```

Expected crypto summary shape:

```text
possible_encryption_summary: stream_cipher_like: ChaCha20/Salsa20/RC4
```

Expected ransomware prediction shape:

```json
{
  "predicted_family": "BLACKCAT",
  "confidence": 0.7572,
  "top_predictions": [
    {
      "label": "BLACKCAT",
      "confidence": 0.7572
    }
  ]
}
```

## Recommendation

Do not perform large structural refactors until the following are in place:

- pytest and pytest-cov installed in the active environment;
- tests for API prediction;
- tests for CLI train/extract command behavior;
- one or two real benchmark commands for feature extraction speed.

The next safest cleanup would be to add tests around API response shape, then
optionally align API prediction with CLI prediction.
