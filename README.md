# AI-based Prediction of Ransomware Encryption Algorithm Groups

**Nghiên cứu ứng dụng AI trong dự đoán nhóm thuật toán mã hoá được sử dụng bởi mã độc ransomware**

## 📋 Tổng quan

Dự án này xây dựng một hệ thống sử dụng AI/ML để dự đoán nhóm thuật toán mã hoá có khả năng được ransomware sử dụng dựa trên các đặc trưng thống kê và cấu trúc của file đã bị tác động.

Hệ thống không khẳng định chính xác tuyệt đối thuật toán mã hoá, mà đưa ra kết quả theo dạng xác suất, kèm độ tin cậy và bằng chứng hỗ trợ.

## ⚠️ Giới hạn Khoa Học Quan Trọng

**QUAN TRỌNG**: Không được tuyên bố rằng hệ thống có thể xác định tuyệt đối thuật toán mã hoá chỉ từ ciphertext.

Lý do:
- Ciphertext của các thuật toán hiện đại thường gần ngẫu nhiên
- AES, ChaCha20, Salsa20 nếu dùng đúng cách có thể rất khó phân biệt chỉ bằng thống kê
- Ransomware thường dùng hybrid encryption (AES/ChaCha20/Salsa20 + RSA)
- Entropy cao không chứng minh file bị mã hoá (file nén cũng có entropy cao)

Hệ thống chỉ nên kết luận theo dạng: **"File có khả năng thuộc nhóm AES_like với độ tin cậy 0.82. Đây là dự đoán xác suất, không phải chứng minh tuyệt đối."**

## 🎯 Mục Tiêu

Xây dựng một pipeline ML hoàn chỉnh để:
1. Phân tích file nghi bị ransomware tác động
2. Dự đoán nhóm thuật toán mã hoá
3. Cung cấp confidence score và evidence
4. Đưa ra cảnh báo về giới hạn của dự đoán

## 📦 Các Nhóm Nhãn Hỗ Trợ

```
not_encrypted          - File bình thường, chưa mã hoá
compressed_only        - File nén hoặc entropy cao tự nhiên (zip, rar, jpg, mp4)
AES_like              - Mã hoá bằng AES hoặc block cipher gần AES
ChaCha20_Salsa20_like - Nhóm stream cipher hiện đại
RC4_like              - Nhóm stream cipher cũ
3DES_like             - Block cipher cũ (block size 8 byte)
Blowfish_like         - Block cipher legacy
DES_like              - Legacy DES block cipher
RC2_like              - Legacy RC2 block cipher
CAST5_like            - Legacy CAST5 block cipher
XOR_like              - Simple repeating-key XOR obfuscation
hybrid_AES_RSA_like   - Symmetric key + RSA hybrid encryption
hybrid_ChaCha20_RSA_like - ChaCha20 + RSA hybrid encryption
hybrid_Salsa20_RSA_like  - Salsa20 + RSA hybrid encryption
unknown_encrypted     - Dữ liệu có vẻ mã hoá nhưng không đủ chắc
```

## 🏗️ Cấu Trúc Thư Mục

```
ransomware-crypto-ai/
├── configs/
│   └── default.yaml              # Configuration
├── data/
│   ├── raw/                      # Original files
│   │   ├── original/
│   │   └── external/
│   ├── generated/                # Generated encrypted samples
│   │   ├── AES_like/
│   │   ├── ChaCha20_Salsa20_like/
│   │   ├── RC4_like/
│   │   ├── 3DES_like/
│   │   ├── hybrid_AES_RSA_like/
│   │   ├── compressed_only/
│   │   └── not_encrypted/
│   ├── metadata/                 # Metadata CSV files
│   │   └── dataset.csv
│   └── features/                 # Extracted features
│       └── features.parquet
├── models/
│   └── crypto_predictor.pkl      # Trained model
├── reports/
│   ├── metrics.json
│   ├── classification_report.txt
│   ├── confusion_matrix.png
│   └── feature_importance.png
├── src/
│   ├── config.py                 # Configuration management
│   ├── cli.py                    # Command-line interface
│   ├── dataset/                  # Dataset preparation
│   │   ├── build_dataset.py
│   │   ├── split_original_files.py
│   │   ├── generate_encrypted_samples.py
│   │   ├── generate_compressed_samples.py
│   │   └── build_metadata.py
│   ├── crypto/                   # Encryption algorithms
│   │   ├── encrypt_aes.py
│   │   ├── encrypt_chacha20.py
│   │   ├── encrypt_salsa20.py
│   │   ├── encrypt_rc4.py
│   │   ├── encrypt_3des.py
│   │   └── encrypt_hybrid.py
│   ├── features/                 # Feature extraction
│   │   ├── entropy.py
│   │   ├── byte_stats.py
│   │   ├── file_structure.py
│   │   └── extract_features.py
│   ├── models/                   # Model training & evaluation
│   │   ├── train.py
│   │   ├── evaluate.py
│   │   └── predict.py
│   └── api/                      # FastAPI application
│       └── app.py
├── tests/
│   ├── test_entropy.py
│   ├── test_feature_extraction.py
│   └── test_prediction_schema.py
├── README.md
├── requirements.txt
├── pyproject.toml
└── .gitignore
```

## 🚀 Cài Đặt

### Yêu cầu

- Python 3.8+
- pip hoặc conda

### Bước 1: Clone project

```bash
cd d:\crypto_detect_byAI
```

### Bước 2: Cài đặt dependencies

```bash
pip install -r requirements.txt
```

Nếu gặp vấn đề với xgboost, có thể bỏ qua:
```bash
pip install -r requirements.txt --ignore-installed xgboost
```

### Bước 3: Cấu hình

Chỉnh sửa `configs/default.yaml` nếu cần thiết.

## Workflow hien tai nen dung

Nen chay thanh 2 pipeline rieng:

- `crypto_family`: train tu du lieu synthetic sinh tu `data/raw/original`
- `ransomware_family`: train tu du lieu ransomware family that trong `data/ransomware_family/<FAMILY>/`

Khong nen gop 2 dataset nay vao cung mot model vi `crypto_family` va `ransomware_family` la 2 cap nhan khac nhau.

### 1. Smoke test nhanh

```powershell
python -m src.cli generate-samples `
  --input data/raw/original `
  --output data/generated `
  --metadata data/metadata/dataset.csv `
  --limit 100 `
  --clean-output `
  --workers 0 `
  --profile group-balanced `
  --skip-hybrid
  
```

```powershell
python -m src.cli build-ransomware-metadata `
  --input data/ransomware_family `
  --output data/metadata/ransomware_family_dataset.csv `
  --limit-per-family 100
```

### 2. Train model crypto_family

`crypto_family` gop cac nhan chi tiet nhu sau:

```text
block_cipher_like  = AES_like + 3DES_like + Blowfish_like + DES_like + RC2_like + CAST5_like
stream_cipher_like = ChaCha20_Salsa20_like + RC4_like
weak_obfuscation_like = XOR_like
hybrid_cipher_like = hybrid_AES_RSA_like + hybrid_ChaCha20_RSA_like + hybrid_Salsa20_RSA_like
compressed_only    = compressed_only
not_encrypted      = not_encrypted
unknown_encrypted  = unknown_encrypted
```

Sinh du lieu synthetic tu raw:

```powershell
python -m src.cli generate-samples `
  --input data/raw/original `
  --output data/generated `
  --metadata data/metadata/dataset.csv `
  --limit 1000 `
  --clean-output `
  --workers 0 `
  --profile group-balanced
```

`group-balanced` sinh so mau can bang theo `crypto_family`, phu hop voi muc tieu du doan nhom.
Neu muon train nhan chi tiet `label_group`, dung `--profile all-variants`.
`--workers 0` tu dong dung nhieu worker de gen nhanh hon; dat `--workers 1` neu muon chay tuan tu.

Trich xuat feature:

```powershell
python -m src.cli extract-features `
  --input data/generated `
  --output data/features/features.parquet `
  --metadata data/metadata/dataset.csv
```

Train va sinh report:

```powershell
python -m src.cli train `
  --features data/features/features.parquet `
  --metadata data/metadata/dataset.csv `
  --label-column crypto_family `
  --model-output models/crypto_family_predictor.pkl `
  --report-dir reports/crypto_family
```

Report sinh ra:

```text
reports/crypto_family/metrics.json
reports/crypto_family/classification_report.txt
reports/crypto_family/confusion_matrix.png
reports/crypto_family/top_features.json
```

### 3. Train model ransomware_family

Chuan bi du lieu theo cau truc:

```text
data/ransomware_family/
  WANNACRY/
  LOCKBIT/
  CONTI/
  BLACKCAT/
  CERBER/
  GANDCRAB/
  RYUK/
  SODINOKIBI/
  PHOBOS/
  NOTPETYA/
```

Tao metadata family:

```powershell
python -m src.cli build-ransomware-metadata `
  --input data/ransomware_family `
  --output data/metadata/ransomware_family_dataset.csv `
  
  
```

Trich xuat feature:

```powershell
python -m src.cli extract-features `
  --input data/ransomware_family `
  --output data/features/ransomware_family_features.parquet `
  --metadata data/metadata/ransomware_family_dataset.csv
```

Train va sinh report:

```powershell
python -m src.cli train `
  --features data/features/ransomware_family_features.parquet `
  --metadata data/metadata/ransomware_family_dataset.csv `
  --label-column ransomware_family `
  --model-output models/ransomware_family_predictor.pkl `
  --report-dir reports/ransomware_family
```

Report sinh ra:

```text
reports/ransomware_family/metrics.json
reports/ransomware_family/classification_report.txt
reports/ransomware_family/confusion_matrix.png
reports/ransomware_family/top_features.json
```

### 4. Quy mo data khuyen nghi

```text
Smoke test:
  raw synthetic:        200-500 raw files
  ransomware_family:    50-100 files/family

Baseline:
  raw synthetic:        1000 raw files
  ransomware_family:    500 files/family

Train nghiem tuc:
  raw synthetic:        toan bo data/raw/original
  ransomware_family:    1000+ files/family
```

Khi da chay on, bo `--limit` o `generate-samples` va tang `--limit-per-family` len `1000` hoac cao hon.

### 5. Du Doan File

```bash
# Dự đoán thuật toán mã hoá cho một file
python -m src.cli predict \
    --file suspicious.enc \
    --model models/crypto_predictor.pkl
```

## 🔌 API Endpoint

### Chạy API server

```bash
uvicorn src.api.app:app --reload --port 8000
```

### Health Check

```bash
curl http://localhost:8000/health
```

### Dự Đoán File (Multipart Upload)

```bash
curl -X POST -F "file=@suspicious.enc" http://localhost:8000/predict
```

### Model Information

```bash
curl http://localhost:8000/model/info
```

## 📈 Đặc Trưng Trích Xuất

Tổng số cột feature hiện tại: **386**

- Bao gồm cột metadata/string: `path`, `magic_bytes_hex`, `footer_bytes_hex`
- Nếu chỉ tính feature số cho mô hình: **383**
- Khi train, model loai bo cac feature de hoc artifact synthetic:
  `first_byte_value`, `last_byte_value`, `footer_length_marker_value`,
  va `footer_marker_layout_*`.

### 1) File basic features

- `path`
- `file_size`
- `file_size_mod_8`
- `file_size_mod_16`
- `file_size_mod_256`

### 2) Entropy (full + block)

- `shannon_entropy_full`
- `entropy_mean`
- `entropy_std`
- `entropy_min`
- `entropy_max`
- `entropy_median`
- `entropy_first_block`
- `entropy_last_block`
- `high_entropy_block_ratio`
- `very_high_entropy_block_ratio`

### 3) Byte statistics

- `unique_byte_count`
- `printable_byte_ratio`
- `null_byte_ratio`
- `byte_mean`
- `byte_std`
- `byte_min`
- `byte_max`
- `byte_median`

### 4) Byte histogram (256 features)

- `byte_0_freq` ... `byte_255_freq`

### 5) Advanced byte features

- `byte_chi_square_uniformity`
- `byte_serial_correlation`
- `adjacent_equal_byte_ratio`
- `adjacent_abs_diff_mean`
- `adjacent_abs_diff_std`
- `adjacent_xor_mean`
- `unique_bigram_ratio`
- `run_count_ratio`
- `longest_byte_run`
- `mean_byte_run_length`

### 6) Segment features

- `first_256_entropy`
- `first_256_printable_ratio`
- `first_256_null_byte_ratio`
- `first_256_unique_byte_count`
- `first_1024_entropy`
- `first_1024_printable_ratio`
- `first_1024_null_byte_ratio`
- `first_1024_unique_byte_count`
- `last_256_entropy`
- `last_256_printable_ratio`
- `last_256_null_byte_ratio`
- `last_256_unique_byte_count`
- `last_1024_entropy`
- `last_1024_printable_ratio`
- `last_1024_null_byte_ratio`
- `last_1024_unique_byte_count`
- `middle_1024_entropy`
- `middle_1024_printable_ratio`
- `middle_1024_null_byte_ratio`
- `middle_1024_unique_byte_count`
- `first_byte_value`
- `last_byte_value`

### 7) File structure and raw signatures

- `has_known_signature`
- `magic_bytes_hex`
- `footer_bytes_hex`

### 8) Footer heuristics

- `footer_8_entropy` ... `footer_512_entropy`
- `footer_8_normalized_entropy` ... `footer_512_normalized_entropy`
- `footer_8_unique_ratio` ... `footer_512_unique_ratio`
- `footer_has_length_marker`
- `footer_marker_layout_suffix`
- `footer_marker_layout_prefix`
- `footer_length_marker_value`
- `footer_length_marker_ratio`
- `footer_marker_body_entropy`
- `footer_nonce12_like`
- `footer_nonce12_tag16_like`
- `footer_nonce24_tag16_like`
- `footer_iv8_like`
- `footer_iv16_or_tag16_like`
- `footer_rsa2048_wrapped_key_like`
- `footer_rsa4096_wrapped_key_like`
- `footer_entropy_delta_vs_body`
- `footer_metadata_score`

## 📋 Output Format

### Dạng JSON từ dự đoán

```json
{
  "file": {
    "path": "samples/suspicious.enc",
    "size_bytes": 245912
  },
  "is_encrypted": true,
  "crypto_group": "stream_cipher_like",
  "algorithm_guess": "chacha20_salsa20_family",
  "confidence": 0.78,
  "certainty": "probable_from_file_statistics_and_footer_heuristics",
  "basis": [
    "file_statistics",
    "footer_heuristics"
  ],
  "top_groups": [
    {
      "crypto_group": "stream_cipher_like",
      "confidence": 0.78
    },
    {
      "crypto_group": "block_cipher_like",
      "confidence": 0.14
    },
    {
      "crypto_group": "hybrid_cipher_like",
      "confidence": 0.06
    }
  ],
  "top_predictions": [
    {
      "label": "ChaCha20_Salsa20_like",
      "confidence": 0.78
    },
    {
      "label": "AES_like",
      "confidence": 0.14
    }
  ],
  "features_summary": {
    "shannon_entropy_full": 7.91,
    "entropy_mean": 7.88,
    "high_entropy_block_ratio": 0.96,
    "printable_byte_ratio": 0.03,
    "footer_metadata_score": 1.0,
    "footer_nonce12_tag16_like": 1.0
  },
  "evidence": [
    "entropy toan file cao, gan du lieu ngau nhien",
    "printable byte ratio rat thap",
    "footer co candidate nonce 12 bytes va authentication tag 16 bytes",
    "khong thay tin hieu padding/block-size ro cua block cipher"
  ],
  "warning": "Ket qua la du doan theo nhom thuat toan, khong khang dinh chinh xac thuat toan cu the."
}
```

## 🧪 Kiểm Tra

Chạy test suite:

```bash
pytest tests/ -v
```

Các test file:
- `test_entropy.py` - Test tính toán entropy
- `test_feature_extraction.py` - Test trích xuất đặc trưng
- `test_prediction_schema.py` - Test schema output

## 📚 Metadata CSV Schema

```csv
sample_id,path,label_group,crypto_family,algorithm,mode,key_size,original_file_id,original_type,tool,split,file_size
000001,data/generated/AES_like/000001.enc,AES_like,block_cipher_like,AES,CBC,256,orig_0001,pdf,openssl,train,582312
000002,data/generated/ChaCha20_Salsa20_like/000002.enc,ChaCha20_Salsa20_like,stream_cipher_like,ChaCha20,,256,orig_0002,txt,pycrypto,val,245102
```

## 🤖 Model Architecture

### Baseline: Random Forest Classifier

- **n_estimators**: 200
- **max_depth**: 20
- **min_samples_split**: 5
- **min_samples_leaf**: 2

### Thống kê Input

- **Features**: 380+ (entropy, byte histogram 256, footer heuristics, file structure, etc.)
- **Samples**: ~1000+ (tùy vào số file gốc)
- **Classes**: 15 label groups, or 7 broad crypto families

## 📝 Lưu Ý Khi Sử Dụng

1. **Không dùng làm bằng chứng tuyệt đối** - Kết quả là dự đoán xác suất
2. **Hạn chế dữ liệu training** - Model hoạt động tốt trên file loại tương tự training set
3. **Entropy cao không chứng minh mã hoá** - File nén cũng có entropy cao
4. **Không phân tích file nghi vấn thật sự có malware** - Chỉ phân tích ciphertext

## 🔒 Yêu Cầu An Toàn

- ✅ Không chạy ransomware thật
- ✅ Không tải hoặc thực thi malware
- ✅ Chỉ dùng thư viện mật mã hợp pháp
- ✅ Không viết chức năng phá mã hoặc tấn công
- ✅ Không dùng để hỗ trợ hành vi độc hại

## 📄 License

MIT License

## 👥 Contribution

Đóng góp được hoan nghênh! Vui lòng tạo pull request.

## ❓ FAQ

### Q: Tại sao kết quả không chính xác 100%?
A: Vì ciphertext của các thuật toán mã hoá tốt thường khó phân biệt chỉ bằng thống kê. Hệ thống chỉ đưa ra xác suất, không khẳng định tuyệt đối.

### Q: Có thể sử dụng model để phá mã không?
A: Không. Model chỉ dự đoán nhóm thuật toán, không khôi phục key hoặc plaintext.

### Q: Cần bao nhiêu file để training?
A: Ít nhất 100-200 file per class là tốt. Nhiều hơn càng tốt (1000+).

### Q: Có thể train model trên dữ liệu khác?
A: Có. Chuẩn bị dữ liệu theo schema CSV, rồi chạy `extract-features` và `train`.

---

**Tác giả**: Crypto AI Team  
**Phiên bản**: 0.1.0  
**Cập nhật lần cuối**: 2024
