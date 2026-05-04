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
hybrid_AES_RSA_like   - Symmetric key + RSA hybrid encryption
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

## 📊 Workflow Chính

### 1. Chuẩn bị Dataset

```bash
# Chia file gốc thành train/val/test
python -m src.dataset.split_original_files \
    --input data/raw/original \
    --train-ratio 0.7 \
    --val-ratio 0.15 \
    --test-ratio 0.15
```

### 2. Sinh Dữ Liệu Mã Hoá

```bash
# Sinh các mẫu mã hoá từ file gốc
python -m src.dataset.generate_encrypted_samples \
    --input data/raw/original \
    --output data/generated \
    --samples-per-file 3
```

### 3. Trích Xuất Đặc Trưng

```bash
# Trích xuất tất cả các đặc trưng
python -m src.cli extract-features \
    --input data/generated \
    --output data/features/features.parquet \
    --metadata data/metadata/dataset.csv
```

### 4. Huấn Luyện Model

```bash
# Train Random Forest classifier
python -m src.cli train \
    --features data/features/features.parquet \
    --model-output models/crypto_predictor.pkl \
    --report-dir reports
```

### 5. Đánh Giá Model

```bash
# Tính metrics và tạo báo cáo
python -m src.cli evaluate \
    --model models/crypto_predictor.pkl \
    --features data/features/features_test.parquet \
    --report-dir reports
```

### 6. Dự Đoán File

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

### Entropy Features

- `shannon_entropy_full` - Shannon entropy của toàn bộ file
- `entropy_mean` - Entropy trung bình của các block
- `entropy_std` - Độ lệch chuẩn entropy
- `entropy_min`, `entropy_max`, `entropy_median` - Min/max/median entropy
- `high_entropy_block_ratio_75` - % block có entropy > 7.5
- `high_entropy_block_ratio_78` - % block có entropy > 7.8

### Byte Statistics

- `unique_byte_count` - Số byte value unique (0-256)
- `printable_byte_ratio` - % byte là ký tự in được (ASCII 32-126)
- `null_byte_ratio` - % null byte (0x00)
- `byte_*_freq` (256 features) - Tần suất từng byte value (0-255)

### File Structure

- `file_size`, `file_size_mod_8`, `file_size_mod_16`, `file_size_mod_256`
- `magic_bytes_hex` - Magic bytes header
- `identified_format` - Định dạng file được phát hiện
- `has_known_signature` - Có file signature đã biết hay không
- Header/footer entropy features

## 📋 Output Format

### Dạng JSON từ dự đoán

```json
{
  "file": {
    "path": "samples/suspicious.enc",
    "size_bytes": 245912
  },
  "classification": {
    "is_encrypted": true,
    "predicted_crypto_group": "AES_like",
    "confidence": 0.82,
    "top_predictions": [
      {
        "label": "AES_like",
        "confidence": 0.82
      },
      {
        "label": "ChaCha20_Salsa20_like",
        "confidence": 0.13
      },
      {
        "label": "unknown_encrypted",
        "confidence": 0.05
      }
    ]
  },
  "features_summary": {
    "shannon_entropy_full": 7.91,
    "entropy_mean": 7.88,
    "high_entropy_block_ratio": 0.96,
    "file_size_mod_16": 0,
    "printable_byte_ratio": 0.03
  },
  "evidence": [
    "entropy trung bình cao",
    "96% block có entropy > 7.5",
    "file size có dấu hiệu phù hợp nhóm block cipher",
    "byte histogram gần với nhóm AES_like trong tập train"
  ],
  "warning": "Kết quả là dự đoán xác suất, không khẳng định tuyệt đối thuật toán mã hoá."
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
sample_id,path,label_group,algorithm,mode,key_size,original_file_id,original_type,tool,split,file_size
000001,data/generated/AES_like/000001.enc,AES_like,AES,CBC,256,orig_0001,pdf,openssl,train,582312
000002,data/generated/ChaCha20_Salsa20_like/000002.enc,ChaCha20_Salsa20_like,ChaCha20,,256,orig_0002,txt,pycrypto,val,245102
```

## 🤖 Model Architecture

### Baseline: Random Forest Classifier

- **n_estimators**: 200
- **max_depth**: 20
- **min_samples_split**: 5
- **min_samples_leaf**: 2

### Thống kê Input

- **Features**: 280+ (entropy, byte histogram 256, file structure, etc.)
- **Samples**: ~1000+ (tùy vào số file gốc)
- **Classes**: 8 (encryption groups)

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
