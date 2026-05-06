# Phân tích mã hóa trong tệp ransomware

Dự án này dùng các đặc trưng thống kê của tệp để dự đoán kiểu mã hóa có trong
tệp nghi bị ransomware tác động. Hệ thống gồm hai bài toán riêng:

- `crypto_family`: dự đoán nhóm mã hóa của tệp.
- `ransomware_family`: dự đoán họ ransomware khi có mô hình riêng cho tập dữ liệu
  theo từng họ.

Công cụ này không giải mã tệp, không khôi phục khóa và không khẳng định chính
xác thuật toán mã hóa. Kết quả cần được hiểu là dự đoán xác suất dựa trên đặc
trưng dữ liệu.

## Giới Hạn Của Bài Toán

Nhiều dạng dữ liệu mã hóa hiện đại có phân bố byte rất giống ngẫu nhiên. Vì vậy
AES, ChaCha20, Salsa20, RC4, dữ liệu nén và các tệp entropy cao có thể khó phân
biệt nếu chỉ dựa trên thống kê byte.

Ví dụ:

```text
predicted_label: stream_cipher_like
possible_encryption_summary: stream_cipher_like: ChaCha20/Salsa20/RC4
confidence: 0.49
```

Kết quả trên có nghĩa là tệp giống nhóm stream/counter cipher, không có nghĩa là
hệ thống đã xác định chính xác tệp dùng ChaCha20, Salsa20 hay RC4.

## Cấu Trúc Thư Mục

```text
crypto_detect_byAI/
  configs/
    default.yaml
  data/
    raw/
      original/
    metadata/
      dataset.csv
      ransomware_family_dataset.csv
    ransomware_family/
  models/
    crypto_family_predictor.pkl
    crypto_predictor.pkl
    ransomware_family_predictor.pkl
  reports/
    crypto_family/
    ransomware_family/
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
  main.py
  requirements.txt
  pyproject.toml
```

## Cài Đặt

Chạy lệnh từ thư mục gốc của dự án:

```powershell
python -m pip install -r requirements.txt
```

Nếu cần chạy test:

```powershell
python -m pip install pytest pytest-cov
```

## Các Lệnh Chính

Xem danh sách lệnh:

```powershell
python -m src.cli --help
```

Các lệnh đang dùng:

```text
generate-samples
build-ransomware-metadata
extract-features
train
predict
examples
```

## Quy Trình Xử Lý Dữ Liệu

### 1. Tạo mẫu mã hóa tổng hợp

Đặt các tệp gốc vào `data/raw/original/`, sau đó chạy:

```powershell
python -m src.cli generate-samples `
  --input data/raw/original `
  --output data/generated `
  --metadata data/metadata/dataset.csv `
  --workers 0 `
  --profile group-balanced
```

`group-balanced` tạo dữ liệu theo nhóm mã hóa. Nếu muốn huấn luyện chi tiết theo
từng biến thể thuật toán, có thể dùng `--profile all-variants`.

### 2. Trích xuất đặc trưng cho bài toán mã hóa

```powershell
python -m src.cli extract-features `
  --input data/generated `
  --output data/features/features.parquet `
  --metadata data/metadata/dataset.csv
```

### 3. Huấn luyện mô hình nhóm mã hóa

```powershell
python -m src.cli train `
  --features data/features/features.parquet `
  --metadata data/metadata/dataset.csv `
  --label-column crypto_family `
  --model-output models/crypto_family_predictor.pkl `
  --report-dir reports/crypto_family
```

Kết quả đánh giá được lưu tại:

```text
reports/crypto_family/metrics.json
reports/crypto_family/classification_report.txt
reports/crypto_family/confusion_matrix.png
reports/crypto_family/top_features.json
```

### 4. Chuẩn bị dữ liệu họ ransomware

Dữ liệu ransomware được sắp xếp theo thư mục họ:

```text
data/ransomware_family/
  BLACKCAT/
  CERBER/
  CONTI/
  LOCKBIT/
  NOTPETYA/
  RYUK/
  SODINOKIBI/
  WANNACRY/
```

Tạo metadata:

```powershell
python -m src.cli build-ransomware-metadata `
  --input data/ransomware_family `
  --output data/metadata/ransomware_family_dataset.csv `
  --limit-per-family 1000
```

Trích xuất đặc trưng:

```powershell
python -m src.cli extract-features `
  --input data/ransomware_family `
  --output data/features/ransomware_family_features.parquet `
  --metadata data/metadata/ransomware_family_dataset.csv
```

Huấn luyện mô hình họ ransomware:

```powershell
python -m src.cli train `
  --features data/features/ransomware_family_features.parquet `
  --metadata data/metadata/ransomware_family_dataset.csv `
  --label-column ransomware_family `
  --model-output models/ransomware_family_predictor.pkl `
  --report-dir reports/ransomware_family
```

## Dự Đoán Một Tệp Bằng CLI

Lệnh mặc định dùng cả mô hình nhóm mã hóa và mô hình họ ransomware nếu hai file
mô hình tồn tại:

```powershell
python -m src.cli predict `
  --file .\data\ransomware_family\CONTI\0001-doc.doc.MRBNY
```

Chỉ định rõ mô hình:

```powershell
python -m src.cli predict `
  --file suspicious.enc `
  --model models/crypto_family_predictor.pkl `
  --ransomware-model models/ransomware_family_predictor.pkl
```

Bỏ qua dự đoán họ ransomware:

```powershell
python -m src.cli predict `
  --file suspicious.enc `
  --ransomware-model ""
```

## Nhãn Dữ Liệu Và Cách Gom Nhóm

Dữ liệu tổng hợp có các nhãn chi tiết:

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

Khi huấn luyện với `--label-column crypto_family`, các nhãn chi tiết được gom thành
nhóm:

```text
AES_like, 3DES_like, Blowfish_like, DES_like, RC2_like, CAST5_like
  -> block_padded_mode_like

ChaCha20_Salsa20_like, RC4_like
  -> stream_or_counter_mode_like

XOR_like
  -> weak_obfuscation_like

hybrid_AES_RSA_like, hybrid_ChaCha20_RSA_like, hybrid_Salsa20_RSA_like
  -> hybrid_encryption_like

compressed_only
  -> compressed_only

not_encrypted
  -> not_encrypted

unknown_encrypted
  -> unknown_encrypted
```

Khi hiển thị kết quả, một số tên nhóm được rút gọn để dễ đọc:

```text
block_padded_mode_like      -> block_cipher_like
stream_or_counter_mode_like -> stream_cipher_like
hybrid_encryption_like      -> hybrid_cipher_like
```

Vì vậy, nếu kết quả có:

```text
block_cipher_like: AES/3DES/Blowfish/DES/RC2/CAST5
```

thì cần hiểu là mô hình dự đoán tệp thuộc nhóm block cipher. Danh sách sau dấu
hai chấm là các thuật toán có thể nằm trong nhóm đó, không phải kết luận chính
xác từng thuật toán.

## Đặc Trưng Dùng Để Huấn Luyện

Quá trình trích xuất đặc trưng lấy các thông tin chính:

- entropy toàn tệp;
- thống kê entropy theo từng block;
- histogram byte `byte_0_freq` đến `byte_255_freq`;
- tỷ lệ byte in được, byte null, số byte khác nhau;
- đặc trưng phân bố byte;
- đặc trưng đoạn đầu, giữa và cuối tệp;
- kích thước tệp và các phép chia dư của kích thước;
- dấu hiệu footer như nonce, tag, khóa đối xứng được bọc bởi RSA.

Khi huấn luyện, các cột có nguy cơ làm lộ nhãn một cách trực tiếp sẽ bị loại bỏ, ví
dụ tên file, đuôi file, nhãn metadata, thuật toán, mode và các trường tương tự.
Phần này nằm trong `ModelTrainer.prepare_data()`.

## Định Dạng Kết Quả

Kết quả CLI gồm các phần chính:

- `file`: đường dẫn và kích thước tệp.
- `models`: mô hình đã dùng.
- `features_summary`: tóm tắt một số đặc trưng quan trọng.
- `crypto_prediction`: kết quả dự đoán nhóm mã hóa.
- `ransomware_prediction`: kết quả dự đoán họ ransomware nếu có mô hình.

Ví dụ rút gọn:

```json
{
  "file": {
    "path": ".\\data\\ransomware_family\\CONTI\\0001-doc.doc.MRBNY",
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
    "printable_byte_ratio": 0.3722
  },
  "crypto_prediction": {
    "predicted_label": "stream_or_counter_mode_like",
    "crypto_group": "stream_or_counter_mode_like",
    "algorithm_guess": "stream_or_counter_mode_family",
    "possible_encryption_summary": "stream_cipher_like: ChaCha20/Salsa20/RC4",
    "confidence": 0.49,
    "certainty": "low_confidence_group_candidate",
    "basis": [
      "file_statistics"
    ]
  },
  "is_encrypted": true,
  "ransomware_prediction": {
    "predicted_family": "CONTI",
    "confidence": 0.75
  }
}
```

Ý nghĩa một số trường:

- `predicted_label`: nhãn mô hình chọn sau khi chuẩn hóa tên cũ.
- `confidence`: xác suất mô hình gán cho nhãn đã chọn.
- `certainty`: mức diễn giải dựa trên confidence và cơ sở bằng chứng; đây không
  phải mô hình riêng.
- `possible_encryption_summary`: các thuật toán có thể xuất hiện trong nhóm dự
  đoán.
- `top_predictions`: các nhãn có xác suất cao tiếp theo.

## Ứng Dụng Web Và API

Ứng dụng web cho phép chọn mô hình, tải lên nhiều tệp và xem kết quả JSON.

Chạy server:

```powershell
python -m uvicorn src.api.app:app --reload --host 127.0.0.1 --port 8001
```

Mở trình duyệt:

```text
http://127.0.0.1:8001/
```

Các đường dẫn API chính:

```text
GET  /health
GET  /models
GET  /model/info
POST /predict
POST /predict/batch
```

Dự đoán một tệp:

```powershell
curl -X POST -F "file=@suspicious.enc" http://localhost:8001/predict
```

Dự đoán nhiều tệp:

```powershell
curl -X POST `
  -F "crypto_model=crypto_family_predictor.pkl" `
  -F "ransomware_model=ransomware_family_predictor.pkl" `
  -F "files=@sample1.enc" `
  -F "files=@sample2.enc" `
  http://localhost:8001/predict/batch
```

Mô hình mặc định:

```text
models/crypto_family_predictor.pkl
models/ransomware_family_predictor.pkl
```

## Kiểm Thử

Chạy toàn bộ test:

```powershell
python -m pytest
```

Các file test hiện có:

```text
tests/test_cli_predict_output.py
tests/test_crypto_generation.py
tests/test_entropy.py
tests/test_feature_extraction.py
tests/test_prediction_schema.py
```

## Lưu Ý An Toàn

- Không chạy trực tiếp mẫu malware thật.
- Dự án chỉ đọc byte trong tệp và trích xuất đặc trưng thống kê.
- Dự án không giải mã, không lấy lại plaintext và không khôi phục khóa.
- Kết quả nên được dùng như một tín hiệu tham khảo trong quá trình phân tích.

## Trạng Thái Hiện Tại

Repo hiện có:

```text
models/crypto_family_predictor.pkl
models/ransomware_family_predictor.pkl
reports/crypto_family/
reports/ransomware_family/
```

CLI, API và ứng dụng web đều dùng chung logic kết quả trong `src/models/predict.py`.
