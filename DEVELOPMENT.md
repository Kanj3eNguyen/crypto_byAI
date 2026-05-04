# Development Workflow Guide

## Các bước thực hiện dự án

### 1. Chuẩn bị Dataset

#### 1.1 Collect file gốc
- Tải file từ NapierOne, Govdocs1, hoặc Digital Corpora
- Hoặc sử dụng file ví dụ từ hệ thống của bạn
- Lưu vào: `data/raw/original/`

#### 1.2 Chia train/val/test
```bash
python -c "
from src.dataset.split_original_files import split_original_files
train_files, val_files, test_files = split_original_files(
    'data/raw/original',
    train_ratio=0.7,
    val_ratio=0.15,
    test_ratio=0.15
)
print(f'Train: {len(train_files)}, Val: {len(val_files)}, Test: {len(test_files)}')
"
```

### 2. Sinh Dữ Liệu Mã Hoá

#### 2.1 Mã hoá với AES
```python
from src.crypto.encrypt_aes import encrypt_aes_cbc, encrypt_aes_gcm
from src.dataset.generate_encrypted_samples import EncryptedSampleGenerator

gen = EncryptedSampleGenerator('data/generated', 'data/metadata/dataset.csv')

# Mã hoá file với AES-CBC
with open('data/raw/original/file.pdf', 'rb') as f:
    data = f.read()

ciphertext, metadata = encrypt_aes_cbc(data, key_size=256)

sample = gen.add_sample(
    original_file_path='data/raw/original/file.pdf',
    original_file_id='orig_0001',
    original_type='pdf',
    label_group='AES_like',
    algorithm='AES',
    mode='CBC',
    key_size=256,
    tool='pycrypto',
    split='train',
    ciphertext=ciphertext
)
```

#### 2.2 Mã hoá với ChaCha20
```python
from src.crypto.encrypt_chacha20 import encrypt_chacha20

ciphertext, metadata = encrypt_chacha20(data, key_size=256)
```

#### 2.3 Tạo file nén
```python
from src.dataset.generate_compressed_samples import CompressedSampleGenerator

comp_gen = CompressedSampleGenerator('data/generated')
comp_gen.create_zip_compressed('data/raw/original/file.pdf', 'sample_001')
```

### 3. Trích Xuất Đặc Trưng

```bash
python -m src.cli extract-features \
    --input data/generated \
    --output data/features/features.parquet \
    --block-size 4096
```

### 4. Huấn Luyện Model

```bash
python -m src.cli train \
    --features data/features/features.parquet \
    --label-column label_group \
    --model-output models/crypto_predictor.pkl \
    --report-dir reports
```

### 5. Dự Đoán

```bash
python -m src.cli predict \
    --file test_file.enc \
    --model models/crypto_predictor.pkl
```

## Scripts Hữu Ích

### Script sinh dữ liệu đầy đủ

```python
#!/usr/bin/env python
"""
Sinh dữ liệu mã hoá từ file gốc
"""

import os
from pathlib import Path
from tqdm import tqdm
from src.dataset.split_original_files import split_original_files
from src.dataset.generate_encrypted_samples import EncryptedSampleGenerator
from src.dataset.generate_compressed_samples import CompressedSampleGenerator
from src.crypto.encrypt_aes import encrypt_aes_cbc, encrypt_aes_ctr, encrypt_aes_gcm
from src.crypto.encrypt_chacha20 import encrypt_chacha20
from src.crypto.encrypt_salsa20 import encrypt_salsa20
from src.crypto.encrypt_rc4 import encrypt_rc4
from src.crypto.encrypt_3des import encrypt_3des_cbc
from src.crypto.encrypt_hybrid import encrypt_hybrid_aes_rsa

def main():
    input_dir = 'data/raw/original'
    output_dir = 'data/generated'
    metadata_file = 'data/metadata/dataset.csv'
    
    # Chia file
    train_files, val_files, test_files = split_original_files(input_dir)
    
    gen = EncryptedSampleGenerator(output_dir, metadata_file)
    comp_gen = CompressedSampleGenerator(output_dir)
    
    sample_counter = 1
    
    # Process training files
    for split, files in [('train', train_files), ('val', val_files), ('test', test_files)]:
        for file_name in tqdm(files, desc=f"Processing {split}"):
            file_path = os.path.join(input_dir, file_name)
            
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Add unencrypted version
            comp_gen.copy_unencrypted_sample(
                file_path,
                'not_encrypted',
                f'{sample_counter:06d}'
            )
            sample_counter += 1
            
            # AES variants
            for mode in [encrypt_aes_cbc, encrypt_aes_ctr, encrypt_aes_gcm]:
                ct, meta = mode(data)
                gen.add_sample(
                    file_path, f'orig_{sample_counter}', 'pdf',
                    'AES_like', meta['algorithm'], meta['mode'],
                    256, 'pycrypto', split, ct
                )
                sample_counter += 1
            
            # ChaCha20
            ct, meta = encrypt_chacha20(data)
            gen.add_sample(file_path, f'orig_{sample_counter}', 'pdf',
                'ChaCha20_Salsa20_like', 'ChaCha20', '', 256,
                'pycrypto', split, ct)
            sample_counter += 1
    
    gen.save_metadata()
    print(f"Generated {sample_counter} samples")

if __name__ == '__main__':
    main()
```

### Script đánh giá model

```python
#!/usr/bin/env python
"""
Evaluate model on test set
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from src.models.train import ModelTrainer
from src.models.evaluate import ModelEvaluator

def main():
    # Load features
    df = pd.read_parquet('data/features/features.parquet')
    
    # Prepare data
    trainer = ModelTrainer()
    X, y, features = trainer.prepare_data(df, 'label_group')
    
    # Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Train
    trainer.train(X_train, y_train)
    
    # Evaluate
    y_pred, _ = trainer.predict(X_test)
    
    evaluator = ModelEvaluator(trainer.label_encoder)
    metrics = evaluator.evaluate(y_test, y_pred)
    
    # Save reports
    evaluator.save_metrics('reports/metrics.json')
    evaluator.plot_confusion_matrix('reports/confusion_matrix.png')
    evaluator.save_classification_report('reports/classification_report.txt')
    
    # Print results
    print(f"Accuracy: {metrics['accuracy']:.4f}")
    print(f"F1 (macro): {metrics['f1_macro']:.4f}")

if __name__ == '__main__':
    main()
```

## Troubleshooting

### Issue: `ModuleNotFoundError: No module named 'src'`
**Solution**: Chạy command từ root directory của project
```bash
cd d:\crypto_detect_byAI
python -m src.cli predict ...
```

### Issue: `FileNotFoundError: Model not found`
**Solution**: Đảm bảo đã train model
```bash
python -m src.cli train --features data/features/features.parquet
```

### Issue: Memory error khi extract features
**Solution**: Process từng thư mục nhỏ hơn:
```bash
python -c "
from src.features.extract_features import extract_features_batch
import os

# Process per label directory
for label in os.listdir('data/generated'):
    files = []
    for f in os.listdir(f'data/generated/{label}'):
        files.append(os.path.join(f'data/generated/{label}', f))
    
    if files:
        df = extract_features_batch(files)
        # ... process and save
"
```

## Resources

- [pycryptodome Documentation](https://pycryptodome.readthedocs.io/)
- [scikit-learn Documentation](https://scikit-learn.org/)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [Pandas Documentation](https://pandas.pydata.org/)

