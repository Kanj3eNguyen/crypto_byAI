"""
Giao diện dòng lệnh cho chương trình phân tích mã hóa ransomware.
"""

import click
import os
import json
import random
import shutil
from concurrent.futures import ThreadPoolExecutor
import pandas as pd
from pathlib import Path

from src.features.extract_features import extract_features_batch
from src.models.train import ModelTrainer
from src.models.evaluate import ModelEvaluator
from src.models.predict import (
    CRYPTO_GROUP_LABELS,
    LABEL_TO_CRYPTO_GROUP,
    build_combined_prediction_output,
    predict_all,
)


CRYPTO_FAMILY_DEFINITIONS = {
    key: CRYPTO_GROUP_LABELS[key]
    for key in (
        'block_padded_mode_like',
        'stream_or_counter_mode_like',
        'weak_obfuscation_like',
        'aead_mode_like',
        'hybrid_encryption_like',
    )
}
CRYPTO_FAMILY_DEFINITIONS.update({
    'compressed_only': ['compressed_only'],
    'not_encrypted': ['not_encrypted'],
    'unknown_encrypted': ['unknown_encrypted'],
    'ambiguous': ['ambiguous'],
})
CRYPTO_FAMILY_MAP = LABEL_TO_CRYPTO_GROUP
KNOWN_LABELS = (
    set(CRYPTO_FAMILY_MAP)
    | (set(CRYPTO_FAMILY_MAP.values()) - {'weak_obfuscation_like'})
    | {'aead_mode_like', 'ambiguous'}
)


def add_crypto_family_column(df: pd.DataFrame) -> pd.DataFrame:
    """Thêm cột nhóm mã hóa tổng quát từ `label_group`."""
    if 'label_group' in df.columns and 'crypto_family' not in df.columns:
        df['crypto_family'] = df['label_group'].map(CRYPTO_FAMILY_MAP)
    return df


def normalize_path_key(path_value) -> str:
    """Chuẩn hóa đường dẫn để join metadata ổn định giữa các kiểu dấu gạch."""
    return str(path_value).replace('\\', '/').rstrip('/').lower()


def assign_split(index: int, total: int, train_ratio: float, val_ratio: float) -> str:
    """Gán split train/val/test theo vị trí của mẫu."""
    train_cutoff = int(total * train_ratio)
    val_cutoff = train_cutoff + int(total * val_ratio)
    if index < train_cutoff:
        return 'train'
    if index < val_cutoff:
        return 'val'
    return 'test'


@click.group()
def cli():
    """Công cụ dòng lệnh phân tích mã hóa ransomware."""
    pass


@cli.command()
@click.option('--input', '-i', default='data/raw/original', help='Thư mục chứa tệp gốc')
@click.option('--output', '-o', default='data/generated', help='Thư mục lưu mẫu đã sinh')
@click.option('--metadata', '-m', default='data/metadata/dataset.csv', help='Đường dẫn metadata CSV')
@click.option('--limit', type=int, help='Số tệp gốc tối đa cần xử lý')
@click.option(
    '--workers',
    default=1,
    show_default=True,
    type=click.IntRange(min=0),
    help='Số worker khi sinh mẫu. Dùng 0 để tự chọn.',
)
@click.option('--include-hybrid/--skip-hybrid', default=True, help='Có sinh mẫu mã hóa lai hay không')
@click.option(
    '--clean-output/--keep-output',
    default=False,
    help='Xóa mẫu đã sinh trước đó trước khi ghi mẫu mới.',
)
@click.option(
    '--profile',
    type=click.Choice(['group-balanced', 'all-variants']),
    default='group-balanced',
    show_default=True,
    help='Kiểu sinh mẫu. group-balanced phù hợp khi huấn luyện crypto_family.',
)
def generate_samples(input, output, metadata, limit, workers, include_hybrid, clean_output, profile):
    """Tạo mẫu plain, nén và mã hóa có nhãn từ các tệp gốc."""
    import gzip

    from src.crypto.encrypt_3des import encrypt_3des_cbc
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
    from src.crypto.encrypt_chacha20 import encrypt_chacha20
    from src.crypto.encrypt_des import encrypt_des_cbc
    from src.crypto.encrypt_hybrid import (
        encrypt_hybrid_aes_rsa,
        encrypt_hybrid_chacha20_rsa,
        encrypt_hybrid_salsa20_rsa,
        warm_hybrid_rsa_key,
    )
    from src.crypto.encrypt_rc4 import encrypt_rc4
    from src.crypto.encrypt_salsa20 import encrypt_salsa20
    from src.crypto.encrypt_xor import encrypt_repeating_xor
    from src.dataset.generate_encrypted_samples import EncryptedSampleGenerator
    from src.dataset.split_original_files import split_original_files

    input_path = Path(input)
    if not input_path.exists():
        raise click.ClickException(f"Input directory not found: {input}")

    files = sorted([p for p in input_path.iterdir() if p.is_file()])
    if limit:
        files = files[:limit]

    if not files:
        raise click.ClickException(f"No files found in: {input}")

    output_path = Path(output)
    if clean_output and output_path.exists():
        resolved_output = output_path.resolve()
        if len(resolved_output.parts) <= 2 or resolved_output == Path.cwd().resolve():
            raise click.ClickException(f"Refusing to clean unsafe output path: {output}")
        shutil.rmtree(output_path)

    train_files, val_files, test_files = split_original_files(str(input_path))
    split_by_name = {name: 'train' for name in train_files}
    split_by_name.update({name: 'val' for name in val_files})
    split_by_name.update({name: 'test' for name in test_files})

    gen = EncryptedSampleGenerator(output, metadata)
    skipped = 0

    block_specs = [
        ('AES_like', encrypt_aes_cbc),
        ('AES_like', encrypt_aes_ecb),
        ('AES_like', encrypt_aes_ctr),
        ('AES_like', encrypt_aes_cfb),
        ('AES_like', encrypt_aes_ofb),
        ('AES_like', encrypt_aes_gcm),
        ('3DES_like', encrypt_3des_cbc),
        ('Blowfish_like', encrypt_blowfish_cbc),
        ('DES_like', encrypt_des_cbc),
        ('RC2_like', encrypt_rc2_cbc),
        ('CAST5_like', encrypt_cast5_cbc),
    ]
    stream_specs = [
        ('ChaCha20_Salsa20_like', encrypt_chacha20),
        ('ChaCha20_Salsa20_like', encrypt_salsa20),
        ('RC4_like', encrypt_rc4),
    ]
    weak_specs = [('XOR_like', encrypt_repeating_xor)]
    hybrid_specs = [
        ('hybrid_AES_RSA_like', encrypt_hybrid_aes_rsa),
        ('hybrid_ChaCha20_RSA_like', encrypt_hybrid_chacha20_rsa),
        ('hybrid_Salsa20_RSA_like', encrypt_hybrid_salsa20_rsa),
    ]

    if workers == 0:
        workers = max((os.cpu_count() or 2) - 1, 1)
    if include_hybrid:
        warm_hybrid_rsa_key()

    def build_records(item):
        file_index, file_path = item
        try:
            data = file_path.read_bytes()
            original_type = file_path.suffix.lstrip('.').lower() or 'unknown'
            original_id = file_path.stem
            split = split_by_name.get(file_path.name, 'train')
            records = [
                {
                    'original_file_path': str(file_path),
                    'original_file_id': original_id,
                    'original_type': original_type,
                    'label_group': 'not_encrypted',
                    'algorithm': 'none',
                    'mode': '',
                    'key_size': 0,
                    'split': split,
                    'ciphertext': data,
                },
                {
                    'original_file_path': str(file_path),
                    'original_file_id': original_id,
                    'original_type': original_type,
                    'label_group': 'compressed_only',
                    'algorithm': 'gzip',
                    'mode': '',
                    'key_size': 0,
                    'split': split,
                    'ciphertext': gzip.compress(data, compresslevel=1),
                },
            ]

            if profile == 'all-variants':
                selected_specs = block_specs + stream_specs + weak_specs
                if include_hybrid:
                    selected_specs += hybrid_specs
            else:
                selected_specs = [
                    block_specs[file_index % len(block_specs)],
                    stream_specs[file_index % len(stream_specs)],
                    weak_specs[file_index % len(weak_specs)],
                ]
                if include_hybrid:
                    selected_specs.append(hybrid_specs[file_index % len(hybrid_specs)])

            for label_group, encryptor in selected_specs:
                ciphertext, meta = encryptor(data)
                records.append({
                    'original_file_path': str(file_path),
                    'original_file_id': original_id,
                    'original_type': original_type,
                    'label_group': label_group,
                    'algorithm': meta['algorithm'],
                    'mode': meta.get('mode', ''),
                    'key_size': meta['key_size'],
                    'split': split,
                    'ciphertext': ciphertext,
                })

            return records, None
        except Exception as exc:
            return [], f"Skipped {file_path}: {exc}"

    def add_record(record):
        label_group = record['label_group']
        gen.add_sample(
            original_file_path=record['original_file_path'],
            original_file_id=record['original_file_id'],
            original_type=record['original_type'],
            label_group=label_group,
            algorithm=record['algorithm'],
            mode=record['mode'],
            key_size=record['key_size'],
            tool='pycryptodome',
            split=record['split'],
            ciphertext=record['ciphertext'],
            crypto_family=CRYPTO_FAMILY_MAP.get(label_group, label_group),
        )

    click.echo(f"Generating samples from {len(files)} original files")
    click.echo(f"Generation profile: {profile}")
    click.echo(f"Workers: {workers}")
    indexed_files = list(enumerate(files))
    if workers <= 1 or len(indexed_files) <= 1:
        record_batches = map(build_records, indexed_files)
    else:
        executor = ThreadPoolExecutor(max_workers=workers)
        record_batches = executor.map(build_records, indexed_files)

    try:
        with click.progressbar(record_batches, length=len(indexed_files), label='Generating') as bar:
            for records, error in bar:
                if error:
                    skipped += 1
                    click.echo(error, err=True)
                    continue
                for record in records:
                    add_record(record)
    finally:
        if workers > 1 and len(indexed_files) > 1:
            executor.shutdown(wait=True)

    gen.save_metadata()
    click.echo(f"Generated {gen.get_samples_count()} samples")
    click.echo(f"Metadata saved to: {metadata}")
    if skipped:
        click.echo(f"Skipped {skipped} files")


@cli.command()
@click.option('--input', '-i', default='data/ransomware_family', help='Thư mục có các thư mục con theo họ ransomware')
@click.option('--output', '-o', default='data/metadata/ransomware_family_dataset.csv', help='Đường dẫn metadata CSV')
@click.option('--limit-per-family', type=int, help='Số tệp tối đa dùng trong mỗi họ')
@click.option('--train-ratio', default=0.7, show_default=True, help='Tỷ lệ train cho mỗi họ')
@click.option('--val-ratio', default=0.15, show_default=True, help='Tỷ lệ validation cho mỗi họ')
@click.option('--test-ratio', default=0.15, show_default=True, help='Tỷ lệ test cho mỗi họ')
@click.option('--random-state', default=42, show_default=True, help='Seed khi xáo trộn tệp trong từng họ')
def build_ransomware_metadata(
    input,
    output,
    limit_per_family,
    train_ratio,
    val_ratio,
    test_ratio,
    random_state,
):
    """Tạo metadata cho tập dữ liệu ransomware được chia theo họ."""
    input_path = Path(input)
    if not input_path.exists():
        raise click.ClickException(f"Input directory not found: {input}")

    ratio_sum = train_ratio + val_ratio + test_ratio
    if abs(ratio_sum - 1.0) > 0.001:
        raise click.ClickException(f"Split ratios must sum to 1.0, got {ratio_sum}")

    rows = []
    rng = random.Random(random_state)

    family_dirs = sorted(
        path for path in input_path.iterdir()
        if path.is_dir() and not path.name.startswith('.')
    )
    if not family_dirs:
        raise click.ClickException(f"No family directories found in: {input}")

    for family_dir in family_dirs:
        files = sorted(
            path for path in family_dir.rglob('*')
            if path.is_file()
            and not path.name.startswith('.')
            and not any(part.startswith('.') for part in path.relative_to(family_dir).parts)
        )
        rng.shuffle(files)
        if limit_per_family:
            files = files[:limit_per_family]

        for index, file_path in enumerate(files):
            rows.append({
                'path': str(file_path),
                'ransomware_family': family_dir.name.upper(),
                'label_group': 'unknown_encrypted',
                'crypto_family': 'unknown_encrypted',
                'split': assign_split(index, len(files), train_ratio, val_ratio),
                'file_size': file_path.stat().st_size,
            })

    if not rows:
        raise click.ClickException(f"No files found under family directories in: {input}")

    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df = pd.DataFrame(rows)
    df.to_csv(output_path, index=False)

    click.echo(f"Metadata saved to: {output}")
    click.echo(f"Families: {df['ransomware_family'].nunique()}")
    click.echo(f"Files: {len(df)}")
    click.echo("Split counts:")
    click.echo(df['split'].value_counts().to_string())


@cli.command()
@click.option('--input', '-i', required=True, help='Tệp hoặc thư mục đầu vào')
@click.option('--output', '-o', default='data/features/features.parquet', help='File parquet đầu ra')
@click.option('--metadata', '-m', help='File metadata CSV có nhãn')
@click.option('--block-size', default=4096, type=click.IntRange(min=1), help='Kích thước block khi tính entropy')
@click.option(
    '--workers',
    default=1,
    show_default=True,
    type=click.IntRange(min=0),
    help='Số worker xử lý song song. Dùng 0 để tự chọn theo CPU.',
)
def extract_features(input, output, metadata, block_size, workers):
    """Trích xuất đặc trưng từ tệp hoặc thư mục."""
    click.echo(f"Extracting features from: {input}")

    # Lấy danh sách tệp cần xử lý.
    if os.path.isfile(input):
        files = [input]
    else:
        files = []
        for root, dirs, filenames in os.walk(input):
            dirs[:] = [dirname for dirname in dirs if not dirname.startswith('.')]
            for filename in filenames:
                if filename.startswith('.'):
                    continue
                files.append(os.path.join(root, filename))

    click.echo(f"Found {len(files)} files")

    # Trích xuất đặc trưng.
    df = extract_features_batch(files, block_size=block_size, workers=workers, verbose=True)

    # Gắn nhãn từ metadata nếu có truyền vào.
    if metadata and os.path.exists(metadata):
        meta_df = pd.read_csv(metadata)
        # Join theo cột `path` sau khi chuẩn hóa đường dẫn.
        if 'path' in meta_df.columns and 'path' in df.columns:
            metadata_columns = [
                column
                for column in [
                    'path',
                    'label_group',
                    'crypto_family',
                    'ransomware_family',
                    'split',
                ]
                if column in meta_df.columns
            ]
            df['__path_key'] = df['path'].map(normalize_path_key)
            metadata_view = meta_df[metadata_columns].copy()
            metadata_view['__path_key'] = metadata_view['path'].map(normalize_path_key)
            metadata_view = metadata_view.drop(columns=['path'])
            df = df.merge(metadata_view, on='__path_key', how='left')
            df = df.drop(columns=['__path_key'])
    elif 'path' in df.columns:
        df['label_group'] = df['path'].apply(
            lambda file_path: Path(file_path).parent.name
            if Path(file_path).parent.name in KNOWN_LABELS
            else None
        )

    df = add_crypto_family_column(df)
    
    # Lưu kết quả ra file parquet.
    os.makedirs(os.path.dirname(output) or '.', exist_ok=True)
    df.to_parquet(output, index=False)
    click.echo(f"Features saved to: {output}")


@cli.command()
@click.option('--features', '-f', required=True, help='File parquet chứa đặc trưng')
@click.option('--label-column', default='label_group', help='Tên cột nhãn')
@click.option('--model-output', '-o', default='models/crypto_predictor.pkl', help='Đường dẫn lưu mô hình')
@click.option('--report-dir', default='reports', help='Thư mục lưu báo cáo')
@click.option('--metadata', '-m', default='data/metadata/dataset.csv', help='File metadata CSV có nhãn và split')
def train(features, label_column, model_output, report_dir, metadata):
    """Huấn luyện mô hình dự đoán mã hóa."""
    click.echo(f"Loading features from: {features}")
    
    # Đọc file đặc trưng.
    df = pd.read_parquet(features)
    df = add_crypto_family_column(df)
    click.echo(f"Loaded {len(df)} samples with {len(df.columns)} features")

    if metadata and os.path.exists(metadata) and 'path' in df.columns:
        meta_df = pd.read_csv(metadata)
        if 'path' in meta_df.columns:
            merge_columns = ['path']
            if label_column in meta_df.columns:
                merge_columns.append(label_column)
            for optional_column in ['label_group', 'crypto_family', 'ransomware_family']:
                if (
                    optional_column in meta_df.columns
                    and optional_column not in merge_columns
                    and optional_column not in df.columns
                ):
                    merge_columns.append(optional_column)
            if (
                label_column == 'crypto_family'
                and 'label_group' in meta_df.columns
                and 'label_group' not in df.columns
            ):
                merge_columns.append('label_group')
            if 'split' in meta_df.columns:
                merge_columns.append('split')

            metadata_view = meta_df[merge_columns].copy()
            rename_map = {}
            if label_column in df.columns and label_column in metadata_view.columns:
                rename_map[label_column] = f'__metadata_{label_column}'
            if 'split' in df.columns and 'split' in metadata_view.columns:
                rename_map['split'] = '__metadata_split'
            metadata_view = metadata_view.rename(columns=rename_map)

            df['__path_key'] = df['path'].map(normalize_path_key)
            metadata_view['__path_key'] = metadata_view['path'].map(normalize_path_key)
            metadata_view = metadata_view.drop(columns=['path'])
            df = df.merge(metadata_view, on='__path_key', how='left')
            df = df.drop(columns=['__path_key'])

            metadata_label = f'__metadata_{label_column}'
            if metadata_label in df.columns:
                df[label_column] = df[label_column].fillna(df[metadata_label])
                df = df.drop(columns=[metadata_label])
            if '__metadata_split' in df.columns:
                df['split'] = df['split'].fillna(df['__metadata_split'])
                df = df.drop(columns=['__metadata_split'])

    df = add_crypto_family_column(df)
    
    # Kiểm tra cột nhãn cần huấn luyện.
    if label_column not in df.columns:
        click.echo(f"ERROR: Label column '{label_column}' not found in dataframe")
        click.echo(f"Available columns: {', '.join(df.columns[:10])}")
        return
    
    # Huấn luyện mô hình.
    trainer = ModelTrainer(model_type='random_forest')
    X, y, _ = trainer.prepare_data(df, label_column)
    split = df.loc[X.index, 'split'] if 'split' in df.columns else None
    
    click.echo(f"Prepared {len(X)} samples with {X.shape[1]} features")
    
    train_info = trainer.train(X, y, split=split)
    if label_column == 'crypto_family':
        train_info['class_definitions'] = {
            class_name: CRYPTO_FAMILY_DEFINITIONS.get(class_name, [class_name])
            for class_name in train_info['classes']
        }
    click.echo(
        "Trained model: "
        f"split={train_info['evaluation_split']}, "
        f"accuracy={train_info['accuracy']:.4f}, "
        f"f1_macro={train_info['f1_macro']:.4f}, "
        f"f1_weighted={train_info['f1_weighted']:.4f}"
    )
    
    # Lưu mô hình.
    trainer.save_model(model_output)
    click.echo(f"Model saved to: {model_output}")
    
    os.makedirs(report_dir, exist_ok=True)

    evaluator = ModelEvaluator(trainer.label_encoder)
    evaluator.metrics = train_info
    evaluator.save_metrics(os.path.join(report_dir, 'metrics.json'))
    evaluator.save_classification_report(os.path.join(report_dir, 'classification_report.txt'))
    evaluator.plot_confusion_matrix(
        os.path.join(report_dir, 'confusion_matrix.png'),
        class_names=trainer.label_encoder.classes_.tolist(),
    )
    click.echo(f"Evaluation reports saved to: {report_dir}")

    # Lưu độ quan trọng của đặc trưng.
    if hasattr(trainer.model, 'feature_importances_'):
        importance = trainer.get_feature_importance()
        
        # Lưu 30 đặc trưng quan trọng nhất.
        with open(os.path.join(report_dir, 'top_features.json'), 'w', encoding='utf-8') as f:
            top_features = {k: v for k, v in list(importance.items())[:30]}
            json.dump(top_features, f, indent=2)
        
        click.echo(f"Feature importance saved to: {report_dir}/top_features.json")


@cli.command()
@click.option('--file', '-f', required=True, help='Tệp cần dự đoán')
@click.option('--model', '-m', default='models/crypto_family_predictor.pkl', help='Đường dẫn mô hình nhóm mã hóa')
@click.option('--ransomware-model', '-r', default='models/ransomware_family_predictor.pkl', help='Đường dẫn mô hình họ ransomware, có thể bỏ trống')
@click.option('--features', help='Lưu đặc trưng đã trích xuất nếu cần')
def predict(file, model, ransomware_model, features):
    """Dự đoán nhóm mã hóa và có thể kèm họ ransomware cho một tệp."""

    # Kiểm tra mô hình nhóm mã hóa.
    if not os.path.exists(model):
        click.echo(f"ERROR: Crypto model not found at {model}")
        return

    # Nếu thiếu mô hình họ ransomware thì vẫn tiếp tục dự đoán nhóm mã hóa.
    if ransomware_model and not os.path.exists(ransomware_model):
        click.echo(f"WARNING: Ransomware model not found at {ransomware_model}; skipping ransomware prediction")
        ransomware_model = None

    click.echo(f"Analyzing file: {file}")

    combined = predict_all(
        file_path=file,
        crypto_model_path=model,
        ransomware_model_path=ransomware_model,
        top_k=3,
    )

    click.echo(json.dumps(
        build_predict_output(
            file_path=file,
            crypto_model_path=model,
            ransomware_model_path=ransomware_model,
            combined=combined,
        ),
        indent=2,
        ensure_ascii=False,
    ))

    # Lưu đặc trưng nếu người dùng yêu cầu.
    features_path = features
    if features_path and combined.get('features') is not None:
        with open(features_path, 'w', encoding='utf-8') as f:
            json.dump(combined['features'], f, indent=2, ensure_ascii=False)
        click.echo(f"Features saved to: {features_path}")


def build_predict_output(file_path, crypto_model_path, ransomware_model_path, combined):
    """Tạo output gộp cho lệnh predict."""
    return build_combined_prediction_output(
        file_path=file_path,
        crypto_model_path=crypto_model_path,
        ransomware_model_path=ransomware_model_path,
        combined=combined,
    )


@cli.command()
@click.option('--help', is_flag=True, help='Hiển thị ví dụ sử dụng')
def examples(help):
    """Hiển thị một số lệnh ví dụ."""
    examples_text = """
VI DU SU DUNG
=============

1. Trich xuat dac trung:
   python -m src.cli extract-features --input data/generated --output data/features/features.parquet

2. Huan luyen mo hinh:
   python -m src.cli train --features data/features/features.parquet --model-output models/crypto_predictor.pkl

3. Du doan mot tep:
   python -m src.cli predict --file suspicious.enc --model models/crypto_predictor.pkl

4. Chay API server:
   uvicorn src.api.app:app --reload --port 8000

5. Kiem tra API:
   curl http://localhost:8000/health
   curl -X POST -F "file=@suspicious.enc" http://localhost:8000/predict
"""
    click.echo(examples_text)


if __name__ == '__main__':
    cli()
