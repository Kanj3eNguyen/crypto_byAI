"""
Command-line interface for ransomware crypto prediction
"""

import click
import os
import json
import random
import shutil
from concurrent.futures import ThreadPoolExecutor
import pandas as pd
from pathlib import Path

from src.config import Config
from src.features.extract_features import extract_features_from_file, extract_features_batch
from src.models.train import ModelTrainer
from src.models.evaluate import ModelEvaluator
from src.models.predict import (
    Predictor,
    certainty_from_prediction,
    format_prediction_json,
    infer_prediction_basis,
    is_encrypted_label,
)


CRYPTO_FAMILY_MAP = {
    'AES_like': 'block_cipher_like',
    '3DES_like': 'block_cipher_like',
    'Blowfish_like': 'block_cipher_like',
    'DES_like': 'block_cipher_like',
    'RC2_like': 'block_cipher_like',
    'CAST5_like': 'block_cipher_like',
    'ChaCha20_Salsa20_like': 'stream_cipher_like',
    'RC4_like': 'stream_cipher_like',
    'XOR_like': 'weak_obfuscation_like',
    'hybrid_AES_RSA_like': 'hybrid_cipher_like',
    'hybrid_ChaCha20_RSA_like': 'hybrid_cipher_like',
    'hybrid_Salsa20_RSA_like': 'hybrid_cipher_like',
    'compressed_only': 'compressed_only',
    'not_encrypted': 'not_encrypted',
    'unknown_encrypted': 'unknown_encrypted',
}


CRYPTO_FAMILY_DEFINITIONS = {
    'block_cipher_like': [
        'AES_like',
        '3DES_like',
        'Blowfish_like',
        'DES_like',
        'RC2_like',
        'CAST5_like',
    ],
    'stream_cipher_like': ['ChaCha20_Salsa20_like', 'RC4_like'],
    'weak_obfuscation_like': ['XOR_like'],
    'hybrid_cipher_like': [
        'hybrid_AES_RSA_like',
        'hybrid_ChaCha20_RSA_like',
        'hybrid_Salsa20_RSA_like',
    ],
    'compressed_only': ['compressed_only'],
    'not_encrypted': ['not_encrypted'],
    'unknown_encrypted': ['unknown_encrypted'],
}


def add_crypto_family_column(df: pd.DataFrame) -> pd.DataFrame:
    """Add broad crypto family labels derived from label_group."""
    if 'label_group' in df.columns and 'crypto_family' not in df.columns:
        df['crypto_family'] = df['label_group'].map(CRYPTO_FAMILY_MAP)
    return df


def normalize_path_key(path_value) -> str:
    """Normalize path strings for stable metadata joins across slash styles."""
    return str(path_value).replace('\\', '/').rstrip('/').lower()


def assign_split(index: int, total: int, train_ratio: float, val_ratio: float) -> str:
    """Assign deterministic train/val/test split by item position."""
    train_cutoff = int(total * train_ratio)
    val_cutoff = train_cutoff + int(total * val_ratio)
    if index < train_cutoff:
        return 'train'
    if index < val_cutoff:
        return 'val'
    return 'test'


@click.group()
def cli():
    """Ransomware Crypto AI - Command Line Interface"""
    pass


@cli.command()
@click.option('--input', '-i', default='data/raw/original', help='Directory with original files')
@click.option('--output', '-o', default='data/generated', help='Generated sample output directory')
@click.option('--metadata', '-m', default='data/metadata/dataset.csv', help='Metadata CSV output path')
@click.option('--limit', type=int, help='Maximum number of original files to process')
@click.option(
    '--workers',
    default=1,
    show_default=True,
    type=click.IntRange(min=0),
    help='Parallel file-generation workers. Use 0 to auto-select.',
)
@click.option('--include-hybrid/--skip-hybrid', default=True, help='Include hybrid AES+RSA samples')
@click.option(
    '--clean-output/--keep-output',
    default=False,
    help='Remove existing generated samples before writing new ones.',
)
@click.option(
    '--profile',
    type=click.Choice(['group-balanced', 'all-variants']),
    default='group-balanced',
    show_default=True,
    help='Generation profile. Use group-balanced for crypto_family training.',
)
def generate_samples(input, output, metadata, limit, workers, include_hybrid, clean_output, profile):
    """Generate labeled encrypted/compressed/plain samples from original files."""
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
@click.option('--input', '-i', default='data/ransomware_family', help='Directory with one subdirectory per ransomware family')
@click.option('--output', '-o', default='data/metadata/ransomware_family_dataset.csv', help='Metadata CSV output path')
@click.option('--limit-per-family', type=int, help='Maximum files to use from each family directory')
@click.option('--train-ratio', default=0.7, show_default=True, help='Train split ratio per family')
@click.option('--val-ratio', default=0.15, show_default=True, help='Validation split ratio per family')
@click.option('--test-ratio', default=0.15, show_default=True, help='Test split ratio per family')
@click.option('--random-state', default=42, show_default=True, help='Random seed for per-family shuffling')
def build_ransomware_metadata(
    input,
    output,
    limit_per_family,
    train_ratio,
    val_ratio,
    test_ratio,
    random_state,
):
    """Build metadata for real ransomware-family encrypted datasets."""
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
@click.option('--input', '-i', required=True, help='Input file or directory')
@click.option('--output', '-o', default='data/features/features.parquet', help='Output parquet file')
@click.option('--metadata', '-m', help='Metadata CSV file with labels')
@click.option('--block-size', default=4096, type=click.IntRange(min=1), help='Block size for entropy calculation')
@click.option(
    '--workers',
    default=1,
    show_default=True,
    type=click.IntRange(min=0),
    help='Parallel worker processes. Use 0 to auto-select CPU count.',
)
def extract_features(input, output, metadata, block_size, workers):
    """Extract features from files"""
    click.echo(f"Extracting features from: {input}")
    
    # Get list of files
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
    
    # Extract features
    df = extract_features_batch(files, block_size=block_size, workers=workers, verbose=True)
    
    # Add labels from metadata if provided
    if metadata and os.path.exists(metadata):
        meta_df = pd.read_csv(metadata)
        # Try to join on 'path' column
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
        known_labels = {
            'not_encrypted',
            'compressed_only',
            'AES_like',
            'ChaCha20_Salsa20_like',
            'RC4_like',
            '3DES_like',
            'Blowfish_like',
            'DES_like',
            'RC2_like',
            'CAST5_like',
            'XOR_like',
            'hybrid_AES_RSA_like',
            'hybrid_ChaCha20_RSA_like',
            'hybrid_Salsa20_RSA_like',
            'unknown_encrypted',
        }
        df['label_group'] = df['path'].apply(
            lambda file_path: Path(file_path).parent.name
            if Path(file_path).parent.name in known_labels
            else None
        )

    df = add_crypto_family_column(df)
    
    # Save output
    os.makedirs(os.path.dirname(output) or '.', exist_ok=True)
    df.to_parquet(output, index=False)
    click.echo(f"Features saved to: {output}")


@cli.command()
@click.option('--features', '-f', required=True, help='Features parquet file')
@click.option('--label-column', default='label_group', help='Label column name')
@click.option('--model-output', '-o', default='models/crypto_predictor.pkl', help='Model output path')
@click.option('--report-dir', default='reports', help='Report output directory')
@click.option('--metadata', '-m', default='data/metadata/dataset.csv', help='Metadata CSV file with labels/splits')
def train(features, label_column, model_output, report_dir, metadata):
    """Train encryption prediction model"""
    click.echo(f"Loading features from: {features}")
    
    # Load features
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
    
    # Check if label column exists
    if label_column not in df.columns:
        click.echo(f"ERROR: Label column '{label_column}' not found in dataframe")
        click.echo(f"Available columns: {', '.join(df.columns[:10])}")
        return
    
    # Train model
    trainer = ModelTrainer(model_type='random_forest')
    X, y, feature_cols = trainer.prepare_data(df, label_column)
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
    
    # Save model
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

    # Save feature importance
    if hasattr(trainer.model, 'feature_importances_'):
        importance = trainer.get_feature_importance()
        
        # Save top 30 features
        with open(os.path.join(report_dir, 'top_features.json'), 'w', encoding='utf-8') as f:
            top_features = {k: v for k, v in list(importance.items())[:30]}
            json.dump(top_features, f, indent=2)
        
        click.echo(f"Feature importance saved to: {report_dir}/top_features.json")


@cli.command()
@click.option('--file', '-f', required=True, help='File to predict')
@click.option('--model', '-m', default='models/crypto_predictor.pkl', help='Model path')
@click.option('--features', help='Optionally save extracted features')
def predict(file, model, features):
    """Predict encryption algorithm for a file"""
    
    # Check if model exists
    if not os.path.exists(model):
        click.echo(f"ERROR: Model not found at {model}")
        return
    
    # Load model
    trainer = ModelTrainer()
    trainer.load_model(model)
    predictor = Predictor(trainer)
    
    # Extract features
    click.echo(f"Analyzing file: {file}")
    file_features = extract_features_from_file(file)
    
    # Prepare feature array
    feature_array = pd.DataFrame([
        {name: file_features.get(name, 0) for name in trainer.feature_columns}
    ])
    
    # Predict
    result = predictor.predict_with_confidence(feature_array, top_k=3)
    
    # Generate evidence
    predicted_class = result['predicted_class']
    confidence = result['confidence']
    is_encrypted = is_encrypted_label(predicted_class)
    basis = infer_prediction_basis(file_features)
    
    evidence = predictor.generate_evidence(file_features, predicted_class, confidence)
    
    # Format output
    file_size = os.path.getsize(file)
    output = format_prediction_json(
        file_path=file,
        file_size=file_size,
        is_encrypted=is_encrypted,
        predicted_class=predicted_class,
        confidence=confidence,
        top_predictions=result['top_predictions'],
        features_summary={
            'shannon_entropy_full': file_features.get('shannon_entropy_full', 0),
            'entropy_mean': file_features.get('entropy_mean', 0),
            'high_entropy_block_ratio': file_features.get('high_entropy_block_ratio', 0),
            'unique_byte_count': file_features.get('unique_byte_count', 0),
            'printable_byte_ratio': file_features.get('printable_byte_ratio', 0),
            'footer_metadata_score': file_features.get('footer_metadata_score', 0),
            'footer_nonce12_tag16_like': file_features.get('footer_nonce12_tag16_like', 0),
            'footer_nonce24_tag16_like': file_features.get('footer_nonce24_tag16_like', 0),
            'footer_rsa2048_wrapped_key_like': file_features.get(
                'footer_rsa2048_wrapped_key_like',
                0,
            ),
        },
        evidence=evidence,
        top_groups=result.get('top_groups'),
        basis=basis,
        certainty=certainty_from_prediction(is_encrypted, confidence, basis),
    )
    
    # Print output
    click.echo(json.dumps(output, indent=2, ensure_ascii=False))
    
    # Optionally save features
    if features:
        with open(features, 'w') as f:
            json.dump(file_features, f, indent=2, ensure_ascii=False)
        click.echo(f"Features saved to: {features}")


@cli.command()
@click.option('--help', is_flag=True, help='Show example usage')
def examples(help):
    """Show example commands"""
    examples_text = """
RANSOMWARE CRYPTO AI - USAGE EXAMPLES
====================================

1. Extract features from files:
   python -m src.cli extract-features --input data/generated --output data/features/features.parquet

2. Train model:
   python -m src.cli train --features data/features/features.parquet --model-output models/crypto_predictor.pkl

3. Predict encryption for a file:
   python -m src.cli predict --file suspicious.enc --model models/crypto_predictor.pkl

4. Run API server:
   uvicorn src.api.app:app --reload --port 8000

5. Check API endpoints:
   curl http://localhost:8000/health
   curl -X POST -F "file=@suspicious.enc" http://localhost:8000/predict
"""
    click.echo(examples_text)


if __name__ == '__main__':
    cli()
