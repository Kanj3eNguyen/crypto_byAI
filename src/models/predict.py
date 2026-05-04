"""
Model prediction utilities
"""

import json
import os
from typing import Dict, List, Any
import numpy as np


class Predictor:
    """Make predictions on new data with evidence generation"""
    
    def __init__(self, model_trainer, feature_columns: list = None):
        """
        Initialize predictor
        
        Args:
            model_trainer: Trained ModelTrainer instance
            feature_columns: List of feature column names
        """
        self.model_trainer = model_trainer
        self.feature_columns = feature_columns or model_trainer.feature_columns
    
    def predict_with_confidence(
        self,
        X: np.ndarray,
        top_k: int = 3
    ) -> Dict[str, Any]:
        """
        Make predictions with confidence scores
        
        Args:
            X: Feature array
            top_k: Number of top predictions to return
        
        Returns:
            Dictionary with predictions and confidence
        """
        predictions, probabilities = self.model_trainer.predict(X)
        
        # Get class names
        class_names = self.model_trainer.label_encoder.classes_
        
        # Get top predictions
        top_indices = np.argsort(probabilities[0])[-top_k:][::-1]
        
        top_predictions = []
        for idx in top_indices:
            top_predictions.append({
                'label': class_names[idx],
                'confidence': float(probabilities[0][idx])
            })
        
        return {
            'predicted_class': class_names[predictions[0]],
            'confidence': float(probabilities[0][predictions[0]]),
            'all_probabilities': {class_names[i]: float(probabilities[0][i]) 
                                 for i in range(len(class_names))},
            'top_predictions': top_predictions
        }
    
    def generate_evidence(
        self,
        features: Dict[str, Any],
        prediction: str,
        confidence: float
    ) -> List[str]:
        """
        Generate human-readable evidence for prediction
        
        Args:
            features: Dictionary of extracted features
            prediction: Predicted class
            confidence: Prediction confidence
        
        Returns:
            List of evidence strings
        """
        evidence = []
        
        # Entropy-based evidence
        entropy_mean = features.get('entropy_mean', 0)
        if entropy_mean > 7.5:
            evidence.append("entropy trung bình cao (> 7.5)")
        elif entropy_mean > 7.0:
            evidence.append("entropy trung bình cao (> 7.0)")
        
        # High entropy blocks
        high_entropy_ratio = features.get('high_entropy_block_ratio_75', 0)
        if high_entropy_ratio > 0.8:
            evidence.append(f"{high_entropy_ratio*100:.1f}% block có entropy > 7.5")
        
        # File size alignment
        file_size_mod_16 = features.get('file_size_mod_16', 0)
        file_size_mod_8 = features.get('file_size_mod_8', 0)
        
        if prediction in ['AES_like'] and file_size_mod_16 == 0:
            evidence.append("kích thước file là bội số của 16 (block AES)")
        elif prediction in ['3DES_like'] and file_size_mod_8 == 0:
            evidence.append("kích thước file là bội số của 8 (block 3DES)")
        
        # Byte distribution
        printable_ratio = features.get('printable_byte_ratio', 0)
        if printable_ratio < 0.05:
            evidence.append("phần lớn byte không phải ký tự in được")
        
        # Null bytes
        null_ratio = features.get('null_byte_ratio', 0)
        if null_ratio > 0.05:
            evidence.append(f"{null_ratio*100:.2f}% byte null (0x00)")
        
        # Unique bytes
        unique_bytes = features.get('unique_byte_count', 0)
        if unique_bytes > 250:
            evidence.append(f"sử dụng {unique_bytes} giá trị byte khác nhau (gần ngẫu nhiên)")
        
        if not evidence:
            evidence.append("dữ liệu phù hợp với phân bố entropy của nhóm dự đoán")
        
        return evidence


def format_prediction_json(
    file_path: str,
    file_size: int,
    is_encrypted: bool,
    predicted_class: str,
    confidence: float,
    top_predictions: List[Dict],
    features_summary: Dict[str, Any],
    evidence: List[str]
) -> Dict[str, Any]:
    """
    Format prediction output as JSON
    
    Args:
        file_path: Path to analyzed file
        file_size: Size of file in bytes
        is_encrypted: Whether file appears encrypted
        predicted_class: Predicted encryption class
        confidence: Prediction confidence
        top_predictions: List of top predictions
        features_summary: Summary of extracted features
        evidence: List of evidence strings
    
    Returns:
        JSON-serializable dictionary
    """
    return {
        'file': {
            'path': file_path,
            'size_bytes': file_size
        },
        'classification': {
            'is_encrypted': is_encrypted,
            'predicted_crypto_group': predicted_class,
            'confidence': confidence,
            'top_predictions': top_predictions
        },
        'features_summary': features_summary,
        'evidence': evidence,
        'warning': 'Kết quả là dự đoán xác suất, không khẳng định tuyệt đối thuật toán mã hoá.'
    }
