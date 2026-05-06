"""
Các hàm hỗ trợ đánh giá mô hình.
"""

import json
import os
from typing import Dict, Any
import numpy as np
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)


class ModelEvaluator:
    """Đánh giá chất lượng mô hình."""
    
    def __init__(self, label_encoder=None):
        """Khởi tạo bộ đánh giá."""
        self.label_encoder = label_encoder
        self.metrics = {}
    
    def evaluate(
        self,
        y_true: np.ndarray,
        y_pred: np.ndarray,
        class_names: list = None
    ) -> Dict[str, Any]:
        """
        Tính các chỉ số đánh giá.

        Args:
            y_true: Nhãn đúng.
            y_pred: Nhãn mô hình dự đoán.
            class_names: Tên các lớp.

        Returns:
            Dictionary chứa các chỉ số đánh giá.
        """
        self.metrics = {
            'accuracy': float(accuracy_score(y_true, y_pred)),
            'precision_macro': float(precision_score(y_true, y_pred, average='macro', zero_division=0)),
            'recall_macro': float(recall_score(y_true, y_pred, average='macro', zero_division=0)),
            'f1_macro': float(f1_score(y_true, y_pred, average='macro', zero_division=0)),
            'f1_weighted': float(f1_score(y_true, y_pred, average='weighted', zero_division=0)),
        }
        
        # Lấy tên lớp từ encoder nếu chưa truyền vào.
        if class_names is None and self.label_encoder:
            class_names = self.label_encoder.classes_.tolist()
        
        # Ma trận nhầm lẫn.
        cm = confusion_matrix(y_true, y_pred)
        self.metrics['confusion_matrix'] = cm.tolist()
        
        # Báo cáo phân loại.
        class_report = classification_report(
            y_true, y_pred, 
            target_names=class_names,
            output_dict=True,
            zero_division=0
        )
        self.metrics['classification_report'] = class_report
        
        return self.metrics
    
    def save_metrics(self, output_path: str) -> None:
        """Lưu chỉ số đánh giá ra file JSON."""
        os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
        
        # Chuyển kiểu numpy sang kiểu Python để ghi JSON.
        def convert_types(obj):
            if isinstance(obj, (np.integer, np.floating)):
                return obj.item()
            elif isinstance(obj, np.ndarray):
                return obj.tolist()
            elif isinstance(obj, dict):
                return {k: convert_types(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_types(v) for v in obj]
            return obj
        
        metrics_to_save = convert_types(self.metrics)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(metrics_to_save, f, indent=2, ensure_ascii=False)
    
    def plot_confusion_matrix(self, output_path: str, class_names: list = None) -> None:
        """Vẽ và lưu ma trận nhầm lẫn."""
        if 'confusion_matrix' not in self.metrics:
            raise ValueError("No confusion matrix in metrics")
        
        cm = np.array(self.metrics['confusion_matrix'])
        
        if class_names is None and self.label_encoder:
            class_names = self.label_encoder.classes_.tolist()
        
        plt.figure(figsize=(12, 10))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                   xticklabels=class_names, yticklabels=class_names)
        plt.title('Confusion Matrix')
        plt.ylabel('True Label')
        plt.xlabel('Predicted Label')
        plt.tight_layout()
        
        os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
        plt.savefig(output_path, dpi=150)
        plt.close()
    
    def save_classification_report(self, output_path: str) -> None:
        """Lưu báo cáo phân loại dạng text."""
        if 'classification_report' not in self.metrics:
            raise ValueError("No classification report in metrics")
        
        report = self.metrics['classification_report']
        
        os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            # Ghi các chỉ số tổng quát.
            f.write("MODEL EVALUATION REPORT\n")
            f.write("=" * 50 + "\n\n")
            
            f.write(f"Accuracy: {self.metrics['accuracy']:.4f}\n")
            f.write(f"Precision (Macro): {self.metrics['precision_macro']:.4f}\n")
            f.write(f"Recall (Macro): {self.metrics['recall_macro']:.4f}\n")
            f.write(f"F1 Score (Macro): {self.metrics['f1_macro']:.4f}\n")
            f.write(f"F1 Score (Weighted): {self.metrics['f1_weighted']:.4f}\n\n")

            class_definitions = self.metrics.get('class_definitions')
            if class_definitions:
                f.write("CLASS DEFINITIONS\n")
                f.write("-" * 50 + "\n")
                for class_name, members in class_definitions.items():
                    member_text = ", ".join(members)
                    f.write(f"{class_name}: {member_text}\n")
                f.write("\n")
            
            # Ghi chỉ số cho từng lớp.
            f.write("PER-CLASS METRICS\n")
            f.write("-" * 50 + "\n")
            
            for class_name, metrics in report.items():
                if class_name not in ['accuracy', 'macro avg', 'weighted avg']:
                    if isinstance(metrics, dict):
                        f.write(f"\n{class_name}:\n")
                        f.write(f"  Precision: {metrics.get('precision', 0):.4f}\n")
                        f.write(f"  Recall: {metrics.get('recall', 0):.4f}\n")
                        f.write(f"  F1-Score: {metrics.get('f1-score', 0):.4f}\n")
                        f.write(f"  Support: {int(metrics.get('support', 0))}\n")
