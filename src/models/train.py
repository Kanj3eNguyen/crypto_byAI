"""
Train classification models for encryption prediction.
"""

import os
from typing import Any, Dict, List, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder


class ModelTrainer:
    """Train, save, load, and run the crypto-group classifier."""

    METADATA_COLUMNS = {
        "sample_id",
        "path",
        "label_group",
        "crypto_family",
        "ransomware_family",
        "algorithm",
        "mode",
        "key_size",
        "original_file_id",
        "original_type",
        "tool",
        "split",
    }
    LEAKY_FEATURE_PREFIXES = (
        "filename_",
        "final_extension_",
        "footer_marker_layout_",
    )
    LEAKY_FEATURE_COLUMNS = {
        "suffix_count",
        "has_double_extension",
        "prior_extension_is_common_original",
        "final_extension_is_common_original",
        "first_byte_value",
        "last_byte_value",
        "footer_length_marker_value",
    }

    def __init__(self, model_type: str = "random_forest", random_state: int = 42):
        self.model_type = model_type
        self.random_state = random_state
        self.model = None
        self.label_encoder = LabelEncoder()
        self.feature_columns: List[str] = []
        self.trained = False

    def _create_model(self):
        if self.model_type == "random_forest":
            return RandomForestClassifier(
                n_estimators=200,
                max_depth=20,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=self.random_state,
                n_jobs=1,
                class_weight="balanced",
            )

        raise ValueError(f"Unknown model type: {self.model_type}")

    def prepare_data(
        self,
        df: pd.DataFrame,
        label_column: str = "label_group",
    ) -> Tuple[pd.DataFrame, pd.Series, List[str]]:
        """Split a feature dataframe into numeric X, labels y, and feature names."""
        if label_column not in df.columns:
            raise ValueError(f"Label column not found: {label_column}")

        df = df.dropna(subset=[label_column]).copy()
        if df.empty:
            raise ValueError(f"No rows left after dropping empty labels in {label_column}")

        exclude_columns = set(self.METADATA_COLUMNS)
        exclude_columns.add(label_column)

        feature_df = df.drop(columns=[c for c in exclude_columns if c in df.columns])
        leaky_columns = [
            column
            for column in feature_df.columns
            if column in self.LEAKY_FEATURE_COLUMNS
            or column.startswith(self.LEAKY_FEATURE_PREFIXES)
        ]
        feature_df = feature_df.drop(columns=leaky_columns)
        feature_df = feature_df.select_dtypes(include=[np.number])
        if feature_df.empty:
            raise ValueError("No numeric feature columns found for training")

        feature_df = feature_df.replace([np.inf, -np.inf], np.nan).fillna(0)

        self.feature_columns = feature_df.columns.tolist()
        return feature_df, df[label_column].astype(str), self.feature_columns

    def train(
        self,
        X: pd.DataFrame,
        y: pd.Series,
        split: pd.Series = None,
        test_size: float = 0.2,
    ) -> Dict[str, Any]:
        """Train the configured classifier and return basic holdout metrics."""
        if len(X) != len(y):
            raise ValueError("X and y must have the same number of rows")

        if not self.feature_columns:
            self.feature_columns = list(X.columns)

        y_encoded = self.label_encoder.fit_transform(y)
        class_count = len(self.label_encoder.classes_)

        if class_count < 2:
            raise ValueError("Training needs at least two label classes")

        min_class_count = int(np.bincount(y_encoded).min())
        can_stratify = min_class_count >= 2
        test_count = int(np.ceil(len(X) * test_size))
        train_count = len(X) - test_count
        can_split = can_stratify and test_count >= class_count and train_count >= class_count

        self.model = self._create_model()
        evaluation_name = "random_holdout"

        if split is not None and split.notna().any():
            split_normalized = split.astype(str).str.lower()
            train_mask = split_normalized.eq("train")
            eval_mask = split_normalized.eq("test")
            evaluation_name = "metadata_test"

            if not eval_mask.any() and split_normalized.eq("val").any():
                eval_mask = split_normalized.eq("val")
                evaluation_name = "metadata_val"

            if not train_mask.any():
                raise ValueError("Split column exists but has no train rows")
            if not eval_mask.any():
                raise ValueError("Split column exists but has no test or val rows")

            train_classes = set(np.unique(y_encoded[train_mask]))
            all_classes = set(range(class_count))
            if train_classes != all_classes:
                missing = sorted(all_classes - train_classes)
                missing_names = self.label_encoder.inverse_transform(missing).tolist()
                raise ValueError(f"Train split is missing label classes: {missing_names}")

            X_train = X.loc[train_mask]
            y_train = y_encoded[train_mask]
            X_test = X.loc[eval_mask]
            y_test = y_encoded[eval_mask]
            self.model.fit(X_train, y_train)
            y_pred = self.model.predict(X_test)
            can_split = True
        elif can_split:
            X_train, X_test, y_train, y_test = train_test_split(
                X,
                y_encoded,
                test_size=test_size,
                random_state=self.random_state,
                stratify=y_encoded,
            )
            self.model.fit(X_train, y_train)
            y_pred = self.model.predict(X_test)
        else:
            self.model.fit(X, y_encoded)
            X_test = X
            y_test = y_encoded
            y_pred = self.model.predict(X_test)
            evaluation_name = "train_set"

        self.trained = True
        class_names = self.label_encoder.classes_.tolist()

        return {
            "samples": int(len(X)),
            "train_samples": int(len(X_train) if can_split else len(X)),
            "evaluation_samples": int(len(y_test)),
            "evaluation_split": evaluation_name,
            "classes": class_names,
            "feature_count": int(len(self.feature_columns)),
            "holdout_used": bool(can_split),
            "accuracy": float(accuracy_score(y_test, y_pred)),
            "precision_macro": float(
                precision_score(y_test, y_pred, average="macro", zero_division=0)
            ),
            "recall_macro": float(recall_score(y_test, y_pred, average="macro", zero_division=0)),
            "f1_macro": float(f1_score(y_test, y_pred, average="macro", zero_division=0)),
            "f1_weighted": float(f1_score(y_test, y_pred, average="weighted", zero_division=0)),
            "confusion_matrix": confusion_matrix(
                y_test,
                y_pred,
                labels=list(range(class_count)),
            ).tolist(),
            "classification_report": classification_report(
                y_test,
                y_pred,
                labels=list(range(class_count)),
                target_names=class_names,
                output_dict=True,
                zero_division=0,
            ),
        }

    def predict(self, X):
        """Return encoded predictions and class probabilities."""
        if not self.trained or self.model is None:
            raise ValueError("Model must be trained before prediction")

        if isinstance(X, pd.DataFrame):
            X_prepared = X.reindex(columns=self.feature_columns, fill_value=0)
            X_prepared = X_prepared.replace([np.inf, -np.inf], np.nan).fillna(0)
        else:
            X_prepared = np.asarray(X)

        predictions = self.model.predict(X_prepared)
        probabilities = self.model.predict_proba(X_prepared)
        return predictions, probabilities

    def get_feature_importance(self) -> Dict[str, float]:
        if not self.trained or self.model is None:
            raise ValueError("Model must be trained before getting feature importance")

        if not hasattr(self.model, "feature_importances_"):
            return {}

        pairs = zip(self.feature_columns, self.model.feature_importances_)
        return {
            feature: float(importance)
            for feature, importance in sorted(pairs, key=lambda item: item[1], reverse=True)
        }

    def save_model(self, model_path: str) -> None:
        os.makedirs(os.path.dirname(model_path) or ".", exist_ok=True)
        joblib.dump(
            {
                "model_type": self.model_type,
                "random_state": self.random_state,
                "model": self.model,
                "label_encoder": self.label_encoder,
                "feature_columns": self.feature_columns,
                "trained": self.trained,
            },
            model_path,
        )

    def load_model(self, model_path: str) -> None:
        state = joblib.load(model_path)

        if isinstance(state, dict) and "model" in state:
            self.model_type = state.get("model_type", self.model_type)
            self.random_state = state.get("random_state", self.random_state)
            self.model = state["model"]
            self.label_encoder = state["label_encoder"]
            self.feature_columns = state.get("feature_columns", [])
            self.trained = state.get("trained", True)
            return

        self.model = state
        self.trained = True

    def save(self, model_path: str, encoder_path: str = None) -> None:
        self.save_model(model_path)
        if encoder_path:
            os.makedirs(os.path.dirname(encoder_path) or ".", exist_ok=True)
            joblib.dump(self.label_encoder, encoder_path)

    def load(self, model_path: str, encoder_path: str = None) -> None:
        self.load_model(model_path)
        if encoder_path:
            self.label_encoder = joblib.load(encoder_path)


CryptoPredictor = ModelTrainer
