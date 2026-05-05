"""
FastAPI application for ransomware encryption prediction
"""

from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import JSONResponse
import os
import tempfile
import pandas as pd

from src.models.train import ModelTrainer
from src.models.predict import (
    Predictor,
    certainty_from_prediction,
    format_prediction_json,
    infer_prediction_basis,
    is_encrypted_label,
)
from src.features.extract_features import extract_features_from_file

app = FastAPI(
    title="Ransomware Crypto Predictor",
    description="AI-based prediction of ransomware encryption algorithm groups",
    version="0.1.0"
)

# Global model and predictor
_model = None
_predictor = None


def load_model():
    """Load pretrained model"""
    global _model, _predictor
    
    model_path = "models/crypto_predictor.pkl"
    
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model not found at {model_path}")
    
    _model = ModelTrainer()
    _model.load_model(model_path)
    _predictor = Predictor(_model)


@app.on_event("startup")
async def startup_event():
    """Load model on startup"""
    try:
        load_model()
    except Exception as e:
        print(f"Warning: Could not load model: {e}")


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "ok", "model_loaded": _model is not None}


@app.post("/predict")
async def predict(file: UploadFile = File(...)):
    """
    Predict encryption algorithm group for uploaded file
    
    Args:
        file: Uploaded file to analyze
    
    Returns:
        JSON prediction with confidence and evidence
    """
    if _model is None:
        raise HTTPException(status_code=503, detail="Model not loaded")
    
    try:
        # Read uploaded file
        contents = await file.read()
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(contents)
            tmp_path = tmp.name
        
        try:
            # Extract features
            features = extract_features_from_file(tmp_path)
            
            # Prepare feature array
            feature_names = _model.feature_columns
            feature_array = pd.DataFrame([
                {name: features.get(name, 0) for name in feature_names}
            ])
            
            # Make prediction
            result = _predictor.predict_with_confidence(feature_array, top_k=3)
            
            # Determine if encrypted
            predicted_class = result['predicted_class']
            is_encrypted = is_encrypted_label(predicted_class)
            basis = infer_prediction_basis(features)
            
            # Generate evidence
            from src.models.predict import Predictor as P
            evidence = P(
                _model,
                feature_names
            ).generate_evidence(features, predicted_class, result['confidence'])
            
            # Format response
            response = format_prediction_json(
                file_path=file.filename,
                file_size=len(contents),
                is_encrypted=is_encrypted,
                predicted_class=predicted_class,
                confidence=result['confidence'],
                top_predictions=result['top_predictions'],
                features_summary={
                    'shannon_entropy_full': features.get('shannon_entropy_full', 0),
                    'entropy_mean': features.get('entropy_mean', 0),
                    'high_entropy_block_ratio': features.get('high_entropy_block_ratio', 0),
                    'unique_byte_count': features.get('unique_byte_count', 0),
                    'printable_byte_ratio': features.get('printable_byte_ratio', 0),
                    'footer_metadata_score': features.get('footer_metadata_score', 0),
                    'footer_nonce12_tag16_like': features.get('footer_nonce12_tag16_like', 0),
                    'footer_nonce24_tag16_like': features.get('footer_nonce24_tag16_like', 0),
                    'footer_rsa2048_wrapped_key_like': features.get(
                        'footer_rsa2048_wrapped_key_like',
                        0,
                    ),
                },
                evidence=evidence,
                top_groups=result.get('top_groups'),
                basis=basis,
                certainty=certainty_from_prediction(is_encrypted, result['confidence'], basis),
            )
            
            return JSONResponse(content=response)
        
        finally:
            # Clean up temp file
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing file: {str(e)}")


@app.get("/model/info")
async def model_info():
    """Get information about loaded model"""
    if _model is None:
        return {"status": "Model not loaded"}
    
    return {
        "model_type": _model.model_type,
        "feature_count": len(_model.feature_columns) if _model.feature_columns else 0,
        "classes": _model.label_encoder.classes_.tolist()
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
