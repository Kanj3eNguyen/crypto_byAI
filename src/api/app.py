"""
FastAPI application for ransomware encryption prediction
"""

from typing import List, Optional

from fastapi import FastAPI, File, Form, UploadFile, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
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
    build_combined_prediction_output,
    predict_with_trainers,
    summarize_prediction_features,
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
MODELS_DIR = "models"
DEFAULT_CRYPTO_MODEL = "crypto_family_predictor.pkl"
DEFAULT_RANSOMWARE_MODEL = "ransomware_family_predictor.pkl"


WEB_APP_HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Ransomware Crypto Predictor</title>
  <style>
    :root {
      color-scheme: light;
      --ink: #16212f;
      --muted: #5b6878;
      --line: #d8dee8;
      --surface: #ffffff;
      --band: #eef3f8;
      --blue: #2457d6;
      --green: #0b7a5a;
      --amber: #9b5c00;
      --red: #b42318;
      --shadow: 0 8px 26px rgba(22, 33, 47, 0.10);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--band);
      color: var(--ink);
      font-size: 15px;
      letter-spacing: 0;
    }
    header {
      background: #111827;
      color: #fff;
      padding: 18px 24px;
      border-bottom: 4px solid #3aa17e;
    }
    header h1 {
      margin: 0;
      font-size: 22px;
      line-height: 1.2;
      font-weight: 700;
    }
    main {
      max-width: 1280px;
      margin: 0 auto;
      padding: 22px;
    }
    .layout {
      display: grid;
      grid-template-columns: minmax(280px, 360px) minmax(0, 1fr);
      gap: 18px;
      align-items: start;
    }
    section, aside {
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
    }
    .panel {
      padding: 18px;
    }
    h2 {
      margin: 0 0 16px;
      font-size: 17px;
      line-height: 1.2;
    }
    label {
      display: block;
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
      margin: 14px 0 7px;
      text-transform: uppercase;
    }
    select, input[type="file"] {
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #fff;
      color: var(--ink);
      padding: 10px;
      min-height: 42px;
    }
    .actions {
      display: flex;
      gap: 10px;
      margin-top: 16px;
      flex-wrap: wrap;
    }
    button {
      border: 0;
      border-radius: 6px;
      padding: 10px 14px;
      min-height: 40px;
      cursor: pointer;
      font-weight: 700;
    }
    button.primary {
      background: var(--blue);
      color: #fff;
    }
    button.secondary {
      background: #e7edf5;
      color: var(--ink);
    }
    button:disabled {
      opacity: .55;
      cursor: not-allowed;
    }
    .status {
      min-height: 22px;
      margin-top: 12px;
      color: var(--muted);
      font-size: 13px;
    }
    .summary {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      border-bottom: 1px solid var(--line);
      background: #f8fafc;
    }
    .metric {
      padding: 14px 16px;
      border-right: 1px solid var(--line);
    }
    .metric:last-child { border-right: 0; }
    .metric strong {
      display: block;
      font-size: 20px;
      line-height: 1.1;
      margin-top: 4px;
    }
    .metric span {
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
    }
    table {
      width: 100%;
      border-collapse: collapse;
    }
    th, td {
      padding: 12px 14px;
      border-bottom: 1px solid var(--line);
      text-align: left;
      vertical-align: top;
    }
    th {
      background: #f8fafc;
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
    }
    .mono {
      font-family: "Cascadia Mono", Consolas, monospace;
      font-size: 12px;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
    }
    .pill {
      display: inline-block;
      border-radius: 999px;
      padding: 3px 8px;
      font-size: 12px;
      font-weight: 700;
      background: #e7edf5;
      color: var(--ink);
    }
    .pill.ok { background: #dff5eb; color: var(--green); }
    .pill.warn { background: #fff0cf; color: var(--amber); }
    .pill.err { background: #fde7e4; color: var(--red); }
    details {
      margin-top: 8px;
    }
    summary {
      cursor: pointer;
      color: var(--blue);
      font-weight: 700;
    }
    pre {
      margin: 8px 0 0;
      max-height: 420px;
      overflow: auto;
      background: #0f172a;
      color: #e5e7eb;
      border-radius: 6px;
      padding: 12px;
    }
    .empty {
      padding: 42px 16px;
      color: var(--muted);
      text-align: center;
    }
    @media (max-width: 900px) {
      .layout { grid-template-columns: 1fr; }
      .summary { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      table, thead, tbody, th, td, tr { display: block; }
      thead { display: none; }
      tr { border-bottom: 1px solid var(--line); }
      td { border-bottom: 0; }
      td::before {
        content: attr(data-label);
        display: block;
        color: var(--muted);
        font-size: 12px;
        font-weight: 700;
        text-transform: uppercase;
        margin-bottom: 4px;
      }
    }
  </style>
</head>
<body>
  <header>
    <h1>Ransomware Crypto Predictor</h1>
  </header>
  <main>
    <div class="layout">
      <aside class="panel">
        <h2>Batch Predict</h2>
        <form id="predictForm">
          <label for="cryptoModel">Crypto model</label>
          <select id="cryptoModel" name="crypto_model" required></select>

          <label for="ransomwareModel">Ransomware model</label>
          <select id="ransomwareModel" name="ransomware_model"></select>

          <label for="files">Files</label>
          <input id="files" name="files" type="file" multiple required>

          <div class="actions">
            <button class="primary" id="runButton" type="submit">Run Predict</button>
            <button class="secondary" id="clearButton" type="button">Clear</button>
          </div>
          <div class="status" id="status">Loading models...</div>
        </form>
      </aside>

      <section>
        <div class="summary">
          <div class="metric"><span>Files</span><strong id="metricFiles">0</strong></div>
          <div class="metric"><span>Done</span><strong id="metricDone">0</strong></div>
          <div class="metric"><span>Errors</span><strong id="metricErrors">0</strong></div>
          <div class="metric"><span>Encrypted</span><strong id="metricEncrypted">0</strong></div>
        </div>
        <div id="results">
          <div class="empty">No predictions yet.</div>
        </div>
      </section>
    </div>
  </main>

  <script>
    const form = document.getElementById('predictForm');
    const statusEl = document.getElementById('status');
    const cryptoModelEl = document.getElementById('cryptoModel');
    const ransomwareModelEl = document.getElementById('ransomwareModel');
    const filesEl = document.getElementById('files');
    const resultsEl = document.getElementById('results');
    const runButton = document.getElementById('runButton');
    const clearButton = document.getElementById('clearButton');

    const metrics = {
      files: document.getElementById('metricFiles'),
      done: document.getElementById('metricDone'),
      errors: document.getElementById('metricErrors'),
      encrypted: document.getElementById('metricEncrypted'),
    };

    function setStatus(text) {
      statusEl.textContent = text;
    }

    function option(value, label) {
      const node = document.createElement('option');
      node.value = value;
      node.textContent = label;
      return node;
    }

    async function loadModels() {
      const response = await fetch('/models');
      if (!response.ok) throw new Error('Could not load models');
      const payload = await response.json();
      cryptoModelEl.replaceChildren();
      ransomwareModelEl.replaceChildren(option('', 'None'));

      payload.models.forEach((name) => {
        cryptoModelEl.appendChild(option(name, name));
        ransomwareModelEl.appendChild(option(name, name));
      });

      if (payload.default_crypto_model) {
        cryptoModelEl.value = payload.default_crypto_model;
      }
      if (payload.default_ransomware_model) {
        ransomwareModelEl.value = payload.default_ransomware_model;
      }
      setStatus(`${payload.models.length} model file(s) found.`);
    }

    function confidenceText(value) {
      if (value === null || value === undefined) return '';
      return `${(Number(value) * 100).toFixed(1)}%`;
    }

    function confidencePill(value) {
      if (value >= 0.7) return 'pill ok';
      if (value >= 0.5) return 'pill warn';
      return 'pill err';
    }

    function escapeHtml(value) {
      return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
    }

    function resetMetrics() {
      metrics.files.textContent = '0';
      metrics.done.textContent = '0';
      metrics.errors.textContent = '0';
      metrics.encrypted.textContent = '0';
    }

    function renderResults(payload) {
      const results = payload.results || [];
      const errors = results.filter((item) => !item.ok).length;
      const encrypted = results.filter((item) => item.ok && item.output && item.output.is_encrypted).length;
      metrics.files.textContent = String(payload.count || results.length);
      metrics.done.textContent = String(results.length - errors);
      metrics.errors.textContent = String(errors);
      metrics.encrypted.textContent = String(encrypted);

      if (!results.length) {
        resultsEl.innerHTML = '<div class="empty">No predictions returned.</div>';
        return;
      }

      const rows = results.map((item) => {
        const fileName = escapeHtml(item.file);
        if (!item.ok) {
          return `
            <tr>
              <td data-label="File" class="mono">${fileName}</td>
              <td data-label="Crypto"><span class="pill err">Error</span></td>
              <td data-label="Confidence"></td>
              <td data-label="Ransomware"></td>
              <td data-label="Output" class="mono">${escapeHtml(item.error)}</td>
            </tr>`;
        }

        const output = item.output;
        const crypto = output.crypto_prediction || {};
        const family = output.ransomware_prediction || {};
        const conf = crypto.confidence;
        const json = JSON.stringify(output, null, 2)
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;');

        return `
          <tr>
            <td data-label="File" class="mono">${fileName}</td>
            <td data-label="Crypto">
              <div><span class="${confidencePill(conf)}">${escapeHtml(crypto.predicted_label || '')}</span></div>
              <div class="mono">${escapeHtml(crypto.possible_encryption_summary || '')}</div>
              <div class="mono">${escapeHtml(crypto.certainty || '')}</div>
            </td>
            <td data-label="Confidence">${confidenceText(conf)}</td>
            <td data-label="Ransomware">
              ${family.predicted_family ? `<span class="pill ok">${escapeHtml(family.predicted_family)}</span>` : ''}
              <div>${family.confidence !== undefined ? confidenceText(family.confidence) : ''}</div>
            </td>
            <td data-label="Output">
              <details>
                <summary>JSON</summary>
                <pre>${json}</pre>
              </details>
            </td>
          </tr>`;
      }).join('');

      resultsEl.innerHTML = `
        <table>
          <thead>
            <tr>
              <th>File</th>
              <th>Crypto</th>
              <th>Confidence</th>
              <th>Ransomware</th>
              <th>Output</th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>`;
    }

    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      if (!filesEl.files.length) {
        setStatus('Select at least one file.');
        return;
      }

      const formData = new FormData();
      formData.append('crypto_model', cryptoModelEl.value);
      formData.append('ransomware_model', ransomwareModelEl.value);
      for (const file of filesEl.files) {
        formData.append('files', file);
      }

      runButton.disabled = true;
      setStatus(`Running ${filesEl.files.length} file(s)...`);

      try {
        const response = await fetch('/predict/batch', {
          method: 'POST',
          body: formData,
        });
        const payload = await response.json();
        if (!response.ok) {
          throw new Error(payload.detail || 'Prediction failed');
        }
        renderResults(payload);
        setStatus('Done.');
      } catch (error) {
        setStatus(error.message);
      } finally {
        runButton.disabled = false;
      }
    });

    clearButton.addEventListener('click', () => {
      filesEl.value = '';
      resultsEl.innerHTML = '<div class="empty">No predictions yet.</div>';
      resetMetrics();
      setStatus('Cleared.');
    });

    loadModels().catch((error) => setStatus(error.message));
  </script>
</body>
</html>
"""


def load_model():
    """Load pretrained model"""
    global _model, _predictor
    
    model_path = os.path.join(MODELS_DIR, DEFAULT_CRYPTO_MODEL)
    
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model not found at {model_path}")
    
    _model = ModelTrainer()
    _model.load_model(model_path)
    _predictor = Predictor(_model)


def list_model_files() -> List[str]:
    """Return available model artifact filenames."""
    if not os.path.isdir(MODELS_DIR):
        return []

    return sorted(
        name
        for name in os.listdir(MODELS_DIR)
        if name.endswith(".pkl")
        and os.path.isfile(os.path.join(MODELS_DIR, name))
    )


def default_model_name(name: str) -> str:
    """Return the default model name if it exists."""
    return name if name in list_model_files() else ""


def resolve_model_path(model_name: str, required: bool = True) -> Optional[str]:
    """Resolve a selected model filename to a path under the models directory."""
    if not model_name:
        if required:
            raise HTTPException(status_code=400, detail="Model selection is required")
        return None

    if os.path.basename(model_name) != model_name or not model_name.endswith(".pkl"):
        raise HTTPException(status_code=400, detail=f"Invalid model name: {model_name}")

    model_path = os.path.join(MODELS_DIR, model_name)
    if not os.path.exists(model_path):
        raise HTTPException(status_code=404, detail=f"Model not found: {model_name}")

    return model_path


async def predict_upload(
    file: UploadFile,
    crypto_trainer: ModelTrainer,
    ransomware_trainer: Optional[ModelTrainer],
    crypto_model_path: str,
    ransomware_model_path: Optional[str],
) -> dict:
    """Predict one uploaded file and return the merged output."""
    contents = await file.read()
    suffix = os.path.splitext(file.filename or "")[1]

    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(contents)
        tmp_path = tmp.name

    try:
        combined = predict_with_trainers(
            file_path=tmp_path,
            crypto_trainer=crypto_trainer,
            ransomware_trainer=ransomware_trainer,
            top_k=3,
            display_path=file.filename,
            file_size=len(contents),
        )

        return build_combined_prediction_output(
            file_path=file.filename,
            crypto_model_path=crypto_model_path,
            ransomware_model_path=ransomware_model_path,
            combined=combined,
        )
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


@app.on_event("startup")
async def startup_event():
    """Load model on startup"""
    try:
        load_model()
    except Exception as e:
        print(f"Warning: Could not load model: {e}")


@app.get("/", response_class=HTMLResponse)
async def web_app():
    """Serve the batch prediction web app."""
    return HTMLResponse(content=WEB_APP_HTML)


@app.get("/models")
async def available_models():
    """Return selectable model artifacts."""
    models = list_model_files()
    return {
        "models": models,
        "default_crypto_model": default_model_name(DEFAULT_CRYPTO_MODEL),
        "default_ransomware_model": default_model_name(DEFAULT_RANSOMWARE_MODEL),
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "ok", "model_loaded": _model is not None}


@app.post("/predict/batch")
async def predict_batch(
    files: List[UploadFile] = File(...),
    crypto_model: str = Form(DEFAULT_CRYPTO_MODEL),
    ransomware_model: str = Form(DEFAULT_RANSOMWARE_MODEL),
):
    """Predict multiple uploaded files with selected models."""
    if not files:
        raise HTTPException(status_code=400, detail="At least one file is required")

    crypto_model_path = resolve_model_path(crypto_model, required=True)
    ransomware_model_path = resolve_model_path(ransomware_model, required=False)

    crypto_trainer = ModelTrainer()
    crypto_trainer.load_model(crypto_model_path)

    ransomware_trainer = None
    if ransomware_model_path:
        ransomware_trainer = ModelTrainer()
        ransomware_trainer.load_model(ransomware_model_path)

    results = []
    for upload in files:
        file_name = upload.filename or "uploaded_file"
        try:
            output = await predict_upload(
                file=upload,
                crypto_trainer=crypto_trainer,
                ransomware_trainer=ransomware_trainer,
                crypto_model_path=crypto_model_path,
                ransomware_model_path=ransomware_model_path,
            )
            results.append({
                "file": file_name,
                "ok": True,
                "output": output,
            })
        except Exception as exc:
            results.append({
                "file": file_name,
                "ok": False,
                "error": str(exc),
            })

    return {
        "count": len(results),
        "results": results,
    }


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
            evidence = _predictor.generate_evidence(
                features,
                predicted_class,
                result['confidence'],
            )
            
            # Format response
            response = format_prediction_json(
                file_path=file.filename,
                file_size=len(contents),
                is_encrypted=is_encrypted,
                predicted_class=predicted_class,
                confidence=result['confidence'],
                top_predictions=result['top_predictions'],
                features_summary=summarize_prediction_features(features),
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
