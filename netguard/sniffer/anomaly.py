import os
import joblib
import numpy as np
from netguard.core.config import Config
from netguard.core.events import log_event

# Global variable to cache the loaded model
_anomaly_model = None
_model_loaded = False

def load_anomaly_model():
    """Load the pre-trained IsolationForest model from disk."""
    global _anomaly_model, _model_loaded
    model_path = Config.ANOMALY_MODEL_PATH
    
    if os.path.exists(model_path):
        try:
            _anomaly_model = joblib.load(model_path)
            _model_loaded = True
            print(f"ML Anomaly Model successfully loaded from: {model_path}")
            return True
        except Exception as e:
            print(f"Warning: Failed to load ML anomaly model from {model_path}: {e}")
            _anomaly_model = None
            _model_loaded = False
    else:
        # Don't fail, just run rule-based fallback
        _anomaly_model = None
        _model_loaded = False
        
    return False

def score_anomaly(features: list[float]) -> tuple[bool, float]:
    """
    Score a feature vector using the loaded IsolationForest model.
    
    Returns:
        tuple (is_anomaly, score)
    """
    global _anomaly_model, _model_loaded
    
    # Attempt to load if not already checked/loaded
    if not _model_loaded and _anomaly_model is None:
        load_anomaly_model()
        
    if _anomaly_model is None:
        # Default fallback: return neutral normal score
        return False, 0.0
        
    try:
        # features needs to be reshaped to (1, -1) for single sample prediction
        X = np.array([features])
        # IsolationForest decision_function returns float
        score = float(_anomaly_model.decision_function(X)[0])
        # Usually, negative scores represent anomalies (specifically, below the threshold)
        is_anomaly = score < Config.ANOMALY_THRESHOLD
        
        return is_anomaly, score
    except Exception as e:
        print(f"Error executing anomaly prediction: {e}")
        return False, 0.0
