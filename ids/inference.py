"""
Phase 3 (inference) — Load pickled models and run predictions.
No retraining. This is what Streamlit calls.
"""

import pickle
import pandas as pd
import numpy as np
from ids.config import (
    ISO_FOREST_PKL, RF_PKL, SCALER_PKL,
    ARIMA_PKL, RULES_PKL, FEATURES, MODELS_DIR
)


def _load(path):
    with open(path, 'rb') as f:
        return pickle.load(f)


def predict_anomaly(df: pd.DataFrame) -> pd.DataFrame:
    """Run Isolation Forest on a DataFrame of flows."""
    scaler   = _load(SCALER_PKL)
    iso      = _load(ISO_FOREST_PKL)
    X_scaled = scaler.transform(df[FEATURES])
    preds    = iso.predict(X_scaled)
    scores   = iso.score_samples(X_scaled)
    out      = df.copy()
    out['iso_pred']      = (preds == -1).astype(int)
    out['anomaly_score'] = scores
    return out


def predict_attack(df: pd.DataFrame) -> pd.DataFrame:
    """Run Random Forest classifier on a DataFrame of flows."""
    rf    = _load(RF_PKL)
    proba = rf.predict_proba(df[FEATURES])[:, 1]
    preds = rf.predict(df[FEATURES])
    out   = df.copy()
    out['rf_pred']       = preds
    out['attack_proba']  = proba
    return out


def get_rf_metrics() -> dict:
    """Return test-set metrics (precomputed at train time)."""
    from sklearn.metrics import classification_report, roc_auc_score
    rf      = _load(RF_PKL)
    split   = _load(MODELS_DIR / 'rf_test_split.pkl')
    X_test  = split['X_test']
    y_test  = split['y_test']
    y_pred  = rf.predict(X_test)
    y_proba = rf.predict_proba(X_test)[:, 1]
    return {
        'report'  : classification_report(y_test, y_pred, output_dict=True),
        'roc_auc' : roc_auc_score(y_test, y_proba),
        'feature_importance': pd.Series(
            rf.feature_importances_, index=FEATURES
        ).sort_values(ascending=False)
    }


def get_forecast(steps: int = 18) -> pd.DataFrame:
    """Return ARIMA forecast for next `steps` x 5-min buckets."""
    payload     = _load(ARIMA_PKL)
    model       = payload['model']
    full_ts     = payload['full_ts']
    forecast    = model.get_forecast(steps=steps)
    fc_mean     = forecast.predicted_mean
    fc_ci       = forecast.conf_int()
    return pd.DataFrame({
        'forecast'  : fc_mean.values,
        'lower_ci'  : fc_ci.iloc[:, 0].values,
        'upper_ci'  : fc_ci.iloc[:, 1].values,
    }, index=fc_mean.index), full_ts


def get_association_rules() -> pd.DataFrame:
    """Return saved association rules."""
    return _load(RULES_PKL)