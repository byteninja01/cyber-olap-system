"""
Phase 3 — Train all models and save to disk with pickle.
Call train_all() once. Models load instantly in Streamlit via inference.py.
"""

import pickle
import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from statsmodels.tsa.arima.model import ARIMA
from mlxtend.frequent_patterns import apriori, association_rules

from ids.config import (
    MODELS_DIR, FEATURES,
    ISO_FOREST_PKL, RF_PKL, SCALER_PKL, ARIMA_PKL, RULES_PKL
)
from ids.warehouse import get_connection


def _save(obj, path: Path):
    path.parent.mkdir(exist_ok=True)
    with open(path, 'wb') as f:
        pickle.dump(obj, f)
    print(f"  Saved → {path.name}")


def _load_ml_data():
    con = get_connection()
    df  = con.execute("""
        SELECT f.*, dtr.is_attack, dt.time_bucket, dt.hour
        FROM fact_flows f
        JOIN dim_time    dt  ON f.time_id    = dt.time_id
        JOIN dim_traffic dtr ON f.traffic_id = dtr.traffic_id
        ORDER BY dt.time_bucket
    """).df()
    df['time_bucket'] = pd.to_datetime(df['time_bucket'])
    con.close()
    return df


def train_isolation_forest(df: pd.DataFrame):
    print("Training Isolation Forest...")
    X        = df[FEATURES].values
    y        = df['is_attack'].values
    scaler   = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    X_benign = X_scaled[y == 0]

    iso = IsolationForest(n_estimators=100, contamination=0.15,
                          random_state=42, n_jobs=-1)
    iso.fit(X_benign)

    _save(scaler, SCALER_PKL)
    _save(iso,    ISO_FOREST_PKL)
    return iso, scaler


def train_random_forest(df: pd.DataFrame):
    print("Training Random Forest...")
    X = df[FEATURES]
    y = df['is_attack']
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    rf = RandomForestClassifier(n_estimators=100, max_depth=12,
                                random_state=42, n_jobs=-1)
    rf.fit(X_train, y_train)
    _save(rf, RF_PKL)

    # Save test split for eval in inference
    _save({'X_test': X_test, 'y_test': y_test}, MODELS_DIR / 'rf_test_split.pkl')
    return rf


def train_arima(df: pd.DataFrame):
    print("Training ARIMA...")
    ts = (
        df[df['is_attack'] == 1]
        .groupby('time_bucket')
        .size()
        .rename('attack_count')
        .asfreq('5min', fill_value=0)
    )
    train_ts = ts.iloc[: len(ts) - 12]
    model    = ARIMA(train_ts, order=(2, 1, 2)).fit()
    _save({'model': model, 'full_ts': ts}, ARIMA_PKL)
    return model, ts


def train_association_rules(df: pd.DataFrame):
    print("Mining association rules...")

    def discretize(d):
        out = pd.DataFrame()
        out['high_SYN']       = (d['SYN Flag Count'] > 0)
        out['low_ACK']        = (d['ACK Flag Count'] == 0)
        out['high_pkt_rate']  = (d['Flow Packets/s'] > d['Flow Packets/s'].median())
        out['small_packets']  = (d['Packet Length Mean'] < d['Packet Length Mean'].median())
        out['short_duration'] = (d['Flow Duration'] < d['Flow Duration'].median())
        out['low_bytes']      = (d['Flow Bytes/s'] < d['Flow Bytes/s'].median())
        out['high_fwd_pkts']  = (d['Total Fwd Packets'] > d['Total Fwd Packets'].median())
        out['ATTACK']         = (d['is_attack'] == 1)
        return out

    sample      = df.sample(n=50000, random_state=42)
    binary_df   = discretize(sample)
    freq_items  = apriori(binary_df, min_support=0.1,
                          use_colnames=True, max_len=4)
    rules       = association_rules(freq_items, metric='confidence',
                                    min_threshold=0.7)
    attack_rules = rules[
        rules['consequents'].apply(lambda x: 'ATTACK' in x)
    ].sort_values('lift', ascending=False).reset_index(drop=True)

    _save(attack_rules, RULES_PKL)
    return attack_rules


def train_all(force: bool = False):
    """
    Train and pickle all models.
    Set force=True to retrain even if pickles already exist.
    """
    all_exist = all(p.exists() for p in
                    [ISO_FOREST_PKL, RF_PKL, SCALER_PKL, ARIMA_PKL, RULES_PKL])

    if all_exist and not force:
        print("All models already trained. Pass force=True to retrain.")
        return

    df = _load_ml_data()
    print(f"Data loaded: {df.shape}")

    train_isolation_forest(df)
    train_random_forest(df)
    train_arima(df)
    train_association_rules(df)

    print("\nAll models trained and saved to ./models/")