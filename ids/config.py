from pathlib import Path

# ── Root paths ────────────────────────────────────────────
ROOT        = Path(__file__).resolve().parent.parent
DATA_DIR    = ROOT / "data"
WAREHOUSE   = ROOT / "warehouse"
MODELS_DIR  = ROOT / "models"

# ── File paths ────────────────────────────────────────────
RAW_CSV     = DATA_DIR    / "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
DUCKDB_PATH = WAREHOUSE   / "ids_warehouse.duckdb"

# Pickled model files
ISO_FOREST_PKL  = MODELS_DIR / "isolation_forest.pkl"
RF_PKL          = MODELS_DIR / "random_forest.pkl"
SCALER_PKL      = MODELS_DIR / "scaler.pkl"
ARIMA_PKL       = MODELS_DIR / "arima.pkl"
RULES_PKL       = MODELS_DIR / "association_rules.pkl"

# ── Feature config ────────────────────────────────────────
FEATURES = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Packet Length Mean",
    "Packet Length Std",
    "SYN Flag Count",
    "ACK Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
]

SELECTED_COLUMNS = FEATURES + ["Destination Port", "Label"]

# ── Streaming config ──────────────────────────────────────
BATCH_SIZE       = 500
STREAM_SLEEP_SEC = 0.3
ROLLING_WINDOW   = 30

# ── Time simulation config ────────────────────────────────
BASE_TIME        = "2017-07-07 13:00:00"
STREAM_HOURS     = 4