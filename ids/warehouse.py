"""
Phase 1 — Build star schema and persist to DuckDB.
Call build_warehouse() once. Skips rebuild if DB already exists.
"""

import pandas as pd
import numpy as np
import duckdb
from ids.config import (
    RAW_CSV, DUCKDB_PATH, WAREHOUSE,
    SELECTED_COLUMNS, BASE_TIME, STREAM_HOURS
)


def _load_raw() -> pd.DataFrame:
    df = pd.read_csv(RAW_CSV)
    df.columns = df.columns.str.strip()
    df = df[SELECTED_COLUMNS].copy()
    df.dropna(inplace=True)
    df.reset_index(drop=True, inplace=True)
    return df


def _add_timestamps(df: pd.DataFrame) -> pd.DataFrame:
    base      = pd.Timestamp(BASE_TIME)
    total_sec = STREAM_HOURS * 3600
    np.random.seed(42)
    offsets   = np.sort(np.random.uniform(0, total_sec, size=len(df)))
    df        = df.copy()
    df['timestamp']   = base + pd.to_timedelta(offsets, unit='s')
    df['hour']        = df['timestamp'].dt.hour
    df['minute']      = df['timestamp'].dt.minute
    df['second']      = df['timestamp'].dt.second
    df['time_bucket'] = df['timestamp'].dt.floor('5min')
    df['period']      = pd.cut(
        df['hour'],
        bins=[12, 14, 16, 18],
        labels=['early_afternoon', 'mid_afternoon', 'late_afternoon'],
        right=False
    )
    return df


def _build_dim_time(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    dim = (
        df[['timestamp', 'hour', 'minute', 'second', 'time_bucket', 'period']]
        .drop_duplicates()
        .sort_values('timestamp')
        .reset_index(drop=True)
    )
    dim['time_id'] = dim.index + 1
    df = df.merge(dim[['timestamp', 'time_id']], on='timestamp', how='left')
    return dim, df


def _classify_port(port: int) -> str:
    well_known = {
        80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 21: 'FTP',
        25: 'SMTP', 53: 'DNS', 110: 'POP3', 143: 'IMAP',
        3306: 'MySQL', 3389: 'RDP', 8080: 'HTTP-Alt'
    }
    if port in well_known:
        return well_known[port]
    if port == 0:   return 'Unknown'
    if port < 1024: return 'Well-Known'
    if port < 49152: return 'Registered'
    return 'Dynamic/Private'


def _build_dim_port(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    dim = (
        df[['Destination Port']]
        .drop_duplicates()
        .sort_values('Destination Port')
        .reset_index(drop=True)
    )
    dim['port_id']      = dim.index + 1
    dim['service_type'] = dim['Destination Port'].apply(_classify_port)
    dim['is_privileged'] = (dim['Destination Port'] < 1024).astype(int)
    df = df.merge(dim[['Destination Port', 'port_id']], on='Destination Port', how='left')
    return dim, df


def _build_dim_traffic(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    def flow_type(row):
        if row['Label'] != 'BENIGN':        return 'attack'
        if row['SYN Flag Count'] > 0 and row['ACK Flag Count'] == 0: return 'syn_only'
        if row['ACK Flag Count'] > 0:       return 'established'
        return 'other'

    df = df.copy()
    df['flow_type'] = df.apply(flow_type, axis=1)
    df['is_attack'] = (df['Label'] != 'BENIGN').astype(int)
    df['direction'] = df.apply(
        lambda r: 'outbound_heavy'
        if r['Total Fwd Packets'] > r['Total Backward Packets']
        else 'inbound_heavy', axis=1
    )
    dim = df[['Label', 'flow_type', 'is_attack', 'direction']].drop_duplicates().reset_index(drop=True)
    dim['traffic_id'] = dim.index + 1
    df = df.merge(dim, on=['Label', 'flow_type', 'is_attack', 'direction'], how='left')
    return dim, df


def _build_fact(df: pd.DataFrame) -> pd.DataFrame:
    fact = df[[
        'time_id', 'port_id', 'traffic_id',
        'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
        'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
        'Flow Bytes/s', 'Flow Packets/s', 'Packet Length Mean',
        'Packet Length Std', 'SYN Flag Count', 'ACK Flag Count',
        'Down/Up Ratio', 'Average Packet Size', 'Label'
    ]].copy().reset_index(drop=True)
    fact.index.name = 'flow_id'
    fact = fact.reset_index()
    fact['flow_id'] = fact['flow_id'] + 1
    return fact


def build_warehouse(force: bool = False) -> None:
    """
    Build star schema and persist to DuckDB.
    Set force=True to rebuild even if warehouse already exists.
    """
    WAREHOUSE.mkdir(exist_ok=True)

    if DUCKDB_PATH.exists() and not force:
        print(f"Warehouse already exists at {DUCKDB_PATH}. Pass force=True to rebuild.")
        return

    print("Building warehouse...")
    df = _load_raw()
    print(f"  Raw data loaded       : {df.shape}")

    df              = _add_timestamps(df)
    dim_time,  df   = _build_dim_time(df)
    dim_port,  df   = _build_dim_port(df)
    dim_traffic, df = _build_dim_traffic(df)
    fact_flows      = _build_fact(df)

    con = duckdb.connect(str(DUCKDB_PATH))
    for name, table in [
        ('dim_time',    dim_time),
        ('dim_port',    dim_port),
        ('dim_traffic', dim_traffic),
        ('fact_flows',  fact_flows),
    ]:
        con.execute(f"DROP TABLE IF EXISTS {name}")
        con.register(f'_{name}', table)
        con.execute(f"CREATE TABLE {name} AS SELECT * FROM _{name}")
        print(f"  {name:15s} → {len(table):,} rows")
    con.close()
    print(f"Warehouse saved → {DUCKDB_PATH}")


def get_connection() -> duckdb.DuckDBPyConnection:
    """Return a live DuckDB connection to the warehouse."""
    return duckdb.connect(str(DUCKDB_PATH))