"""
Phase 4 — StreamEngine, extracted from notebook into importable class.
"""

from collections import deque
import pandas as pd
from ids.config import BATCH_SIZE, ROLLING_WINDOW
from ids.warehouse import get_connection


def load_stream_data() -> pd.DataFrame:
    """Load all flows in chronological order for streaming replay."""
    con = get_connection()
    df  = con.execute("""
        SELECT f.flow_id, f."Flow Duration", f."Flow Bytes/s",
               f."Flow Packets/s", f."Packet Length Mean",
               f."Packet Length Std", f."SYN Flag Count",
               f."ACK Flag Count", f."Average Packet Size",
               f."Down/Up Ratio", f.Label,
               dtr.is_attack, dt.time_bucket,
               dt.hour, dt.minute, dp.service_type, dp.is_privileged
        FROM fact_flows f
        JOIN dim_time    dt  ON f.time_id    = dt.time_id
        JOIN dim_traffic dtr ON f.traffic_id = dtr.traffic_id
        JOIN dim_port    dp  ON f.port_id    = dp.port_id
        ORDER BY dt.time_bucket, f.flow_id
    """).df()
    con.close()
    df['time_bucket'] = pd.to_datetime(df['time_bucket'])
    return df


class StreamEngine:
    def __init__(self, df: pd.DataFrame, batch_size: int = BATCH_SIZE):
        self.df            = df
        self.batch_size    = batch_size
        self.cursor        = 0
        self.total_flows   = 0
        self.total_attacks = 0
        self.total_benign  = 0
        self.flow_counts   = deque(maxlen=ROLLING_WINDOW)
        self.attack_counts = deque(maxlen=ROLLING_WINDOW)
        self.benign_counts = deque(maxlen=ROLLING_WINDOW)
        self.timestamps    = deque(maxlen=ROLLING_WINDOW)
        self.avg_bytes     = deque(maxlen=ROLLING_WINDOW)
        self.avg_pkt_size  = deque(maxlen=ROLLING_WINDOW)
        self.olap_hour     = {}
        self.olap_port     = {}
        self.alert_log     = []

    @property
    def is_exhausted(self) -> bool:
        return self.cursor >= len(self.df)

    @property
    def progress(self) -> float:
        return self.cursor / len(self.df)

    def next_batch(self) -> pd.DataFrame | None:
        if self.is_exhausted:
            return None
        batch        = self.df.iloc[self.cursor : self.cursor + self.batch_size]
        self.cursor += self.batch_size
        return batch

    def process_batch(self, batch: pd.DataFrame) -> dict:
        n          = len(batch)
        n_attacks  = int(batch['is_attack'].sum())
        n_benign   = n - n_attacks
        ts         = batch['time_bucket'].iloc[0]

        self.total_flows   += n
        self.total_attacks += n_attacks
        self.total_benign  += n_benign
        self.timestamps.append(ts)
        self.flow_counts.append(n)
        self.attack_counts.append(n_attacks)
        self.benign_counts.append(n_benign)
        self.avg_bytes.append(batch['Flow Bytes/s'].mean())
        self.avg_pkt_size.append(batch['Average Packet Size'].mean())

        for hour, grp in batch.groupby('hour'):
            if hour not in self.olap_hour:
                self.olap_hour[hour] = {'attack': 0, 'benign': 0, 'bytes': 0.0}
            self.olap_hour[hour]['attack'] += int(grp['is_attack'].sum())
            self.olap_hour[hour]['benign'] += int((grp['is_attack'] == 0).sum())
            self.olap_hour[hour]['bytes']  += float(grp['Flow Bytes/s'].sum())

        for stype, grp in batch.groupby('service_type'):
            self.olap_port[stype] = self.olap_port.get(stype, 0) + len(grp)

        self._detect_alerts(batch, ts)

        return {
            'batch_flows'   : n,
            'batch_attacks' : n_attacks,
            'batch_benign'  : n_benign,
            'attack_ratio'  : round(n_attacks / n, 3) if n > 0 else 0,
            'avg_bytes'     : round(batch['Flow Bytes/s'].mean(), 2),
            'avg_pkt_size'  : round(batch['Average Packet Size'].mean(), 2),
            'timestamp'     : ts,
        }

    def _detect_alerts(self, batch: pd.DataFrame, ts):
        syn_flood = batch[
            (batch['SYN Flag Count'] > 0) &
            (batch['ACK Flag Count'] == 0) &
            (batch['is_attack'] == 1)
        ]
        if len(syn_flood) > 50:
            self.alert_log.append(
                {'time': ts, 'type': 'SYN Flood',
                 'severity': 'HIGH', 'count': len(syn_flood)}
            )

        scan_burst = batch[
            (batch['Packet Length Mean'] < 50) &
            (batch['Flow Packets/s'] > batch['Flow Packets/s'].quantile(0.75)) &
            (batch['is_attack'] == 1)
        ]
        if len(scan_burst) > 30:
            self.alert_log.append(
                {'time': ts, 'type': 'Port Scan Burst',
                 'severity': 'MEDIUM', 'count': len(scan_burst)}
            )

        n = len(batch)
        n_attacks = int(batch['is_attack'].sum())
        if n > 100 and (n_attacks / n) > 0.8:
            self.alert_log.append(
                {'time': ts, 'type': 'Attack Ratio Spike',
                 'severity': 'CRITICAL', 'count': n_attacks}
            )

    def get_olap_snapshot(self) -> tuple[pd.DataFrame, pd.DataFrame]:
        hour_df = pd.DataFrame(
            [{'hour': h, **v} for h, v in self.olap_hour.items()]
        ).sort_values('hour') if self.olap_hour else pd.DataFrame()

        port_df = pd.DataFrame(
            [{'service_type': k, 'flow_count': v}
             for k, v in self.olap_port.items()]
        ).sort_values('flow_count', ascending=False) if self.olap_port else pd.DataFrame()

        return hour_df, port_df

    def get_alerts(self, last_n: int = 5) -> list:
        return self.alert_log[-last_n:]

    def reset(self):
        """Reset stream to beginning for replay."""
        self.__init__(self.df, self.batch_size)