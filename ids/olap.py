"""
Phase 2 — All OLAP operations.
Every function takes a DuckDB connection and returns a DataFrame.
"""

import pandas as pd
import duckdb


def slice_attacks(con: duckdb.DuckDBPyConnection) -> pd.DataFrame:
    """SLICE — only attack flows."""
    return con.execute("""
        SELECT f.flow_id, dt.hour, dt.time_bucket,
               dp."Destination Port", dp.service_type,
               f."Flow Bytes/s", f."Flow Packets/s",
               f."Average Packet Size",
               f."SYN Flag Count", f."ACK Flag Count"
        FROM fact_flows f
        JOIN dim_time    dt  ON f.time_id    = dt.time_id
        JOIN dim_port    dp  ON f.port_id    = dp.port_id
        JOIN dim_traffic dtr ON f.traffic_id = dtr.traffic_id
        WHERE dtr.is_attack = 1
        ORDER BY dt.time_bucket
    """).df()


def dice_attacks(con, hour_start=14, hour_end=16,
                 privileged_only=True) -> pd.DataFrame:
    """DICE — attacks filtered across multiple dimensions."""
    priv_filter = "AND dp.is_privileged = 1" if privileged_only else ""
    return con.execute(f"""
        SELECT dt.hour, dt.period, dp.service_type,
               COUNT(*)                               AS flow_count,
               ROUND(AVG(f."Flow Bytes/s"), 2)        AS avg_bytes_sec,
               ROUND(AVG(f."SYN Flag Count"), 3)      AS avg_syn,
               ROUND(AVG(f."Average Packet Size"), 2) AS avg_pkt_size
        FROM fact_flows f
        JOIN dim_time    dt  ON f.time_id    = dt.time_id
        JOIN dim_port    dp  ON f.port_id    = dp.port_id
        JOIN dim_traffic dtr ON f.traffic_id = dtr.traffic_id
        WHERE dtr.is_attack = 1
          AND dt.hour BETWEEN {hour_start} AND {hour_end}
          {priv_filter}
        GROUP BY dt.hour, dt.period, dp.service_type
        ORDER BY flow_count DESC
    """).df()


def rollup(con, level: str = 'hour') -> pd.DataFrame:
    """
    ROLL-UP — aggregate by time granularity.
    level: '5min' | 'hour' | 'period'
    """
    group_map = {
        '5min'  : ('dt.time_bucket', 'time_bucket'),
        'hour'  : ('dt.hour',        'hour'),
        'period': ('dt.period',      'period'),
    }
    if level not in group_map:
        raise ValueError(f"level must be one of {list(group_map)}")

    col_expr, col_alias = group_map[level]
    return con.execute(f"""
        SELECT {col_expr} AS {col_alias},
               dtr.is_attack,
               COUNT(*)                              AS flow_count,
               ROUND(AVG(f."Flow Bytes/s"), 2)       AS avg_bytes_sec,
               ROUND(AVG(f."Packet Length Mean"), 2) AS avg_pkt_len
        FROM fact_flows f
        JOIN dim_time    dt  ON f.time_id    = dt.time_id
        JOIN dim_traffic dtr ON f.traffic_id = dtr.traffic_id
        GROUP BY {col_expr}, dtr.is_attack
        ORDER BY {col_expr}
    """).df()


def drilldown(con) -> dict[str, pd.DataFrame]:
    """DRILL-DOWN — period → hour → 5-min bucket, data-driven."""
    by_period = con.execute("""
        SELECT dt.period, COUNT(*) AS attack_flows
        FROM fact_flows f
        JOIN dim_time    dt  ON f.time_id    = dt.time_id
        JOIN dim_traffic dtr ON f.traffic_id = dtr.traffic_id
        WHERE dtr.is_attack = 1
        GROUP BY dt.period ORDER BY attack_flows DESC
    """).df()

    busiest_period = by_period.iloc[0]['period']
    by_hour = con.execute(f"""
        SELECT dt.hour, COUNT(*) AS attack_flows,
               ROUND(AVG(f."Flow Packets/s"), 2) AS avg_pkt_per_sec
        FROM fact_flows f
        JOIN dim_time    dt  ON f.time_id    = dt.time_id
        JOIN dim_traffic dtr ON f.traffic_id = dtr.traffic_id
        WHERE dtr.is_attack = 1 AND dt.period = '{busiest_period}'
        GROUP BY dt.hour ORDER BY dt.hour
    """).df()

    busiest_hour = int(by_hour.sort_values('attack_flows', ascending=False).iloc[0]['hour'])
    by_bucket = con.execute(f"""
        SELECT dt.time_bucket, COUNT(*) AS attack_flows,
               ROUND(AVG(f."SYN Flag Count"), 3)  AS avg_syn,
               ROUND(AVG(f."Flow Bytes/s"), 2)    AS avg_bytes_sec
        FROM fact_flows f
        JOIN dim_time    dt  ON f.time_id    = dt.time_id
        JOIN dim_traffic dtr ON f.traffic_id = dtr.traffic_id
        WHERE dtr.is_attack = 1 AND dt.hour = {busiest_hour}
        GROUP BY dt.time_bucket ORDER BY dt.time_bucket
    """).df()

    return {
        'by_period'      : by_period,
        'busiest_period' : busiest_period,
        'by_hour'        : by_hour,
        'busiest_hour'   : busiest_hour,
        'by_bucket'      : by_bucket,
    }


def pivot_hour_label(con) -> pd.DataFrame:
    """PIVOT — rows=hour, columns=attack/benign counts."""
    return con.execute("""
        SELECT dt.hour,
               COUNT(*) FILTER (WHERE dtr.is_attack = 0) AS benign_flows,
               COUNT(*) FILTER (WHERE dtr.is_attack = 1) AS attack_flows,
               COUNT(*)                                   AS total_flows,
               ROUND(100.0 * COUNT(*) FILTER (WHERE dtr.is_attack = 1) / COUNT(*), 2) AS attack_pct
        FROM fact_flows f
        JOIN dim_time    dt  ON f.time_id    = dt.time_id
        JOIN dim_traffic dtr ON f.traffic_id = dtr.traffic_id
        GROUP BY dt.hour ORDER BY dt.hour
    """).df()


def pivot_service_metrics(con) -> pd.DataFrame:
    """PIVOT — rows=service_type, columns=metrics (attack flows only)."""
    return con.execute("""
        SELECT dp.service_type,
               COUNT(*)                               AS flow_count,
               ROUND(AVG(f."Average Packet Size"), 2) AS avg_pkt_size,
               ROUND(AVG(f."Flow Bytes/s"), 2)        AS avg_bytes_sec,
               ROUND(AVG(f."SYN Flag Count"), 3)      AS avg_syn,
               ROUND(AVG(f."Down/Up Ratio"), 3)       AS avg_downup_ratio
        FROM fact_flows f
        JOIN dim_port    dp  ON f.port_id    = dp.port_id
        JOIN dim_traffic dtr ON f.traffic_id = dtr.traffic_id
        WHERE dtr.is_attack = 1
        GROUP BY dp.service_type ORDER BY flow_count DESC
    """).df()