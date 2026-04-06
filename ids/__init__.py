# exposes clean top-level imports
from ids.warehouse  import build_warehouse, get_connection
from ids.ml         import train_all
from ids.inference  import (predict_anomaly, predict_attack,
                            get_rf_metrics, get_forecast,
                            get_association_rules)
from ids.stream     import StreamEngine, load_stream_data
from ids import olap