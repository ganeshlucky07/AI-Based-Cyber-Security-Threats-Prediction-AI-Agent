from pathlib import Path
from typing import Dict, Any, List

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"

DATASETS: Dict[str, Dict[str, Any]] = {
    "aads2017": {
        "path": DATA_DIR / "aads2017" / "aads2017.csv",
        "label_column": "label",
        "normal_labels": ["normal", "benign", "BENIGN"],
    },
    "unsw_nb15": {
        "path": DATA_DIR / "unsw_nb15" / "unsw_nb15.csv",
        "label_column": "label",
        "normal_labels": ["normal", "benign", "BENIGN"],
    },
    "nsl_kdd": {
        "path": DATA_DIR / "nsl_kdd" / "nsl_kdd.csv",
        "label_column": "label",
        "normal_labels": ["normal", "benign", "BENIGN"],
    },
    "ton_iot": {
        "path": DATA_DIR / "ton_iot" / "ton_iot.csv",
        "label_column": "label",
        "normal_labels": ["normal", "benign", "BENIGN"],
    },
    "mawilab": {
        "path": DATA_DIR / "mawilab" / "mawilab.csv",
        "label_column": "label",
        "normal_labels": ["normal", "benign", "BENIGN"],
    },
}

TARGET_COLUMN = "target"

NORMAL_LABELS_LOWER: Dict[str, List[str]] = {
    name: [value.lower() for value in cfg["normal_labels"]]
    for name, cfg in DATASETS.items()
}
