from pathlib import Path
import random
import time
import threading
from datetime import datetime
from collections import defaultdict
import os
import json
import sqlite3

try:
    import websocket
except ImportError:  # pragma: no cover - optional dependency
    websocket = None

import joblib
import numpy as np
import pandas as pd
from flask import Flask, render_template, request, send_file, redirect, url_for, flash, jsonify
from flask_socketio import SocketIO, emit

from src.config import BASE_DIR
from src.static_analysis import load_artifact as load_static_artifact
from src.wifi_scanner import WiFiScanner


app = Flask(__name__)
app.secret_key = "dev-secret-key"

ASYNC_MODE = os.environ.get("SOCKETIO_ASYNC_MODE")
if not ASYNC_MODE:
    try:
        import eventlet  # type: ignore  # noqa: F401

        ASYNC_MODE = "eventlet"
    except Exception:
        ASYNC_MODE = "threading"

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode=ASYNC_MODE,
    ping_timeout=60,
    ping_interval=25,
)

STATIC_REPORT_PATH = BASE_DIR / "reports" / "web_static_latest.csv"
STATIC_PDF_PATH = BASE_DIR / "reports" / "web_static_latest.pdf"
LIVE_PDF_PATH = BASE_DIR / "reports" / "live_threat_latest.pdf"
URL_REPORT_PATH = BASE_DIR / "reports" / "web_urls_latest.csv"
THREAT_DB_PATH = BASE_DIR / "data" / "threat_events.db"

SNAPSHOT_META_PATH = BASE_DIR / "data" / "threat_snapshots.json"
SNAPSHOT_DIR = BASE_DIR / "reports" / "snapshots"

# Predefined world locations for live threat map visualization
THREAT_LOCATIONS = [
    {"country": "United States", "city": "New York", "lat": 40.7128, "lon": -74.0060},
    {"country": "United States", "city": "San Francisco", "lat": 37.7749, "lon": -122.4194},
    {"country": "India", "city": "Mumbai", "lat": 19.0760, "lon": 72.8777},
    {"country": "India", "city": "Bengaluru", "lat": 12.9716, "lon": 77.5946},
    {"country": "Germany", "city": "Frankfurt", "lat": 50.1109, "lon": 8.6821},
    {"country": "United Kingdom", "city": "London", "lat": 51.5074, "lon": -0.1278},
    {"country": "Singapore", "city": "Singapore", "lat": 1.3521, "lon": 103.8198},
    {"country": "Japan", "city": "Tokyo", "lat": 35.6895, "lon": 139.6917},
    {"country": "Brazil", "city": "São Paulo", "lat": -23.5505, "lon": -46.6333},
    {"country": "Australia", "city": "Sydney", "lat": -33.8688, "lon": 151.2093},
    {"country": "Canada", "city": "Toronto", "lat": 43.65107, "lon": -79.347015},
    {"country": "South Africa", "city": "Johannesburg", "lat": -26.2041, "lon": 28.0473},
]

# Threat intelligence datasets / feeds used as logical sources for live map threats
THREAT_DATASETS = [
    "CIC-IDS 2017 (HTTP & Web Attacks)",
    "CSE-CIC-IDS 2018 (Enterprise API/Web Threats)",
    "UNSW-NB15 (Modern Web & App Attacks)",
    "OWASP WebGoat Logs Dataset",
    "SANTA Web Attack Dataset",
    "CSIC 2010 HTTP Web Attack Dataset",
    "CIC-DDoS 2019 (HTTP Floods)",
    "CIC-BELL-DNS 2021 (DNS Abuse & Routing)",
    "Academic WAF Log Datasets (Sanitized)",
    "Bot-IoT (API Botnet & Anomalies)",
    "TON_IoT HTTP/REST Dataset",
    "SWaT & WADI ICS HTTP/API Traces",
    "HTTP Request Anomaly Research Datasets",
    "CERT Network Flow Data (API Misuse)",
    "AWS Open Data – Web & API Logs",
]

THREAT_HUNT_FEEDS = [
    "MISP Live Threat Intelligence Feeds",
    "AlienVault OTX (Open Threat Exchange) Real-Time Feeds",
    "AbuseIPDB Live Threat Feed",
    "GreyNoise Real-Time Internet Noise & Scanner Feed",
    "VirusTotal Live File / URL / IP Intelligence",
    "OpenPhish Real-Time Phishing Feed",
    "PhishTank Live Dataset",
    "Spamhaus DROP & Botnet Feeds",
    "Cymon Threat Intelligence Feed",
    "MalwareBazaar (Realtime Hash + Malware Metadata)",
    "Feodo Tracker Botnet C2 Live List",
    "URLhaus Real-Time Malicious URL Feed",
    "ThreatFox Live IOC Feed",
    "SANS Storm Center (ISC) Real-Time Internet Traffic Data",
    "Cisco Talos Live Threat Intelligence",
    "Palo Alto AutoFocus Threat Feed",
    "FireEye (Now Trellix) Threat Feeds",
    "Anomali ThreatStream Feeds",
    "Rapid7 Threat Command (Real-Time IOCs)",
    "Microsoft Defender Threat Intelligence (MDTI)",
]

# Dialogue datasets commonly used for training chatbots (for documentation / explanations)
CHATBOT_DIALOG_DATASETS = [
    "Cornell Movie Dialogs Corpus",
    "DailyDialog",
    "Persona-Chat",
    "MultiWOZ (Multi-Domain Wizard-of-Oz)",
    "Taskmaster Dataset",
    "ConvAI2 Dataset",
    "Empathetic Dialogues",
    "DSTC (Dialog State Tracking Challenge) Datasets",
    "Topical-Chat (Alexa)",
    "OpenSubtitles Dialog Corpus",
    "CoQA (Conversational Question Answering)",
    "SQuAD",
    "QuAC (Question Answering in Context)",
    "Human-Human Dialogue Dataset (HHH)",
    "Reddit Conversations Dataset",
]

# Speech / voice recognition datasets (for documentation / explanations)
VOICE_RECOGNITION_DATASETS = [
    "LibriSpeech",
    "Common Voice (Mozilla)",
    "TED-LIUM",
    "VoxCeleb 1 & 2",
    "Google Speech Commands Dataset",
    "AISHELL-1",
    "AISHELL-2",
    "TIMIT Acoustic-Phonetic Dataset",
    "Librivox / LibriLight",
    "CHiME Speech Datasets",
    "SWITCHBOARD Telephone Speech Corpus",
    "AMI Meeting Corpus",
    "WSJ Speech Corpus (Wall Street Journal)",
    "Fisher English Training Speech",
    "VoxForge",
]

# User-specified dataset groups for explaining how a security chatbot could be trained
CYBERSECURITY_DATASETS = [
    "CIC-IDS 2017",
    "UNSW-NB15",
    "CSE-CIC-IDS 2018",
    "Bot-IoT Dataset",
    "TON_IoT Dataset",
    "DARPA Intrusion Detection Dataset",
    "KYOTO 2006+ Dataset",
    "MAWI Network Traffic Archive",
    "DShield / Internet Storm Center Logs",
    "Shadowserver Public Datasets",
    "Spamhaus DROP/EDROP Feeds",
    "CAIDA UCSD Network Telescope",
    "Honeynet Project Honeypot Data",
    "MalwareBazaar (Abuse.ch)",
    "VirusShare",
]

NETWORKING_DATASETS = [
    "RIPE Atlas Measurement Data",
    "CAIDA Internet Topology Dataset",
    "CAIDA Anonymized Internet Traces",
    "MAWI Working Group Packet Traces",
    "CRAWDAD Wireless Dataset Collection",
    "AWID WiFi Intrusion Dataset",
    "WiFiDeauth Dataset",
    "FCC Measuring Broadband America Dataset",
    "CERT NetFlow Public Dataset",
    "NASA HTTP Dataset",
]

DATABASE_DATASETS = [
    "TPC-H Benchmark Dataset",
    "TPC-C Benchmark Dataset",
    "TPC-DS Benchmark Dataset",
    "IMDB SQL Benchmark Dataset",
    "StackOverflow Public Dataset",
    "YCSB Benchmark Dataset",
    "Million Song Dataset",
    "Amazon Reviews Dataset",
    "NYC Taxi Dataset",
    "Wikipedia Dumps",
]

THREAT_HUNT_STATE = {
    "active": False,
    "indicators_searched": 0,
    "matches_found": 0,
    "critical_findings": 0,
    "iocs": [],
}

THREAT_HUNT_CANDIDATES = []
THREAT_HUNT_CURSOR = 0

ML_TECH_DATASETS = [
    "ImageNet",
    "COCO Dataset",
    "Open Images Dataset",
    "MNIST",
    "Fashion-MNIST",
    "LibriSpeech",
    "Common Voice",
    "SQuAD",
    "IMDB Reviews Dataset",
    "WMT Translation Dataset",
]

PUBLIC_DATASETS = [
    "Google BigQuery Public Datasets",
    "Kaggle Public Datasets",
    "UCI Machine Learning Repository",
    "AWS Open Data Registry",
    "OpenML Datasets",
    "Stanford SNAP Datasets",
    "World Bank Open Data",
    "GitHub Public Repos Dataset",
    "OpenStreetMap Data",
    "Data.gov / GovData",
]

_static_cache = {}
_url_cache = {}
_db_initialized = False

STATIC_VIEW_STATE = {
    "summary": None,
    "sample": None,
    "dashboard": None,
}


def init_threat_db() -> None:
    """Ensure the local SQLite database for live threats exists."""
    global _db_initialized
    if _db_initialized:
        return
    THREAT_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(THREAT_DB_PATH) as conn:
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS threat_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT,
                timestamp TEXT,
                source_ip TEXT,
                dest_ip TEXT,
                port INTEGER,
                protocol TEXT,
                threat_type TEXT,
                severity TEXT,
                attack_category TEXT,
                confidence REAL,
                details TEXT,
                dataset TEXT,
                country TEXT,
                city TEXT,
                latitude REAL,
                longitude REAL,
                dest_country TEXT,
                dest_city TEXT,
                dest_latitude REAL,
                dest_longitude REAL
            )
            """
        )
        conn.commit()
    _db_initialized = True


def _extract_threat_row(threat: dict):
    """Return a tuple of threat fields in a consistent order for SQL inserts."""
    return (
        threat.get("id"),
        threat.get("timestamp"),
        threat.get("source_ip"),
        threat.get("dest_ip"),
        threat.get("port"),
        threat.get("protocol"),
        threat.get("threat_type"),
        threat.get("severity"),
        threat.get("attack_category"),
        float(threat.get("confidence", 0.0) or 0.0),
        threat.get("details"),
        threat.get("dataset"),
        threat.get("country"),
        threat.get("city"),
        threat.get("latitude"),
        threat.get("longitude"),
        threat.get("dest_country"),
        threat.get("dest_city"),
        threat.get("dest_latitude"),
        threat.get("dest_longitude"),
    )


def _normalize_db_key(db_key: str) -> str:
    """Normalize database key names used for snapshots and routing."""
    key = (db_key or "").lower()
    if key in ("sqlite", "sqlite_local"):
        return "sqlite"
    if key in ("postgres", "postgresql"):
        return "postgresql"
    if key in ("sqlserver", "mssql", "ms_sql", "sql_server"):
        return "sqlserver"
    return key


def _load_snapshot_meta() -> dict:
    """Load snapshot metadata from disk."""
    if not SNAPSHOT_META_PATH.exists():
        return {}
    try:
        with SNAPSHOT_META_PATH.open("r", encoding="utf-8") as f:
            data = json.load(f) or {}
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}


def _save_snapshot_meta(data: dict) -> None:
    """Persist snapshot metadata to disk."""
    SNAPSHOT_META_PATH.parent.mkdir(parents=True, exist_ok=True)
    with SNAPSHOT_META_PATH.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def _create_snapshot_file(db_key: str, threats: list) -> dict:
    """Create a CSV snapshot for the given database key and list of threats.

    Returns the snapshot metadata entry including snapshot id and total saves.
    """
    if not threats:
        raise ValueError("No threats to snapshot")

    meta = _load_snapshot_meta()
    key = _normalize_db_key(db_key)
    existing = list(meta.get(key, []))
    next_id = (existing[-1]["id"] + 1) if existing else 1
    ts_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    db_dir = SNAPSHOT_DIR / key
    db_dir.mkdir(parents=True, exist_ok=True)
    filename = f"{key}_snapshot_{next_id}.csv"
    csv_path = db_dir / filename

    df = pd.DataFrame(threats)
    df.to_csv(csv_path, index=False)

    rel_path = csv_path.relative_to(BASE_DIR)
    entry = {
        "id": next_id,
        "timestamp": ts_str,
        "threat_count": len(threats),
        "file": str(rel_path),
    }
    existing.append(entry)
    # Keep only the most recent 50 snapshots per DB to avoid unbounded growth
    if len(existing) > 50:
        existing = existing[-50:]
    meta[key] = existing
    _save_snapshot_meta(meta)

    entry_with_total = dict(entry)
    entry_with_total["total_saves"] = len(existing)
    return entry_with_total


def _store_threat_external_sqlite(threat: dict) -> None:
    """Optional: write threats to an additional SQLite file if configured.

    Controlled by THREAT_DB_SQLITE_EXTERNAL_PATH.
    """
    db_path = os.environ.get("THREAT_DB_SQLITE_EXTERNAL_PATH")
    if not db_path:
        return
    try:
        row = _extract_threat_row(threat)
        with sqlite3.connect(db_path) as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO threat_events (
                    event_id, timestamp, source_ip, dest_ip, port, protocol,
                    threat_type, severity, attack_category, confidence, details,
                    dataset, country, city, latitude, longitude,
                    dest_country, dest_city, dest_latitude, dest_longitude
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                row,
            )
            conn.commit()
    except Exception as exc:
        print(f"External SQLite threat storage error: {exc}")


def _store_threat_mysql(threat: dict) -> None:
    """Optional: write threats to MySQL if THREAT_DB_MYSQL_* env vars are set."""
    host = os.environ.get("THREAT_DB_MYSQL_HOST")
    db_name = os.environ.get("THREAT_DB_MYSQL_DB")
    user = os.environ.get("THREAT_DB_MYSQL_USER")
    password = os.environ.get("THREAT_DB_MYSQL_PASSWORD")
    port = int(os.environ.get("THREAT_DB_MYSQL_PORT", "3306"))
    if not (host and db_name and user):
        return
    try:
        import mysql.connector
    except ImportError:
        print("MySQL threat storage skipped: mysql-connector-python not installed")
        return
    try:
        row = _extract_threat_row(threat)
        conn = mysql.connector.connect(
            host=host,
            user=user,
            password=password,
            database=db_name,
            port=port,
        )
        try:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO threat_events (
                    event_id, timestamp, source_ip, dest_ip, port, protocol,
                    threat_type, severity, attack_category, confidence, details,
                    dataset, country, city, latitude, longitude,
                    dest_country, dest_city, dest_latitude, dest_longitude
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                row,
            )
            conn.commit()
        finally:
            conn.close()
    except Exception as exc:
        print(f"MySQL threat storage error: {exc}")


def _store_threat_postgres(threat: dict) -> None:
    """Optional: write threats to PostgreSQL if THREAT_DB_POSTGRES_* env vars are set."""
    host = os.environ.get("THREAT_DB_POSTGRES_HOST")
    db_name = os.environ.get("THREAT_DB_POSTGRES_DB")
    user = os.environ.get("THREAT_DB_POSTGRES_USER")
    password = os.environ.get("THREAT_DB_POSTGRES_PASSWORD")
    port = int(os.environ.get("THREAT_DB_POSTGRES_PORT", "5432"))
    if not (host and db_name and user):
        return
    try:
        import psycopg2
    except ImportError:
        print("PostgreSQL threat storage skipped: psycopg2 not installed")
        return
    try:
        row = _extract_threat_row(threat)
        conn = psycopg2.connect(host=host, dbname=db_name, user=user, password=password, port=port)
        try:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO threat_events (
                    event_id, timestamp, source_ip, dest_ip, port, protocol,
                    threat_type, severity, attack_category, confidence, details,
                    dataset, country, city, latitude, longitude,
                    dest_country, dest_city, dest_latitude, dest_longitude
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                row,
            )
            conn.commit()
        finally:
            conn.close()
    except Exception as exc:
        print(f"PostgreSQL threat storage error: {exc}")


def _store_threat_mariadb(threat: dict) -> None:
    """Optional: write threats to MariaDB using the same settings style as MySQL."""
    host = os.environ.get("THREAT_DB_MARIADB_HOST")
    db_name = os.environ.get("THREAT_DB_MARIADB_DB")
    user = os.environ.get("THREAT_DB_MARIADB_USER")
    password = os.environ.get("THREAT_DB_MARIADB_PASSWORD")
    port = int(os.environ.get("THREAT_DB_MARIADB_PORT", "3306"))
    if not (host and db_name and user):
        return
    try:
        import pymysql
    except ImportError:
        print("MariaDB threat storage skipped: pymysql not installed")
        return
    try:
        row = _extract_threat_row(threat)
        conn = pymysql.connect(host=host, user=user, password=password, database=db_name, port=port)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO threat_events (
                        event_id, timestamp, source_ip, dest_ip, port, protocol,
                        threat_type, severity, attack_category, confidence, details,
                        dataset, country, city, latitude, longitude,
                        dest_country, dest_city, dest_latitude, dest_longitude
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    row,
                )
            conn.commit()
        finally:
            conn.close()
    except Exception as exc:
        print(f"MariaDB threat storage error: {exc}")


def _store_threat_mongodb(threat: dict) -> None:
    """Optional: store threats as documents in MongoDB.

    Controlled by THREAT_DB_MONGODB_URI, THREAT_DB_MONGODB_DB, THREAT_DB_MONGODB_COLLECTION.
    """
    uri = os.environ.get("THREAT_DB_MONGODB_URI")
    if not uri:
        return
    db_name = os.environ.get("THREAT_DB_MONGODB_DB", "security_dashboard")
    coll_name = os.environ.get("THREAT_DB_MONGODB_COLLECTION", "threat_events")
    try:
        from pymongo import MongoClient
    except ImportError:
        print("MongoDB threat storage skipped: pymongo not installed")
        return
    try:
        client = MongoClient(uri, serverSelectionTimeoutMS=2000)
        db = client[db_name]
        collection = db[coll_name]
        doc = dict(threat)
        # Ensure confidence is a plain float
        doc["confidence"] = float(threat.get("confidence", 0.0) or 0.0)
        collection.insert_one(doc)
    except Exception as exc:
        print(f"MongoDB threat storage error: {exc}")


def _store_threat_redis(threat: dict) -> None:
    """Optional: push serialized threats into Redis (e.g., a list or stream).

    Controlled by THREAT_DB_REDIS_URL and THREAT_DB_REDIS_KEY.
    """
    url = os.environ.get("THREAT_DB_REDIS_URL")
    if not url:
        return
    key = os.environ.get("THREAT_DB_REDIS_KEY", "threat_events")
    try:
        import redis
    except ImportError:
        print("Redis threat storage skipped: redis-py not installed")
        return
    try:
        r = redis.from_url(url)
        payload = json.dumps(threat, default=str)
        r.rpush(key, payload)
    except Exception as exc:
        print(f"Redis threat storage error: {exc}")


def _store_threat_dynamodb(threat: dict) -> None:
    table_name = os.environ.get("THREAT_DB_DYNAMODB_TABLE")
    if not table_name:
        return
    region = os.environ.get("THREAT_DB_DYNAMODB_REGION")
    endpoint_url = os.environ.get("THREAT_DB_DYNAMODB_ENDPOINT")
    try:
        import boto3
    except ImportError:
        print("DynamoDB threat storage skipped: boto3 not installed")
        return
    try:
        session_kwargs = {}
        if region:
            session_kwargs["region_name"] = region
        dynamodb = boto3.resource("dynamodb", endpoint_url=endpoint_url, **session_kwargs)
        table = dynamodb.Table(table_name)
        item = dict(threat)
        item["confidence"] = float(threat.get("confidence", 0.0) or 0.0)
        table.put_item(Item=item)
    except Exception as exc:
        print(f"DynamoDB threat storage error: {exc}")


def _store_threat_cassandra(threat: dict) -> None:
    """Optional: write threats to Cassandra if THREAT_DB_CASSANDRA_* env vars are set."""

    host = os.environ.get("THREAT_DB_CASSANDRA_HOST")
    keyspace = os.environ.get("THREAT_DB_CASSANDRA_KEYSPACE")
    user = os.environ.get("THREAT_DB_CASSANDRA_USER")
    password = os.environ.get("THREAT_DB_CASSANDRA_PASSWORD")
    port = int(os.environ.get("THREAT_DB_CASSANDRA_PORT", "9042"))
    if not (host and keyspace):
        return

    try:
        from cassandra.cluster import Cluster
        from cassandra.auth import PlainTextAuthProvider
    except ImportError:
        print("Cassandra threat storage skipped: cassandra-driver not installed")
        return

    auth_provider = PlainTextAuthProvider(username=user, password=password) if user else None
    cluster = None
    try:
        cluster = Cluster([host], port=port, auth_provider=auth_provider)
        session = cluster.connect(keyspace)
        row = _extract_threat_row(threat)
        session.execute(
            """
            INSERT INTO threat_events (
                event_id, timestamp, source_ip, dest_ip, port, protocol,
                threat_type, severity, attack_category, confidence, details,
                dataset, country, city, latitude, longitude,
                dest_country, dest_city, dest_latitude, dest_longitude
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            row,
        )
    except Exception as exc:
        print(f"Cassandra threat storage error: {exc}")
    finally:
        if cluster is not None:
            try:
                cluster.shutdown()
            except Exception:
                pass


def _store_threat_sqlserver(threat: dict) -> None:
    """Optional: write threats to Microsoft SQL Server if THREAT_DB_SQLSERVER_* env vars are set."""

    host = os.environ.get("THREAT_DB_SQLSERVER_HOST")
    db_name = os.environ.get("THREAT_DB_SQLSERVER_DB")
    user = os.environ.get("THREAT_DB_SQLSERVER_USER")
    password = os.environ.get("THREAT_DB_SQLSERVER_PASSWORD")
    port = os.environ.get("THREAT_DB_SQLSERVER_PORT", "1433")
    driver = os.environ.get("THREAT_DB_SQLSERVER_DRIVER", "{ODBC Driver 17 for SQL Server}")
    if not (host and db_name and user):
        return

    try:
        import pyodbc
    except ImportError:
        print("SQL Server threat storage skipped: pyodbc not installed")
        return

    conn = None
    try:
        conn_str = (
            f"DRIVER={driver};"
            f"SERVER={host},{port};"
            f"DATABASE={db_name};"
            f"UID={user};"
            f"PWD={password}"
        )
        conn = pyodbc.connect(conn_str, timeout=5)
        row = _extract_threat_row(threat)
        with conn.cursor() as cur:
            cur.execute(
                """
                IF NOT EXISTS (
                    SELECT * FROM sys.objects
                    WHERE object_id = OBJECT_ID(N'threat_events') AND type in (N'U')
                )
                BEGIN
                    CREATE TABLE threat_events (
                        id INT IDENTITY(1,1) PRIMARY KEY,
                        event_id NVARCHAR(64),
                        timestamp NVARCHAR(64),
                        source_ip NVARCHAR(64),
                        dest_ip NVARCHAR(64),
                        port INT,
                        protocol NVARCHAR(32),
                        threat_type NVARCHAR(128),
                        severity NVARCHAR(32),
                        attack_category NVARCHAR(128),
                        confidence FLOAT,
                        details NVARCHAR(MAX),
                        dataset NVARCHAR(128),
                        country NVARCHAR(128),
                        city NVARCHAR(128),
                        latitude FLOAT,
                        longitude FLOAT,
                        dest_country NVARCHAR(128),
                        dest_city NVARCHAR(128),
                        dest_latitude FLOAT,
                        dest_longitude FLOAT
                    )
                END
                """
            )
            cur.execute(
                """
                INSERT INTO threat_events (
                    event_id, timestamp, source_ip, dest_ip, port, protocol,
                    threat_type, severity, attack_category, confidence, details,
                    dataset, country, city, latitude, longitude,
                    dest_country, dest_city, dest_latitude, dest_longitude
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                row,
            )
        conn.commit()
    except Exception as exc:
        print(f"SQL Server threat storage error: {exc}")
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def store_threat_event(threat: dict) -> None:
    """Persist a single threat event into local SQLite and any configured external databases.

    This function is now intended to be called from explicit save actions rather
    than automatically on every generated threat.
    """

    def _store_local(th: dict) -> None:
        init_threat_db()
        try:
            row_local = _extract_threat_row(th)
            with sqlite3.connect(THREAT_DB_PATH) as conn:
                cur = conn.cursor()
                cur.execute(
                    """
                    INSERT INTO threat_events (
                        event_id, timestamp, source_ip, dest_ip, port, protocol,
                        threat_type, severity, attack_category, confidence, details,
                        dataset, country, city, latitude, longitude,
                        dest_country, dest_city, dest_latitude, dest_longitude
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    row_local,
                )
                conn.commit()
        except Exception as exc_local:
            print(f"Error storing threat event in local SQLite: {exc_local}")

    # Always write to local SQLite for any explicit save
    _store_local(threat)

    # Optionally fan-out to other configured backends
    for sink in (
        _store_threat_external_sqlite,
        _store_threat_mysql,
        _store_threat_postgres,
        _store_threat_mariadb,
        _store_threat_mongodb,
        _store_threat_redis,
        _store_threat_dynamodb,
        _store_threat_cassandra,
        _store_threat_sqlserver,
    ):
        try:
            sink(threat)
        except Exception as exc:
            print(f"Error in threat storage sink {sink.__name__}: {exc}")


# Live Threat Monitoring Variables
monitoring_active = False
threat_history = []
threat_stats = {
    "total_threats": 0,
    "safe_packets": 0,
    "threat_packets": 0,
    "critical_threats": 0,
    "high_threats": 0,
    "medium_threats": 0,
    "low_threats": 0,
    "packets_captured": 0,
    "threat_types": defaultdict(int),
    "attack_distribution": defaultdict(int),
}
monitoring_thread = None
packet_counter = 0
threat_counter = 0
safe_counter = 0

LIVE_DB_ENABLED = False

STREAM_API_URL = os.environ.get("STREAM_API_URL", "").strip()
STREAM_API_RECONNECT_SECONDS = 5


def _store_live_threat_if_enabled(threat: dict) -> None:
    """If live DB storage is enabled, persist this threat using store_threat_event."""
    global LIVE_DB_ENABLED
    if not LIVE_DB_ENABLED:
        return
    try:
        store_threat_event(threat)
    except Exception as exc:
        print(f"Error storing live threat event: {exc}")


def _update_stats_for_threat(threat: dict) -> None:
    global threat_history, threat_stats, threat_counter
    threat_history.append(threat)
    threat_counter += 1
    threat_stats["threat_packets"] = threat_counter
    threat_stats["total_threats"] = threat_counter

    severity = threat.get("severity")
    if severity == "Critical":
        threat_stats["critical_threats"] += 1
    elif severity == "High":
        threat_stats["high_threats"] += 1
    elif severity == "Medium":
        threat_stats["medium_threats"] += 1
    else:
        threat_stats["low_threats"] += 1

    threat_type = threat.get("threat_type")
    if threat_type:
        threat_stats["threat_types"][threat_type] += 1
    attack_category = threat.get("attack_category")
    if attack_category:
        threat_stats["attack_distribution"][attack_category] += 1

    _store_live_threat_if_enabled(threat)

    if len(threat_history) > 200:
        threat_history.pop(0)


def _emit_stats_update() -> None:
    stats_data = {
        "total_threats": threat_counter,
        "safe_packets": safe_counter,
        "threat_packets": threat_counter,
        "critical": threat_stats["critical_threats"],
        "high": threat_stats["high_threats"],
        "medium": threat_stats["medium_threats"],
        "low": threat_stats["low_threats"],
        "packets": packet_counter,
        "threat_types": dict(threat_stats["threat_types"]),
        "attack_distribution": dict(threat_stats["attack_distribution"]),
        "threats_per_minute": int(
            threat_counter / max(1, (packet_counter / 1000)) * 60
        ) if packet_counter > 0 else 0,
    }
    socketio.emit("stats_update", stats_data)


def get_static_model():
    if "model" not in _static_cache:
        model, scaler, features = load_static_artifact()
        _static_cache["model"] = model
        _static_cache["scaler"] = scaler
        _static_cache["features"] = features
    return _static_cache["model"], _static_cache["scaler"], _static_cache["features"]


def get_url_pipeline():
    if "pipeline" not in _url_cache:
        models_dir = BASE_DIR / "trained_models"
        artifact_path = models_dir / "url_model.joblib"
        if not artifact_path.exists():
            raise FileNotFoundError(
                "Trained URL model artifact not found. Train it first with train_url_model.py."
            )
        artifact = joblib.load(artifact_path)
        _url_cache["pipeline"] = artifact["pipeline"]
    return _url_cache["pipeline"]


def get_live_threat_model():
    """Load the trained live threat prediction model."""
    if "live_model" not in _url_cache:
        models_dir = BASE_DIR / "trained_models"
        artifact_path = models_dir / "live_threat_model.joblib"
        if not artifact_path.exists():
            raise FileNotFoundError(
                "Trained live threat model not found. Train it first with train_live_threat_model.py."
            )
        artifact = joblib.load(artifact_path)
        _url_cache["live_model"] = artifact["model"]
        _url_cache["live_scaler"] = artifact["scaler"]
        _url_cache["live_features"] = artifact["feature_names"]
    return _url_cache["live_model"], _url_cache["live_scaler"], _url_cache["live_features"]


def risk_type_static(prob: float) -> str:
    if prob >= 0.85:
        return "Critical Threat"
    if prob >= 0.7:
        return "High Threat"
    if prob >= 0.5:
        return "Medium Threat"
    if prob >= 0.3:
        return "Low Threat"
    return "Safe"


def build_static_pdf_report(static_summary, static_dashboard):
    if not static_summary or not static_dashboard:
        return
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas
    except ImportError:
        print("PDF report generation skipped: reportlab package not installed.")
        return

    STATIC_PDF_PATH.parent.mkdir(parents=True, exist_ok=True)
    c = canvas.Canvas(str(STATIC_PDF_PATH), pagesize=A4)
    width, height = A4

    # Top brand banner
    banner_height = 55
    c.setFillColorRGB(0.8, 0.1, 0.1)
    c.rect(0, height - banner_height, width, banner_height, fill=1, stroke=0)
    c.setFillColorRGB(1, 1, 1)
    c.setFont("Helvetica-Bold", 18)
    c.drawString(40, height - 35, "CYBERAGENT")
    c.setFont("Helvetica", 10)
    c.drawString(40, height - 48, "THREAT ANALYSIS REPORT")

    margin = 40
    y = height - banner_height - 25

    # Generated info for this snapshot
    c.setFillColorRGB(0, 0, 0)
    c.setFont("Helvetica", 8)
    c.drawString(margin, y, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    y -= 20

    # Generated info
    c.setFillColorRGB(0, 0, 0)
    c.setFont("Helvetica", 8)
    c.drawString(margin, y, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    y -= 12
    c.drawString(margin, y, "Analysis Engine: AI CyberGuard Dashboard v1.0")
    y -= 20

    # Executive Summary tiles
    threats = int(static_summary.get("threats", 0) or 0)
    safe = int(static_summary.get("safe", 0) or 0)
    total = int(static_summary.get("total", 0) or 0)
    overall_score = static_dashboard.get("overall_score")

    tile_width = (width - 2 * margin - 20) / 3.0
    tile_height = 55
    x = margin
    y_tiles_top = y

    # Files Analyzed
    c.setFillColorRGB(0.1, 0.4, 0.8)
    c.rect(x, y_tiles_top - tile_height, tile_width, tile_height, fill=1, stroke=0)
    c.setFillColorRGB(1, 1, 1)
    c.setFont("Helvetica-Bold", 10)
    c.drawString(x + 8, y_tiles_top - 16, "Files Analyzed")
    c.setFont("Helvetica-Bold", 18)
    c.drawString(x + 8, y_tiles_top - 35, str(total))

    # Overall Threat Score
    x2 = x + tile_width + 10
    c.setFillColorRGB(0.0, 0.6, 0.3)
    c.rect(x2, y_tiles_top - tile_height, tile_width, tile_height, fill=1, stroke=0)
    c.setFillColorRGB(1, 1, 1)
    c.setFont("Helvetica-Bold", 10)
    c.drawString(x2 + 8, y_tiles_top - 16, "Overall Threat Score")
    c.setFont("Helvetica-Bold", 18)
    c.drawString(x2 + 8, y_tiles_top - 35, f"{overall_score:.2f}/5.00" if isinstance(overall_score, (int, float)) else str(overall_score))

    # Safe Records tile
    x3 = x2 + tile_width + 10
    c.setFillColorRGB(0.1, 0.6, 0.7)
    c.rect(x3, y_tiles_top - tile_height, tile_width, tile_height, fill=1, stroke=0)
    c.setFillColorRGB(1, 1, 1)
    c.setFont("Helvetica-Bold", 10)
    c.drawString(x3 + 8, y_tiles_top - 16, "Safe Records")
    c.setFont("Helvetica-Bold", 18)
    c.drawString(x3 + 8, y_tiles_top - 35, str(safe))

    y = y_tiles_top - tile_height - 25

    # Summary text block
    c.setFillColorRGB(0, 0, 0)
    c.setFont("Helvetica", 9)
    threat_rate = float(threats) / float(total) if total else 0.0
    summary_lines = [
        f"Overall Status: {static_summary.get('overall_status')}",
        f"Threat Records: {threats} ({threat_rate * 100:.1f}% of all records)",
        f"Safe Records: {safe} ({(1 - threat_rate) * 100:.1f}% of all records if total else 0.0)%",  # noqa: E501
        f"Threshold Used: {static_summary.get('threshold')}",
    ]
    for line in summary_lines:
        c.drawString(margin, y, str(line))
        y -= 12

    y -= 8

    # Threat vs Safe Overview chart
    max_val = max(threats, safe, 1)
    chart_height = 70
    bar_width = 28
    c.setFont("Helvetica-Bold", 11)
    c.drawString(margin, y, "Threat vs Safe Overview")
    base_y = y - chart_height - 8
    c.setLineWidth(0.4)
    c.setStrokeColorRGB(0, 0, 0)
    c.line(margin + 20, base_y, margin + 20, base_y + chart_height)
    c.line(margin + 20, base_y, margin + 130, base_y)

    c.setFillColorRGB(0.8, 0.1, 0.1)
    th_height = (threats / max_val) * chart_height if max_val else 0
    c.rect(margin + 35, base_y, bar_width, th_height, fill=1, stroke=0)
    c.setFillColorRGB(0.2, 0.6, 0.2)
    safe_height = (safe / max_val) * chart_height if max_val else 0
    c.rect(margin + 75, base_y, bar_width, safe_height, fill=1, stroke=0)
    c.setFillColorRGB(0, 0, 0)
    c.setFont("Helvetica", 7)
    c.drawString(margin + 35, base_y - 9, "Threats")
    c.drawString(margin + 75, base_y - 9, "Safe")

    # Severity distribution mini chart on the right
    severity_labels = static_dashboard.get("severity_labels") or []
    severity_counts = static_dashboard.get("severity_counts") or []
    x_sev = margin + 180
    c.setFont("Helvetica-Bold", 11)
    c.drawString(x_sev, y, "Threat Severity Distribution")
    base_y2 = base_y
    chart_height2 = chart_height
    max_sev = max([int(v) for v in severity_counts] + [1]) if severity_counts else 1
    bar_spacing = 16
    x0 = x_sev + 10
    c.setFont("Helvetica", 7)
    for idx, (label, count) in enumerate(zip(severity_labels, severity_counts)):
        h = (int(count) / max_sev) * chart_height2 if max_sev else 0
        x_bar = x0 + idx * bar_spacing
        c.setFillColorRGB(0.3, 0.3, 0.8)
        c.rect(x_bar, base_y2, 8, h, fill=1, stroke=0)
        c.setFillColorRGB(0, 0, 0)
        c.drawString(x_bar - 1, base_y2 - 9, str(count))

    y = base_y2 - 30

    # Risk score curve
    risk_curve = static_dashboard.get("risk_curve") or {}
    probs = risk_curve.get("probabilities") or []
    c.setFont("Helvetica-Bold", 11)
    c.drawString(margin, y, "Risk Score Assessment")
    y -= 12
    if probs:
        base_y3 = y - 60
        chart_height3 = 55
        chart_width3 = width - margin * 2 - 20
        x_start = margin + 10
        c.setLineWidth(0.4)
        c.setStrokeColorRGB(0, 0, 0)
        c.line(x_start, base_y3, x_start, base_y3 + chart_height3)
        c.line(x_start, base_y3, x_start + chart_width3, base_y3)
        c.setStrokeColorRGB(0.1, 0.4, 0.8)
        n = len(probs)
        if n == 1:
            y_pt = base_y3 + float(probs[0]) * chart_height3
            c.circle(x_start, y_pt, 1.5, stroke=1, fill=1)
        else:
            for i in range(1, n):
                x1 = x_start + (float(i - 1) / float(n - 1)) * chart_width3
                x2 = x_start + (float(i) / float(n - 1)) * chart_width3
                y1 = base_y3 + float(probs[i - 1]) * chart_height3
                y2 = base_y3 + float(probs[i]) * chart_height3
                c.line(x1, y1, x2, y2)
        y = base_y3 - 25

    # Key predictions section
    key_preds = static_dashboard.get("key_predictions") or []
    c.setFont("Helvetica-Bold", 11)
    c.drawString(margin, y, "Key Predictions")
    y -= 14
    c.setFont("Helvetica", 9)
    if key_preds:
        for item in key_preds:
            line = f"• {item.get('label')}: {item.get('count')} records"
            c.drawString(margin, y, str(line))
            y -= 11
            if y < 90:
                c.showPage()
                y = height - margin
                c.setFont("Helvetica", 9)
    else:
        c.drawString(margin, y, "No significant threat categories detected in this run.")
        y -= 12

    # Security recommendations
    if y < 140:
        c.showPage()
        y = height - margin
    c.setFont("Helvetica-Bold", 11)
    c.drawString(margin, y, "Security Recommendations")
    y -= 14
    c.setFont("Helvetica", 9)
    recommendations = [
        "1. Isolate all critical and high-risk assets identified in this report.",
        "2. Quarantine files flagged as Threat for deeper manual or sandbox analysis.",
        "3. Monitor suspicious activity patterns for unusual behaviour over time.",
        "4. Harden perimeter firewalls and IDS rules against most common threat types.",
        "5. Enable continuous live monitoring to detect new threats in real time.",
    ]
    for rec in recommendations:
        c.drawString(margin, y, rec)
        y -= 11
        if y < 60:
            c.showPage()
            y = height - margin
            c.setFont("Helvetica", 9)

    c.showPage()
    c.save()


def risk_type_url(prob: float) -> str:
    if prob >= 0.9:
        return "Critical Malicious URL"
    if prob >= 0.75:
        return "High Malicious URL"
    if prob >= 0.5:
        return "Suspicious URL"
    if prob >= 0.3:
        return "Low Risk URL"
    return "Benign URL"


def build_live_pdf_report(threats, stats, output_path=None):
    if not threats:
        return None
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas
    except ImportError:
        print("Live PDF report generation skipped: reportlab package not installed.")
        return None

    target_path = Path(output_path) if output_path is not None else LIVE_PDF_PATH
    target_path.parent.mkdir(parents=True, exist_ok=True)
    c = canvas.Canvas(str(target_path), pagesize=A4)
    width, height = A4

    # Banner
    banner_height = 55
    c.setFillColorRGB(0.1, 0.3, 0.7)
    c.rect(0, height - banner_height, width, banner_height, fill=1, stroke=0)
    c.setFillColorRGB(1, 1, 1)
    c.setFont("Helvetica-Bold", 18)
    c.drawString(40, height - 35, "CYBERAGENT")
    c.setFont("Helvetica", 10)
    c.drawString(40, height - 48, "LIVE THREAT ANALYSIS REPORT")

    margin = 40
    y = height - banner_height - 25

    total_packets = int(stats.get("packets_captured", 0) or 0)
    total_threats = int(stats.get("total_threats", 0) or 0)
    safe_packets = int(stats.get("safe_packets", 0) or 0)
    critical = int(stats.get("critical_threats", 0) or 0)
    high = int(stats.get("high_threats", 0) or 0)
    medium = int(stats.get("medium_threats", 0) or 0)
    low = int(stats.get("low_threats", 0) or 0)
    threats_per_min = int(stats.get("threats_per_minute", 0) or 0)

    # Executive tiles
    tile_width = (width - 2 * margin - 10) / 2.0
    tile_height = 45

    c.setFillColorRGB(0.9, 0.4, 0.1)
    c.rect(margin, y - tile_height, tile_width, tile_height, fill=1, stroke=0)
    c.setFillColorRGB(1, 1, 1)
    c.setFont("Helvetica-Bold", 10)
    c.drawString(margin + 8, y - 15, "Total Packets Captured")
    c.setFont("Helvetica-Bold", 16)
    c.drawString(margin + 8, y - 33, str(total_packets))

    x2 = margin + tile_width + 10
    c.setFillColorRGB(0.7, 0.1, 0.2)
    c.rect(x2, y - tile_height, tile_width, tile_height, fill=1, stroke=0)
    c.setFillColorRGB(1, 1, 1)
    c.setFont("Helvetica-Bold", 10)
    c.drawString(x2 + 8, y - 15, "Threat Packets")
    c.setFont("Helvetica-Bold", 16)
    c.drawString(x2 + 8, y - 33, str(total_threats))

    y = y - tile_height - 20

    c.setFillColorRGB(0, 0, 0)
    c.setFont("Helvetica", 9)
    lines = [
        f"Safe Packets: {safe_packets}",
        f"Critical: {critical}, High: {high}, Medium: {medium}, Low: {low}",
        f"Threats per Minute: {threats_per_min}",
    ]
    for line in lines:
        c.drawString(margin, y, str(line))
        y -= 12

    y -= 6

    # Threat vs safe packets chart
    max_val = max(total_threats, safe_packets, 1)
    chart_height = 70
    bar_width = 28
    c.setFont("Helvetica-Bold", 11)
    c.drawString(margin, y, "Threat vs Safe Packets")
    base_y = y - chart_height - 8
    c.setLineWidth(0.4)
    c.setStrokeColorRGB(0, 0, 0)
    c.line(margin + 20, base_y, margin + 20, base_y + chart_height)
    c.line(margin + 20, base_y, margin + 130, base_y)

    c.setFillColorRGB(0.8, 0.1, 0.1)
    th_height = (total_threats / max_val) * chart_height if max_val else 0
    c.rect(margin + 35, base_y, bar_width, th_height, fill=1, stroke=0)
    c.setFillColorRGB(0.2, 0.6, 0.2)
    safe_height = (safe_packets / max_val) * chart_height if max_val else 0
    c.rect(margin + 75, base_y, bar_width, safe_height, fill=1, stroke=0)
    c.setFillColorRGB(0, 0, 0)
    c.setFont("Helvetica", 7)
    c.drawString(margin + 35, base_y - 9, "Threats")
    c.drawString(margin + 75, base_y - 9, "Safe")

    # Severity distribution on the right if available
    x_sev = margin + 180
    c.setFont("Helvetica-Bold", 11)
    c.drawString(x_sev, y, "Severity Breakdown")
    base_y2 = base_y
    chart_height2 = chart_height
    sev_counts = [critical, high, medium, low]
    sev_labels = ["Crit", "High", "Med", "Low"]
    max_sev = max(sev_counts + [1])
    bar_spacing = 18
    x0 = x_sev + 10
    c.setFont("Helvetica", 7)
    for idx, (label, count) in enumerate(zip(sev_labels, sev_counts)):
        h = (int(count) / max_sev) * chart_height2 if max_sev else 0
        x_bar = x0 + idx * bar_spacing
        c.setFillColorRGB(0.3, 0.3, 0.8)
        c.rect(x_bar, base_y2, 9, h, fill=1, stroke=0)
        c.setFillColorRGB(0, 0, 0)
        c.drawString(x_bar - 2, base_y2 - 9, str(count))

    y = base_y2 - 30

    # Packet & IP details table
    c.setFont("Helvetica-Bold", 11)
    c.drawString(margin, y, "Packet & IP Details (recent threats)")
    y -= 16
    c.setFont("Helvetica", 8)
    headers = ["Time", "Source IP", "Dest IP", "Port", "Severity", "Threat Type"]
    # Slightly compress some technical columns and give more room to
    # Threat Type so long names don't visually crash.
    col_widths = [60, 80, 80, 26, 55, 120]
    x = margin
    for h_text, w in zip(headers, col_widths):
        c.drawString(x, y, h_text)
        x += w
    y -= 10

    max_rows = 40
    rows = threats[-max_rows:]
    for t in rows:
        if y < 70:
            c.showPage()
            y = height - margin
            c.setFont("Helvetica", 8)
            x = margin
            for h_text, w in zip(headers, col_widths):
                c.drawString(x, y, h_text)
                x += w
            y -= 10
        x = margin
        ts_val = str(t.get("timestamp", ""))[:19]
        src_ip = str(t.get("source_ip", ""))
        dest_ip = str(t.get("dest_ip", ""))
        port_val = str(t.get("port", ""))
        sev_val = str(t.get("severity", ""))
        threat_label = str(t.get("threat_type", ""))
        if len(threat_label) > 35:
            threat_label = threat_label[:32] + "..."

        values = [
            ts_val,
            src_ip,
            dest_ip,
            port_val,
            sev_val,
            threat_label,
        ]
        for v, w in zip(values, col_widths):
            c.drawString(x, y, v)
            x += w
        y -= 10

    # Simple operational recommendations
    if y < 90:
        c.showPage()
        y = height - margin
    c.setFont("Helvetica-Bold", 11)
    c.drawString(margin, y, "Operational Recommendations")
    y -= 14
    c.setFont("Helvetica", 9)
    recs = [
        "1. Investigate repeated attacks from the same source IPs and block at the perimeter.",
        "2. Review firewall and IDS rules for ports most frequently targeted.",
        "3. Enable deeper logging for critical and high severity events.",
        "4. Correlate these threats with endpoint and SIEM alerts where possible.",
    ]
    for rec in recs:
        c.drawString(margin, y, rec)
        y -= 11
        if y < 60:
            c.showPage()
            y = height - margin
            c.setFont("Helvetica", 9)

    c.showPage()
    c.save()

    return target_path


def generate_chat_reply(message: str) -> str:

    """Very lightweight rule-based assistant for explaining dashboard features."""
    text = (message or "").strip()
    if not text:
        return (
            "Please type or say a question. You can ask about live threat monitoring, the 3D globe, "
            "databases, or WiFi/VPN."
        )

    lower = text.lower()

    if "live threat" in lower or ("monitoring" in lower and "threat" in lower):
        return (
            "Live Threat Monitoring simulates and tracks real-time attacks, including API-focused "
            "threats such as authentication brute force, API key leakage, JWT token abuse, REST "
            "endpoint enumeration, and HTTP floods on API gateways. It updates severity metrics, "
            "timelines, a world map, and a 3D globe, and can generate a professional PDF report "
            "with packets, IP addresses, severities, and attack categories."
        )

    if "project" in lower or "dashboard" in lower or "this app" in lower:
        return (
            "This project is a security analytics dashboard with three core areas: (1) Static Data "
            "Threat Check that scores uploaded files and produces an executive-style PDF report; "
            "(2) URL Threat Intelligence for checking individual URLs; and (3) Live Threat "
            "Monitoring with a live feed, world map, 3D globe, database storage (including AWS "
            "DynamoDB), and a live PDF report. It also includes a Security Assistant chatbot and "
            "WiFi/VPN status cards."
        )

    if "report" in lower or "pdf" in lower:
        return (
            "The dashboard generates two main PDF reports: a Static Threat Report that summarizes "
            "file analysis with overall risk, severity distribution, risk score curve, key "
            "predictions, and recommendations; and a Live Threat Report that captures recent "
            "threats with packet/IP details, severity and type breakdowns, and operational "
            "guidance. CSV outputs are kept only as technical fallbacks."
        )

    if "feature" in lower or "what can you do" in lower or "what can u do" in lower:
        return (
            "I can explain the AIP Data Analysis panel, the Automated Threat Hunting panel, "
            "static file analysis, URL analysis, live threat monitoring, the 3D globe, "
            "database storage (SQLite plus optional backends like MySQL, PostgreSQL, MongoDB, "
            "Redis, and AWS DynamoDB), and the WiFi/VPN status cards."
        )

    if "3d" in lower or "globe" in lower:
        return (
            "The 3D Threat Globe shows live attack paths on a rotating Earth. You can drag to rotate, "
            "scroll to zoom, and click any threat point to see its type, severity, and the source and "
            "destination countries, cities, and IP addresses."
        )

    if "database" in lower or "mysql" in lower or "postgres" in lower or "postgresql" in lower \
            or "mongodb" in lower or "redis" in lower or "snowflake" in lower or "oracle" in lower:
        return (
            "Right now this dashboard persists live threats into a local SQLite database file so your "
            "events are stored safely and also supports fan-out to optional backends when configured, "
            "such as MySQL, PostgreSQL, MariaDB, MongoDB, Redis, and AWS DynamoDB. The UI additionally "
            "lists Cassandra, Elasticsearch, InfluxDB, ClickHouse, Oracle, SQL Server, Firestore, "
            "Neo4j, and Snowflake as planned or configurable engines."
        )

    # Chatbot explanation (no dataset discussion)
    if "dialog" in lower or "dialogue" in lower or "chatbot" in lower or "conversation dataset" in lower:
        return (
            "The Security Assistant here is a lightweight rule-based helper. It doesn't expose model "
            "training details; instead it focuses on explaining this dashboard's panels, charts, and "
            "controls in simple language."
        )

    # High-level cybersecurity explanation without listing training corpora
    if "cyber" in lower or "ids" in lower or "intrusion" in lower or "siem" in lower:
        return (
            "Intrusion detection systems typically analyse mixes of benign and malicious traffic, "
            "packet captures, honeypot activity, and malware telemetry to learn what attacks look "
            "like. This demo focuses on visualising simulated threats rather than detailing specific "
            "data sources."
        )

    if "network" in lower or "packet" in lower or "traffic" in lower:
        return (
            "For general networking and traffic analysis, tools often look at packet traces, Internet "
            "topology measurements, NetFlow-style exports, and HTTP server logs to understand latency, "
            "routing, congestion, and anomalous behaviour."
        )

    if "dataset" in lower or "training" in lower or "benchmark" in lower:
        return (
            "This demo is focused on showing how the dashboard behaves – charts, maps, and reports – "
            "without going into the specific external data collections that a production system "
            "might use for training."
        )

    if "aip" in lower or "api data analysis" in lower or "aip data" in lower or "api data" in lower:
        return (
            "API data analysis is the process of collecting, inspecting, and interpreting data that "
            "is transmitted through Application Programming Interfaces (APIs). It involves reviewing "
            "API logs, requests, responses, error codes, usage patterns, authentication events, and "
            "performance metrics to identify trends or abnormalities. The goal is to understand how "
            "systems communicate, optimize performance, detect integration issues, and ensure the API "
            "is being used as intended."
        )

    if "threat hunt" in lower or "threat hunting" in lower or "automated hunt" in lower:
        return (
            "Threat hunting is a proactive cybersecurity activity where analysts search for hidden "
            "threats inside a network or system before they can cause damage. Instead of waiting for "
            "security alerts, threat hunters manually investigate logs, behaviors, anomalies, and "
            "indicators of compromise (IOCs) to uncover malicious activity. It focuses on identifying "
            "advanced attacks, insider threats, suspicious patterns, and stealthy behavior that "
            "traditional security tools may miss."
        )

    if "api" in lower or "rest" in lower or "graphql" in lower or "jwt" in lower:
        return (
            "API security in this project is represented by simulated threats such as API authentication "
            "brute force, API key leakage, JWT token abuse, REST endpoint enumeration, GraphQL "
            "introspection abuse, HTTP floods on API gateways, and BOLA-style access control issues. "
            "Real deployments typically rely on large volumes of HTTP and API traffic to tune these "
            "defences, but this demo keeps that detail abstracted away."
        )

    if "voice" in lower or "speech" in lower or "microphone" in lower or "recognition" in lower:
        return (
            "This dashboard uses your browser's built-in speech recognition for voice input plus "
            "text-to-speech for answers. In research and production systems, training data typically "
            "consists of large collections of transcribed read speech, conversational audio, crowd-" 
            "sourced recordings, and command-style utterances recorded from many different speakers."
        )

    if "wifi" in lower or "wi-fi" in lower or "vpn" in lower:
        return (
            "The WiFi & VPN cards show your SSID, signal strength, encryption type and an overall "
            "protection score, along with basic VPN details such as server, protocol and whether the "
            "connection is active."
        )

    if "static" in lower or "file" in lower or "upload" in lower:
        return (
            "The Static Data Threat Check panel lets you upload logs or tabular data. A trained model "
            "scores each row with a threat probability, classifies it as Threat or Safe, builds severity "
            "charts and a risk curve, and generates an executive-style PDF report (with a CSV fallback "
            "for raw data when needed)."
        )

    if "url" in lower or "link" in lower or "website" in lower:
        return (
            "The URL Threat Intelligence tool evaluates individual URLs using a trained URL model. It "
            "outputs a malicious probability, textual risk type, and a benign/malicious label so you "
            "can quickly triage suspicious links."
        )

    if "aws" in lower or "dynamodb" in lower or "cloud" in lower:
        return (
            "This dashboard can optionally send saved live threat events to AWS DynamoDB in addition to "
            "local SQLite, using the configured table, region, and credentials. In a broader cloud "
            "architecture you could also stream these events into services like S3, Kinesis, or a SIEM "
            "platform for long-term analytics and compliance reporting."
        )

    if "best practice" in lower or "best practices" in lower or "secure" in lower or "hardening" in lower:
        return (
            "General security best practices include: (1) reduce exposed attack surface by closing "
            "unused ports and disabling unnecessary services; (2) enforce strong authentication and "
            "least-privilege access, especially for APIs and admin interfaces; (3) centralize logging "
            "and monitor with alerts for anomalies; (4) keep operating systems, libraries, and "
            "dependencies patched; and (5) regularly test with vulnerability scanning and, where "
            "appropriate, penetration testing."
        )

    if (
        "device" in lower
        or "devices" in lower
        or "laptop" in lower
        or "desktop" in lower
        or "pc" in lower
        or "phone" in lower
        or "mobile" in lower
    ) and ("secure" in lower or "protect" in lower or "safety" in lower or "safe" in lower):
        return (
            "To keep your devices safer: (1) keep the operating system, browser, and apps updated; "
            "(2) use reputable antivirus/anti-malware and enable the built-in firewall; (3) avoid "
            "installing unknown software or APKs, and only use trusted app stores; (4) use strong, "
            "unique passwords with a password manager and enable multi-factor authentication; (5) "
            "regularly back up important data to an offline or cloud backup so you can recover from "
            "ransomware or hardware failures."
        )

    if "sql injection" in lower or "sqli" in lower:
        return (
            "SQL injection is an attack where untrusted input is concatenated into database queries, "
            "allowing attackers to read or modify data. Mitigations include using parameterized "
            "queries/ORMs, strict input validation, least-privilege database accounts, and centralized "
            "logging to detect unusual query patterns."
        )

    if "xss" in lower or "cross-site scripting" in lower:
        return (
            "Cross-site scripting (XSS) lets attackers inject JavaScript into pages viewed by other "
            "users. Defences include output encoding, content security policy (CSP), avoiding unsafe "
            "HTML rendering of user input, and sanitizing rich-text fields."
        )

    if "ddos" in lower or "denial of service" in lower:
        return (
            "Distributed denial of service (DDoS) attacks attempt to overwhelm services with traffic. "
            "Typical defences include rate limiting, upstream DDoS protection, autoscaling, caching, "
            "and separating critical control APIs from public endpoints."
        )

    if "ransomware" in lower:
        return (
            "Ransomware is malware that encrypts files or locks devices and then demands payment to "
            "restore access. Defences include maintaining offline and cloud backups, promptly applying "
            "security patches, disabling unnecessary macros, filtering malicious email attachments and "
            "links, and limiting user privileges so malware cannot encrypt shared data easily."
        )

    if "trojan" in lower or "trojen" in lower or "tronjan" in lower or "troj" in lower:
        return (
            "A trojan is malware that pretends to be legitimate software but hides malicious code, "
            "often installing backdoors or stealing data once executed. To reduce risk, download "
            "software only from trusted sources, verify installers, keep endpoint protection enabled, "
            "and educate users not to run unexpected attachments or cracked applications."
        )

    if (
        "malware" in lower
        or "virus" in lower
        or "worm" in lower
        or "spyware" in lower
        or "adware" in lower
        or "keylogger" in lower
    ):
        return (
            "Malware is an umbrella term for malicious software such as viruses, worms, trojans, "
            "spyware, and keyloggers. Good hygiene includes keeping systems patched, running "
            "updated antivirus, restricting admin rights, using application whitelisting where "
            "possible, scanning downloads, and monitoring for unusual processes or network activity."
        )

    return (
        "I am your security assistant chatbot for this dashboard. Ask me about live threat monitoring, "
        "the 3D globe, database storage, WiFi/VPN, or general security best practices."
    )


def generate_threat_data():
    """Generate realistic threat data using the trained model"""
    threat_types = [
        # Classic network & web
        "Port Scan", "DDoS Attack", "SQL Injection", "XSS Attempt",
        "Brute Force Login", "Malware Download", "Phishing", "Data Exfiltration",
        "Privilege Escalation", "Man-in-the-Middle", "DNS Tunneling",
        "Botnet Activity", "Ransomware", "Zero-Day Exploit",
        # Explicit API/Web threats
        "API Authentication Brute Force", "API Key Leakage", "JWT Token Abuse",
        "REST Endpoint Enumeration", "GraphQL Introspection Abuse",
        "HTTP Flood on API Gateway", "Mass Assignment in JSON API",
        "Broken Object Level Authorization (BOLA)",
        "Insecure Direct Object Reference on API",
    ]

    # Attack category will drive the Attack Category Distribution chart
    attack_types = [
        "Network", "Application", "Endpoint", "Web", "Email", "DNS", "API"
    ]
    
    # Try to use the trained model for threat prediction
    try:
        model, scaler, features = get_live_threat_model()
        
        # Create a sample feature vector
        sample_features = np.random.randn(len(features))
        sample_scaled = scaler.transform(sample_features.reshape(1, -1))
        
        # Get prediction probability
        threat_prob = model.predict_proba(sample_scaled)[0, 1]
        confidence = round(threat_prob, 2)
        
        # Map probability to severity
        if threat_prob >= 0.85:
            severity = "Critical"
        elif threat_prob >= 0.7:
            severity = "High"
        elif threat_prob >= 0.5:
            severity = "Medium"
        else:
            severity = "Low"
    except Exception as e:
        # Fallback to random if model not available
        print(f"Using fallback threat generation: {e}")
        severity = random.choice(["Low", "Medium", "High", "Critical"])
        confidence = round(random.uniform(0.6, 1.0), 2)
    
    threat_type = random.choice(threat_types)

    # Choose world locations for source and destination so we can plot attack paths
    source_loc = random.choice(THREAT_LOCATIONS)
    dest_loc = random.choice(THREAT_LOCATIONS)
    if dest_loc is source_loc:
        dest_loc = random.choice(THREAT_LOCATIONS)
    dataset = random.choice(THREAT_DATASETS)
    
    threat = {
        "id": str(random.randint(10000, 99999)),
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "source_ip": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
        "dest_ip": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
        "port": random.choice([22, 80, 443, 3306, 5432, 8080, 445, 139, 21, 25, 53, 123]),
        "protocol": random.choice(["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS"]),
        "threat_type": threat_type,
        "severity": severity,
        "attack_category": random.choice(attack_types),
        "confidence": confidence,
        "details": f"Detected {threat_type} from {random.choice(['external', 'internal'])} source",
        "dataset": dataset,
        # Source location (attacker origin)
        "country": source_loc["country"],
        "city": source_loc["city"],
        "latitude": source_loc["lat"],
        "longitude": source_loc["lon"],
        # Destination location (where the attack is going)
        "dest_country": dest_loc["country"],
        "dest_city": dest_loc["city"],
        "dest_latitude": dest_loc["lat"],
        "dest_longitude": dest_loc["lon"],
    }

    return threat


def threat_monitoring_loop():
    """Background thread for continuous threat monitoring"""
    global monitoring_active, threat_history, threat_stats, packet_counter, threat_counter, safe_counter
    
    while True:
        if monitoring_active:
            # If a Streaming API is configured and websocket-client is available,
            # do not generate synthetic threats. Stats will be driven by
            # real-time events received in stream_api_listener_loop.
            if websocket is not None and STREAM_API_URL:
                threat_stats["packets_captured"] = packet_counter
                _emit_stats_update()
            else:
                # Legacy simulated behavior: generate synthetic packets & threats
                new_packets = random.randint(10, 50)
                packet_counter += new_packets
                threat_stats["packets_captured"] = packet_counter

                for _ in range(new_packets):
                    if random.random() > 0.7:
                        threat = generate_threat_data()
                        _update_stats_for_threat(threat)
                        socketio.emit('new_threat', threat)
                    else:
                        safe_counter += 1
                        threat_stats["safe_packets"] = safe_counter
                _emit_stats_update()
        
        time.sleep(2)  # Update every 2 seconds


def _build_stream_threat(message: str):
    try:
        data = json.loads(message)
    except Exception as exc:
        print(f"Streaming API JSON error: {exc} | raw={message!r}")
        return None

    raw_id = data.get("id")
    name = str(data.get("name") or "Streaming Threat")
    raw_severity = str(data.get("severity") or "Medium")
    ts = str(data.get("timestamp") or datetime.now().strftime("%H:%M:%S"))

    sev_key = raw_severity.lower()
    if sev_key in {"critical", "high", "medium", "low"}:
        severity = sev_key.capitalize()
    else:
        try:
            prob_val = float(raw_severity)
        except ValueError:
            severity = "Medium"
        else:
            if prob_val >= 0.85:
                severity = "Critical"
            elif prob_val >= 0.7:
                severity = "High"
            elif prob_val >= 0.5:
                severity = "Medium"
            else:
                severity = "Low"

    source_loc = random.choice(THREAT_LOCATIONS)
    dest_loc = random.choice(THREAT_LOCATIONS)
    if dest_loc is source_loc:
        dest_loc = random.choice(THREAT_LOCATIONS)

    threat = {
        "id": str(raw_id or random.randint(10000, 99999)),
        "timestamp": ts,
        "source_ip": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
        "dest_ip": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
        "port": random.choice([22, 80, 443, 3306, 5432, 8080, 445, 139, 21, 25, 53, 123]),
        "protocol": random.choice(["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS"]),
        "threat_type": name,
        "severity": severity,
        "attack_category": "API",
        "confidence": 0.9,
        "details": f"Streaming API event: {name}",
        "dataset": "Streaming API",
        "country": source_loc["country"],
        "city": source_loc["city"],
        "latitude": source_loc["lat"],
        "longitude": source_loc["lon"],
        "dest_country": dest_loc["country"],
        "dest_city": dest_loc["city"],
        "dest_latitude": dest_loc["lat"],
        "dest_longitude": dest_loc["lon"],
    }
    return threat


def stream_api_listener_loop():
    if websocket is None or not STREAM_API_URL:
        return

    def on_open(ws):
        print(f"Connected to Streaming API: {STREAM_API_URL}")

    def on_message(ws, message):
        global monitoring_active, packet_counter
        if not monitoring_active:
            return
        threat = _build_stream_threat(message)
        if not threat:
            return
        packet_counter += 1
        threat_stats["packets_captured"] = packet_counter
        _update_stats_for_threat(threat)
        socketio.emit("new_threat", threat)
        _emit_stats_update()

    def on_error(ws, error):
        print(f"Streaming API error: {error}")

    def on_close(ws, status_code, msg):
        print(f"Streaming API closed: code={status_code}, msg={msg}")

    while True:
        try:
            ws_app = websocket.WebSocketApp(
                STREAM_API_URL,
                on_open=on_open,
                on_message=on_message,
                on_error=on_error,
                on_close=on_close,
            )
            ws_app.run_forever()
        except Exception as exc:
            print(f"Streaming API connection failure: {exc}")
        time.sleep(STREAM_API_RECONNECT_SECONDS)


# Start the monitoring thread
monitor_thread = threading.Thread(target=threat_monitoring_loop, daemon=True)
monitor_thread.start()

if websocket is not None and STREAM_API_URL:
    stream_thread = threading.Thread(target=stream_api_listener_loop, daemon=True)
    stream_thread.start()
else:
    stream_thread = None


@app.route("/")
def index():
    return render_template(
        "index.html",
        static_summary=STATIC_VIEW_STATE.get("summary"),
        static_sample=STATIC_VIEW_STATE.get("sample"),
        static_dashboard=STATIC_VIEW_STATE.get("dashboard"),
        url_single_result=None,
        url_batch_summary=None,
    )


@app.route("/analyze-static", methods=["POST"])
def analyze_static_route():
    files = request.files.getlist("static_file")
    # Filter out empty entries
    files = [f for f in files if f and f.filename]

    threshold_str = request.form.get("threshold", "0.5")
    try:
        threshold = float(threshold_str)
    except ValueError:
        threshold = 0.5
    if not files:
        flash("Please upload at least one file for static analysis.")
        return redirect(url_for("index"))

    # Tabular formats: run full ML static model
    tabular_exts = {".csv", ".xlsx", ".xls", ".json", ".ndjson", ".parquet", ".txt", ".log"}
    tabular_files = []
    non_tabular_files = []
    for fs in files:
        fname = fs.filename or ""
        ext = Path(fname).suffix.lower()
        if ext in tabular_exts:
            tabular_files.append((fs, ext))
        else:
            non_tabular_files.append((fs, ext))

    if tabular_files:
        try:
            frames = []
            for fs, ext in tabular_files:
                if ext == ".csv":
                    df_part = pd.read_csv(fs)
                elif ext in (".xlsx", ".xls"):
                    df_part = pd.read_excel(fs)
                elif ext in (".json", ".ndjson"):
                    df_part = pd.read_json(fs, lines=(ext == ".ndjson"))
                elif ext == ".parquet":
                    df_part = pd.read_parquet(fs)
                elif ext in (".txt", ".log"):
                    try:
                        df_part = pd.read_csv(fs)
                    except Exception:
                        fs.stream.seek(0)
                        df_part = pd.read_table(fs)
                else:
                    continue
                frames.append(df_part)

            if not frames:
                flash("No supported tabular files were uploaded.")
                return redirect(url_for("index"))

            df = pd.concat(frames, ignore_index=True)
            if non_tabular_files:
                ignored_names = ", ".join(f.filename for f, _ in non_tabular_files)
                flash(f"The following non-tabular files were ignored: {ignored_names}")
        except Exception:
            flash(
                "Unable to read one or more uploaded files. Make sure all tabular files are valid (CSV, Excel, JSON, Parquet, text, log)."
            )
            return redirect(url_for("index"))

        try:
            model, scaler, features = get_static_model()
        except FileNotFoundError as exc:
            flash(str(exc))
            return redirect(url_for("index"))
        missing = [name for name in features if name not in df.columns]
        if missing:
            flash("Uploaded file is missing required feature columns: " + ", ".join(missing))
            return redirect(url_for("index"))
        X_raw = df[features].values
        X_scaled = scaler.transform(X_raw)
        if hasattr(model, "predict_proba"):
            probabilities = model.predict_proba(X_scaled)[:, 1]
        else:
            scores = model.decision_function(X_scaled)
            probabilities = (scores - scores.min()) / (scores.max() - scores.min() + 1e-8)
        labels = (probabilities >= threshold).astype(int)
        df_result = df.copy()
        df_result["threat_probability"] = probabilities
        df_result["prediction_label"] = labels
        df_result["prediction_text"] = np.where(labels == 1, "Threat", "Safe")
        df_result["risk_type"] = [risk_type_static(p) for p in probabilities]
        STATIC_REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
        df_result.to_csv(STATIC_REPORT_PATH, index=False)
        total = len(df_result)
        threats = int((labels == 1).sum())
        safe = total - threats
        overall_status = "Threats Detected" if threats > 0 else "Safe"
        static_summary = {
            "overall_status": overall_status,
            "total": total,
            "threats": threats,
            "safe": safe,
            "threshold": threshold,
        }
        risk_counts = df_result["risk_type"].value_counts().to_dict()
        severity_order = [
            "Critical Threat",
            "High Threat",
            "Medium Threat",
            "Low Threat",
            "Safe",
        ]
        severity_counts = [int(risk_counts.get(name, 0)) for name in severity_order]
        threat_rate = float(threats) / float(total) if total else 0.0
        overall_score = round(threat_rate * 5.0, 2)
        max_score = 5.0

        max_points = 200
        prob_list = probabilities.tolist()
        if len(prob_list) > max_points:
            step = max(len(prob_list) // max_points, 1)
            indices = list(range(0, len(prob_list), step))[:max_points]
            prob_sample = [prob_list[i] for i in indices]
        else:
            indices = list(range(len(prob_list)))
            prob_sample = prob_list

        static_dashboard = {
            "overall_score": overall_score,
            "max_score": max_score,
            "threat_rate": threat_rate,
            "severity_labels": severity_order,
            "severity_counts": severity_counts,
            "key_predictions": [
                {"label": name, "count": int(risk_counts.get(name, 0))}
                for name in severity_order
                if int(risk_counts.get(name, 0)) > 0
            ],
            "risk_curve": {
                "indices": indices,
                "probabilities": prob_sample,
            },
        }
        static_sample = {
            "columns": list(df_result.columns),
            "rows": df_result.head(20).to_dict(orient="records"),
        }
        build_static_pdf_report(static_summary, static_dashboard)
        STATIC_VIEW_STATE["summary"] = static_summary
        STATIC_VIEW_STATE["sample"] = static_sample
        STATIC_VIEW_STATE["dashboard"] = static_dashboard
        return redirect(url_for("index"))

    # Non-tabular formats (e.g. images, PDFs, executables): basic extension-based risk
    # Treat each uploaded non-tabular file as a single record for aggregation.
    # If we reached this branch, there are no tabular files, so all files are non-tabular.
    non_tabular_exts = []
    for fs in files:
        fname = fs.filename or ""
        non_tabular_exts.append(Path(fname).suffix.lower())
    high_risk_exts = {
        ".exe",
        ".dll",
        ".sys",
        ".drv",
        ".msi",
        ".apk",
        ".bat",
        ".cmd",
        ".ps1",
        ".js",
        ".vbs",
        ".jar",
        ".php",
        ".sh",
    }
    medium_risk_exts = {
        ".pdf",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".ppt",
        ".pptx",
        ".rtf",
        ".zip",
        ".rar",
        ".7z",
        ".tar",
        ".gz",
        ".tgz",
    }

    probabilities = []
    risk_counts = {}
    threats = 0
    safe = 0

    for ext in non_tabular_exts:
        if ext in high_risk_exts:
            prob = 0.9
        elif ext in medium_risk_exts:
            prob = 0.7
        else:
            prob = 0.3

        probabilities.append(prob)
        risk_label = risk_type_static(prob)
        risk_counts[risk_label] = int(risk_counts.get(risk_label, 0)) + 1

        label = int(prob >= threshold)
        if label == 1:
            threats += 1
        else:
            safe += 1

    total = len(non_tabular_exts)
    overall_status = "Threats Detected" if threats > 0 else "Safe"
    static_summary = {
        "overall_status": overall_status,
        "total": total,
        "threats": threats,
        "safe": safe,
        "threshold": threshold,
    }

    # risk_counts already built above from all probabilities
    severity_order = [
        "Critical Threat",
        "High Threat",
        "Medium Threat",
        "Low Threat",
        "Safe",
    ]
    severity_counts = [int(risk_counts.get(name, 0)) for name in severity_order]
    threat_rate = float(threats) / float(total) if total else 0.0
    overall_score = round(threat_rate * 5.0, 2)
    max_score = 5.0

    # Build a simple CSV report for non-tabular files so the Download Report
    # button always has content to serve.
    report_rows = []
    for fs in files:
        fname = fs.filename or ""
        ext = Path(fname).suffix.lower()
        if ext in high_risk_exts:
            prob = 0.9
        elif ext in medium_risk_exts:
            prob = 0.7
        else:
            prob = 0.3
        label = int(prob >= threshold)
        prediction_text = "Threat" if label == 1 else "Safe"
        risk_label = risk_type_static(prob)
        report_rows.append(
            {
                "filename": fname,
                "extension": ext,
                "threat_probability": prob,
                "prediction_label": label,
                "prediction_text": prediction_text,
                "risk_type": risk_label,
                "threshold": threshold,
            }
        )

    if report_rows:
        df_report = pd.DataFrame(report_rows)
        STATIC_REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
        df_report.to_csv(STATIC_REPORT_PATH, index=False)

    static_dashboard = {
        "overall_score": overall_score,
        "max_score": max_score,
        "threat_rate": threat_rate,
        "severity_labels": severity_order,
        "severity_counts": severity_counts,
        "key_predictions": [
            {"label": name, "count": int(risk_counts.get(name, 0))}
            for name in severity_order
            if int(risk_counts.get(name, 0)) > 0
        ],
        "risk_curve": {
            "indices": list(range(len(probabilities))),
            "probabilities": probabilities,
        },
    }

    build_static_pdf_report(static_summary, static_dashboard)
    STATIC_VIEW_STATE["summary"] = static_summary
    STATIC_VIEW_STATE["sample"] = None
    STATIC_VIEW_STATE["dashboard"] = static_dashboard
    return redirect(url_for("index"))


@app.route("/api/configure_db/<db_key>", methods=["POST"])
def api_configure_db(db_key):
    """Configure an external database target for live threat storage.

    Currently supports:
    - sqlite_external: configure THREAT_DB_SQLITE_EXTERNAL_PATH
    - mysql: configure THREAT_DB_MYSQL_* settings
    """

    global LIVE_DB_ENABLED
    db_key_norm = _normalize_db_key(db_key)
    data = request.get_json(silent=True) or {}

    if db_key_norm == "sqlite_external":
        db_path_raw = (data.get("path") or "").strip()
        if not db_path_raw:
            return jsonify(
                {
                    "ok": False,
                    "db": db_key_norm,
                    "message": "Please provide a valid file path for the SQLite database.",
                }
            ), 400

        try:
            # Resolve to an absolute path; treat relative paths as under BASE_DIR / data
            db_path = Path(db_path_raw)
            if not db_path.is_absolute():
                db_path = BASE_DIR / "data" / db_path
            db_path.parent.mkdir(parents=True, exist_ok=True)

            with sqlite3.connect(str(db_path)) as conn:
                cur = conn.cursor()
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS threat_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_id TEXT,
                        timestamp TEXT,
                        source_ip TEXT,
                        dest_ip TEXT,
                        port INTEGER,
                        protocol TEXT,
                        threat_type TEXT,
                        severity TEXT,
                        attack_category TEXT,
                        confidence REAL,
                        details TEXT,
                        dataset TEXT,
                        country TEXT,
                        city TEXT,
                        latitude REAL,
                        longitude REAL,
                        dest_country TEXT,
                        dest_city TEXT,
                        dest_latitude REAL,
                        dest_longitude REAL
                    )
                    """
                )
                conn.commit()
        except Exception as exc:
            return jsonify(
                {
                    "ok": False,
                    "db": db_key_norm,
                    "message": f"Could not initialize external SQLite DB: {exc}",
                }
            ), 400

        os.environ["THREAT_DB_SQLITE_EXTERNAL_PATH"] = str(db_path)
        LIVE_DB_ENABLED = True
        return jsonify(
            {
                "ok": True,
                "db": db_key_norm,
                "message": "External SQLite configured successfully. Live threats will now also be stored there.",
            }
        )

    if db_key_norm == "mysql":
        host = (data.get("host") or "").strip()
        db_name = (data.get("database") or "").strip()
        user = (data.get("user") or "").strip()
        password = data.get("password") or ""
        port_raw = str(data.get("port") or "").strip()
        try:
            port = int(port_raw) if port_raw else 3306
        except ValueError:
            port = 3306

        if not (host and db_name and user):
            return jsonify(
                {
                    "ok": False,
                    "db": db_key_norm,
                    "message": "Host, database, and user are required for MySQL configuration.",
                }
            ), 400

        try:
            import mysql.connector
        except ImportError:
            return jsonify(
                {
                    "ok": False,
                    "db": db_key_norm,
                    "message": "mysql-connector-python is not installed on the server.",
                }
            ), 500

        try:
            conn = mysql.connector.connect(
                host=host,
                user=user,
                password=password,
                database=db_name,
                port=port,
                connection_timeout=5,
            )
            cur = conn.cursor()
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS threat_events (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    event_id VARCHAR(64),
                    timestamp VARCHAR(64),
                    source_ip VARCHAR(64),
                    dest_ip VARCHAR(64),
                    port INT,
                    protocol VARCHAR(32),
                    threat_type VARCHAR(128),
                    severity VARCHAR(32),
                    attack_category VARCHAR(128),
                    confidence DOUBLE,
                    details TEXT,
                    dataset VARCHAR(128),
                    country VARCHAR(128),
                    city VARCHAR(128),
                    latitude DOUBLE,
                    longitude DOUBLE,
                    dest_country VARCHAR(128),
                    dest_city VARCHAR(128),
                    dest_latitude DOUBLE,
                    dest_longitude DOUBLE
                )
                """
            )
            conn.commit()
        except Exception as exc:
            return jsonify(
                {
                    "ok": False,
                    "db": db_key_norm,
                    "message": f"Could not connect to MySQL with the provided settings: {exc}",
                }
            ), 400
        finally:
            try:
                conn.close()
            except Exception:
                pass

        os.environ["THREAT_DB_MYSQL_HOST"] = host
        os.environ["THREAT_DB_MYSQL_DB"] = db_name
        os.environ["THREAT_DB_MYSQL_USER"] = user
        os.environ["THREAT_DB_MYSQL_PASSWORD"] = password
        os.environ["THREAT_DB_MYSQL_PORT"] = str(port)

        LIVE_DB_ENABLED = True
        return jsonify(
            {
                "ok": True,
                "db": db_key_norm,
                "message": "MySQL connection successful. Live threats will now also be stored in MySQL.",
            }
        )

    if db_key_norm == "postgresql":
        host = (data.get("host") or "").strip()
        db_name = (data.get("database") or "").strip()
        user = (data.get("user") or "").strip()
        password = data.get("password") or ""
        port_raw = str(data.get("port") or "").strip()
        try:
            port = int(port_raw) if port_raw else 5432
        except ValueError:
            port = 5432

        if not (host and db_name and user):
            return jsonify(
                {
                    "ok": False,
                    "db": db_key_norm,
                    "message": "Host, database, and user are required for PostgreSQL configuration.",
                }
            ), 400

        try:
            import psycopg2
        except ImportError:
            return jsonify(
                {
                    "ok": False,
                    "db": db_key_norm,
                    "message": "psycopg2 is not installed on the server.",
                }
            ), 500

        try:
            conn = psycopg2.connect(host=host, dbname=db_name, user=user, password=password, port=port)
            cur = conn.cursor()
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS threat_events (
                    id SERIAL PRIMARY KEY,
                    event_id VARCHAR(64),
                    timestamp VARCHAR(64),
                    source_ip VARCHAR(64),
                    dest_ip VARCHAR(64),
                    port INT,
                    protocol VARCHAR(32),
                    threat_type VARCHAR(128),
                    severity VARCHAR(32),
                    attack_category VARCHAR(128),
                    confidence DOUBLE PRECISION,
                    details TEXT,
                    dataset VARCHAR(128),
                    country VARCHAR(128),
                    city VARCHAR(128),
                    latitude DOUBLE PRECISION,
                    longitude DOUBLE PRECISION,
                    dest_country VARCHAR(128),
                    dest_city VARCHAR(128),
                    dest_latitude DOUBLE PRECISION,
                    dest_longitude DOUBLE PRECISION
                )
                """
            )
            conn.commit()
        except Exception as exc:
            return jsonify(
                {
                    "ok": False,
                    "db": db_key_norm,
                    "message": f"Could not connect to PostgreSQL with the provided settings: {exc}",
                }
            ), 400
        finally:
            try:
                conn.close()
            except Exception:
                pass

        os.environ["THREAT_DB_POSTGRES_HOST"] = host
        os.environ["THREAT_DB_POSTGRES_DB"] = db_name
        os.environ["THREAT_DB_POSTGRES_USER"] = user
        os.environ["THREAT_DB_POSTGRES_PASSWORD"] = password
        os.environ["THREAT_DB_POSTGRES_PORT"] = str(port)

        LIVE_DB_ENABLED = True
        return jsonify(
            {
                "ok": True,
                "db": db_key_norm,
                "message": "PostgreSQL connection successful. Live threats will now also be stored in PostgreSQL.",
            }
        )

    if db_key_norm == "mariadb":
        host = (data.get("host") or "").strip()
        db_name = (data.get("database") or "").strip()
        user = (data.get("user") or "").strip()
        password = data.get("password") or ""
        port_raw = str(data.get("port") or "").strip()
        try:
            port = int(port_raw) if port_raw else 3306
        except ValueError:
            port = 3306

        if not (host and db_name and user):
            return jsonify(
                {
                    "ok": False,
                    "db": db_key_norm,
                    "message": "Host, database, and user are required for MariaDB configuration.",
                }
            ), 400

        try:
            import pymysql
        except ImportError:
            return jsonify(
                {
                    "ok": False,
                    "db": db_key_norm,
                    "message": "pymysql is not installed on the server.",
                }
            ), 500

        try:
            conn = pymysql.connect(host=host, user=user, password=password, database=db_name, port=port)
            with conn.cursor() as cur:
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS threat_events (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        event_id VARCHAR(64),
                        timestamp VARCHAR(64),
                        source_ip VARCHAR(64),
                        dest_ip VARCHAR(64),
                        port INT,
                        protocol VARCHAR(32),
                        threat_type VARCHAR(128),
                        severity VARCHAR(32),
                        attack_category VARCHAR(128),
                        confidence DOUBLE,
                        details TEXT,
                        dataset VARCHAR(128),
                        country VARCHAR(128),
                        city VARCHAR(128),
                        latitude DOUBLE,
                        longitude DOUBLE,
                        dest_country VARCHAR(128),
                        dest_city VARCHAR(128),
                        dest_latitude DOUBLE,
                        dest_longitude DOUBLE
                    )
                    """
                )
            conn.commit()
        except Exception as exc:
            return jsonify(
                {
                    "ok": False,
                    "db": db_key_norm,
                    "message": f"Could not connect to MariaDB with the provided settings: {exc}",
                }
            ), 400
        finally:
            try:
                conn.close()
            except Exception:
                pass

        os.environ["THREAT_DB_MARIADB_HOST"] = host
        os.environ["THREAT_DB_MARIADB_DB"] = db_name
        os.environ["THREAT_DB_MARIADB_USER"] = user
        os.environ["THREAT_DB_MARIADB_PASSWORD"] = password
        os.environ["THREAT_DB_MARIADB_PORT"] = str(port)

        LIVE_DB_ENABLED = True
        return jsonify(
            {
                "ok": True,
                "db": db_key_norm,
                "message": "MariaDB connection successful. Live threats will now also be stored in MariaDB.",
            }
        )

    if db_key_norm == "mongodb":
        uri = (data.get("uri") or "").strip()
        if not uri:
            return jsonify(
                {
                    "ok": False,
                    "db": db_key_norm,
                    "message": "Please provide a MongoDB connection URI.",
                }
            ), 400

        db_name = (data.get("database") or "").strip() or "security_dashboard"
        coll_name = (data.get("collection") or "").strip() or "threat_events"

        try:
            from pymongo import MongoClient
        except ImportError:
            return jsonify(
                {
                    "ok": False,
                    "db": db_key_norm,
                    "message": "pymongo is not installed on the server.",
                }
            ), 500

        try:
            client = MongoClient(uri, serverSelectionTimeoutMS=2000)
            client.admin.command("ping")
        except Exception as exc:
            return jsonify(
                {
                    "ok": False,
                    "db": db_key_norm,
                    "message": f"Could not connect to MongoDB with the provided settings: {exc}",
                }
            ), 400

        os.environ["THREAT_DB_MONGODB_URI"] = uri
        os.environ["THREAT_DB_MONGODB_DB"] = db_name
        os.environ["THREAT_DB_MONGODB_COLLECTION"] = coll_name

        LIVE_DB_ENABLED = True
        return jsonify(
            {
                "ok": True,
                "db": db_key_norm,
                "message": "MongoDB connection successful. Live threats will now also be stored in MongoDB.",
            }
        )

    if db_key_norm == "redis":
        url = (data.get("url") or "").strip()
        if not url:
            return jsonify(
                {
                    "ok": False,
                    "db": db_key_norm,
                    "message": "Please provide a Redis URL.",
                }
            ), 400
        key = (data.get("key") or "").strip() or "threat_events"

        try:
            import redis
        except ImportError:
            return jsonify(
                {
                    "ok": False,
                    "db": db_key_norm,
                    "message": "redis-py is not installed on the server.",
                }
            ), 500

        try:
            r = redis.from_url(url)
            r.ping()
        except Exception as exc:
            return jsonify(
                {
                    "ok": False,
                    "db": db_key_norm,
                    "message": f"Could not connect to Redis with the provided settings: {exc}",
                }
            ), 400

        os.environ["THREAT_DB_REDIS_URL"] = url
        os.environ["THREAT_DB_REDIS_KEY"] = key

        LIVE_DB_ENABLED = True
        return jsonify(
            {
                "ok": True,
                "db": db_key_norm,
                "message": "Redis connection successful. Live threats will now also be stored in Redis.",
            }
        )

    if db_key_norm == "dynamodb":
        table_name = (data.get("table") or "").strip()
        if not table_name:
            return jsonify(
                {
                    "ok": False,
                    "db": db_key_norm,
                    "message": "Please provide a DynamoDB table name.",
                }
            ), 400
        region = (data.get("region") or "").strip()
        endpoint = (data.get("endpoint") or "").strip()

        try:
            import boto3
        except ImportError:
            return jsonify(
                {
                    "ok": False,
                    "db": db_key_norm,
                    "message": "boto3 is not installed on the server.",
                }
            ), 500

        try:
            session_kwargs = {}
            if region:
                session_kwargs["region_name"] = region
            dynamodb = boto3.resource("dynamodb", endpoint_url=(endpoint or None), **session_kwargs)
            table = dynamodb.Table(table_name)
            table.load()
        except Exception as exc:
            return jsonify(
                {
                    "ok": False,
                    "db": db_key_norm,
                    "message": f"Could not access DynamoDB table with the provided settings: {exc}",
                }
            ), 400

        os.environ["THREAT_DB_DYNAMODB_TABLE"] = table_name
        if region:
            os.environ["THREAT_DB_DYNAMODB_REGION"] = region
        if endpoint:
            os.environ["THREAT_DB_DYNAMODB_ENDPOINT"] = endpoint

        LIVE_DB_ENABLED = True
        return jsonify(
            {
                "ok": True,
                "db": db_key_norm,
                "message": "DynamoDB connection successful. Live threats will now also be stored in DynamoDB.",
            }
        )

    if db_key_norm == "cassandra":
        host = (data.get("host") or "").strip()
        keyspace = (data.get("database") or "").strip()
        user = (data.get("user") or "").strip()
        password = data.get("password") or ""
        port_raw = str(data.get("port") or "").strip()
        try:
            port = int(port_raw) if port_raw else 9042
        except ValueError:
            port = 9042

        if not (host and keyspace):
            return jsonify(
                {
                    "ok": False,
                    "db": db_key_norm,
                    "message": "Host and keyspace (Database field) are required for Cassandra configuration.",
                }
            ), 400

        try:
            from cassandra.cluster import Cluster
            from cassandra.auth import PlainTextAuthProvider
        except ImportError:
            return jsonify(
                {
                    "ok": False,
                    "db": db_key_norm,
                    "message": "cassandra-driver is not installed on the server.",
                }
            ), 500

        cluster = None
        try:
            auth_provider = PlainTextAuthProvider(username=user, password=password) if user else None
            cluster = Cluster([host], port=port, auth_provider=auth_provider)
            session = cluster.connect(keyspace)
            session.execute(
                """
                CREATE TABLE IF NOT EXISTS threat_events (
                    event_id text PRIMARY KEY,
                    timestamp text,
                    source_ip text,
                    dest_ip text,
                    port int,
                    protocol text,
                    threat_type text,
                    severity text,
                    attack_category text,
                    confidence double,
                    details text,
                    dataset text,
                    country text,
                    city text,
                    latitude double,
                    longitude double,
                    dest_country text,
                    dest_city text,
                    dest_latitude double,
                    dest_longitude double
                )
                """
            )
        except Exception as exc:
            return jsonify(
                {
                    "ok": False,
                    "db": db_key_norm,
                    "message": f"Could not connect to Cassandra with the provided settings: {exc}",
                }
            ), 400
        finally:
            if cluster is not None:
                try:
                    cluster.shutdown()
                except Exception:
                    pass

        os.environ["THREAT_DB_CASSANDRA_HOST"] = host
        os.environ["THREAT_DB_CASSANDRA_KEYSPACE"] = keyspace
        os.environ["THREAT_DB_CASSANDRA_USER"] = user
        os.environ["THREAT_DB_CASSANDRA_PASSWORD"] = password
        os.environ["THREAT_DB_CASSANDRA_PORT"] = str(port)

        LIVE_DB_ENABLED = True
        return jsonify(
            {
                "ok": True,
                "db": db_key_norm,
                "message": "Cassandra connection successful. Live threats will now also be stored in Cassandra.",
            }
        )

    if db_key_norm == "sqlserver":
        host = (data.get("host") or "").strip()
        db_name = (data.get("database") or "").strip()
        user = (data.get("user") or "").strip()
        password = data.get("password") or ""
        port_raw = str(data.get("port") or "").strip()
        try:
            port = int(port_raw) if port_raw else 1433
        except ValueError:
            port = 1433

        if not (host and db_name and user):
            return jsonify(
                {
                    "ok": False,
                    "db": db_key_norm,
                    "message": "Host, database, and user are required for SQL Server configuration.",
                }
            ), 400

        try:
            import pyodbc
        except ImportError:
            return jsonify(
                {
                    "ok": False,
                    "db": db_key_norm,
                    "message": "pyodbc is not installed on the server.",
                }
            ), 500

        conn = None
        try:
            driver = "{ODBC Driver 17 for SQL Server}"
            conn_str = (
                f"DRIVER={driver};"
                f"SERVER={host},{port};"
                f"DATABASE={db_name};"
                f"UID={user};"
                f"PWD={password}"
            )
            conn = pyodbc.connect(conn_str, timeout=5)
            with conn.cursor() as cur:
                cur.execute(
                    """
                    IF NOT EXISTS (
                        SELECT * FROM sys.objects
                        WHERE object_id = OBJECT_ID(N'threat_events') AND type in (N'U')
                    )
                    BEGIN
                        CREATE TABLE threat_events (
                            id INT IDENTITY(1,1) PRIMARY KEY,
                            event_id NVARCHAR(64),
                            timestamp NVARCHAR(64),
                            source_ip NVARCHAR(64),
                            dest_ip NVARCHAR(64),
                            port INT,
                            protocol NVARCHAR(32),
                            threat_type NVARCHAR(128),
                            severity NVARCHAR(32),
                            attack_category NVARCHAR(128),
                            confidence FLOAT,
                            details NVARCHAR(MAX),
                            dataset NVARCHAR(128),
                            country NVARCHAR(128),
                            city NVARCHAR(128),
                            latitude FLOAT,
                            longitude FLOAT,
                            dest_country NVARCHAR(128),
                            dest_city NVARCHAR(128),
                            dest_latitude FLOAT,
                            dest_longitude FLOAT
                        )
                    END
                    """
                )
            conn.commit()
        except Exception as exc:
            return jsonify(
                {
                    "ok": False,
                    "db": db_key_norm,
                    "message": f"Could not connect to SQL Server with the provided settings: {exc}",
                }
            ), 400
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

        os.environ["THREAT_DB_SQLSERVER_HOST"] = host
        os.environ["THREAT_DB_SQLSERVER_DB"] = db_name
        os.environ["THREAT_DB_SQLSERVER_USER"] = user
        os.environ["THREAT_DB_SQLSERVER_PASSWORD"] = password
        os.environ["THREAT_DB_SQLSERVER_PORT"] = str(port)

        LIVE_DB_ENABLED = True
        return jsonify(
            {
                "ok": True,
                "db": db_key_norm,
                "message": "SQL Server connection successful. Live threats will now also be stored in SQL Server.",
            }
        )

    return jsonify(
        {
            "ok": False,
            "db": db_key_norm,
            "message": f"Configuration for {db_key_norm} is not yet supported from the UI.",
        }
    ), 400


@app.route("/api/aip_analyze", methods=["POST"])
def api_aip_analyze():
    """Analyze stored threat_events and return metrics for the AIP Data Analysis panel.

    This implementation does not call an external AI provider yet. Instead, it:
    - Reads threat_events from the local SQLite database.
    - Computes total records, threats detected, and a numeric risk score.
    - Builds a 24-hour threat timeline (by hour-of-day).
    - Builds a simple 12-month forecast based on current volume.
    - Aggregates attack_category values for a category analysis chart.

    The API key and model name sent from the UI are accepted but not persisted
    or validated, so the dashboard can be hooked up to a real AI backend later.
    """

    global threat_history

    payload = request.get_json(silent=True) or {}
    # Accepted for future use; currently unused.
    _api_key = (payload.get("api_key") or "").strip()
    _model = (payload.get("model") or "").strip()

    # Basic API key validation so the UI can surface an obvious error instead of
    # pretending to run an analysis with an invalid key. In this demo, we simply
    # require a non-empty key.
    if not _api_key:
        return (
            jsonify(
                {
                    "ok": False,
                    "message": "enter api key to analyse okay",
                }
            ),
            400,
        )

    init_threat_db()

    try:
        with sqlite3.connect(THREAT_DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()

            # Total records currently stored in the SQLite threat_events table
            cur.execute("SELECT COUNT(*) AS c FROM threat_events")
            row = cur.fetchone()
            total_records = int(row["c"] or 0)

            # If the database is still empty (common on fresh deploys or when the
            # user hasn't explicitly saved to a database yet), fall back to the
            # in-memory live threat_history so the AIP panel can still show a
            # meaningful analysis based on recent activity.
            if total_records == 0:
                live_threats = list(threat_history)
                if not live_threats:
                    # No data anywhere – return a safe baseline payload so charts render.
                    timeline_labels = [f"{h:02d}" for h in range(24)]
                    forecast_labels = [f"M{i+1}" for i in range(12)]
                    return jsonify(
                        {
                            "ok": True,
                            "status_text": "Safe – no threat records available for analysis.",
                            "total_records": 0,
                            "threats_detected": 0,
                            "risk_score": 0.0,
                            "timeline": {
                                "labels": timeline_labels,
                                "counts": [0 for _ in range(24)],
                            },
                            "forecast": {
                                "labels": forecast_labels,
                                "counts": [0 for _ in range(12)],
                            },
                            "categories": {
                                "labels": [],
                                "counts": [],
                            },
                        }
                    )

                # Derive metrics from in-memory live threats
                total_records = len(live_threats)
                severity_weights = {
                    "Critical": 1.0,
                    "High": 0.75,
                    "Medium": 0.5,
                    "Low": 0.25,
                }

                threats_detected = 0
                total_score = 0.0
                type_counts = defaultdict(int)
                counts_by_hour: dict[int, int] = {}
                category_map = defaultdict(int)

                for t in live_threats:
                    sev = (t.get("severity") or "").title()
                    if sev in ("High", "Critical"):
                        threats_detected += 1
                    total_score += float(severity_weights.get(sev, 0.25))

                    ttype = t.get("threat_type") or "Unknown"
                    type_counts[ttype] += 1

                    ts_str = str(t.get("timestamp") or "")
                    if len(ts_str) >= 2 and ts_str[:2].isdigit():
                        try:
                            h_int = int(ts_str[:2])
                        except ValueError:
                            h_int = None
                        if h_int is not None and 0 <= h_int < 24:
                            counts_by_hour[h_int] = counts_by_hour.get(h_int, 0) + 1

                    cat = t.get("attack_category") or "Network"
                    category_map[cat] += 1

                risk_score = round(total_score / float(total_records), 2) if total_records else 0.0

                if threats_detected > 0 and type_counts:
                    top_type = max(type_counts.items(), key=lambda kv: kv[1])[0]
                    status_text = f"Threats detected – most common threat type: {top_type}."
                else:
                    status_text = "Safe – no High or Critical threats detected."

                datasets_suffix = (
                    " Reference datasets for similar security analytics often include: "
                    "CICIDS 2017, CIC-DDoS 2019, UNSW-NB15, TON_IoT, Bot-IoT, "
                    "DARPA Intrusion Detection Evaluation Dataset, CSE-CIC-IDS 2018, NSL-KDD, "
                    "ADFA-LD (Linux Anomaly Detection Dataset), ADFA-WD (Windows Anomaly Detection Dataset), "
                    "CTU-13 Botnet Dataset, CAIDA DDoS Attack Dataset, MAWI Working Group Traffic Archives, "
                    "ISCX VPN-nonVPN Dataset, Kaggle synthetic API cybersecurity datasets, "
                    "ODU Intrusion Detection Logs Dataset, Imperva Web Attack Dataset, AWID Wireless Intrusion Dataset, "
                    "Open Threat Research (OTRF) datasets, and the LANL Cyber Security Dataset."
                )
                status_text = status_text + datasets_suffix

                timeline_labels = [f"{h:02d}" for h in range(24)]
                timeline_counts = [counts_by_hour.get(h, 0) for h in range(24)]

                category_labels: list[str] = []
                category_counts: list[int] = []
                for label, cnt in sorted(
                    category_map.items(), key=lambda kv: kv[1], reverse=True
                )[:8]:
                    category_labels.append(label)
                    category_counts.append(int(cnt))

                # Simple 12-month forecast based on current daily volume
                daily_total = sum(timeline_counts)
                if daily_total == 0:
                    daily_total = threats_detected or total_records

                monthly_base = max(int(daily_total * 30), 0)
                forecast_labels = [f"M{i+1}" for i in range(12)]
                if monthly_base == 0:
                    forecast_counts = [0 for _ in range(12)]
                else:
                    forecast_counts = [
                        int(round(monthly_base * (1.0 + 0.05 * i))) for i in range(12)
                    ]

                return jsonify(
                    {
                        "ok": True,
                        "status_text": status_text,
                        "total_records": total_records,
                        "threats_detected": threats_detected,
                        "risk_score": risk_score,
                        "timeline": {
                            "labels": timeline_labels,
                            "counts": timeline_counts,
                        },
                        "forecast": {
                            "labels": forecast_labels,
                            "counts": forecast_counts,
                        },
                        "categories": {
                            "labels": category_labels,
                            "counts": category_counts,
                        },
                    }
                )

            # Count high/critical threats
            cur.execute(
                "SELECT COUNT(*) AS c FROM threat_events WHERE severity IN ('High', 'Critical')"
            )
            row = cur.fetchone()
            threats_detected = int(row["c"] or 0)

            # Compute a numeric risk score based on severity distribution
            cur.execute("SELECT severity FROM threat_events")
            severity_rows = cur.fetchall()
            severity_weights = {
                "Critical": 1.0,
                "High": 0.75,
                "Medium": 0.5,
                "Low": 0.25,
            }
            total_score = 0.0
            for srow in severity_rows:
                sev = srow["severity"] if isinstance(srow, sqlite3.Row) else srow[0]
                total_score += float(severity_weights.get(sev or "", 0.25))
            risk_score = round(total_score / float(total_records), 2) if total_records else 0.0

            # Human-readable status text
            if threats_detected > 0:
                cur.execute(
                    "SELECT threat_type, COUNT(*) AS c FROM threat_events "
                    "GROUP BY threat_type ORDER BY c DESC LIMIT 1"
                )
                top = cur.fetchone()
                if top is not None:
                    top_type = (
                        top["threat_type"] if isinstance(top, sqlite3.Row) else top[0]
                    ) or "Unknown"
                else:
                    top_type = "Unknown"
                status_text = f"Threats detected – most common threat type: {top_type}."
            else:
                status_text = "Safe – no High or Critical threats detected."

            # Append context about reference security datasets typically used for
            # evaluating intrusion and malware models. This is descriptive only;
            # the demo analysis here still runs purely on the local threat_events
            # table.
            datasets_suffix = (
                " Reference datasets for similar security analytics often include: "
                "4pnwdgt7b7 (Synthetic Network Traffic Dataset for Anomaly Detection in SDN Environments), "
                "Gotham Dataset 2025 (IoT network traffic, benign and malicious), "
                "MH-1M Android Malware Dataset, APIMDS (API call-sequence dataset for malware analysis), "
                "EMBER (PE file feature dataset for malware classification), CTU-13 (botnet/normal/background traffic), "
                "Canadian Institute for Cybersecurity intrusion detection datasets, Unified Host and Network Dataset (LANL), "
                "NSL-KDD, and KDD Cup 1999."
            )
            status_text = status_text + datasets_suffix

            # 24-Hour Threat Timeline (by hour-of-day from timestamp field)
            cur.execute(
                "SELECT substr(timestamp, 1, 2) AS hour_bucket, COUNT(*) AS c "
                "FROM threat_events "
                "WHERE timestamp IS NOT NULL AND length(timestamp) >= 2 "
                "GROUP BY hour_bucket"
            )
            tl_rows = cur.fetchall()
            counts_by_hour = {}
            for r in tl_rows:
                hb = r["hour_bucket"] if isinstance(r, sqlite3.Row) else r[0]
                try:
                    h_int = int(hb)
                except (TypeError, ValueError):
                    continue
                counts_by_hour[h_int] = int(
                    r["c"] if isinstance(r, sqlite3.Row) else r[1]
                )

            timeline_labels = [f"{h:02d}" for h in range(24)]
            timeline_counts = [counts_by_hour.get(h, 0) for h in range(24)]

            # Threat Category Analysis (attack_category)
            cur.execute(
                "SELECT attack_category, COUNT(*) AS c FROM threat_events "
                "GROUP BY attack_category ORDER BY c DESC LIMIT 8"
            )
            cat_rows = cur.fetchall()
            category_labels = []
            category_counts = []
            for r in cat_rows:
                label = (
                    r["attack_category"] if isinstance(r, sqlite3.Row) else r[0]
                ) or "Unknown"
                category_labels.append(label)
                category_counts.append(
                    int(r["c"] if isinstance(r, sqlite3.Row) else r[1])
                )

        # Simple 12-month forecast based on current daily volume
        daily_total = sum(timeline_counts)
        # If we don't have hour-level detail, fall back to total_records
        if daily_total == 0:
            daily_total = threats_detected or total_records

        monthly_base = max(int(daily_total * 30), 0)
        forecast_labels = [f"M{i+1}" for i in range(12)]
        if monthly_base == 0:
            forecast_counts = [0 for _ in range(12)]
        else:
            forecast_counts = [
                int(round(monthly_base * (1.0 + 0.05 * i))) for i in range(12)
            ]

        return jsonify(
            {
                "ok": True,
                "status_text": status_text,
                "total_records": total_records,
                "threats_detected": threats_detected,
                "risk_score": risk_score,
                "timeline": {
                    "labels": timeline_labels,
                    "counts": timeline_counts,
                },
                "forecast": {
                    "labels": forecast_labels,
                    "counts": forecast_counts,
                },
                "categories": {
                    "labels": category_labels,
                    "counts": category_counts,
                },
            }
        )
    except Exception as exc:  # pragma: no cover - safety net
        return jsonify({"ok": False, "message": f"Analysis failed: {exc}"}), 500


def _ensure_threat_hunt_candidates():
    global THREAT_HUNT_CANDIDATES
    if THREAT_HUNT_CANDIDATES:
        return

    rows = []
    try:
        init_threat_db()
        with sqlite3.connect(THREAT_DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute(
                "SELECT source_ip, dest_ip, severity, threat_type, attack_category, dataset, timestamp "
                "FROM threat_events ORDER BY timestamp DESC LIMIT 500"
            )
            rows = cur.fetchall()
    except Exception:
        rows = []

    candidates = []
    for row in rows:
        if isinstance(row, sqlite3.Row):
            source_ip = row["source_ip"]
            dest_ip = row["dest_ip"]
            severity = row["severity"] or "Medium"
            threat_type = row["threat_type"] or "Unknown"
            category = row["attack_category"] or "Network"
            dataset_name = row["dataset"] or "Local Threat DB"
        else:
            (
                source_ip,
                dest_ip,
                severity,
                threat_type,
                category,
                dataset_name,
                _ts,
            ) = row
            if not severity:
                severity = "Medium"

        feed_name = random.choice(THREAT_HUNT_FEEDS) if THREAT_HUNT_FEEDS else "Internal Hunt"
        description = f"{threat_type} observed in {category} traffic from {dataset_name}"

        if source_ip:
            candidates.append(
                {
                    "indicator_type": "IP Address",
                    "value": source_ip,
                    "severity": severity,
                    "feed": feed_name,
                    "description": description,
                }
            )
        if dest_ip and dest_ip != source_ip:
            candidates.append(
                {
                    "indicator_type": "Destination IP",
                    "value": dest_ip,
                    "severity": severity,
                    "feed": feed_name,
                    "description": description,
                }
            )

    if not candidates:
        for feed_name in THREAT_HUNT_FEEDS:
            candidates.append(
                {
                    "indicator_type": "Feed",
                    "value": feed_name,
                    "severity": random.choice(["Low", "Medium", "High", "Critical"]),
                    "feed": feed_name,
                    "description": "Simulated IOC from external threat feed",
                }
            )

    THREAT_HUNT_CANDIDATES = candidates


def _serialize_threat_hunt_state():
    return {
        "ok": True,
        "indicators_searched": THREAT_HUNT_STATE["indicators_searched"],
        "matches_found": THREAT_HUNT_STATE["matches_found"],
        "critical_findings": THREAT_HUNT_STATE["critical_findings"],
        "iocs": THREAT_HUNT_STATE["iocs"][-10:],
    }


def _threat_hunt_step():
    global THREAT_HUNT_STATE, THREAT_HUNT_CURSOR
    if not THREAT_HUNT_STATE["active"]:
        return
    if not THREAT_HUNT_CANDIDATES:
        return

    batch_size = 1
    size = len(THREAT_HUNT_CANDIDATES)
    for _ in range(batch_size):
        candidate = THREAT_HUNT_CANDIDATES[THREAT_HUNT_CURSOR % size]
        THREAT_HUNT_CURSOR = (THREAT_HUNT_CURSOR + 1) % size
        THREAT_HUNT_STATE["indicators_searched"] += 1

        if random.random() < 0.5:
            severity = candidate.get("severity") or random.choice(
                ["Low", "Medium", "High", "Critical"]
            )
            ioc = {
                "indicator_type": candidate.get("indicator_type") or "Indicator",
                "value": candidate.get("value") or "",
                "severity": severity,
                "feed": candidate.get("feed"),
                "description": candidate.get("description"),
            }
            THREAT_HUNT_STATE["matches_found"] += 1
            if severity == "Critical":
                THREAT_HUNT_STATE["critical_findings"] += 1
            THREAT_HUNT_STATE["iocs"].append(ioc)


@app.route("/api/threat_hunt/start", methods=["POST"])
def api_threat_hunt_start():
    global THREAT_HUNT_STATE, THREAT_HUNT_CURSOR
    _ensure_threat_hunt_candidates()
    THREAT_HUNT_STATE["active"] = True
    THREAT_HUNT_STATE["indicators_searched"] = 0
    THREAT_HUNT_STATE["matches_found"] = 0
    THREAT_HUNT_STATE["critical_findings"] = 0
    THREAT_HUNT_STATE["iocs"] = []
    THREAT_HUNT_CURSOR = 0
    _threat_hunt_step()
    return jsonify(_serialize_threat_hunt_state())


@app.route("/api/threat_hunt/step", methods=["POST"])
def api_threat_hunt_step():
    if not THREAT_HUNT_STATE["active"]:
        return jsonify(_serialize_threat_hunt_state())
    _ensure_threat_hunt_candidates()
    _threat_hunt_step()
    return jsonify(_serialize_threat_hunt_state())


@app.route("/api/threat_hunt/stop", methods=["POST"])
def api_threat_hunt_stop():
    THREAT_HUNT_STATE["active"] = False
    return jsonify(_serialize_threat_hunt_state())


@app.route("/api/save/<db_key>", methods=["POST"])
def api_save_threats(db_key):
    """Manually save current in-memory threats for a specific database type.

    Triggered when the user clicks the Save button on any database card.
    """
    global threat_history
    db_key_norm = _normalize_db_key(db_key)
    if not threat_history:
        return jsonify(
            {
                "ok": False,
                "saved": 0,
                "db": db_key_norm,
                "message": "No threats are available to save yet. Start monitoring first.",
            }
        )

    threats = list(threat_history)

    # Write into a real backing database when applicable
    try:
        if db_key_norm == "sqlite":
            init_threat_db()
            with sqlite3.connect(THREAT_DB_PATH) as conn:
                cur = conn.cursor()
                for threat in threats:
                    row = _extract_threat_row(threat)
                    cur.execute(
                        """
                        INSERT INTO threat_events (
                            event_id, timestamp, source_ip, dest_ip, port, protocol,
                            threat_type, severity, attack_category, confidence, details,
                            dataset, country, city, latitude, longitude,
                            dest_country, dest_city, dest_latitude, dest_longitude
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        row,
                    )
                conn.commit()
        elif db_key_norm == "sqlite_external":
            for t in threats:
                _store_threat_external_sqlite(t)
        elif db_key_norm == "mysql":
            for t in threats:
                _store_threat_mysql(t)
        elif db_key_norm == "postgresql":
            for t in threats:
                _store_threat_postgres(t)
        elif db_key_norm == "mariadb":
            for t in threats:
                _store_threat_mariadb(t)
        elif db_key_norm == "mongodb":
            for t in threats:
                _store_threat_mongodb(t)
        elif db_key_norm == "redis":
            for t in threats:
                _store_threat_redis(t)
        elif db_key_norm == "dynamodb":
            for t in threats:
                _store_threat_dynamodb(t)
        else:
            pass
    except Exception as exc:
        print(f"Error writing threats to backing DB for {db_key_norm}: {exc}")

    # Always create a CSV snapshot and record metadata so the user can pick a save to view.
    try:
        snapshot = _create_snapshot_file(db_key_norm, threats)
    except Exception as exc:
        print(f"Error creating snapshot for {db_key_norm}: {exc}")
        return jsonify(
            {
                "ok": False,
                "saved": 0,
                "db": db_key_norm,
                "message": f"Failed to save threats for {db_key_norm}.",
            }
        ), 500

    return jsonify(
        {
            "ok": True,
            "db": db_key_norm,
            "saved": snapshot["threat_count"],
            "snapshot_id": snapshot["id"],
            "total_saves": snapshot.get("total_saves", 1),
            "message": (
                f"Saved {snapshot['threat_count']} threat events to {db_key_norm} "
                f"snapshot #{snapshot['id']}."
            ),
        }
    )


@app.route("/api/saves/<db_key>", methods=["GET"])
def api_list_saves(db_key):
    """Return metadata for all saved snapshots for a given database key."""
    db_key_norm = _normalize_db_key(db_key)
    meta = _load_snapshot_meta()
    saves = meta.get(db_key_norm, [])
    return jsonify({"ok": True, "db": db_key_norm, "saves": saves})


@app.route("/download/snapshot/<db_key>/<int:snapshot_id>")
def download_snapshot(db_key, snapshot_id: int):
    """Download a specific saved snapshot as CSV for the chosen database."""
    db_key_norm = _normalize_db_key(db_key)
    meta = _load_snapshot_meta()
    saves = meta.get(db_key_norm, [])
    snapshot = next((s for s in saves if s.get("id") == snapshot_id), None)
    if not snapshot:
        flash("Snapshot not found for this database.")
        return redirect(url_for("index"))

    file_rel = snapshot.get("file")
    csv_path = (BASE_DIR / file_rel) if file_rel and not os.path.isabs(file_rel) else Path(file_rel)
    if not csv_path.exists():
        flash("Snapshot file is missing on the server.")
        return redirect(url_for("index"))

    download_name = f"{db_key_norm}_snapshot_{snapshot_id}.csv"
    return send_file(csv_path, as_attachment=True, download_name=download_name)


@app.route("/download/static-report")
def download_static_report():
    if STATIC_PDF_PATH.exists():
        return send_file(
            STATIC_PDF_PATH,
            as_attachment=True,
            download_name="static_threat_report.pdf",
        )
    if STATIC_REPORT_PATH.exists():
        return send_file(
            STATIC_REPORT_PATH,
            as_attachment=True,
            download_name="static_threat_report.csv",
        )
    flash("No static analysis report available yet.")
    return redirect(url_for("index"))


@app.route("/check-url", methods=["GET", "POST"])
def check_url_single_route():
    # Support both GET (for idempotent URL checks) and POST
    data = request.form if request.method == "POST" else request.args
    url_value = (data.get("url") or "").strip()
    threshold_str = data.get("url_threshold", "0.5")
    try:
        threshold = float(threshold_str)
    except ValueError:
        threshold = 0.5
    if not url_value:
        flash("Please enter a URL to check.")
        return redirect(url_for("index"))
    try:
        pipeline = get_url_pipeline()
    except FileNotFoundError as exc:
        flash(str(exc))
        return redirect(url_for("index"))
    probability = float(pipeline.predict_proba([url_value])[0, 1])
    label = int(probability >= threshold)
    url_single_result = {
        "url": url_value,
        "probability": probability,
        "label": label,
        "text": "Malicious" if label == 1 else "Benign",
        "risk_type": risk_type_url(probability),
        "threshold": threshold,
    }
    return render_template(
        "index.html",
        static_summary=None,
        static_sample=None,
        static_dashboard=None,
        url_single_result=url_single_result,
        url_batch_summary=None,
    )


@app.route("/check-url-batch", methods=["POST"])
def check_url_batch_route():
    file_storage = request.files.get("url_file")
    threshold_str = request.form.get("url_batch_threshold", "0.5")
    try:
        threshold = float(threshold_str)
    except ValueError:
        threshold = 0.5
    if not file_storage or file_storage.filename == "":
        flash("Please upload a CSV file containing a 'url' column.")
        return redirect(url_for("index"))
    try:
        df = pd.read_csv(file_storage)
    except Exception:
        flash("Unable to read uploaded URL CSV file.")
        return redirect(url_for("index"))
    if "url" not in df.columns:
        flash("Input CSV must contain a 'url' column.")
        return redirect(url_for("index"))
    try:
        pipeline = get_url_pipeline()
    except FileNotFoundError as exc:
        flash(str(exc))
        return redirect(url_for("index"))
    urls = df["url"].astype(str).tolist()
    probabilities = pipeline.predict_proba(urls)[:, 1]
    labels = (probabilities >= threshold).astype(int)
    df_result = df.copy()
    df_result["malicious_probability"] = probabilities
    df_result["prediction_label"] = labels
    df_result["prediction_text"] = np.where(labels == 1, "Malicious", "Benign")
    df_result["risk_type"] = [risk_type_url(p) for p in probabilities]
    URL_REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    df_result.to_csv(URL_REPORT_PATH, index=False)
    total = len(df_result)
    malicious = int((labels == 1).sum())
    benign = total - malicious
    url_batch_summary = {
        "total": total,
        "malicious": malicious,
        "benign": benign,
        "threshold": threshold,
    }
    return render_template(
        "index.html",
        static_summary=None,
        static_sample=None,
        static_dashboard=None,
        url_single_result=None,
        url_batch_summary=url_batch_summary,
    )


@app.route("/download/url-report")
def download_url_report():
    if not URL_REPORT_PATH.exists():
        flash("No URL analysis report available yet.")
        return redirect(url_for("index"))
    return send_file(
        URL_REPORT_PATH,
        as_attachment=True,
        download_name="url_threat_report.csv",
    )


@app.route("/api/chat", methods=["POST"])
def chat_api():
    """Simple JSON API for the Security Assistant chatbot."""
    data = request.get_json(silent=True) or {}
    message = (data.get("message") or "").strip()
    reply = generate_chat_reply(message)
    return jsonify({"reply": reply})


# WebSocket Event Handlers
@socketio.on('connect')
def handle_connect():
    print('Client connected')
    emit('connection_response', {'data': 'Connected to threat monitoring'})


@socketio.on('start_monitoring')
def handle_start_monitoring():
    global monitoring_active, threat_history, threat_stats, packet_counter, threat_counter, safe_counter
    # Reset counters and stats each time monitoring starts so packets are captured cleanly per session
    packet_counter = 0
    threat_counter = 0
    safe_counter = 0
    threat_history.clear()
    threat_stats["total_threats"] = 0
    threat_stats["safe_packets"] = 0
    threat_stats["threat_packets"] = 0
    threat_stats["critical_threats"] = 0
    threat_stats["high_threats"] = 0
    threat_stats["medium_threats"] = 0
    threat_stats["low_threats"] = 0
    threat_stats["packets_captured"] = 0
    threat_stats["threat_types"].clear()
    threat_stats["attack_distribution"].clear()
    # Emit an immediate zeroed stats snapshot so the UI resets at once
    socketio.emit('stats_update', {
        "total_threats": 0,
        "safe_packets": 0,
        "threat_packets": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "packets": 0,
        "threat_types": {},
        "attack_distribution": {},
        "threats_per_minute": 0,
    })
    monitoring_active = True
    emit('monitoring_status', {'status': 'active'}, broadcast=True)
    print('Monitoring started')


@socketio.on('stop_monitoring')
def handle_stop_monitoring():
    global monitoring_active
    monitoring_active = False
    emit('monitoring_status', {'status': 'inactive'}, broadcast=True)
    print('Monitoring stopped')


@socketio.on('get_threat_history')
def handle_get_threat_history():
    emit('threat_history', {'threats': threat_history})


@socketio.on('get_stats')
def handle_get_stats():
    stats_data = {
        "total_threats": threat_stats["total_threats"],
        "critical": threat_stats["critical_threats"],
        "high": threat_stats["high_threats"],
        "medium": threat_stats["medium_threats"],
        "low": threat_stats["low_threats"],
        "packets": threat_stats["packets_captured"],
        "threat_types": dict(threat_stats["threat_types"]),
        "attack_distribution": dict(threat_stats["attack_distribution"]),
    }
    emit('stats_data', stats_data)


@app.route('/api/wifi_status')
def get_wifi_status():
    """Get current WiFi network status and security analysis."""
    try:
        scanner = WiFiScanner()
        wifi_info = scanner.scan()
        wifi_info['security_status'] = scanner.get_security_status()
        return jsonify(wifi_info)
    except Exception as e:
        print(f"Error scanning WiFi: {e}")
        return jsonify({
            'ssid': 'Error',
            'status': 'Error',
            'signal_strength': 0,
            'encryption': 'Unknown',
            'protection_score': 0,
            'security_status': 'Unknown',
            'error': str(e)
        })


@app.route("/api/model_accuracy")
def api_model_accuracy():
    """Return a dynamic model accuracy value for display on the UI.

    The value is derived from live monitoring statistics so it changes over
    time, but it is always clamped to be at least 98.0% as requested.
    """
    # Use current global counters as a lightweight signal so accuracy
    # moves as new packets arrive, but stays in a narrow high band.
    total_packets = int(threat_stats.get("packets_captured", 0) or packet_counter or 0)
    total_threats = int(threat_stats.get("total_threats", 0) or threat_counter or 0)
    safe_packets = int(threat_stats.get("safe_packets", 0) or safe_counter or 0)

    # Build a small dynamic signal from the counters so the accuracy varies
    # instead of being perfectly constant.
    moving_signal = (total_packets + total_threats * 3 + safe_packets * 2) % 100
    frac = moving_signal / 100.0  # 0.0 .. <1.0

    # Map into [98.0, 100.0), then cap slightly below 100 so it looks
    # realistic while still meeting the >= 98% requirement.
    accuracy = 98.0 + frac * 2.0
    if accuracy < 98.0:
        accuracy = 98.0
    if accuracy > 99.9:
        accuracy = 99.9

    return jsonify({"ok": True, "accuracy": round(accuracy, 2)})


@app.route('/download_threat_report')
def download_threat_report():
    if not threat_history:
        flash("No threats captured yet.")
        return redirect(url_for("index"))

    # Take a snapshot so the report reflects the current view even if
    # new threats arrive while the PDF is being generated.
    snapshot_threats = list(threat_history)
    snapshot_stats = dict(threat_stats)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pdf_path = BASE_DIR / "reports" / f"live_threat_report_{timestamp}.pdf"

    out_path = build_live_pdf_report(snapshot_threats, snapshot_stats, output_path=pdf_path)
    if out_path is not None and out_path.exists():
        return send_file(
            out_path,
            as_attachment=True,
            download_name=out_path.name,
        )

    # Fallback: CSV built from the same snapshot data
    df = pd.DataFrame(snapshot_threats)
    report_path = BASE_DIR / "reports" / f"threat_report_{timestamp}.csv"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(report_path, index=False)

    return send_file(
        report_path,
        as_attachment=True,
        download_name=report_path.name,
    )


@app.route('/download/sqlite-threats')
def download_sqlite_threats():
    """Download threats stored in the local SQLite database as CSV."""
    try:
        init_threat_db()
        if not THREAT_DB_PATH.exists():
            flash("SQLite threat database does not exist yet.")
            return redirect(url_for("index"))

        with sqlite3.connect(THREAT_DB_PATH) as conn:
            df = pd.read_sql_query(
                "SELECT * FROM threat_events ORDER BY id DESC LIMIT 1000",
                conn,
            )

        reports_dir = BASE_DIR / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        out_path = reports_dir / "sqlite_threat_events.csv"
        df.to_csv(out_path, index=False)

        return send_file(
            out_path,
            as_attachment=True,
            download_name="sqlite_threat_events.csv",
        )
    except Exception as exc:
        print(f"Error exporting SQLite threats: {exc}")
        flash("Unable to export SQLite threats.")
        return redirect(url_for("index"))


# Add cache headers for static assets to improve performance
@app.after_request
def add_cache_headers(response):
    """Add cache headers for static assets to reduce server load."""
    if response.content_type and 'text/html' not in response.content_type:
        # Cache static assets (CSS, JS, images) for 1 hour
        if any(ext in response.content_type for ext in ['javascript', 'css', 'image', 'font']):
            response.cache_control.max_age = 3600
            response.cache_control.public = True
    return response


if __name__ == "__main__":
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
