#!/usr/bin/env python3
"""Streaming API listener for cyber-threat events.

- Connects to a WebSocket stream (placeholder URL).
- Parses each JSON message.
- Stores events into a MySQL `threats` table.
- Automatically reconnects to both the WebSocket and MySQL.
"""

import json
import logging
import ssl
import time
from uuid import uuid4

import mysql.connector
from mysql.connector import Error
import websocket  # from websocket-client


# =========================
# Configuration (edit this)
# =========================

# Placeholder Stream API URL – replace with your real endpoint
STREAM_URL = "wss://your-stream-api-endpoint/live"

# MySQL connection settings – replace with your real credentials/db name
DB_CONFIG = {
    "host": "localhost",
    "user": "your_mysql_user",
    "password": "your_mysql_password",
    "database": "your_database_name",
    "port": 3306,
}

# How long to wait before retrying connections (seconds)
RECONNECT_DELAY_SECONDS = 5


# ============================================
# Database helper to manage MySQL connections
# ============================================

class ThreatDatabase:
    """Wraps a MySQL connection for inserting threat events with auto-reconnect."""

    def __init__(self, config: dict) -> None:
        self.config = config
        self.conn = None
        self.cursor = None
        self._connect()
        self._ensure_table()

    def _connect(self) -> None:
        """Open a MySQL connection, retrying until it succeeds."""
        while True:
            try:
                if self.conn is not None:
                    try:
                        self.conn.close()
                    except Exception:
                        pass

                logging.info("Connecting to MySQL...")
                self.conn = mysql.connector.connect(**self.config)
                self.conn.autocommit = False  # we commit manually after each insert
                self.cursor = self.conn.cursor()
                logging.info("Connected to MySQL.")
                return
            except Error as e:
                logging.error("MySQL connection failed: %s", e)
                logging.info(
                    "Retrying MySQL connection in %s seconds...",
                    RECONNECT_DELAY_SECONDS,
                )
                time.sleep(RECONNECT_DELAY_SECONDS)

    def _ensure_table(self) -> None:
        """Create the threats table if it does not exist."""
        create_sql = """
        CREATE TABLE IF NOT EXISTS threats (
            id VARCHAR(64) PRIMARY KEY,
            name VARCHAR(255),
            severity VARCHAR(32),
            timestamp VARCHAR(64)
        )
        """
        self.cursor.execute(create_sql)
        self.conn.commit()
        logging.info("Ensured table `threats` exists.")

    def insert_threat(self, threat: dict) -> None:
        """Insert a single threat event into the database.

        Automatically reconnects and retries once if needed.
        """
        sql = """
        INSERT INTO threats (id, name, severity, timestamp)
        VALUES (%s, %s, %s, %s)
        """
        params = (
            threat["id"],
            threat["name"],
            threat["severity"],
            threat["timestamp"],
        )

        for attempt in range(2):  # try at most twice
            try:
                if not self.conn.is_connected():
                    logging.warning("MySQL connection lost. Reconnecting...")
                    self._connect()

                self.cursor.execute(sql, params)
                self.conn.commit()
                logging.info(
                    "Inserted threat: id=%s name=%s severity=%s timestamp=%s",
                    threat["id"],
                    threat["name"],
                    threat["severity"],
                    threat["timestamp"],
                )
                return
            except Error as e:
                logging.error(
                    "MySQL insert error (attempt %d): %s", attempt + 1, e
                )
                # Reconnect and retry once
                self._connect()

        logging.error("Failed to insert threat after retries: %s", threat)


# =====================================
# JSON message parsing / safe defaults
# =====================================


def parse_threat_message(message_text: str) -> dict | None:
    """Parse a raw JSON message from the stream and return a normalized dict.

    Expected fields:
      - id
      - name
      - severity
      - timestamp

    Safe defaults:
      - id: random UUID if missing
      - name: "unknown"
      - severity: "unknown"
      - timestamp: current UTC ISO string if missing
    """
    try:
        data = json.loads(message_text)
    except json.JSONDecodeError as e:
        logging.error("JSON parse error: %s; raw=%s", e, message_text)
        return None

    if not isinstance(data, dict):
        logging.error("Unexpected message format (not a JSON object): %s", data)
        return None

    threat_id = str(data.get("id") or uuid4().hex)
    name = str(data.get("name") or "unknown")
    severity = str(data.get("severity") or "unknown")
    timestamp = str(
        data.get("timestamp")
        or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    )

    return {
        "id": threat_id,
        "name": name,
        "severity": severity,
        "timestamp": timestamp,
    }


# ============================
# Streaming listener main loop
# ============================


def start_listener() -> None:
    """Open the database connection and start the WebSocket stream listener.

    This function runs indefinitely, with automatic reconnection.
    """
    # Configure console logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    # ----- Step 1: Connect to the database -----
    db = ThreatDatabase(DB_CONFIG)

    # ----- Step 2: Define WebSocket callbacks -----

    def on_open(ws):
        logging.info("WebSocket connection opened to %s", STREAM_URL)

    def on_message(ws, message: str):
        """Handle each incoming JSON message from the stream."""
        threat = parse_threat_message(message)
        if threat is None:
            return
        db.insert_threat(threat)

    def on_error(ws, error):
        logging.error("WebSocket error: %s", error)

    def on_close(ws, close_status_code, close_msg):
        logging.warning(
            "WebSocket closed: code=%s msg=%s",
            close_status_code,
            close_msg,
        )

    # ----- Step 3: Connect to the stream with auto-reconnect -----
    while True:
        try:
            logging.info("Connecting to streaming API: %s", STREAM_URL)

            ws_app = websocket.WebSocketApp(
                STREAM_URL,
                on_open=on_open,
                on_message=on_message,
                on_error=on_error,
                on_close=on_close,
            )

            # run_forever blocks until the connection is closed or an error occurs
            ws_app.run_forever(
                sslopt={"cert_reqs": ssl.CERT_NONE},  # skip TLS verification if needed
                ping_interval=30,
                ping_timeout=10,
            )

            logging.warning(
                "WebSocket disconnected. Reconnecting in %s seconds...",
                RECONNECT_DELAY_SECONDS,
            )
        except Exception as e:
            logging.error("WebSocket run_forever exception: %s", e)

        time.sleep(RECONNECT_DELAY_SECONDS)


# ======================
# Script entry point
# ======================

if __name__ == "__main__":
    # Running this file directly will start the listener:
    #   python stream_listener.py
    start_listener()
