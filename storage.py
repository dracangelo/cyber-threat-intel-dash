import os
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List

class ThreatStorage:
    def __init__(self, db_path: str = None):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        data_dir = os.path.join(base_dir, "data")
        os.makedirs(data_dir, exist_ok=True)
        self.db_path = db_path or os.path.join(data_dir, "threat_history.db")
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.cursor()
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS summary (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    total_threats INTEGER NOT NULL,
                    high_risk_indicators INTEGER NOT NULL,
                    active_campaigns INTEGER NOT NULL,
                    sources_online INTEGER NOT NULL,
                    abuse_last24h INTEGER NOT NULL,
                    otx_last24h INTEGER NOT NULL,
                    vt_malicious INTEGER NOT NULL,
                    risk_score INTEGER NOT NULL
                )
                """
            )
            conn.commit()

    def insert_summary(self, summary: Dict) -> None:
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO summary (
                    timestamp,
                    total_threats,
                    high_risk_indicators,
                    active_campaigns,
                    sources_online,
                    abuse_last24h,
                    otx_last24h,
                    vt_malicious,
                    risk_score
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """
                (
                    summary.get("timestamp"),
                    int(summary.get("total_threats", 0)),
                    int(summary.get("high_risk_indicators", 0)),
                    int(summary.get("active_campaigns", 0)),
                    int(summary.get("sources_online", 0)),
                    int(summary.get("abuse_last24h", 0)),
                    int(summary.get("otx_last24h", 0)),
                    int(summary.get("vt_malicious", 0)),
                    int(summary.get("risk_score", 0))
                )
            )
            conn.commit()

    def get_summary_history(self, days: int = 7) -> List[Dict]:
        since = datetime.utcnow() - timedelta(days=days)
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute(
                """
                SELECT timestamp, total_threats, high_risk_indicators, active_campaigns, risk_score
                FROM summary
                WHERE timestamp >= ?
                ORDER BY timestamp ASC
                """,
                (since.isoformat(),)
            )
            rows = cur.fetchall()

        return [dict(row) for row in rows]
