from __future__ import annotations

import json
import sqlite3
import uuid
from pathlib import Path
from threading import RLock
from typing import Any

SCHEMA_VERSION = 4


class Storage:
    def __init__(self, data_dir: str):
        self.data_dir = Path(data_dir).expanduser().resolve()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        legacy_path = self.data_dir / "hap-v4.sqlite3"
        self.db_path = self.data_dir / "hap.sqlite3"
        if legacy_path.exists() and not self.db_path.exists():
            legacy_path.replace(self.db_path)
            for suffix in ("-wal", "-shm"):
                legacy_sidecar = Path(str(legacy_path) + suffix)
                if legacy_sidecar.exists():
                    legacy_sidecar.replace(Path(str(self.db_path) + suffix))
        self.connection = sqlite3.connect(
            self.db_path, check_same_thread=False, timeout=10.0
        )
        self.connection.row_factory = sqlite3.Row
        self.lock = RLock()
        self._closed = False
        self._create_schema()

    def _create_schema(self) -> None:
        with self.lock, self.connection:
            self.connection.executescript(
                """
                PRAGMA journal_mode=WAL;
                PRAGMA synchronous=FULL;
                PRAGMA foreign_keys=ON;
                PRAGMA busy_timeout=10000;
                PRAGMA wal_autocheckpoint=1000;

                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS records (
                    ingest_seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    record_id TEXT NOT NULL UNIQUE,
                    kind TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    target_record_id TEXT,
                    author_id TEXT NOT NULL,
                    body TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_records_target ON records(target_record_id);

                CREATE TABLE IF NOT EXISTS batches (
                    ingest_seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    batch_id TEXT NOT NULL UNIQUE,
                    created_at INTEGER NOT NULL,
                    network TEXT NOT NULL,
                    merkle_root TEXT NOT NULL,
                    payload_hex TEXT NOT NULL,
                    body TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS record_batches (
                    record_id TEXT NOT NULL,
                    batch_id TEXT NOT NULL,
                    position INTEGER NOT NULL,
                    PRIMARY KEY(record_id, batch_id),
                    FOREIGN KEY(record_id) REFERENCES records(record_id),
                    FOREIGN KEY(batch_id) REFERENCES batches(batch_id)
                );
                CREATE INDEX IF NOT EXISTS idx_record_batches_batch ON record_batches(batch_id, position);

                CREATE TABLE IF NOT EXISTS anchors (
                    ingest_seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    txid TEXT NOT NULL,
                    vout INTEGER NOT NULL,
                    batch_id TEXT NOT NULL,
                    network TEXT NOT NULL,
                    status TEXT NOT NULL,
                    anchored_at INTEGER NOT NULL,
                    block_hash TEXT,
                    block_height INTEGER,
                    UNIQUE(txid, vout),
                    FOREIGN KEY(batch_id) REFERENCES batches(batch_id)
                );
                CREATE INDEX IF NOT EXISTS idx_anchors_batch ON anchors(batch_id);

                CREATE TABLE IF NOT EXISTS bitcoin_blocks (
                    height INTEGER PRIMARY KEY,
                    block_hash TEXT NOT NULL UNIQUE,
                    block_time INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS commitments (
                    ingest_seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    txid TEXT NOT NULL,
                    vout INTEGER NOT NULL,
                    batch_id TEXT NOT NULL,
                    payload_hex TEXT NOT NULL,
                    network TEXT NOT NULL,
                    block_height INTEGER NOT NULL,
                    block_hash TEXT NOT NULL,
                    block_time INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    discovered_at INTEGER NOT NULL,
                    resolved INTEGER NOT NULL DEFAULT 0,
                    UNIQUE(txid, vout)
                );
                CREATE INDEX IF NOT EXISTS idx_commitments_batch ON commitments(batch_id);
                CREATE INDEX IF NOT EXISTS idx_commitments_height ON commitments(block_height);
                CREATE INDEX IF NOT EXISTS idx_commitments_resolved ON commitments(resolved, ingest_seq);
                """
            )
            row = self.connection.execute(
                "SELECT value FROM metadata WHERE key = 'schema_version'"
            ).fetchone()
            if row is None:
                version = SCHEMA_VERSION
                self.connection.execute(
                    "INSERT INTO metadata(key, value) VALUES ('schema_version', ?)",
                    (str(SCHEMA_VERSION),),
                )
            else:
                version = int(row["value"])
                if version not in {2, 3, SCHEMA_VERSION}:
                    raise RuntimeError(
                        f"database schema version {version} is not supported by this build "
                        f"(expected 2, 3, or {SCHEMA_VERSION})"
                    )
            anchor_columns = {
                str(item["name"])
                for item in self.connection.execute(
                    "PRAGMA table_info(anchors)"
                ).fetchall()
            }
            if "vout" not in anchor_columns:
                self.connection.execute("DROP INDEX IF EXISTS idx_anchors_batch")
                self.connection.execute("ALTER TABLE anchors RENAME TO anchors_pre_v4")
                self.connection.executescript(
                    """
                    CREATE TABLE anchors (
                        ingest_seq INTEGER PRIMARY KEY AUTOINCREMENT,
                        txid TEXT NOT NULL,
                        vout INTEGER NOT NULL,
                        batch_id TEXT NOT NULL,
                        network TEXT NOT NULL,
                        status TEXT NOT NULL,
                        anchored_at INTEGER NOT NULL,
                        block_hash TEXT,
                        block_height INTEGER,
                        UNIQUE(txid, vout),
                        FOREIGN KEY(batch_id) REFERENCES batches(batch_id)
                    );
                    INSERT INTO anchors(
                        ingest_seq, txid, vout, batch_id, network, status, anchored_at, block_hash, block_height
                    )
                    SELECT ingest_seq, txid, 0, batch_id, network, status, anchored_at, block_hash, block_height
                    FROM anchors_pre_v4;
                    DROP TABLE anchors_pre_v4;
                    CREATE INDEX idx_anchors_batch ON anchors(batch_id);
                    """
                )
            if version != SCHEMA_VERSION:
                self.connection.execute(
                    "UPDATE metadata SET value = ? WHERE key = 'schema_version'",
                    (str(SCHEMA_VERSION),),
                )
            node_row = self.connection.execute(
                "SELECT value FROM metadata WHERE key = 'node_instance_id'"
            ).fetchone()
            if node_row is None:
                self.connection.execute(
                    "INSERT INTO metadata(key, value) VALUES ('node_instance_id', ?)",
                    (uuid.uuid4().hex,),
                )

    def close(self) -> None:
        """Close the SQLite connection safely and idempotently."""
        with self.lock:
            if self._closed:
                return
            self.connection.close()
            self._closed = True

    def __enter__(self) -> "Storage":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def __del__(self) -> None:
        # Best-effort protection for short-lived tools/tests. Long-running callers
        # should still close explicitly or use the context-manager interface.
        try:
            self.close()
        except Exception:
            pass

    def check(self) -> dict[str, Any]:
        with self.lock:
            integrity = self.connection.execute("PRAGMA quick_check").fetchone()[0]
            schema = self.connection.execute(
                "SELECT value FROM metadata WHERE key = 'schema_version'"
            ).fetchone()["value"]
        return {
            "database": "ok" if integrity == "ok" else integrity,
            "schema_version": int(schema),
        }

    def metadata_get(self, key: str) -> str | None:
        with self.lock:
            row = self.connection.execute(
                "SELECT value FROM metadata WHERE key = ?", (key,)
            ).fetchone()
        return str(row["value"]) if row else None

    def metadata_set(self, key: str, value: str) -> None:
        with self.lock, self.connection:
            self.connection.execute(
                "INSERT INTO metadata(key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

    @property
    def node_instance_id(self) -> str:
        value = self.metadata_get("node_instance_id")
        if not value:
            raise RuntimeError("node_instance_id is missing")
        return value

    def peer_sync_state(self, peer_key: str) -> dict[str, Any] | None:
        value = self.metadata_get(f"peer_sync:{peer_key}")
        return json.loads(value) if value else None

    def set_peer_sync_state(self, peer_key: str, state: dict[str, Any]) -> None:
        self.metadata_set(
            f"peer_sync:{peer_key}",
            json.dumps(state, sort_keys=True, separators=(",", ":")),
        )

    def backup_database(self, destination: str | Path) -> Path:
        path = Path(destination).expanduser().resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        target = sqlite3.connect(path)
        try:
            with self.lock:
                self.connection.backup(target)
        finally:
            target.close()
        return path

    def add_record(self, record: dict[str, Any]) -> bool:
        with self.lock, self.connection:
            cursor = self.connection.execute(
                """
                INSERT OR IGNORE INTO records(record_id, kind, created_at, target_record_id, author_id, body)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    record["record_id"],
                    record["kind"],
                    record["created_at"],
                    record.get("target_record_id"),
                    record["author_id"],
                    json.dumps(record, ensure_ascii=False, separators=(",", ":")),
                ),
            )
            return cursor.rowcount > 0

    def record(self, record_id: str) -> dict[str, Any] | None:
        with self.lock:
            row = self.connection.execute(
                "SELECT body FROM records WHERE record_id = ?", (record_id,)
            ).fetchone()
        return json.loads(row["body"]) if row else None

    def records_by_ids(self, record_ids: list[str]) -> list[dict[str, Any]]:
        return [
            record
            for record_id in record_ids
            if (record := self.record(record_id)) is not None
        ]

    def records(
        self, *, limit: int = 100, unbatched_only: bool = False
    ) -> list[dict[str, Any]]:
        if unbatched_only:
            query = """
                SELECT body FROM records
                WHERE NOT EXISTS (
                    SELECT 1 FROM record_batches rb WHERE rb.record_id = records.record_id
                )
                ORDER BY ingest_seq ASC LIMIT ?
            """
        else:
            query = "SELECT body FROM records ORDER BY ingest_seq ASC LIMIT ?"
        with self.lock:
            rows = self.connection.execute(query, (limit,)).fetchall()
        return [json.loads(row["body"]) for row in rows]

    def record_sync_page(
        self, after_seq: int, *, limit: int
    ) -> tuple[list[dict[str, Any]], int | None]:
        with self.lock:
            rows = self.connection.execute(
                "SELECT ingest_seq, body FROM records WHERE ingest_seq > ? ORDER BY ingest_seq ASC LIMIT ?",
                (after_seq, limit),
            ).fetchall()
        items = [json.loads(row["body"]) for row in rows]
        return items, (int(rows[-1]["ingest_seq"]) if rows else None)

    def latest_records(self, *, limit: int = 100) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.connection.execute(
                "SELECT body FROM records ORDER BY ingest_seq DESC LIMIT ?", (limit,)
            ).fetchall()
        return [json.loads(row["body"]) for row in rows]

    def linked_records(self, target_record_id: str) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.connection.execute(
                "SELECT body FROM records WHERE target_record_id = ? ORDER BY ingest_seq ASC",
                (target_record_id,),
            ).fetchall()
        return [json.loads(row["body"]) for row in rows]

    def add_batch(self, batch: dict[str, Any]) -> bool:
        with self.lock, self.connection:
            cursor = self.connection.execute(
                """
                INSERT OR IGNORE INTO batches(batch_id, created_at, network, merkle_root, payload_hex, body)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    batch["batch_id"],
                    batch["created_at"],
                    batch["network"],
                    batch["merkle_root"],
                    batch["payload_hex"],
                    json.dumps(batch, ensure_ascii=False, separators=(",", ":")),
                ),
            )
            self.connection.executemany(
                "INSERT OR IGNORE INTO record_batches(record_id, batch_id, position) VALUES (?, ?, ?)",
                [
                    (record_id, batch["batch_id"], position)
                    for position, record_id in enumerate(batch["record_ids"])
                ],
            )
            return cursor.rowcount > 0

    def batch(self, batch_id: str) -> dict[str, Any] | None:
        with self.lock:
            row = self.connection.execute(
                "SELECT body FROM batches WHERE batch_id = ?", (batch_id,)
            ).fetchone()
        return json.loads(row["body"]) if row else None

    def batches(self, *, limit: int = 100) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.connection.execute(
                "SELECT body FROM batches ORDER BY ingest_seq DESC LIMIT ?", (limit,)
            ).fetchall()
        return [json.loads(row["body"]) for row in rows]

    def batch_sync_page(
        self, after_seq: int, *, limit: int
    ) -> tuple[list[dict[str, Any]], int | None]:
        with self.lock:
            rows = self.connection.execute(
                "SELECT ingest_seq, body FROM batches WHERE ingest_seq > ? ORDER BY ingest_seq ASC LIMIT ?",
                (after_seq, limit),
            ).fetchall()
        items = [json.loads(row["body"]) for row in rows]
        return items, (int(rows[-1]["ingest_seq"]) if rows else None)

    def batches_for_record(self, record_id: str) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.connection.execute(
                """
                SELECT b.body FROM batches b
                JOIN record_batches rb ON rb.batch_id = b.batch_id
                WHERE rb.record_id = ?
                ORDER BY b.ingest_seq ASC
                """,
                (record_id,),
            ).fetchall()
        return [json.loads(row["body"]) for row in rows]

    def add_anchor(self, anchor: dict[str, Any]) -> bool:
        with self.lock, self.connection:
            existed = self.connection.execute(
                "SELECT 1 FROM anchors WHERE txid = ? AND vout = ?",
                (anchor["txid"], anchor["vout"]),
            ).fetchone()
            self.connection.execute(
                """
                INSERT INTO anchors(txid, vout, batch_id, network, status, anchored_at, block_hash, block_height)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(txid, vout) DO UPDATE SET
                    batch_id = excluded.batch_id,
                    network = excluded.network,
                    status = excluded.status,
                    anchored_at = excluded.anchored_at,
                    block_hash = excluded.block_hash,
                    block_height = excluded.block_height
                """,
                (
                    anchor["txid"],
                    anchor["vout"],
                    anchor["batch_id"],
                    anchor["network"],
                    anchor["status"],
                    anchor["anchored_at"],
                    anchor.get("block_hash"),
                    anchor.get("block_height"),
                ),
            )
            return existed is None

    def anchor(self, txid: str, vout: int = 0) -> dict[str, Any] | None:
        with self.lock:
            row = self.connection.execute(
                "SELECT * FROM anchors WHERE txid = ? AND vout = ?", (txid, vout)
            ).fetchone()
        if not row:
            return None
        return {key: row[key] for key in row.keys() if key != "ingest_seq"}

    def anchors(self, batch_id: str | None = None) -> list[dict[str, Any]]:
        with self.lock:
            if batch_id:
                rows = self.connection.execute(
                    "SELECT * FROM anchors WHERE batch_id = ? ORDER BY ingest_seq ASC",
                    (batch_id,),
                ).fetchall()
            else:
                rows = self.connection.execute(
                    "SELECT * FROM anchors ORDER BY ingest_seq ASC"
                ).fetchall()
        return [
            {key: row[key] for key in row.keys() if key != "ingest_seq"} for row in rows
        ]

    def anchor_sync_page(
        self, after_seq: int, *, limit: int
    ) -> tuple[list[dict[str, Any]], int | None]:
        with self.lock:
            rows = self.connection.execute(
                "SELECT * FROM anchors WHERE ingest_seq > ? ORDER BY ingest_seq ASC LIMIT ?",
                (after_seq, limit),
            ).fetchall()
        items = [
            {key: row[key] for key in row.keys() if key != "ingest_seq"} for row in rows
        ]
        return items, (int(rows[-1]["ingest_seq"]) if rows else None)

    def anchored_record_ids(self) -> set[str]:
        with self.lock:
            rows = self.connection.execute(
                """
                SELECT DISTINCT rb.record_id
                FROM record_batches rb
                JOIN anchors a ON a.batch_id = rb.batch_id
                WHERE a.status = 'confirmed'
                """
            ).fetchall()
        return {str(row["record_id"]) for row in rows}

    def confirmed_anchor_height_for_record(self, record_id: str) -> int | None:
        with self.lock:
            row = self.connection.execute(
                """
                SELECT MIN(a.block_height) AS block_height
                FROM record_batches rb
                JOIN anchors a ON a.batch_id = rb.batch_id
                WHERE rb.record_id = ? AND a.status = 'confirmed' AND a.block_height IS NOT NULL
                """,
                (record_id,),
            ).fetchone()
        return (
            int(row["block_height"])
            if row and row["block_height"] is not None
            else None
        )

    def confirmed_anchor_heights(self, record_ids: list[str]) -> dict[str, int]:
        return {
            record_id: height
            for record_id in record_ids
            if (height := self.confirmed_anchor_height_for_record(record_id))
            is not None
        }

    def add_scanned_block(self, height: int, block_hash: str, block_time: int) -> None:
        with self.lock, self.connection:
            self.connection.execute(
                "INSERT OR REPLACE INTO bitcoin_blocks(height, block_hash, block_time) VALUES (?, ?, ?)",
                (height, block_hash, block_time),
            )

    def scanned_block(self, height: int) -> dict[str, Any] | None:
        with self.lock:
            row = self.connection.execute(
                "SELECT height, block_hash, block_time FROM bitcoin_blocks WHERE height = ?",
                (height,),
            ).fetchone()
        return dict(row) if row else None

    def latest_scanned_block(self) -> dict[str, Any] | None:
        with self.lock:
            row = self.connection.execute(
                "SELECT height, block_hash, block_time FROM bitcoin_blocks ORDER BY height DESC LIMIT 1"
            ).fetchone()
        return dict(row) if row else None

    def add_commitment(self, commitment: dict[str, Any]) -> bool:
        with self.lock, self.connection:
            existed = self.connection.execute(
                "SELECT 1 FROM commitments WHERE txid = ? AND vout = ?",
                (commitment["txid"], commitment["vout"]),
            ).fetchone()
            self.connection.execute(
                """
                INSERT INTO commitments(
                    txid, vout, batch_id, payload_hex, network, block_height, block_hash,
                    block_time, status, discovered_at, resolved
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(txid, vout) DO UPDATE SET
                    batch_id = excluded.batch_id,
                    payload_hex = excluded.payload_hex,
                    network = excluded.network,
                    block_height = excluded.block_height,
                    block_hash = excluded.block_hash,
                    block_time = excluded.block_time,
                    status = excluded.status
                """,
                (
                    commitment["txid"],
                    commitment["vout"],
                    commitment["batch_id"],
                    commitment["payload_hex"],
                    commitment["network"],
                    commitment["block_height"],
                    commitment["block_hash"],
                    commitment["block_time"],
                    commitment["status"],
                    commitment["discovered_at"],
                    int(bool(commitment.get("resolved", False))),
                ),
            )
            return existed is None

    def commitment(self, txid: str, vout: int = 0) -> dict[str, Any] | None:
        with self.lock:
            row = self.connection.execute(
                "SELECT * FROM commitments WHERE txid = ? AND vout = ?", (txid, vout)
            ).fetchone()
        return (
            {key: row[key] for key in row.keys() if key != "ingest_seq"}
            if row
            else None
        )

    def commitments(
        self,
        *,
        unresolved_only: bool = False,
        batch_id: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        with self.lock:
            if unresolved_only and batch_id is not None:
                rows = self.connection.execute(
                    "SELECT * FROM commitments WHERE resolved = 0 AND batch_id = ? "
                    "ORDER BY ingest_seq ASC LIMIT ?",
                    (batch_id, limit),
                ).fetchall()
            elif unresolved_only:
                rows = self.connection.execute(
                    "SELECT * FROM commitments WHERE resolved = 0 ORDER BY ingest_seq ASC LIMIT ?",
                    (limit,),
                ).fetchall()
            elif batch_id is not None:
                rows = self.connection.execute(
                    "SELECT * FROM commitments WHERE batch_id = ? ORDER BY ingest_seq ASC LIMIT ?",
                    (batch_id, limit),
                ).fetchall()
            else:
                rows = self.connection.execute(
                    "SELECT * FROM commitments ORDER BY ingest_seq ASC LIMIT ?",
                    (limit,),
                ).fetchall()
        return [
            {key: row[key] for key in row.keys() if key != "ingest_seq"} for row in rows
        ]

    def mark_commitment_resolved(self, txid: str, vout: int) -> None:
        with self.lock, self.connection:
            self.connection.execute(
                "UPDATE commitments SET resolved = 1 WHERE txid = ? AND vout = ?",
                (txid, vout),
            )

    def rewind_bitcoin_scan(self, ancestor_height: int) -> None:
        with self.lock, self.connection:
            rows = self.connection.execute(
                "SELECT txid, vout FROM commitments WHERE block_height > ?",
                (ancestor_height,),
            ).fetchall()
            anchor_points = [(row["txid"], row["vout"]) for row in rows]
            if anchor_points:
                self.connection.executemany(
                    "UPDATE anchors SET status = 'reorganised' WHERE txid = ? AND vout = ?",
                    anchor_points,
                )
            self.connection.execute(
                "DELETE FROM commitments WHERE block_height > ?", (ancestor_height,)
            )
            self.connection.execute(
                "DELETE FROM bitcoin_blocks WHERE height > ?", (ancestor_height,)
            )

    def counts(self) -> dict[str, int]:
        with self.lock:
            records = self.connection.execute(
                "SELECT COUNT(*) AS count FROM records"
            ).fetchone()["count"]
            batches = self.connection.execute(
                "SELECT COUNT(*) AS count FROM batches"
            ).fetchone()["count"]
            anchors = self.connection.execute(
                "SELECT COUNT(*) AS count FROM anchors"
            ).fetchone()["count"]
            commitments = self.connection.execute(
                "SELECT COUNT(*) AS count FROM commitments"
            ).fetchone()["count"]
            unresolved = self.connection.execute(
                "SELECT COUNT(*) AS count FROM commitments WHERE resolved = 0"
            ).fetchone()["count"]
            unbatched = self.connection.execute(
                "SELECT COUNT(*) AS count FROM records r WHERE NOT EXISTS "
                "(SELECT 1 FROM record_batches rb WHERE rb.record_id = r.record_id)"
            ).fetchone()["count"]
        return {
            "records": int(records),
            "batches": int(batches),
            "anchors": int(anchors),
            "bitcoin_commitments": int(commitments),
            "unresolved_commitments": int(unresolved),
            "unbatched_records": int(unbatched),
        }
