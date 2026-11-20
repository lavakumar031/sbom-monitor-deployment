from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import sys
import threading
import time
import subprocess
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Set, Tuple

from flask import Flask, jsonify, render_template, request, send_from_directory

# ---------------- PATH SETUP FIRST ----------------
REPO_ROOT = Path(__file__).resolve().parent
SBOM_MODULE_PATH = REPO_ROOT / "sbom-tools"

if str(SBOM_MODULE_PATH) not in sys.path:
    sys.path.insert(0, str(SBOM_MODULE_PATH))
# --------------------------------------------------

from db_monitor_job import monitor_once

_config = None
_scanner_class = None

DEFAULT_RISK_WEIGHTS = {
    "impact_weight": 40.0,
    "exploitation_weight": 25.0,
    "exposure_weight": 10.0,
    "persistence_weight": 10.0,
    "remediation_weight": 15.0,
}


def has_fixed_version(value: object) -> bool:
    text = str(value or "").strip().lower()
    return bool(text and text not in {"n/a", "none", "not available", "unknown", "null", "-"})


def choose_compatible_fixed_version(values: List[object], current_version: str = "") -> str | None:
    """Choose the smallest valid fix, preferring the installed major-version line."""
    from packaging.version import InvalidVersion, Version

    unique = []
    for value in values:
        text = str(value or "").strip()
        if has_fixed_version(text) and text not in unique:
            unique.append(text)
    if not unique:
        return None
    parsed: List[Tuple[Version, str]] = []
    for text in unique:
        try:
            parsed.append((Version(text.lstrip("v")), text))
        except InvalidVersion:
            continue
    if not parsed:
        return unique[0]
    parsed.sort(key=lambda item: item[0])
    try:
        current = Version(str(current_version).lstrip("v")) if current_version else None
    except InvalidVersion:
        current = None
    if current is not None:
        same_major = [item for item in parsed if item[0].major == current.major and item[0] >= current]
        if same_major:
            return same_major[0][1]
        newer = [item for item in parsed if item[0] >= current]
        if newer:
            return newer[0][1]
    return parsed[0][1]


def calculate_risk_score(
    severity: object,
    fixed_version: object,
    affected_repositories: int = 1,
    age_days: int = 0,
    intelligence: Dict[str, object] | None = None,
    weights: Dict[str, object] | None = None,
) -> Dict[str, object]:
    """Return a transparent 0-100 score using only evidence available to the system."""
    intel = intelligence or {}
    configured = {**DEFAULT_RISK_WEIGHTS, **(weights or {})}
    try:
        impact_weight = float(configured["impact_weight"])
        exploitation_weight = float(configured["exploitation_weight"])
        exposure_weight = float(configured["exposure_weight"])
        persistence_weight = float(configured["persistence_weight"])
        remediation_weight = float(configured["remediation_weight"])
    except (KeyError, TypeError, ValueError):
        impact_weight = DEFAULT_RISK_WEIGHTS["impact_weight"]
        exploitation_weight = DEFAULT_RISK_WEIGHTS["exploitation_weight"]
        exposure_weight = DEFAULT_RISK_WEIGHTS["exposure_weight"]
        persistence_weight = DEFAULT_RISK_WEIGHTS["persistence_weight"]
        remediation_weight = DEFAULT_RISK_WEIGHTS["remediation_weight"]
    try:
        cvss = float(intel.get("cvss_score")) if intel.get("cvss_score") is not None else None
    except (TypeError, ValueError):
        cvss = None
    severity_name = str(severity or intel.get("severity") or "unknown").lower()
    severity_factors = {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25,
                        "negligible": 0.075, "unknown": 0.125}
    impact = (round(min(1.0, max(0.0, cvss / 10.0)) * impact_weight, 1)
              if cvss is not None else round(severity_factors.get(severity_name, 0.125) * impact_weight, 1))

    try:
        epss = float(intel.get("epss_score")) if intel.get("epss_score") is not None else 0.0
    except (TypeError, ValueError):
        epss = 0.0
    exploitation = (exploitation_weight if bool(intel.get("known_exploited"))
                    else round(min(0.8, max(0.0, epss)) * exploitation_weight, 1))
    exposure = round(min(1.0, max(1, int(affected_repositories or 1)) / 5.0) * exposure_weight, 1)
    persistence = round(min(1.0, max(0, int(age_days or 0)) / 90.0) * persistence_weight, 1)
    remediation = round(remediation_weight * (2.0 / 15.0), 1) if has_fixed_version(fixed_version) else remediation_weight
    score = round(min(100.0, impact + exploitation + exposure + persistence + remediation), 1)
    level = "critical" if score >= 75 else "high" if score >= 50 else "medium" if score >= 30 else "low"
    return {
        "score": score,
        "level": level,
        "breakdown": {
            "impact": impact,
            "exploitation": exploitation,
            "repository_exposure": exposure,
            "persistence": persistence,
            "remediation": remediation,
        },
        "evidence": {
            "cvss_available": cvss is not None,
            "epss_available": intel.get("epss_score") is not None,
            "cisa_kev_checked": intel.get("sources", {}).get("cisa_kev") == "available" if isinstance(intel.get("sources"), dict) else False,
            "dependency_depth_available": False,
        },
        "method": (
            f"Impact {impact_weight:g} + exploitation {exploitation_weight:g} + "
            f"repository exposure {exposure_weight:g} + persistence {persistence_weight:g} + "
            f"remediation {remediation_weight:g}"
        ),
    }


def get_config():
    global _config
    if _config is None:
        from sbom import Config  # type: ignore
        _config = Config
    return _config


def get_scanner_class():
    global _scanner_class
    if _scanner_class is None:
        from sbom import SBOMScanner  # type: ignore
        if not hasattr(SBOMScanner, "get_report"):
            raise RuntimeError(
                "SBOMScanner class is missing 'get_report' method. Please check sbom.py file."
            )
        _scanner_class = SBOMScanner
    return _scanner_class


@dataclass
class TreeNode:
    name: str
    children: List["TreeNode"]


def build_dependency_tree(graph: List[Dict[str, str]]) -> List[Dict[str, object]]:
    children_map: Dict[str, List[str]] = {}
    child_counts: Dict[str, int] = {}

    for edge in graph:
        parent = edge.get("parent")
        child = edge.get("child")
        if not parent or not child:
            continue

        children_map.setdefault(parent, []).append(child)
        child_counts[child] = child_counts.get(child, 0) + 1
        child_counts.setdefault(parent, child_counts.get(parent, 0))

    all_nodes = set(children_map.keys()) | set(child_counts.keys())
    roots = [node for node in all_nodes if child_counts.get(node, 0) == 0]
    if not roots and all_nodes:
        roots = sorted(all_nodes)

    def build_node(name: str, visited: Set[str]) -> TreeNode:
        if name in visited:
            return TreeNode(name=name, children=[])

        visited = set(visited)
        visited.add(name)

        children = [
            build_node(child, visited)
            for child in sorted(children_map.get(name, []))
        ]
        return TreeNode(name=name, children=children)

    tree = [build_node(root, set()) for root in sorted(roots)]
    return [
        {"name": node.name, "children": _serialize_child_nodes(node.children)}
        for node in tree
    ]


def _serialize_child_nodes(children: List[TreeNode]) -> List[Dict[str, object]]:
    serialized: List[Dict[str, object]] = []
    for child in children:
        serialized.append(
            {"name": child.name, "children": _serialize_child_nodes(child.children)}
        )
    return serialized


def normalize_active(value) -> int:
    if isinstance(value, bool):
        return 1 if value else 0
    if value is None:
        return 1

    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "y", "active"}:
        return 1
    if text in {"0", "false", "no", "n", "inactive"}:
        return 0
    return 1


def clean_target_row(row: Dict[str, object]) -> Dict[str, object]:
    return {
        "target_id": str(row.get("target_id", "")).strip(),
        "target_type": str(row.get("target_type", "")).strip(),
        "source_name": str(row.get("source_name", "")).strip(),
        "notes": str(row.get("notes", "")).strip(),
        "active": normalize_active(row.get("active", 1)),
    }


def validate_target_row(row: Dict[str, object]) -> str | None:
    if not row["target_id"]:
        return "Target ID is required"
    if not row["target_type"]:
        return "Target Type is required"
    if not row["source_name"]:
        return "Source Name is required"
    return None


def parse_csv_targets(raw_text: str) -> List[Dict[str, object]]:
    reader = csv.DictReader(io.StringIO(raw_text))
    rows: List[Dict[str, object]] = []
    for item in reader:
        rows.append(clean_target_row(item))
    return rows


def parse_json_targets(raw_text: str) -> List[Dict[str, object]]:
    parsed = json.loads(raw_text)

    if isinstance(parsed, list):
        source_rows = parsed
    elif isinstance(parsed, dict) and isinstance(parsed.get("rows"), list):
        source_rows = parsed["rows"]
    else:
        raise ValueError("JSON must be an array of target objects or an object containing a 'rows' array")

    rows: List[Dict[str, object]] = []
    for item in source_rows:
        if not isinstance(item, dict):
            raise ValueError("Each JSON row must be an object")
        rows.append(clean_target_row(item))

    return rows


def get_server_port() -> int:
    return int(os.getenv("SBOM_SERVER_PORT", "5050"))


def open_browser_window(url: str | None = None) -> None:
    url = url or f"http://127.0.0.1:{get_server_port()}"
    try:
        time.sleep(2)

        if os.name == "nt":
            try:
                os.startfile(url)  # type: ignore[attr-defined]
                return
            except Exception as e:
                print(f"[BROWSER] os.startfile failed: {e}")

        try:
            import webbrowser
            opened = webbrowser.open_new(url)
            if not opened:
                print("[BROWSER] webbrowser.open_new returned False")
        except Exception as e:
            print(f"[BROWSER] webbrowser fallback failed: {e}")

    except Exception as e:
        print(f"[BROWSER] Could not open browser automatically: {e}")


def start_browser_thread() -> None:
    if os.getenv("SBOM_OPEN_BROWSER", "false").lower() != "true":
        return
    try:
        threading.Thread(target=open_browser_window, daemon=True).start()
    except Exception as e:
        print(f"[BROWSER] Failed to start browser thread: {e}")


def refresh_analytics_assets() -> None:
    refresh_script = REPO_ROOT / "refresh_dashboard_assets.py"
    try:
        print("[ANALYTICS] Refresh started...")
        subprocess.run(
            [sys.executable, str(refresh_script)],
            cwd=str(REPO_ROOT),
            check=True
        )
        print("[ANALYTICS] Refresh completed successfully.")
    except Exception as exc:
        print(f"[ANALYTICS] Refresh failed: {exc}")


def start_refresh_analytics_thread() -> None:
    try:
        threading.Thread(target=refresh_analytics_assets, daemon=True).start()
    except Exception as exc:
        print(f"[ANALYTICS] Failed to start refresh thread: {exc}")


def refresh_analytics_after_scan() -> None:
    """Refresh large analytics files only when explicitly enabled."""
    if os.getenv("SBOM_AUTO_ANALYTICS_REFRESH", "false").lower() == "true":
        start_refresh_analytics_thread()


def create_app() -> Flask:
    app = Flask(
        __name__,
        template_folder="ui/templates",
        static_folder="ui/static",
    )

    app.config["scanner_lock"] = threading.Lock()
    app.config["batch_jobs"] = {}
    app.config["batch_jobs_lock"] = threading.Lock()
    app.config["scheduler_cycle_lock"] = threading.Lock()
    app.config["scheduler_wakeup"] = threading.Event()
    app.config["scheduler_tables_lock"] = threading.Lock()
    app.config["scheduler_tables_ready"] = False
    app.config["risk_settings_lock"] = threading.Lock()
    app.config["risk_settings_ready"] = False
    app.config["risk_settings_loaded"] = False
    app.config["risk_settings"] = dict(DEFAULT_RISK_WEIGHTS)

    @app.after_request
    def add_no_cache_headers(response):
        if response.content_type and ("javascript" in response.content_type or "html" in response.content_type):
            response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        return response

    def run_scan_core(target: str, use_cache: bool = True, shallow_clone: bool = True) -> Tuple[str, Dict[str, object]]:
        Config = get_config()
        SBOMScanner = get_scanner_class()
        Config.init_directories()

        lock: threading.Lock = app.config["scanner_lock"]

        with lock:
            scanner = SBOMScanner(
                use_cache=use_cache,
                shallow_clone=shallow_clone,
                skip_vuln=False,
            )
            scan_id = scanner.scan(target)
            report = scanner.get_report(scan_id) if scan_id else None

        if not scan_id:
            raise RuntimeError("Scan failed - no scan ID returned")

        if not report:
            raise RuntimeError("Report not found after scan")

        dependency_tree = build_dependency_tree(report.get("dependency_graph", []))
        report["dependency_tree"] = dependency_tree

        if "database_message" not in report:
            report["database_message"] = ""

        return scan_id, report

    def get_active_targets():
        import pymysql
        from lavakumar_db_config import DB_CONFIG

        conn = pymysql.connect(**DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT target_pk, target_id, target_type, source_name, active, notes, last_scan_time
                    FROM monitored_targets
                    WHERE active = 1
                    ORDER BY target_pk
                    """
                )
                return cur.fetchall()
        finally:
            conn.close()

    def update_last_scan_time(target_pk: int):
        import pymysql
        from lavakumar_db_config import DB_CONFIG

        conn = pymysql.connect(**DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE monitored_targets
                    SET last_scan_time = NOW()
                    WHERE target_pk = %s
                    """,
                    (target_pk,),
                )
                conn.commit()
        finally:
            conn.close()

    def ensure_scheduler_tables() -> None:
        import pymysql
        from lavakumar_db_config import DB_CONFIG

        if app.config.get("scheduler_tables_ready"):
            return
        table_lock: threading.Lock = app.config["scheduler_tables_lock"]
        with table_lock:
            if app.config.get("scheduler_tables_ready"):
                return
            conn = pymysql.connect(**DB_CONFIG)
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        CREATE TABLE IF NOT EXISTS scan_scheduler_config (
                            config_id TINYINT PRIMARY KEY,
                            enabled TINYINT(1) NOT NULL DEFAULT 0,
                            interval_minutes INT NOT NULL DEFAULT 60,
                            last_run_at DATETIME NULL,
                            next_run_at DATETIME NULL,
                            status VARCHAR(30) NOT NULL DEFAULT 'stopped',
                            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                        )
                        """
                    )
                    cur.execute(
                        """
                        INSERT INTO scan_scheduler_config
                            (config_id, enabled, interval_minutes, status)
                        VALUES (1, 0, 60, 'stopped')
                        ON DUPLICATE KEY UPDATE config_id = config_id
                        """
                    )
                    cur.execute(
                        """
                        CREATE TABLE IF NOT EXISTS scheduled_scan_history (
                            history_id BIGINT AUTO_INCREMENT PRIMARY KEY,
                            run_group_id VARCHAR(32) NOT NULL,
                            target_pk INT NULL,
                            target_id VARCHAR(512) NOT NULL,
                            trigger_type VARCHAR(20) NOT NULL,
                            scheduled_for DATETIME NULL,
                            started_at DATETIME NOT NULL,
                            finished_at DATETIME NULL,
                            status VARCHAR(20) NOT NULL,
                            scan_id VARCHAR(255) NULL,
                            total_packages INT NOT NULL DEFAULT 0,
                            total_vulnerabilities INT NOT NULL DEFAULT 0,
                            error_message TEXT NULL,
                            KEY idx_schedule_started (started_at),
                            KEY idx_schedule_target (target_id(191)),
                            KEY idx_schedule_group (run_group_id)
                        )
                        """
                    )
                    cur.execute(
                        """
                        CREATE TABLE IF NOT EXISTS scheduled_scan_targets (
                            scheduler_target_id INT AUTO_INCREMENT PRIMARY KEY,
                            target_pk INT NOT NULL,
                            enabled TINYINT(1) NOT NULL DEFAULT 1,
                            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            UNIQUE KEY uq_scheduler_target (target_pk),
                            FOREIGN KEY (target_pk) REFERENCES monitored_targets(target_pk) ON DELETE CASCADE
                        )
                        """
                    )
                conn.commit()
                app.config["scheduler_tables_ready"] = True
            finally:
                conn.close()

    def scheduler_config() -> Dict[str, object]:
        import pymysql
        from lavakumar_db_config import DB_CONFIG

        ensure_scheduler_tables()
        conn = pymysql.connect(**DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT enabled, interval_minutes, last_run_at, next_run_at, status, updated_at
                    FROM scan_scheduler_config WHERE config_id = 1
                    """
                )
                return cur.fetchone() or {}
        finally:
            conn.close()

    def get_scheduled_targets() -> List[Dict[str, object]]:
        import pymysql
        from lavakumar_db_config import DB_CONFIG

        ensure_scheduler_tables()
        conn = pymysql.connect(**DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT mt.target_pk, mt.target_id, mt.target_type, mt.source_name,
                           st.enabled, mt.last_scan_time, st.added_at
                    FROM scheduled_scan_targets st
                    INNER JOIN monitored_targets mt ON mt.target_pk = st.target_pk
                    WHERE st.enabled = 1
                    ORDER BY st.scheduler_target_id
                    """
                )
                return cur.fetchall()
        finally:
            conn.close()

    def update_scheduler_config(**values) -> None:
        import pymysql
        from lavakumar_db_config import DB_CONFIG

        allowed = {"enabled", "interval_minutes", "last_run_at", "next_run_at", "status"}
        fields = [(key, value) for key, value in values.items() if key in allowed]
        if not fields:
            return
        conn = pymysql.connect(**DB_CONFIG)
        try:
            assignments = ", ".join(f"{key} = %s" for key, _ in fields)
            with conn.cursor() as cur:
                cur.execute(
                    f"UPDATE scan_scheduler_config SET {assignments} WHERE config_id = 1",
                    tuple(value for _, value in fields),
                )
            conn.commit()
        finally:
            conn.close()

    def ensure_risk_settings() -> None:
        import pymysql
        from lavakumar_db_config import DB_CONFIG

        if app.config.get("risk_settings_ready"):
            return
        settings_lock: threading.Lock = app.config["risk_settings_lock"]
        with settings_lock:
            if app.config.get("risk_settings_ready"):
                return
            conn = pymysql.connect(**DB_CONFIG)
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        CREATE TABLE IF NOT EXISTS risk_scoring_settings (
                            settings_id TINYINT PRIMARY KEY,
                            impact_weight DECIMAL(6,2) NOT NULL DEFAULT 40,
                            exploitation_weight DECIMAL(6,2) NOT NULL DEFAULT 25,
                            exposure_weight DECIMAL(6,2) NOT NULL DEFAULT 10,
                            persistence_weight DECIMAL(6,2) NOT NULL DEFAULT 10,
                            remediation_weight DECIMAL(6,2) NOT NULL DEFAULT 15,
                            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                        )
                        """
                    )
                    cur.execute(
                        """
                        INSERT INTO risk_scoring_settings
                            (settings_id, impact_weight, exploitation_weight, exposure_weight,
                             persistence_weight, remediation_weight)
                        VALUES (1, 40, 25, 10, 10, 15)
                        ON DUPLICATE KEY UPDATE settings_id = settings_id
                        """
                    )
                conn.commit()
                app.config["risk_settings_ready"] = True
            finally:
                conn.close()

    def get_risk_settings() -> Dict[str, object]:
        import pymysql
        from lavakumar_db_config import DB_CONFIG

        ensure_risk_settings()
        if app.config.get("risk_settings_loaded"):
            return dict(app.config["risk_settings"])
        conn = pymysql.connect(**DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT impact_weight, exploitation_weight, exposure_weight,
                           persistence_weight, remediation_weight, updated_at
                    FROM risk_scoring_settings WHERE settings_id = 1
                    """
                )
                row = cur.fetchone() or {}
        finally:
            conn.close()
        settings = dict(DEFAULT_RISK_WEIGHTS)
        for name in DEFAULT_RISK_WEIGHTS:
            try:
                settings[name] = float(row.get(name, settings[name]))
            except (TypeError, ValueError):
                pass
        settings["updated_at"] = row.get("updated_at")
        app.config["risk_settings"] = settings
        app.config["risk_settings_loaded"] = True
        return settings

    def save_risk_settings(values: Dict[str, float]) -> Dict[str, object]:
        import pymysql
        from lavakumar_db_config import DB_CONFIG

        ensure_risk_settings()
        conn = pymysql.connect(**DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE risk_scoring_settings
                    SET impact_weight = %s, exploitation_weight = %s, exposure_weight = %s,
                        persistence_weight = %s, remediation_weight = %s
                    WHERE settings_id = 1
                    """,
                    (
                        values["impact_weight"], values["exploitation_weight"],
                        values["exposure_weight"], values["persistence_weight"],
                        values["remediation_weight"],
                    ),
                )
            conn.commit()
        finally:
            conn.close()
        app.config["risk_settings_loaded"] = False
        return get_risk_settings()

    def add_schedule_history(
        run_group_id: str,
        row: Dict[str, object],
        trigger_type: str,
        scheduled_for: datetime | None,
    ) -> int:
        import pymysql
        from lavakumar_db_config import DB_CONFIG

        conn = pymysql.connect(**DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO scheduled_scan_history
                        (run_group_id, target_pk, target_id, trigger_type, scheduled_for, started_at, status)
                    VALUES (%s, %s, %s, %s, %s, NOW(), 'running')
                    """,
                    (run_group_id, row.get("target_pk"), row.get("target_id", ""), trigger_type, scheduled_for),
                )
                history_id = int(cur.lastrowid)
            conn.commit()
            return history_id
        finally:
            conn.close()

    def finish_schedule_history(history_id: int, **values) -> None:
        import pymysql
        from lavakumar_db_config import DB_CONFIG

        allowed = {"status", "scan_id", "total_packages", "total_vulnerabilities", "error_message"}
        fields = [(key, value) for key, value in values.items() if key in allowed]
        conn = pymysql.connect(**DB_CONFIG)
        try:
            assignments = ", ".join(f"{key} = %s" for key, _ in fields)
            with conn.cursor() as cur:
                cur.execute(
                    f"UPDATE scheduled_scan_history SET {assignments}, finished_at = NOW() WHERE history_id = %s",
                    tuple(value for _, value in fields) + (history_id,),
                )
            conn.commit()
        finally:
            conn.close()

    def run_scheduled_cycle(trigger_type: str = "scheduled") -> bool:
        cycle_lock: threading.Lock = app.config["scheduler_cycle_lock"]
        if not cycle_lock.acquire(blocking=False):
            return False

        scheduled_for = datetime.now()
        run_group_id = uuid.uuid4().hex[:12]
        try:
            update_scheduler_config(status="running", last_run_at=scheduled_for)
            targets = get_scheduled_targets()
            if not targets:
                config = scheduler_config()
                interval = max(30, int(config.get("interval_minutes", 60) or 60))
                next_run = datetime.now() + timedelta(minutes=interval) if int(config.get("enabled", 0) or 0) else None
                update_scheduler_config(status="idle" if next_run else "stopped", next_run_at=next_run)
                return True

            for row in targets:
                target_id = str(row.get("target_id") or "").strip()
                if not target_id:
                    continue
                history_id = add_schedule_history(run_group_id, row, trigger_type, scheduled_for)
                try:
                    scan_id, report = run_scan_core(target_id, use_cache=True, shallow_clone=True)
                    update_last_scan_time(int(row.get("target_pk")))
                    summary = report.get("summary", {}) or {}
                    finish_schedule_history(
                        history_id,
                        status="success",
                        scan_id=scan_id,
                        total_packages=int(summary.get("total_packages", 0) or 0),
                        total_vulnerabilities=int(summary.get("total_vulnerabilities", 0) or 0),
                        error_message=None,
                    )
                    try:
                        monitor_once()
                    except Exception as mon_exc:
                        print(f"[SCHEDULER] Timeline monitor refresh failed for {target_id}: {mon_exc}")
                except Exception as exc:
                    finish_schedule_history(history_id, status="failed", error_message=str(exc))

            config = scheduler_config()
            interval = max(30, int(config.get("interval_minutes", 60) or 60))
            next_run = datetime.now() + timedelta(minutes=interval) if int(config.get("enabled", 0) or 0) else None
            update_scheduler_config(status="idle" if next_run else "stopped", next_run_at=next_run)
            refresh_analytics_after_scan()
            return True
        finally:
            cycle_lock.release()

    def background_scan_active_targets():
        targets = get_scheduled_targets()
        if not targets:
            print("[AUTO-SCAN] No active targets found.")
            return

        print(f"[AUTO-SCAN] Found {len(targets)} active target(s).")

        for row in targets:
            target_pk = row.get("target_pk")
            target_id = row.get("target_id", "")

            if not target_id:
                print(f"[AUTO-SCAN] Skipping empty target_id for target_pk={target_pk}")
                continue

            try:
                print(f"[AUTO-SCAN] Scanning: {target_id}")
                scan_id, report = run_scan_core(
                    target=target_id,
                    use_cache=True,
                    shallow_clone=True,
                )
                update_last_scan_time(target_pk)
                print(f"[AUTO-SCAN] Success: {target_id} -> scan_id={scan_id}")

                try:
                    monitor_once()
                except Exception as mon_exc:
                    print(f"[AUTO-SCAN] monitor refresh failed after {target_id}: {mon_exc}")

            except Exception as exc:
                print(f"[AUTO-SCAN] Failed: {target_id} -> {exc}")

    @app.route("/")
    def index():
        reports_dir = str(REPO_ROOT / "reports")
        cache_buster = int(time.time())
        analytics_file = REPO_ROOT / "ui" / "static" / "dashboard_plus" / "dashboard_plus.html"
        analytics_ready = analytics_file.exists()

        return render_template(
            "index.html",
            reports_dir=reports_dir,
            default_target="",
            cache_buster=cache_buster,
            analytics_ready=analytics_ready,
        )

    @app.route("/api/analytics/refresh", methods=["POST"])
    def analytics_refresh():
        start_refresh_analytics_thread()
        return jsonify({"message": "Analytics refresh started in background."})

    @app.route("/api/db/targets", methods=["GET"])
    def get_targets():
        import pymysql
        from lavakumar_db_config import DB_CONFIG

        conn = pymysql.connect(**DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT target_pk, target_id, target_type, source_name, active, last_scan_time, notes
                    FROM monitored_targets
                    ORDER BY target_pk
                    """
                )
                rows = cur.fetchall()

            return jsonify({"rows": rows})
        finally:
            conn.close()

    @app.route("/api/db/targets", methods=["POST"])
    def add_target():
        import pymysql
        from lavakumar_db_config import DB_CONFIG

        payload = request.get_json(silent=True) or {}
        row = clean_target_row(payload)
        validation_error = validate_target_row(row)
        if validation_error:
            return jsonify({"error": validation_error}), 400

        conn = pymysql.connect(**DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT COUNT(*) AS count_value
                    FROM monitored_targets
                    WHERE target_id = %s
                    """,
                    (row["target_id"],),
                )
                existing = cur.fetchone()
                existing_count = existing.get("count_value", 0) if isinstance(existing, dict) else 0

                if existing_count > 0:
                    return jsonify({"error": "Target ID already exists"}), 400

                cur.execute(
                    """
                    INSERT INTO monitored_targets
                    (target_id, target_type, source_name, active, last_scan_time, notes)
                    VALUES (%s, %s, %s, %s, NULL, %s)
                    """,
                    (
                        row["target_id"],
                        row["target_type"],
                        row["source_name"],
                        row["active"],
                        row["notes"],
                    ),
                )
                conn.commit()

            return jsonify({"message": "Target added successfully"})
        finally:
            conn.close()

    @app.route("/api/db/targets/import", methods=["POST"])
    def import_targets():
        import pymysql
        from lavakumar_db_config import DB_CONFIG

        content_type = request.form.get("content_type", "").strip().lower()
        raw_text = request.form.get("raw_text", "")

        uploaded_file = request.files.get("file")
        file_name = uploaded_file.filename if uploaded_file else ""

        try:
            if uploaded_file and file_name:
                ext = Path(file_name).suffix.lower()
                file_bytes = uploaded_file.read()
                raw_text = file_bytes.decode("utf-8-sig")

                if ext == ".csv":
                    content_type = "csv"
                elif ext == ".json":
                    content_type = "json"
                else:
                    return jsonify({"error": "Only CSV and JSON files are supported"}), 400
            else:
                if not raw_text.strip():
                    return jsonify({"error": "No import data provided"}), 400

            if content_type == "csv":
                rows = parse_csv_targets(raw_text)
            elif content_type == "json":
                rows = parse_json_targets(raw_text)
            else:
                return jsonify({"error": "Invalid content_type. Use csv or json"}), 400

        except UnicodeDecodeError:
            return jsonify({"error": "Could not decode uploaded file. Please use UTF-8 encoded CSV/JSON"}), 400
        except json.JSONDecodeError as exc:
            return jsonify({"error": f"Invalid JSON: {exc.msg}"}), 400
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except Exception as exc:
            return jsonify({"error": f"Import parsing failed: {exc}"}), 400

        if not rows:
            return jsonify({"error": "No valid rows found in import data"}), 400

        prepared_rows: List[Dict[str, object]] = []
        row_errors: List[str] = []

        for index, row in enumerate(rows, start=1):
            validation_error = validate_target_row(row)
            if validation_error:
                row_errors.append(f"Row {index}: {validation_error}")
            else:
                prepared_rows.append(row)

        if row_errors:
            return jsonify({"error": "Import validation failed", "details": row_errors}), 400

        conn = pymysql.connect(**DB_CONFIG)
        inserted_count = 0
        skipped_duplicates = 0
        duplicate_ids: List[str] = []

        try:
            with conn.cursor() as cur:
                for row in prepared_rows:
                    cur.execute(
                        """
                        SELECT COUNT(*) AS count_value
                        FROM monitored_targets
                        WHERE target_id = %s
                        """,
                        (row["target_id"],),
                    )
                    existing = cur.fetchone()
                    existing_count = existing.get("count_value", 0) if isinstance(existing, dict) else 0

                    if existing_count > 0:
                        skipped_duplicates += 1
                        duplicate_ids.append(str(row["target_id"]))
                        continue

                    cur.execute(
                        """
                        INSERT INTO monitored_targets
                        (target_id, target_type, source_name, active, last_scan_time, notes)
                        VALUES (%s, %s, %s, %s, NULL, %s)
                        """,
                        (
                            row["target_id"],
                            row["target_type"],
                            row["source_name"],
                            row["active"],
                            row["notes"],
                        ),
                    )
                    inserted_count += 1

                conn.commit()

            return jsonify(
                {
                    "message": "Import completed",
                    "inserted": inserted_count,
                    "skipped_duplicates": skipped_duplicates,
                    "duplicate_ids": duplicate_ids,
                    "received": len(rows),
                }
            )
        finally:
            conn.close()

    @app.route("/api/db/targets/<int:target_pk>/status", methods=["PATCH"])
    def update_target_status(target_pk: int):
        import pymysql
        from lavakumar_db_config import DB_CONFIG

        payload = request.get_json(silent=True) or {}
        active = 1 if payload.get("active", False) else 0

        conn = pymysql.connect(**DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE monitored_targets
                    SET active = %s
                    WHERE target_pk = %s
                    """,
                    (active, target_pk),
                )
                conn.commit()

            return jsonify({"message": "Target status updated"})
        finally:
            conn.close()

    @app.route("/api/db/targets/<int:target_pk>", methods=["DELETE"])
    def delete_target(target_pk: int):
        import pymysql
        from lavakumar_db_config import DB_CONFIG

        conn = pymysql.connect(**DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    DELETE FROM monitored_targets
                    WHERE target_pk = %s
                    """,
                    (target_pk,),
                )
                conn.commit()

            return jsonify({"message": "Target deleted"})
        finally:
            conn.close()

    @app.route("/api/db/targets/<int:target_pk>/scan", methods=["POST"])
    def scan_target_from_db(target_pk: int):
        import pymysql
        from lavakumar_db_config import DB_CONFIG

        payload = request.get_json(silent=True) or {}
        use_cache = payload.get("useCache", True)
        shallow_clone = payload.get("shallowClone", True)

        conn = pymysql.connect(**DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT target_pk, target_id, target_type, source_name, active, notes
                    FROM monitored_targets
                    WHERE target_pk = %s
                    """,
                    (target_pk,),
                )
                row = cur.fetchone()

            if not row:
                return jsonify({"error": "Target not found"}), 404

            target = row.get("target_id", "")
            if not target:
                return jsonify({"error": "Target ID is empty"}), 400

            try:
                scan_id, report = run_scan_core(
                    target=target,
                    use_cache=use_cache,
                    shallow_clone=shallow_clone,
                )
            except (FileNotFoundError, ValueError, RuntimeError) as exc:
                error_msg = str(exc)
                print(f"[ERROR] DB target scan failed: {error_msg}", file=sys.stderr)
                return jsonify({"error": error_msg}), 400
            except Exception as exc:
                error_msg = str(exc)
                print(f"[ERROR] Unexpected DB target scan error: {error_msg}", file=sys.stderr)
                import traceback
                traceback.print_exc()
                return jsonify({"error": f"Scan failed: {error_msg}"}), 500

            update_last_scan_time(target_pk)

            try:
                monitor_once()
            except Exception as mon_exc:
                print(f"[ERROR] monitor refresh failed for {target}: {mon_exc}")

            refresh_analytics_after_scan()

            return jsonify(
                {
                    "message": "Target scanned successfully",
                    "target_pk": target_pk,
                    "target_id": target,
                    "scanId": scan_id,
                    "report": report,
                }
            )
        finally:
            conn.close()

    @app.route("/api/db/targets/scan-all-active", methods=["POST"])
    def scan_all_active_targets():
        payload = request.get_json(silent=True) or {}
        use_cache = payload.get("useCache", True)
        shallow_clone = payload.get("shallowClone", True)
        limit = payload.get("limit")

        rows = get_active_targets()

        if limit is not None:
            try:
                limit_value = int(limit)
                if limit_value > 0:
                    rows = rows[:limit_value]
            except Exception:
                pass

        if not rows:
            return jsonify({"error": "No active targets found"}), 400

        results = []
        success_count = 0
        failed_count = 0

        for row in rows:
            target_pk = row.get("target_pk")
            target_id = row.get("target_id", "")

            try:
                scan_id, report = run_scan_core(
                    target=target_id,
                    use_cache=use_cache,
                    shallow_clone=shallow_clone,
                )
                update_last_scan_time(target_pk)

                try:
                    monitor_once()
                except Exception as mon_exc:
                    print(f"[SCAN-ALL] monitor refresh failed for {target_id}: {mon_exc}")

                success_count += 1
                results.append(
                    {
                        "target_pk": target_pk,
                        "target_id": target_id,
                        "status": "success",
                        "scanId": scan_id,
                        "summary": report.get("summary", {}),
                    }
                )
            except Exception as exc:
                failed_count += 1
                results.append(
                    {
                        "target_pk": target_pk,
                        "target_id": target_id,
                        "status": "failed",
                        "error": str(exc),
                    }
                )

        refresh_analytics_after_scan()

        return jsonify(
            {
                "message": "Scan-all completed",
                "total": len(rows),
                "success_count": success_count,
                "failed_count": failed_count,
                "results": results,
            }
        )

    @app.route("/api/db/targets/scan-all-active/background", methods=["POST"])
    def scan_all_active_targets_background():
        def job():
            try:
                background_scan_active_targets()
            except Exception as exc:
                print(f"[AUTO-SCAN-BG] Background job failed: {exc}")

        threading.Thread(target=job, daemon=True).start()
        return jsonify({"message": "Background scan started"})

    @app.route("/api/db/latest-scans", methods=["GET"])
    def get_latest_scans():
        import pymysql
        from lavakumar_db_config import DB_CONFIG

        conn = pymysql.connect(**DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT scan_id, target_id, scan_time
                    FROM scan
                    ORDER BY scan_id DESC
                    LIMIT 50
                    """
                )
                rows = cur.fetchall()
            return jsonify({"rows": rows})
        finally:
            conn.close()

    @app.route("/api/db/summary", methods=["GET"])
    def get_database_summary():
        """Return dashboard totals based on the latest scan for each repository."""
        import pymysql
        from lavakumar_db_config import DB_CONFIG

        conn = pymysql.connect(**DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        (SELECT COUNT(DISTINCT target_id) FROM scan) AS total_repositories,
                        (SELECT COUNT(*) FROM scan) AS total_scans,
                        (SELECT COUNT(*) FROM packages_name) AS total_packages,
                        COUNT(pvo.spr_id) AS total_vulnerabilities,
                        COALESCE(SUM(LOWER(COALESCE(v.severity, '')) = 'critical'), 0) AS critical,
                        COALESCE(SUM(LOWER(COALESCE(v.severity, '')) = 'high'), 0) AS high,
                        COALESCE(SUM(LOWER(COALESCE(v.severity, '')) = 'medium'), 0) AS medium,
                        COALESCE(SUM(LOWER(COALESCE(v.severity, '')) = 'low'), 0) AS low,
                        COALESCE(SUM(LOWER(COALESCE(v.severity, '')) = 'negligible'), 0) AS negligible,
                        COALESCE(SUM(
                            pvo.spr_id IS NOT NULL AND COALESCE(LOWER(v.severity), '') NOT IN
                            ('critical', 'high', 'medium', 'low', 'negligible')
                        ), 0) AS unknown
                    FROM (
                        SELECT target_id, MAX(scan_id) AS scan_id
                        FROM scan
                        GROUP BY target_id
                    ) latest
                    LEFT JOIN package_vuln_observation pvo ON pvo.scan_id = latest.scan_id
                    LEFT JOIN vulnerability v ON v.vulnerability_id = pvo.vulnerability_id
                    """
                )
                summary = cur.fetchone() or {}

                cur.execute(
                    """
                    SELECT
                        latest.target_id, latest.scan_id, latest.scan_time,
                        COUNT(pvo.spr_id) AS total_vulnerabilities,
                        COALESCE(SUM(LOWER(COALESCE(v.severity, '')) = 'critical'), 0) AS critical,
                        COALESCE(SUM(LOWER(COALESCE(v.severity, '')) = 'high'), 0) AS high,
                        COALESCE(SUM(LOWER(COALESCE(v.severity, '')) = 'medium'), 0) AS medium,
                        COALESCE(SUM(LOWER(COALESCE(v.severity, '')) = 'low'), 0) AS low
                    FROM (
                        SELECT s.target_id, s.scan_id, s.scan_time
                        FROM scan s
                        INNER JOIN (
                            SELECT target_id, MAX(scan_id) AS scan_id
                            FROM scan
                            GROUP BY target_id
                        ) selected ON selected.scan_id = s.scan_id
                    ) latest
                    LEFT JOIN package_vuln_observation pvo ON pvo.scan_id = latest.scan_id
                    LEFT JOIN vulnerability v ON v.vulnerability_id = pvo.vulnerability_id
                    GROUP BY latest.target_id, latest.scan_id, latest.scan_time
                    ORDER BY total_vulnerabilities DESC, critical DESC, high DESC, latest.target_id
                    LIMIT 10
                    """
                )
                top_repositories = cur.fetchall()

                cur.execute(
                    """
                    SELECT
                        pn.package_name,
                        COUNT(DISTINCT latest.target_id) AS affected_repositories,
                        COUNT(pvo.spr_id) AS vulnerability_occurrences,
                        MAX(CASE LOWER(COALESCE(v.severity, ''))
                            WHEN 'critical' THEN 4 WHEN 'high' THEN 3
                            WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0
                        END) AS severity_rank
                    FROM (
                        SELECT target_id, MAX(scan_id) AS scan_id
                        FROM scan
                        GROUP BY target_id
                    ) latest
                    INNER JOIN package_vuln_observation pvo ON pvo.scan_id = latest.scan_id
                    INNER JOIN packages_name pn ON pn.package_id = pvo.package_id
                    INNER JOIN vulnerability v ON v.vulnerability_id = pvo.vulnerability_id
                    GROUP BY pn.package_name
                    ORDER BY affected_repositories DESC, vulnerability_occurrences DESC, pn.package_name
                    LIMIT 10
                    """
                )
                common_packages = cur.fetchall()

            severity_names = {4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "Unknown"}
            for package in common_packages:
                package["highest_severity"] = severity_names.get(package.pop("severity_rank", 0), "Unknown")

            return jsonify({
                "scope": "Latest scan for each repository",
                "summary": summary,
                "top_repositories": top_repositories,
                "common_packages": common_packages,
            })
        finally:
            conn.close()

    @app.route("/api/db/vulnerability-timeline/targets", methods=["GET"])
    def get_vulnerability_timeline_targets():
        """Return every repository with at least one scan."""
        import pymysql
        from lavakumar_db_config import DB_CONFIG

        conn = pymysql.connect(**DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT target_id, COUNT(*) AS scan_count, MAX(scan_time) AS latest_scan_time
                    FROM scan
                    GROUP BY target_id
                    ORDER BY latest_scan_time DESC, target_id
                    """
                )
                rows = cur.fetchall()

            for row in rows:
                if row.get("latest_scan_time"):
                    row["latest_scan_time"] = row["latest_scan_time"].isoformat()

            return jsonify({"rows": rows})
        finally:
            conn.close()

    @app.route("/api/db/vulnerability-timeline", methods=["GET"])
    def get_vulnerability_timeline():
        """Compare consecutive scans for one repository and return timeline changes."""
        import pymysql
        from lavakumar_db_config import DB_CONFIG

        target_id = str(request.args.get("target", "")).strip()
        if not target_id:
            return jsonify({"error": "A repository must be selected"}), 400

        conn = pymysql.connect(**DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT scan_id, scan_time
                    FROM scan
                    WHERE target_id = %s
                    ORDER BY scan_id DESC
                    LIMIT 30
                    """,
                    (target_id,),
                )
                scans = list(reversed(cur.fetchall()))

                if not scans:
                    return jsonify({"error": "No scans were found for this repository"}), 404

                scan_ids = [int(row["scan_id"]) for row in scans]
                placeholders = ",".join(["%s"] * len(scan_ids))
                cur.execute(
                    f"""
                    SELECT DISTINCT
                        pvo.scan_id,
                        pn.package_name,
                        pn.version,
                        v.cve_id,
                        COALESCE(v.severity, 'Unknown') AS severity,
                        pvo.fixed_version
                    FROM package_vuln_observation pvo
                    INNER JOIN packages_name pn ON pn.package_id = pvo.package_id
                    INNER JOIN vulnerability v ON v.vulnerability_id = pvo.vulnerability_id
                    WHERE pvo.scan_id IN ({placeholders})
                    ORDER BY pvo.scan_id, pn.package_name, v.cve_id
                    """,
                    scan_ids,
                )
                observations = cur.fetchall()

            by_scan: Dict[int, List[Dict[str, object]]] = {scan_id: [] for scan_id in scan_ids}
            for row in observations:
                by_scan[int(row["scan_id"])].append(row)

            severity_order = {
                "critical": 5,
                "high": 4,
                "medium": 3,
                "low": 2,
                "negligible": 1,
                "unknown": 0,
            }

            def identity(row: Dict[str, object]) -> Tuple[str, str]:
                return (str(row.get("package_name", "")), str(row.get("cve_id", "")))

            def detail(row: Dict[str, object]) -> Dict[str, object]:
                return {
                    "package_name": row.get("package_name"),
                    "version": row.get("version"),
                    "vulnerability_id": row.get("cve_id"),
                    "severity": row.get("severity") or "Unknown",
                    "fixed_version": row.get("fixed_version"),
                }

            timeline = []
            previous_rows: List[Dict[str, object]] | None = None

            for scan in scans:
                scan_id = int(scan["scan_id"])
                current_rows = by_scan.get(scan_id, [])
                current_map = {identity(row): row for row in current_rows}
                severity_counts = {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "negligible": 0,
                    "unknown": 0,
                }
                for row in current_map.values():
                    key = str(row.get("severity") or "unknown").lower()
                    if key not in severity_counts:
                        key = "unknown"
                    severity_counts[key] += 1

                event: Dict[str, object] = {
                    "scan_id": scan_id,
                    "scan_time": scan["scan_time"].isoformat() if scan.get("scan_time") else None,
                    "total_vulnerabilities": len(current_map),
                    "severity": severity_counts,
                    "baseline": previous_rows is None,
                    "new": [],
                    "resolved": [],
                    "persistent": [],
                    "package_updates": [],
                    "trend": "baseline",
                }

                if previous_rows is not None:
                    previous_map = {identity(row): row for row in previous_rows}
                    current_keys = set(current_map)
                    previous_keys = set(previous_map)

                    new_keys = sorted(current_keys - previous_keys)
                    resolved_keys = sorted(previous_keys - current_keys)
                    persistent_keys = sorted(current_keys & previous_keys)

                    event["new"] = [detail(current_map[key]) for key in new_keys]
                    event["resolved"] = [detail(previous_map[key]) for key in resolved_keys]
                    event["persistent"] = [detail(current_map[key]) for key in persistent_keys]

                    previous_versions: Dict[str, Set[str]] = {}
                    current_versions: Dict[str, Set[str]] = {}
                    for row in previous_rows:
                        previous_versions.setdefault(str(row["package_name"]), set()).add(str(row["version"]))
                    for row in current_rows:
                        current_versions.setdefault(str(row["package_name"]), set()).add(str(row["version"]))

                    package_updates = []
                    for package_name in sorted(set(previous_versions) & set(current_versions)):
                        before = previous_versions[package_name]
                        after = current_versions[package_name]
                        if before != after:
                            package_updates.append({
                                "package_name": package_name,
                                "previous_version": ", ".join(sorted(before)),
                                "current_version": ", ".join(sorted(after)),
                            })
                    event["package_updates"] = package_updates

                    previous_score = sum(
                        severity_order.get(str(row.get("severity") or "unknown").lower(), 0)
                        for row in previous_map.values()
                    )
                    current_score = sum(
                        severity_order.get(str(row.get("severity") or "unknown").lower(), 0)
                        for row in current_map.values()
                    )
                    if current_score < previous_score:
                        event["trend"] = "improved"
                    elif current_score > previous_score:
                        event["trend"] = "worsened"
                    else:
                        event["trend"] = "unchanged"

                event["new_count"] = len(event["new"])
                event["resolved_count"] = len(event["resolved"])
                event["persistent_count"] = len(event["persistent"])
                event["package_update_count"] = len(event["package_updates"])
                timeline.append(event)
                previous_rows = current_rows

            latest = timeline[-1]
            latest_current = [detail(current_map[key]) for key in sorted(current_map)]
            latest["current"] = latest_current

            # Build a lifecycle record for every package/vulnerability pair seen
            # in the available scan history. This supports aging, reintroduction
            # detection and remediation measurements that are not present in a
            # single scan result.
            scan_maps = []
            for scan_id in scan_ids:
                scan_maps.append({identity(row): row for row in by_scan.get(scan_id, [])})

            all_keys = sorted(set().union(*(set(scan_map) for scan_map in scan_maps)))
            latest_index = len(scans) - 1
            latest_time = scans[latest_index].get("scan_time")
            lifecycle_rows = []

            for key in all_keys:
                present_indices = [index for index, scan_map in enumerate(scan_maps) if key in scan_map]
                if not present_indices:
                    continue

                first_index = present_indices[0]
                last_present_index = present_indices[-1]
                is_open = last_present_index == latest_index
                current_streak_start = last_present_index
                while current_streak_start > 0 and key in scan_maps[current_streak_start - 1]:
                    current_streak_start -= 1

                had_earlier_presence = any(
                    key in scan_maps[index] for index in range(0, current_streak_start)
                )

                if is_open:
                    if len(scans) == 1:
                        lifecycle_status = "baseline"
                    elif first_index == latest_index:
                        lifecycle_status = "new"
                    elif had_earlier_presence:
                        lifecycle_status = "reintroduced"
                    else:
                        lifecycle_status = "persistent"
                else:
                    lifecycle_status = "resolved"

                observed_row = scan_maps[last_present_index][key]
                first_seen = scans[first_index].get("scan_time")
                last_seen = scans[last_present_index].get("scan_time")
                open_since = scans[current_streak_start].get("scan_time") if is_open else None
                resolved_at = None
                if not is_open and last_present_index + 1 < len(scans):
                    resolved_at = scans[last_present_index + 1].get("scan_time")

                age_days = None
                if is_open and open_since and latest_time:
                    age_days = max(0, (latest_time - open_since).days)

                resolution_days = None
                if not is_open and first_seen and resolved_at:
                    resolution_days = max(0, (resolved_at - first_seen).days)

                severity = str(observed_row.get("severity") or "Unknown")
                severity_key = severity.lower()
                fixed_version = observed_row.get("fixed_version")

                if not is_open:
                    attention = "resolved"
                elif severity_key == "critical":
                    attention = "urgent"
                elif severity_key == "high" or lifecycle_status == "reintroduced" or (age_days or 0) > 30:
                    attention = "high"
                elif severity_key == "medium" or (age_days or 0) > 7:
                    attention = "medium"
                else:
                    attention = "low"

                lifecycle_rows.append({
                    "package_name": observed_row.get("package_name"),
                    "version": observed_row.get("version"),
                    "vulnerability_id": observed_row.get("cve_id"),
                    "severity": severity,
                    "fixed_version": fixed_version,
                    "status": lifecycle_status,
                    "attention": attention,
                    "first_seen": first_seen.isoformat() if first_seen else None,
                    "last_seen": last_seen.isoformat() if last_seen else None,
                    "open_since": open_since.isoformat() if open_since else None,
                    "resolved_at": resolved_at.isoformat() if resolved_at else None,
                    "age_days": age_days,
                    "resolution_days": resolution_days,
                    "scans_present": len(present_indices),
                    "is_open": is_open,
                })

            attention_order = {"urgent": 5, "high": 4, "medium": 3, "low": 2, "resolved": 1}
            lifecycle_rows.sort(
                key=lambda row: (
                    -attention_order.get(str(row.get("attention")), 0),
                    -int(row.get("age_days") or 0),
                    str(row.get("package_name") or ""),
                    str(row.get("vulnerability_id") or ""),
                )
            )

            open_rows = [row for row in lifecycle_rows if row.get("is_open")]
            resolved_rows = [row for row in lifecycle_rows if row.get("status") == "resolved"]
            resolved_durations = [
                int(row["resolution_days"])
                for row in resolved_rows
                if row.get("resolution_days") is not None
            ]
            lifecycle_summary = {
                "open": len(open_rows),
                "new": sum(1 for row in open_rows if row.get("status") == "new"),
                "persistent": sum(1 for row in open_rows if row.get("status") in {"persistent", "baseline"}),
                "reintroduced": sum(1 for row in open_rows if row.get("status") == "reintroduced"),
                "resolved": len(resolved_rows),
                "fix_available": sum(1 for row in open_rows if row.get("fixed_version")),
                "older_than_30_days": sum(1 for row in open_rows if int(row.get("age_days") or 0) > 30),
                "average_resolution_days": (
                    round(sum(resolved_durations) / len(resolved_durations), 1)
                    if resolved_durations else None
                ),
            }
            return jsonify({
                "target_id": target_id,
                "scan_count": len(timeline),
                "limited_to_latest": 30,
                "summary": {
                    "current_vulnerabilities": latest["total_vulnerabilities"],
                    "fix_available": sum(1 for row in latest_current if row.get("fixed_version")),
                    "new": latest["new_count"],
                    "resolved": latest["resolved_count"],
                    "persistent": latest["persistent_count"],
                    "package_updates": latest["package_update_count"],
                    "trend": latest["trend"],
                },
                "lifecycle": {
                    "summary": lifecycle_summary,
                    "rows": lifecycle_rows,
                    "history_note": "Lifecycle calculations use the latest 30 stored scans for this repository.",
                },
                "timeline": timeline,
            })
        finally:
            conn.close()

    @app.route("/api/scan", methods=["POST"])
    def scan():
        payload = request.get_json(silent=True) or {}
        target = payload.get("target")

        if not target:
            return jsonify({"error": "Target repository or path is required"}), 400

        use_cache = payload.get("useCache", True)
        shallow_clone = payload.get("shallowClone", True)

        try:
            scan_id, report = run_scan_core(
                target=target,
                use_cache=use_cache,
                shallow_clone=shallow_clone,
            )
        except (FileNotFoundError, ValueError, RuntimeError) as exc:
            error_msg = str(exc)
            print(f"[ERROR] Scan failed: {error_msg}", file=sys.stderr)
            return jsonify({"error": error_msg}), 400
        except Exception as exc:
            error_msg = str(exc)
            print(f"[ERROR] Unexpected error during scan: {error_msg}", file=sys.stderr)
            import traceback
            traceback.print_exc()
            return jsonify({"error": f"Scan failed: {error_msg}"}), 500

        refresh_analytics_after_scan()

        return jsonify({"scanId": scan_id, "report": report})

    @app.route("/api/scan/batch", methods=["POST"])
    def start_batch_scan():
        """Start a sequential background scan for up to ten repositories."""
        payload = request.get_json(silent=True) or {}
        raw_targets = payload.get("targets") or []

        if not isinstance(raw_targets, list):
            return jsonify({"error": "Targets must be provided as a list"}), 400

        targets = []
        seen = set()
        for value in raw_targets:
            target = str(value or "").strip()
            if target and target not in seen:
                targets.append(target)
                seen.add(target)

        if not targets:
            return jsonify({"error": "Enter at least one repository URL"}), 400
        if len(targets) > 10:
            return jsonify({"error": "A batch can contain a maximum of 10 repositories"}), 400

        use_cache = payload.get("useCache", True)
        shallow_clone = payload.get("shallowClone", True)
        jobs_lock: threading.Lock = app.config["batch_jobs_lock"]
        jobs: Dict[str, Dict[str, object]] = app.config["batch_jobs"]

        with jobs_lock:
            active_job = next(
                (job for job in jobs.values() if job.get("status") in {"queued", "running"}),
                None,
            )
            if active_job:
                return jsonify({
                    "error": "Another batch scan is already running",
                    "job_id": active_job.get("job_id"),
                }), 409

            job_id = uuid.uuid4().hex[:12]
            jobs[job_id] = {
                "job_id": job_id,
                "status": "queued",
                "total": len(targets),
                "completed": 0,
                "success_count": 0,
                "failed_count": 0,
                "current_target": None,
                "targets": targets,
                "results": [],
                "started_at": None,
                "finished_at": None,
            }

        def run_batch_job() -> None:
            with jobs_lock:
                job = jobs[job_id]
                job["status"] = "running"
                job["started_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")

            for target in targets:
                with jobs_lock:
                    jobs[job_id]["current_target"] = target

                try:
                    scan_id, report = run_scan_core(
                        target=target,
                        use_cache=use_cache,
                        shallow_clone=shallow_clone,
                    )
                    result = {
                        "target": target,
                        "status": "success",
                        "scan_id": scan_id,
                        "total_packages": report.get("summary", {}).get("total_packages", 0),
                        "total_vulnerabilities": report.get("summary", {}).get("total_vulnerabilities", 0),
                    }
                    with jobs_lock:
                        jobs[job_id]["success_count"] = int(jobs[job_id]["success_count"]) + 1
                except Exception as exc:
                    result = {
                        "target": target,
                        "status": "failed",
                        "error": str(exc),
                    }
                    with jobs_lock:
                        jobs[job_id]["failed_count"] = int(jobs[job_id]["failed_count"]) + 1

                with jobs_lock:
                    jobs[job_id]["results"].append(result)
                    jobs[job_id]["completed"] = int(jobs[job_id]["completed"]) + 1

            with jobs_lock:
                jobs[job_id]["status"] = "completed"
                jobs[job_id]["current_target"] = None
                jobs[job_id]["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")

            refresh_analytics_after_scan()

        threading.Thread(target=run_batch_job, daemon=True).start()
        return jsonify({
            "message": "Batch scan started",
            "job_id": job_id,
            "total": len(targets),
        }), 202

    @app.route("/api/scan/batch/<job_id>", methods=["GET"])
    def get_batch_scan_status(job_id: str):
        jobs_lock: threading.Lock = app.config["batch_jobs_lock"]
        jobs: Dict[str, Dict[str, object]] = app.config["batch_jobs"]

        with jobs_lock:
            job = jobs.get(job_id)
            if not job:
                return jsonify({"error": "Batch scan job not found"}), 404
            snapshot = dict(job)
            snapshot["targets"] = list(job.get("targets", []))
            snapshot["results"] = [dict(row) for row in job.get("results", [])]

        return jsonify(snapshot)

    @app.route("/api/reports", methods=["GET"])
    def list_reports():
        SBOMScanner = get_scanner_class()
        use_cache = request.args.get("useCache", "true").lower() != "false"
        shallow_clone = request.args.get("fullClone", "false").lower() != "true"
        scanner = SBOMScanner(use_cache=use_cache, shallow_clone=shallow_clone)
        reports = scanner.list_reports()
        return jsonify({"reports": reports})

    @app.route("/reports/<path:filename>", methods=["GET"])
    def download_report(filename: str):
        Config = get_config()
        return send_from_directory(Config.REPORTS_DIR, filename, as_attachment=True)

    @app.route("/api/db/monitor-log", methods=["GET"])
    def get_monitor_log():
        import pymysql
        from lavakumar_db_config import DB_CONFIG

        conn = pymysql.connect(**DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT log_id, target_id, latest_scan_id, prev_scan_id, scan_time,
                           total_vulns, critical, high, medium, low, new_found, resolved
                    FROM monitor_log
                    ORDER BY log_id DESC
                    LIMIT 100
                    """
                )
                rows = cur.fetchall()
            return jsonify({"rows": rows})
        finally:
            conn.close()

    def ensure_alert_state_table() -> None:
        """Create and migrate the state table used to remember alert reviews."""
        import pymysql
        from lavakumar_db_config import DB_CONFIG

        conn = pymysql.connect(**DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS vulnerability_alert_state (
                        alert_key VARCHAR(64) PRIMARY KEY,
                        status VARCHAR(20) NOT NULL DEFAULT 'open',
                        acknowledged_at DATETIME NULL,
                        reviewed TINYINT(1) NOT NULL DEFAULT 0,
                        reviewed_at DATETIME NULL,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                    )
                    """
                )
                # Older project databases contain only the acknowledged fields.
                # Add review tracking without deleting any existing state.
                cur.execute("SHOW COLUMNS FROM vulnerability_alert_state")
                columns = {str(row.get("Field") or "") for row in cur.fetchall()}
                if "reviewed" not in columns:
                    cur.execute(
                        "ALTER TABLE vulnerability_alert_state "
                        "ADD COLUMN reviewed TINYINT(1) NOT NULL DEFAULT 0 AFTER acknowledged_at"
                    )
                if "reviewed_at" not in columns:
                    cur.execute(
                        "ALTER TABLE vulnerability_alert_state "
                        "ADD COLUMN reviewed_at DATETIME NULL AFTER reviewed"
                    )
                # Preserve earlier acknowledgement work as reviewed work, then
                # return active findings to the normal open lifecycle state.
                cur.execute(
                    """
                    UPDATE vulnerability_alert_state
                    SET reviewed = 1,
                        reviewed_at = COALESCE(reviewed_at, acknowledged_at),
                        status = CASE WHEN status = 'acknowledged' THEN 'open' ELSE status END
                    WHERE status = 'acknowledged'
                    """
                )
            conn.commit()
        finally:
            conn.close()

    def make_alert_key(*parts: object) -> str:
        value = "|".join(str(part or "") for part in parts)
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    @app.route("/api/alerts", methods=["GET"])
    def get_alerts():
        """Build actionable notifications from scan history and scheduler failures."""
        import pymysql
        from lavakumar_db_config import DB_CONFIG

        ensure_alert_state_table()
        conn = pymysql.connect(**DB_CONFIG)
        alerts: List[Dict[str, object]] = []
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    WITH ranked_scans AS (
                        SELECT scan_id, target_id, scan_time,
                               ROW_NUMBER() OVER (PARTITION BY target_id ORDER BY scan_id DESC) AS rn
                        FROM scan
                    )
                    SELECT rs.target_id, rs.scan_id, rs.scan_time,
                           pn.package_name, pn.version, v.cve_id,
                           COALESCE(v.severity, 'Unknown') AS severity,
                           pvo.fixed_version
                    FROM ranked_scans rs
                    LEFT JOIN package_vuln_observation pvo ON pvo.scan_id = rs.scan_id
                    LEFT JOIN packages_name pn ON pn.package_id = pvo.package_id
                    LEFT JOIN vulnerability v ON v.vulnerability_id = pvo.vulnerability_id
                    WHERE rs.rn <= 30
                    ORDER BY rs.target_id, rs.scan_id, pn.package_name, v.cve_id
                    """
                )
                rows = cur.fetchall()

                # Alerts focus on repositories selected for continuous monitoring.
                # If no scheduler list exists yet, all scanned repositories remain available.
                monitored_targets: set[str] = set()
                try:
                    cur.execute(
                        """
                        SELECT mt.target_id
                        FROM scheduled_scan_targets st
                        INNER JOIN monitored_targets mt ON mt.target_pk = st.target_pk
                        WHERE st.enabled = 1
                        """
                    )
                    monitored_targets = {
                        str(item.get("target_id") or "") for item in cur.fetchall()
                        if item.get("target_id")
                    }
                except Exception:
                    monitored_targets = set()
                if monitored_targets:
                    rows = [row for row in rows if str(row.get("target_id") or "") in monitored_targets]

                # Count exposure from every finding in each repository's latest scan.
                # This is more accurate than counting only findings that happened to
                # produce an alert type such as "fix available" or "new".
                repositories_by_vulnerability: Dict[str, Set[str]] = {}
                latest_scan_by_target: Dict[str, int] = {}
                for row in rows:
                    target = str(row.get("target_id") or "")
                    scan_id = int(row.get("scan_id") or 0)
                    latest_scan_by_target[target] = max(latest_scan_by_target.get(target, 0), scan_id)
                for row in rows:
                    target = str(row.get("target_id") or "")
                    if int(row.get("scan_id") or 0) != latest_scan_by_target.get(target):
                        continue
                    vulnerability_key = str(row.get("cve_id") or "").upper()
                    if vulnerability_key and target:
                        repositories_by_vulnerability.setdefault(vulnerability_key, set()).add(target)

                by_target: Dict[str, Dict[int, Dict[str, object]]] = {}
                for row in rows:
                    target = str(row.get("target_id") or "")
                    scan_id = int(row.get("scan_id") or 0)
                    scan_entry = by_target.setdefault(target, {}).setdefault(
                        scan_id,
                        {"scan_time": row.get("scan_time"), "findings": []},
                    )
                    if row.get("cve_id"):
                        scan_entry["findings"].append(row)

                severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "negligible": 0, "unknown": 0}

                def identity(row: Dict[str, object]) -> Tuple[str, str]:
                    return (str(row.get("package_name") or ""), str(row.get("cve_id") or ""))

                def valid_fix(value: object) -> bool:
                    text = str(value or "").strip().lower()
                    return bool(text and text not in {"n/a", "none", "not available", "unknown"})

                def append_alert(
                    alert_type: str,
                    target: str,
                    row: Dict[str, object],
                    title: str,
                    message: str,
                    detected_at: object,
                    default_status: str = "open",
                    priority: str | None = None,
                ) -> None:
                    severity = str(row.get("severity") or "Unknown").lower()
                    calculated_priority = priority or (
                        "critical" if severity == "critical" else
                        "high" if severity == "high" else
                        "medium" if severity == "medium" else "low"
                    )
                    alerts.append({
                        "key": make_alert_key(alert_type, target, row.get("package_name"), row.get("cve_id")),
                        "type": alert_type,
                        "title": title,
                        "message": message,
                        "repository": target,
                        "package": row.get("package_name"),
                        "version": row.get("version"),
                        "vulnerability_id": row.get("cve_id"),
                        "severity": str(row.get("severity") or "Unknown"),
                        "priority": calculated_priority,
                        "fixed_version": row.get("fixed_version"),
                        "detected_at": detected_at.isoformat() if hasattr(detected_at, "isoformat") else detected_at,
                        "status": default_status,
                    })

                for target, scan_dict in by_target.items():
                    ordered = sorted(scan_dict.items())
                    if not ordered:
                        continue
                    latest_id, latest_scan = ordered[-1]
                    latest_time = latest_scan.get("scan_time")
                    maps = [
                        {identity(row): row for row in scan["findings"]}
                        for _, scan in ordered
                    ]
                    current_map = maps[-1]
                    previous_map = maps[-2] if len(maps) > 1 else {}

                    for key in sorted(set(current_map) - set(previous_map)):
                        row = current_map[key]
                        severity = str(row.get("severity") or "unknown").lower()
                        if severity in {"critical", "high"}:
                            append_alert(
                                "new_vulnerability", target, row,
                                f"New {severity.title()} Vulnerability",
                                f"{row.get('cve_id')} was newly detected in {row.get('package_name')}.",
                                latest_time,
                            )

                    for key in sorted(set(previous_map) - set(current_map)):
                        row = previous_map[key]
                        append_alert(
                            "resolved_vulnerability", target, row,
                            "Vulnerability Resolved",
                            f"{row.get('cve_id')} is no longer detected in {row.get('package_name')}.",
                            latest_time, default_status="resolved", priority="low",
                        )

                    all_keys = set().union(*(set(scan_map) for scan_map in maps))
                    for key in sorted(all_keys):
                        present = [index for index, scan_map in enumerate(maps) if key in scan_map]
                        if not present or present[-1] != len(maps) - 1:
                            continue
                        row = current_map[key]
                        streak_start = len(maps) - 1
                        while streak_start > 0 and key in maps[streak_start - 1]:
                            streak_start -= 1
                        had_earlier = any(key in maps[index] for index in range(streak_start))
                        open_since = ordered[streak_start][1].get("scan_time")
                        age_days = 0
                        if latest_time and open_since:
                            age_days = max(0, (latest_time - open_since).days)

                        if had_earlier:
                            append_alert(
                                "reintroduced_vulnerability", target, row,
                                "Vulnerability Reintroduced",
                                f"{row.get('cve_id')} was resolved earlier but has appeared again.",
                                ordered[streak_start][1].get("scan_time"),
                                priority="critical" if str(row.get("severity")).lower() == "critical" else "high",
                            )
                        if valid_fix(row.get("fixed_version")):
                            fix_start = streak_start
                            for index in range(streak_start, len(maps)):
                                candidate = maps[index].get(key)
                                if candidate and valid_fix(candidate.get("fixed_version")):
                                    fix_start = index
                                    break
                            append_alert(
                                "fix_available", target, row,
                                "Fixed Version Available",
                                f"Update {row.get('package_name')} to {row.get('fixed_version')} to address {row.get('cve_id')}.",
                                ordered[fix_start][1].get("scan_time"),
                                priority="high" if severity_rank.get(str(row.get("severity") or "unknown").lower(), 0) >= 3 else "medium",
                            )
                        if age_days > 30:
                            append_alert(
                                "long_open", target, row,
                                "Vulnerability Open Over 30 Days",
                                f"{row.get('cve_id')} has remained open for {age_days} days.",
                                open_since,
                                priority="high" if severity_rank.get(str(row.get("severity") or "unknown").lower(), 0) >= 3 else "medium",
                            )

                try:
                    cur.execute(
                        """
                        WITH latest_history AS (
                            SELECT history_id, target_id, started_at, error_message, status,
                                   ROW_NUMBER() OVER (PARTITION BY target_id ORDER BY history_id DESC) AS rn
                            FROM scheduled_scan_history
                        )
                        SELECT history_id, target_id, started_at, error_message
                        FROM latest_history
                        WHERE rn = 1 AND status = 'failed'
                        ORDER BY history_id DESC LIMIT 50
                        """
                    )
                    for failure in cur.fetchall():
                        if monitored_targets and str(failure.get("target_id") or "") not in monitored_targets:
                            continue
                        key = make_alert_key("scan_failed", failure.get("history_id"))
                        started = failure.get("started_at")
                        alerts.append({
                            "key": key,
                            "type": "scan_failed",
                            "title": "Scheduled Scan Failed",
                            "message": str(failure.get("error_message") or "The scheduled scan did not complete."),
                            "repository": failure.get("target_id"),
                            "package": None,
                            "version": None,
                            "vulnerability_id": None,
                            "severity": "Unknown",
                            "priority": "high",
                            "fixed_version": None,
                            "detected_at": started.isoformat() if hasattr(started, "isoformat") else started,
                            "status": "open",
                        })
                except Exception:
                    pass

                cur.execute(
                    "SELECT alert_key, status, reviewed, reviewed_at "
                    "FROM vulnerability_alert_state"
                )
                saved_states = {row["alert_key"]: row for row in cur.fetchall()}

                cached_intelligence: Dict[str, Dict[str, object]] = {}
                try:
                    cur.execute("SELECT vulnerability_id, payload_json FROM vulnerability_intelligence_cache_v2 ORDER BY fetched_at")
                    for cache_row in cur.fetchall():
                        try:
                            cached_intelligence[str(cache_row.get("vulnerability_id") or "").upper()] = json.loads(
                                cache_row.get("payload_json") or "{}"
                            )
                        except (TypeError, ValueError, json.JSONDecodeError):
                            continue
                except Exception:
                    cached_intelligence = {}

            for alert in alerts:
                saved_state = saved_states.get(alert["key"], {})
                if alert["status"] != "resolved" and saved_state:
                    saved_status = str(saved_state.get("status") or "open")
                    alert["status"] = "open" if saved_status == "acknowledged" else saved_status
                alert["reviewed"] = bool(saved_state.get("reviewed"))
                reviewed_at = saved_state.get("reviewed_at")
                alert["reviewed_at"] = (
                    reviewed_at.isoformat() if hasattr(reviewed_at, "isoformat") else reviewed_at
                )

                priority = str(alert.get("priority") or "low")
                deadline_days = {"critical": 1, "high": 3, "medium": 7, "low": 30}.get(priority, 30)
                detected_value = alert.get("detected_at")
                try:
                    detected_time = datetime.fromisoformat(str(detected_value).replace("Z", "+00:00")).replace(tzinfo=None)
                except (TypeError, ValueError):
                    detected_time = datetime.now()
                due_time = detected_time + timedelta(days=deadline_days)
                remaining_seconds = int((due_time - datetime.now()).total_seconds())
                alert["due_at"] = due_time.isoformat()
                alert["remaining_seconds"] = remaining_seconds
                alert["age_days"] = max(0, (datetime.now() - detected_time).days)
                alert["is_overdue"] = alert.get("status") != "resolved" and remaining_seconds < 0

                vulnerability_key = str(alert.get("vulnerability_id") or "").upper()
                affected_count = len(repositories_by_vulnerability.get(vulnerability_key, set())) if vulnerability_key else 1
                risk = calculate_risk_score(
                    alert.get("severity"),
                    alert.get("fixed_version"),
                    affected_count,
                    int(alert["age_days"]),
                    cached_intelligence.get(vulnerability_key),
                    get_risk_settings(),
                )
                alert["risk_score"] = risk["score"]
                alert["risk_level"] = risk["level"]
                alert["risk_breakdown"] = risk["breakdown"]
                alert["risk_evidence"] = risk["evidence"]
                alert["risk_method"] = risk["method"]
                alert["affected_repository_count"] = affected_count

                if alert.get("status") == "resolved":
                    alert["action_queue"] = "completed"
                elif alert["is_overdue"] or priority == "critical":
                    alert["action_queue"] = "act_now"
                elif priority == "high" or remaining_seconds <= 86400:
                    alert["action_queue"] = "review_soon"
                else:
                    alert["action_queue"] = "monitor"

                if alert.get("type") == "scan_failed":
                    alert["recommended_action"] = "Check the scanner and repository connection, then run the scan again."
                elif alert.get("fixed_version"):
                    alert["recommended_action"] = f"Review and test an update to {alert.get('fixed_version')}."
                elif alert.get("type") == "resolved_vulnerability":
                    alert["recommended_action"] = "Confirm the finding remains absent in the next scheduled scan."
                else:
                    alert["recommended_action"] = "Review the affected package and investigate available remediation."

            priority_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
            alerts.sort(key=lambda item: (priority_rank.get(str(item.get("priority")), 0), str(item.get("detected_at") or "")), reverse=True)
            summary = {
                "total": len(alerts),
                "open": sum(1 for item in alerts if item.get("status") == "open"),
                "critical": sum(1 for item in alerts if item.get("priority") == "critical" and item.get("status") == "open"),
                "high": sum(1 for item in alerts if item.get("priority") == "high" and item.get("status") == "open"),
                "reviewed": sum(1 for item in alerts if item.get("status") != "resolved" and item.get("reviewed")),
                "not_reviewed": sum(1 for item in alerts if item.get("status") != "resolved" and not item.get("reviewed")),
                "resolved": sum(1 for item in alerts if item.get("status") == "resolved"),
                "act_now": sum(1 for item in alerts if item.get("action_queue") == "act_now"),
                "review_soon": sum(1 for item in alerts if item.get("action_queue") == "review_soon"),
                "monitor": sum(1 for item in alerts if item.get("action_queue") == "monitor"),
                "completed": sum(1 for item in alerts if item.get("action_queue") == "completed"),
                "overdue": sum(1 for item in alerts if item.get("is_overdue")),
                "risk_critical": sum(1 for item in alerts if item.get("risk_level") == "critical" and item.get("status") == "open"),
                "risk_high": sum(1 for item in alerts if item.get("risk_level") == "high" and item.get("status") == "open"),
            }
            return jsonify({"summary": summary, "alerts": alerts})
        finally:
            conn.close()

    @app.route("/api/alerts/<alert_key>/status", methods=["POST"])
    def update_alert_status(alert_key: str):
        import pymysql
        from lavakumar_db_config import DB_CONFIG

        payload = request.get_json(silent=True) or {}
        status = str(payload.get("status") or "").lower()
        if status not in {"open", "acknowledged"}:
            return jsonify({"error": "Choose open or acknowledged status"}), 400
        ensure_alert_state_table()
        conn = pymysql.connect(**DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO vulnerability_alert_state (alert_key, status, acknowledged_at)
                    VALUES (%s, %s, CASE WHEN %s = 'acknowledged' THEN NOW() ELSE NULL END)
                    ON DUPLICATE KEY UPDATE
                        status = VALUES(status),
                        acknowledged_at = VALUES(acknowledged_at)
                    """,
                    (alert_key, status, status),
                )
            conn.commit()
            return jsonify({"message": "Alert status updated", "status": status})
        finally:
            conn.close()

    @app.route("/api/alerts/<alert_key>/review", methods=["POST"])
    def update_alert_review(alert_key: str):
        """Persist whether a generated alert has been reviewed by the user."""
        import re
        import pymysql
        from lavakumar_db_config import DB_CONFIG

        if not re.fullmatch(r"[a-f0-9]{64}", alert_key):
            return jsonify({"error": "Invalid alert key"}), 400
        payload = request.get_json(silent=True) or {}
        reviewed_value = payload.get("reviewed")
        if not isinstance(reviewed_value, bool):
            return jsonify({"error": "Reviewed must be true or false"}), 400

        ensure_alert_state_table()
        conn = pymysql.connect(**DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO vulnerability_alert_state
                        (alert_key, status, reviewed, reviewed_at)
                    VALUES (%s, 'open', %s, CASE WHEN %s = 1 THEN NOW() ELSE NULL END)
                    ON DUPLICATE KEY UPDATE
                        reviewed = VALUES(reviewed),
                        reviewed_at = VALUES(reviewed_at)
                    """,
                    (alert_key, int(reviewed_value), int(reviewed_value)),
                )
            conn.commit()
            return jsonify({
                "message": "Alert marked as reviewed" if reviewed_value else "Alert marked as not reviewed",
                "reviewed": reviewed_value,
            })
        finally:
            conn.close()

    def ensure_intelligence_cache_table() -> None:
        import pymysql
        from lavakumar_db_config import DB_CONFIG

        conn = pymysql.connect(**DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS vulnerability_intelligence_cache_v2 (
                        cache_key VARCHAR(64) PRIMARY KEY,
                        vulnerability_id VARCHAR(100) NOT NULL,
                        package_name VARCHAR(255) NOT NULL DEFAULT '',
                        current_version VARCHAR(255) NOT NULL DEFAULT '',
                        payload_json LONGTEXT NOT NULL,
                        fetched_at DATETIME NOT NULL,
                        INDEX idx_intelligence_vulnerability (vulnerability_id)
                    )
                    """
                )
            conn.commit()
        finally:
            conn.close()

    def ensure_upgrade_cache_table() -> None:
        import pymysql
        from lavakumar_db_config import DB_CONFIG

        conn = pymysql.connect(**DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS upgrade_analysis_cache (
                        cache_key VARCHAR(64) PRIMARY KEY,
                        payload_json LONGTEXT NOT NULL,
                        fetched_at DATETIME NOT NULL
                    )
                    """
                )
            conn.commit()
        finally:
            conn.close()

    @app.route("/api/vulnerability-intelligence", methods=["GET"])
    def vulnerability_intelligence():
        """Enrich a stored vulnerability with OSV, EPSS and CISA KEV intelligence."""
        import re
        from urllib.parse import quote

        import pymysql
        import requests
        from lavakumar_db_config import DB_CONFIG

        vulnerability_id = str(request.args.get("id") or "").strip().upper()
        package_name = str(request.args.get("package") or "").strip()
        current_version = str(request.args.get("current") or "").strip()
        if not vulnerability_id or len(vulnerability_id) > 100 or not re.fullmatch(r"[A-Z0-9._-]+", vulnerability_id):
            return jsonify({"error": "A valid vulnerability ID is required"}), 400

        ensure_intelligence_cache_table()
        intelligence_cache_key = hashlib.sha256(
            f"{vulnerability_id}|{package_name}|{current_version}".lower().encode("utf-8")
        ).hexdigest()
        conn = pymysql.connect(**DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT payload_json, fetched_at
                    FROM vulnerability_intelligence_cache_v2
                    WHERE cache_key = %s
                    """,
                    (intelligence_cache_key,),
                )
                cached = cur.fetchone()
                if cached and cached.get("fetched_at") and datetime.now() - cached["fetched_at"] < timedelta(hours=24):
                    payload = json.loads(cached["payload_json"])
                    if payload.get("cache_schema_version") == 4:
                        payload["cached"] = True
                        return jsonify(payload)

                local_sql = """
                    SELECT MIN(s.scan_time) AS first_detected,
                           MAX(s.scan_time) AS latest_detected,
                           COUNT(DISTINCT s.target_id) AS affected_repositories,
                           GROUP_CONCAT(DISTINCT s.target_id ORDER BY s.target_id SEPARATOR '||') AS repositories,
                           MAX(v.severity) AS stored_severity,
                           GROUP_CONCAT(DISTINCT pvo.fixed_version ORDER BY pvo.fixed_version SEPARATOR '||') AS fixed_versions
                    FROM vulnerability v
                    INNER JOIN package_vuln_observation pvo ON pvo.vulnerability_id = v.vulnerability_id
                    INNER JOIN packages_name pn ON pn.package_id = pvo.package_id
                    INNER JOIN scan s ON s.scan_id = pvo.scan_id
                    WHERE UPPER(v.cve_id) = %s
                """
                params: List[object] = [vulnerability_id]
                if package_name:
                    local_sql += " AND pn.package_name = %s"
                    params.append(package_name)
                cur.execute(local_sql, params)
                local = cur.fetchone() or {}

            sources_status = {"osv": "unavailable", "github": "not_applicable", "epss": "not_applicable", "cisa_kev": "unavailable"}
            osv_data: Dict[str, object] = {}
            github_data: Dict[str, object] = {}
            aliases: List[str] = []
            references: List[Dict[str, str]] = []
            try:
                response = requests.get(
                    "https://api.osv.dev/v1/vulns/" + quote(vulnerability_id, safe=""),
                    timeout=8,
                )
                if response.ok:
                    osv_data = response.json()
                    sources_status["osv"] = "available"
                    aliases = [str(value).upper() for value in osv_data.get("aliases", [])]
                    for item in osv_data.get("references", [])[:8]:
                        url = str(item.get("url") or "")
                        if url.startswith(("https://", "http://")):
                            references.append({"type": str(item.get("type") or "Reference"), "url": url})
            except (requests.RequestException, ValueError):
                pass

            if vulnerability_id.startswith("GHSA-"):
                sources_status["github"] = "unavailable"
                try:
                    response = requests.get(
                        "https://api.github.com/advisories/" + quote(vulnerability_id.lower(), safe=""),
                        headers={"Accept": "application/vnd.github+json"},
                        timeout=8,
                    )
                    if response.ok:
                        github_data = response.json()
                        sources_status["github"] = "available"
                        github_cve = str(github_data.get("cve_id") or "").upper()
                        if github_cve and github_cve not in aliases:
                            aliases.append(github_cve)
                        for url in github_data.get("references", [])[:8]:
                            url = str(url or "")
                            if url.startswith(("https://", "http://")) and not any(item["url"] == url for item in references):
                                references.append({"type": "GitHub advisory", "url": url})
                except (requests.RequestException, ValueError):
                    pass

            cve_id = vulnerability_id if vulnerability_id.startswith("CVE-") else next(
                (value for value in aliases if value.startswith("CVE-")), None
            )
            epss_score = None
            epss_percentile = None
            if cve_id:
                sources_status["epss"] = "unavailable"
                try:
                    response = requests.get(
                        "https://api.first.org/data/v1/epss",
                        params={"cve": cve_id},
                        timeout=8,
                    )
                    if response.ok:
                        entries = response.json().get("data", [])
                        if entries:
                            epss_score = float(entries[0].get("epss"))
                            epss_percentile = float(entries[0].get("percentile"))
                            sources_status["epss"] = "available"
                except (requests.RequestException, ValueError, TypeError):
                    pass

            kev_entry = None
            try:
                response = requests.get(
                    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                    timeout=10,
                )
                if response.ok:
                    sources_status["cisa_kev"] = "available"
                    if cve_id:
                        kev_entry = next(
                            (item for item in response.json().get("vulnerabilities", [])
                             if str(item.get("cveID") or "").upper() == cve_id),
                            None,
                        )
            except (requests.RequestException, ValueError):
                pass

            database_specific = osv_data.get("database_specific", {}) if isinstance(osv_data, dict) else {}
            cvss_info = database_specific.get("cvss", {}) if isinstance(database_specific, dict) else {}
            severity_entries = osv_data.get("severity", []) if isinstance(osv_data, dict) else []
            cvss_vector = None
            if severity_entries:
                cvss_vector = severity_entries[0].get("score")
            if not cvss_vector and isinstance(cvss_info, dict):
                cvss_vector = cvss_info.get("vectorString")
            github_cvss = github_data.get("cvss", {}) if isinstance(github_data, dict) else {}
            github_cvss_severities = github_data.get("cvss_severities", {}) if isinstance(github_data, dict) else {}
            github_cvss_v4 = github_cvss_severities.get("cvss_v4", {}) if isinstance(github_cvss_severities, dict) else {}
            github_cvss_v3 = github_cvss_severities.get("cvss_v3", {}) if isinstance(github_cvss_severities, dict) else {}
            preferred_github_cvss = github_cvss
            if not (isinstance(preferred_github_cvss, dict) and preferred_github_cvss.get("score")):
                preferred_github_cvss = github_cvss_v4 if github_cvss_v4.get("score") else github_cvss_v3
            if not cvss_vector and isinstance(github_cvss, dict):
                cvss_vector = preferred_github_cvss.get("vector_string")

            ecosystem = None
            advisory_fixed_version = None
            affected_entries = osv_data.get("affected", []) if isinstance(osv_data, dict) else []
            for affected in affected_entries:
                package_info = affected.get("package", {}) if isinstance(affected, dict) else {}
                candidate_name = str(package_info.get("name") or "")
                if package_name and candidate_name.lower() != package_name.lower():
                    continue
                ecosystem = package_info.get("ecosystem") or ecosystem
                for range_info in affected.get("ranges", []) if isinstance(affected, dict) else []:
                    for event in range_info.get("events", []) if isinstance(range_info, dict) else []:
                        if event.get("fixed"):
                            advisory_fixed_version = str(event["fixed"])
                            break
                    if advisory_fixed_version:
                        break
                if ecosystem or advisory_fixed_version:
                    break

            github_vulnerabilities = github_data.get("vulnerabilities", []) if isinstance(github_data, dict) else []
            for affected in github_vulnerabilities:
                package_info = affected.get("package", {}) if isinstance(affected, dict) else {}
                candidate_name = str(package_info.get("name") or "")
                if package_name and candidate_name.lower() != package_name.lower():
                    continue
                ecosystem = package_info.get("ecosystem") or ecosystem
                patched = affected.get("first_patched_version") if isinstance(affected, dict) else None
                if isinstance(patched, dict) and patched.get("identifier"):
                    advisory_fixed_version = str(patched["identifier"])
                break

            if ecosystem:
                ecosystem = {
                    "pip": "PyPI",
                    "pypi": "PyPI",
                    "npm": "npm",
                    "rubygems": "RubyGems",
                    "maven": "Maven",
                    "nuget": "NuGet",
                    "go": "Go",
                }.get(str(ecosystem).lower(), ecosystem)

            repository_text = str(local.get("repositories") or "")
            stored_fixed_versions = str(local.get("fixed_versions") or "").split("||") if local.get("fixed_versions") else []
            preferred_fixed_version = choose_compatible_fixed_version(
                stored_fixed_versions + ([advisory_fixed_version] if advisory_fixed_version else []),
                current_version,
            )
            risk = calculate_risk_score(
                database_specific.get("severity") or github_data.get("severity") or local.get("stored_severity"),
                preferred_fixed_version,
                int(local.get("affected_repositories") or 0),
                max(0, (datetime.now() - local.get("first_detected")).days) if local.get("first_detected") else 0,
                {
                    "cvss_score": (cvss_info.get("score") if isinstance(cvss_info, dict) else None) or (preferred_github_cvss.get("score") if isinstance(preferred_github_cvss, dict) else None),
                    "epss_score": epss_score,
                    "known_exploited": bool(kev_entry),
                    "sources": sources_status,
                },
                get_risk_settings(),
            )
            payload = {
                "vulnerability_id": vulnerability_id,
                "cve_id": cve_id,
                "package": package_name or None,
                "current_version": current_version or None,
                "summary": osv_data.get("summary") or github_data.get("summary") or "No external summary is currently available.",
                "details": osv_data.get("details") or github_data.get("description") or "Detailed advisory information was not returned by the external sources.",
                "aliases": aliases,
                "severity": database_specific.get("severity") or github_data.get("severity") or local.get("stored_severity") or "Unknown",
                "cvss_score": (cvss_info.get("score") if isinstance(cvss_info, dict) else None) or (preferred_github_cvss.get("score") if isinstance(preferred_github_cvss, dict) else None),
                "cvss_vector": cvss_vector,
                "epss_score": epss_score,
                "epss_percentile": epss_percentile,
                "known_exploited": bool(kev_entry),
                "kev_date_added": kev_entry.get("dateAdded") if kev_entry else None,
                "kev_required_action": kev_entry.get("requiredAction") if kev_entry else None,
                "fixed_version": preferred_fixed_version,
                "ecosystem": ecosystem,
                "first_detected": local.get("first_detected").isoformat() if local.get("first_detected") else None,
                "latest_detected": local.get("latest_detected").isoformat() if local.get("latest_detected") else None,
                "affected_repositories": int(local.get("affected_repositories") or 0),
                "repositories": repository_text.split("||") if repository_text else [],
                "published": osv_data.get("published") or github_data.get("published_at"),
                "modified": osv_data.get("modified") or github_data.get("updated_at"),
                "references": references,
                "sources": sources_status,
                "source_links": {
                    "osv": "https://osv.dev/vulnerability/" + quote(vulnerability_id, safe=""),
                    "github": "https://github.com/advisories/" + quote(vulnerability_id, safe=""),
                    "epss": "https://www.first.org/epss/",
                    "cisa_kev": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                },
                "fetched_at": datetime.now().isoformat(),
                "cached": False,
                "cache_schema_version": 4,
                "risk": risk,
            }

            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO vulnerability_intelligence_cache_v2
                        (cache_key, vulnerability_id, package_name, current_version, payload_json, fetched_at)
                    VALUES (%s, %s, %s, %s, %s, NOW())
                    ON DUPLICATE KEY UPDATE payload_json = VALUES(payload_json), fetched_at = NOW()
                    """,
                    (intelligence_cache_key, vulnerability_id, package_name, current_version, json.dumps(payload)),
                )
            conn.commit()
            return jsonify(payload)
        finally:
            conn.close()

    @app.route("/api/upgrade-analysis", methods=["GET"])
    def upgrade_analysis():
        """Check a recommended version against OSV and package-registry metadata."""
        import re
        from urllib.parse import quote

        import pymysql
        import requests
        from lavakumar_db_config import DB_CONFIG

        vulnerability_id = str(request.args.get("id") or "").strip().upper()
        package_name = str(request.args.get("package") or "").strip()
        current_version = str(request.args.get("current") or "").strip()
        requested_fixed = str(request.args.get("fixed") or "").strip()
        if not vulnerability_id or not package_name:
            return jsonify({"error": "Vulnerability ID and package name are required"}), 400
        if len(vulnerability_id) > 100 or len(package_name) > 255 or not re.fullmatch(r"[A-Z0-9._-]+", vulnerability_id):
            return jsonify({"error": "Invalid vulnerability or package value"}), 400

        ensure_intelligence_cache_table()
        ensure_upgrade_cache_table()
        conn = pymysql.connect(**DB_CONFIG)
        try:
            with conn.cursor() as cur:
                if current_version:
                    cur.execute(
                        """
                        SELECT payload_json FROM vulnerability_intelligence_cache_v2
                        WHERE vulnerability_id = %s AND package_name = %s AND current_version = %s
                        ORDER BY fetched_at DESC LIMIT 1
                        """,
                        (vulnerability_id, package_name, current_version),
                    )
                else:
                    cur.execute(
                        """
                        SELECT payload_json FROM vulnerability_intelligence_cache_v2
                        WHERE vulnerability_id = %s AND package_name = %s
                        ORDER BY fetched_at DESC LIMIT 1
                        """,
                        (vulnerability_id, package_name),
                    )
                intelligence_row = cur.fetchone()
                intelligence = json.loads(intelligence_row["payload_json"]) if intelligence_row else {}
                if not current_version:
                    cur.execute(
                        """
                        SELECT MAX(pn.version) AS current_version,
                               GROUP_CONCAT(DISTINCT pvo.fixed_version ORDER BY pvo.fixed_version SEPARATOR '||') AS fixed_versions
                        FROM vulnerability v
                        INNER JOIN package_vuln_observation pvo ON pvo.vulnerability_id = v.vulnerability_id
                        INNER JOIN packages_name pn ON pn.package_id = pvo.package_id
                        WHERE UPPER(v.cve_id) = %s AND pn.package_name = %s
                        """,
                        (vulnerability_id, package_name),
                    )
                    version_row = cur.fetchone() or {}
                    current_version = str(version_row.get("current_version") or "")
                    if not requested_fixed:
                        requested_fixed = choose_compatible_fixed_version(
                            str(version_row.get("fixed_versions") or "").split("||"), current_version
                        ) or ""

                ecosystem = str(intelligence.get("ecosystem") or "").strip()
                ecosystem = {
                    "pip": "PyPI",
                    "pypi": "PyPI",
                    "npm": "npm",
                    "rubygems": "RubyGems",
                    "maven": "Maven",
                    "nuget": "NuGet",
                    "go": "Go",
                }.get(ecosystem.lower(), ecosystem)
                candidate = requested_fixed if has_fixed_version(requested_fixed) else str(intelligence.get("fixed_version") or "").strip()
                if not candidate or not has_fixed_version(candidate):
                    return jsonify({"error": "No fixed version is currently available for this finding"}), 422
                if not ecosystem:
                    return jsonify({"error": "The package ecosystem could not be identified from the advisory"}), 422

                cache_key = hashlib.sha256(
                    f"{ecosystem}|{package_name}|{current_version}|{candidate}|{vulnerability_id}".lower().encode("utf-8")
                ).hexdigest()
                cur.execute("SELECT payload_json, fetched_at FROM upgrade_analysis_cache WHERE cache_key = %s", (cache_key,))
                cached = cur.fetchone()
                if cached and datetime.now() - cached["fetched_at"] < timedelta(hours=24):
                    result = json.loads(cached["payload_json"])
                    if result.get("cache_schema_version") == 2:
                        result["cached"] = True
                        return jsonify(result)

            remaining_vulnerabilities: List[Dict[str, object]] = []
            osv_status = "unavailable"
            try:
                response = requests.post(
                    "https://api.osv.dev/v1/query",
                    json={"version": candidate, "package": {"name": package_name, "ecosystem": ecosystem}},
                    timeout=10,
                )
                if response.ok:
                    osv_status = "available"
                    for finding in response.json().get("vulns", []):
                        remaining_vulnerabilities.append({
                            "id": finding.get("id"),
                            "summary": finding.get("summary") or "No summary returned",
                            "aliases": finding.get("aliases") or [],
                            "modified": finding.get("modified"),
                        })
            except (requests.RequestException, ValueError):
                pass

            current_identifiers = {vulnerability_id, str(intelligence.get("cve_id") or "").upper()}
            current_identifiers.update(str(item).upper() for item in intelligence.get("aliases", []))
            candidate_identifiers: Set[str] = set()
            for finding in remaining_vulnerabilities:
                candidate_identifiers.add(str(finding.get("id") or "").upper())
                candidate_identifiers.update(str(item).upper() for item in finding.get("aliases", []))
            current_resolved = not bool(current_identifiers & candidate_identifiers) if osv_status == "available" else None

            release_date = None
            latest_release_date = None
            latest_version = None
            registry_status = "unsupported"
            ecosystem_lower = ecosystem.lower()
            try:
                if ecosystem_lower == "pypi":
                    registry_response = requests.get(
                        "https://pypi.org/pypi/" + quote(package_name, safe="") + "/json", timeout=10
                    )
                    if registry_response.ok:
                        registry_status = "available"
                        registry_data = registry_response.json()
                        latest_version = registry_data.get("info", {}).get("version")
                        files = registry_data.get("releases", {}).get(candidate, [])
                        dates = [item.get("upload_time_iso_8601") or item.get("upload_time") for item in files if item.get("upload_time_iso_8601") or item.get("upload_time")]
                        release_date = min(dates) if dates else None
                        latest_files = registry_data.get("releases", {}).get(latest_version, []) if latest_version else []
                        latest_dates = [item.get("upload_time_iso_8601") or item.get("upload_time") for item in latest_files if item.get("upload_time_iso_8601") or item.get("upload_time")]
                        latest_release_date = max(latest_dates) if latest_dates else None
                elif ecosystem_lower == "npm":
                    registry_response = requests.get(
                        "https://registry.npmjs.org/" + quote(package_name, safe="@/"), timeout=10
                    )
                    if registry_response.ok:
                        registry_status = "available"
                        registry_data = registry_response.json()
                        latest_version = registry_data.get("dist-tags", {}).get("latest")
                        release_date = registry_data.get("time", {}).get(candidate)
                        latest_release_date = registry_data.get("time", {}).get(latest_version) if latest_version else None
            except (requests.RequestException, ValueError):
                registry_status = "unavailable"

            release_age_days = None
            maintenance_status = "Unknown"
            maintenance_reference_date = latest_release_date or release_date
            if maintenance_reference_date:
                try:
                    released = datetime.fromisoformat(str(maintenance_reference_date).replace("Z", "+00:00")).replace(tzinfo=None)
                    release_age_days = max(0, (datetime.now() - released).days)
                    maintenance_status = "Recently maintained" if release_age_days <= 365 else "Maintenance review advised" if release_age_days <= 730 else "Possibly inactive"
                except ValueError:
                    pass

            result = {
                "vulnerability_id": vulnerability_id,
                "package": package_name,
                "ecosystem": ecosystem,
                "current_version": current_version or None,
                "recommended_version": candidate,
                "latest_registry_version": latest_version,
                "latest_release_date": latest_release_date,
                "current_vulnerability_resolved": current_resolved,
                "remaining_vulnerability_count": len(remaining_vulnerabilities) if osv_status == "available" else None,
                "remaining_vulnerabilities": remaining_vulnerabilities[:20],
                "release_date": release_date,
                "release_age_days": release_age_days,
                "maintenance_status": maintenance_status,
                "compatibility_status": "Testing required",
                "compatibility_note": "The security check cannot guarantee application compatibility. Test the update before deployment.",
                "sources": {"osv": osv_status, "package_registry": registry_status},
                "checked_at": datetime.now().isoformat(),
                "cached": False,
                "cache_schema_version": 2,
            }
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO upgrade_analysis_cache (cache_key, payload_json, fetched_at)
                    VALUES (%s, %s, NOW())
                    ON DUPLICATE KEY UPDATE payload_json = VALUES(payload_json), fetched_at = NOW()
                    """,
                    (cache_key, json.dumps(result)),
                )
            conn.commit()
            return jsonify(result)
        finally:
            conn.close()

    @app.route("/health")
    def health():
        return jsonify({"status": "ok", "message": "Server is running"}), 200

    @app.route("/api/scheduler/status", methods=["GET"])
    def get_scheduler_status():
        import pymysql
        from lavakumar_db_config import DB_CONFIG

        config = scheduler_config()
        targets = get_scheduled_targets()
        conn = pymysql.connect(**DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT history_id, run_group_id, target_id, trigger_type, scheduled_for,
                           started_at, finished_at, status, scan_id, total_packages,
                           total_vulnerabilities, error_message
                    FROM scheduled_scan_history
                    ORDER BY history_id DESC
                    LIMIT 100
                    """
                )
                history = cur.fetchall()
        finally:
            conn.close()

        # Flask treats naive datetime objects as GMT when serializing JSON.
        # These MySQL values are local project times, so return ISO strings
        # without a false GMT label and let the dashboard display Eastern Time.
        def local_iso_rows(rows, fields):
            converted = []
            for row in rows:
                item = dict(row)
                for field in fields:
                    value = item.get(field)
                    if value is not None and hasattr(value, "isoformat"):
                        item[field] = value.isoformat()
                converted.append(item)
            return converted

        config = local_iso_rows(
            [config],
            {"last_run_at", "next_run_at", "updated_at"},
        )[0]
        targets = local_iso_rows(
            targets,
            {"last_scan_time", "added_at"},
        )
        history = local_iso_rows(
            history,
            {"scheduled_for", "started_at", "finished_at"},
        )

        next_run = config.get("next_run_at")
        upcoming = [
            {
                "target_pk": row.get("target_pk"),
                "target_id": row.get("target_id"),
                "scheduled_for": next_run,
                "order": index + 1,
            }
            for index, row in enumerate(targets)
        ]
        return jsonify({
            "config": config,
            "active_targets": targets,
            "active_target_count": len(targets),
            "upcoming": upcoming,
            "history": history,
            "cycle_running": app.config["scheduler_cycle_lock"].locked(),
        })

    @app.route("/api/scheduler/config", methods=["POST"])
    def save_scheduler_config():
        payload = request.get_json(silent=True) or {}
        enabled = bool(payload.get("enabled", False))
        try:
            interval = int(payload.get("interval_minutes", 60))
        except (TypeError, ValueError):
            return jsonify({"error": "The interval must be a number of minutes"}), 400
        if interval not in {30, 60, 360, 720, 1440}:
            return jsonify({"error": "Choose 30 minutes, 1 hour, 6 hours, 12 hours or 24 hours"}), 400
        if enabled and not get_scheduled_targets():
            return jsonify({"error": "Add at least one repository to the scheduled repository list before enabling the scheduler"}), 400

        now = datetime.now()
        next_run = now + timedelta(minutes=interval) if enabled else None
        update_scheduler_config(
            enabled=1 if enabled else 0,
            interval_minutes=interval,
            next_run_at=next_run,
            status="idle" if enabled else "stopped",
        )
        app.config["scheduler_wakeup"].set()
        return jsonify({
            "message": "Scheduled scanning enabled" if enabled else "Scheduled scanning stopped",
            "enabled": enabled,
            "interval_minutes": interval,
            "next_run_at": next_run.isoformat() if next_run else None,
        })

    @app.route("/api/risk-settings", methods=["GET"])
    def read_risk_settings():
        settings = get_risk_settings()
        updated_at = settings.get("updated_at")
        if updated_at is not None and hasattr(updated_at, "isoformat"):
            settings["updated_at"] = updated_at.isoformat()
        return jsonify({"settings": settings, "required_total": 100})

    @app.route("/api/risk-settings", methods=["POST"])
    def update_risk_settings():
        payload = request.get_json(silent=True) or {}
        fields = list(DEFAULT_RISK_WEIGHTS)
        try:
            values = {field: round(float(payload[field]), 2) for field in fields}
        except (KeyError, TypeError, ValueError):
            return jsonify({"error": "Enter a numeric value for every risk-score weight"}), 400
        if any(value < 0 or value > 100 for value in values.values()):
            return jsonify({"error": "Each weight must be between 0 and 100"}), 400
        if round(sum(values.values()), 2) != 100:
            return jsonify({"error": "The five risk-score weights must add up to 100"}), 400
        settings = save_risk_settings(values)
        updated_at = settings.get("updated_at")
        if updated_at is not None and hasattr(updated_at, "isoformat"):
            settings["updated_at"] = updated_at.isoformat()
        return jsonify({
            "message": "Risk-score settings saved. New risk scores will use these weights.",
            "settings": settings,
            "required_total": 100,
        })

    @app.route("/api/scheduler/targets", methods=["POST"])
    def add_scheduler_target():
        import pymysql
        from lavakumar_db_config import DB_CONFIG

        payload = request.get_json(silent=True) or {}
        target_id = str(payload.get("target_id") or "").strip()
        if not target_id:
            return jsonify({"error": "Enter a repository URL or local path"}), 400

        ensure_scheduler_tables()
        conn = pymysql.connect(**DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT target_pk FROM monitored_targets WHERE target_id = %s LIMIT 1", (target_id,))
                row = cur.fetchone()
                if row:
                    target_pk = int(row["target_pk"])
                else:
                    cur.execute(
                        """
                        INSERT INTO monitored_targets
                            (target_id, target_type, source_name, active, notes)
                        VALUES (%s, 'git', 'Scheduler', 1, 'Added from scan settings')
                        """,
                        (target_id,),
                    )
                    target_pk = int(cur.lastrowid)
                cur.execute(
                    """
                    INSERT INTO scheduled_scan_targets (target_pk, enabled)
                    VALUES (%s, 1)
                    ON DUPLICATE KEY UPDATE enabled = 1
                    """,
                    (target_pk,),
                )
            conn.commit()
        finally:
            conn.close()
        app.config["scheduler_wakeup"].set()
        return jsonify({"message": "Repository added to scheduled scanning", "target_id": target_id}), 201

    @app.route("/api/scheduler/targets/<int:target_pk>", methods=["DELETE"])
    def remove_scheduler_target(target_pk: int):
        import pymysql
        from lavakumar_db_config import DB_CONFIG

        ensure_scheduler_tables()
        conn = pymysql.connect(**DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM scheduled_scan_targets WHERE target_pk = %s", (target_pk,))
                removed = cur.rowcount
            conn.commit()
        finally:
            conn.close()
        if not removed:
            return jsonify({"error": "Scheduled repository not found"}), 404
        return jsonify({"message": "Repository removed from scheduled scanning"})

    @app.route("/api/scheduler/run-now", methods=["POST"])
    def scheduler_run_now():
        if app.config["scheduler_cycle_lock"].locked():
            return jsonify({"error": "A scheduled scan cycle is already running"}), 409
        if not get_scheduled_targets():
            return jsonify({"error": "Add at least one repository to the scheduled repository list first"}), 400
        threading.Thread(target=run_scheduled_cycle, args=("manual",), daemon=True).start()
        return jsonify({"message": "Scheduled scan cycle started for all selected repositories"}), 202

    def scheduler_loop() -> None:
        try:
            ensure_scheduler_tables()
            current = scheduler_config()
            if str(current.get("status")) == "running":
                update_scheduler_config(status="idle" if int(current.get("enabled", 0) or 0) else "stopped")
        except Exception as exc:
            print(f"[SCHEDULER] Initialization failed: {exc}")

        while True:
            try:
                config = scheduler_config()
                if int(config.get("enabled", 0) or 0):
                    next_run = config.get("next_run_at")
                    if next_run is None:
                        interval = max(30, int(config.get("interval_minutes", 60) or 60))
                        update_scheduler_config(next_run_at=datetime.now() + timedelta(minutes=interval), status="idle")
                    elif next_run <= datetime.now() and not app.config["scheduler_cycle_lock"].locked():
                        run_scheduled_cycle("scheduled")
            except Exception as exc:
                print(f"[SCHEDULER] Loop error: {exc}")

            app.config["scheduler_wakeup"].wait(5)
            app.config["scheduler_wakeup"].clear()

    threading.Thread(target=scheduler_loop, daemon=True).start()

    return app


def run_with_flask(application: Flask) -> None:
    port = get_server_port()
    print("=" * 60)
    print("Starting Flask development server...")
    print("=" * 60)
    print("SERVER IS RUNNING!")
    print("Open your browser and go to:")
    print(f"http://127.0.0.1:{port}")
    print("=" * 60)
    print("WARNING: Using Flask development server")
    print("Press Ctrl+C to stop the server")
    print("=" * 60)
    start_browser_thread()
    application.run(debug=False, threaded=True, use_reloader=False, host="127.0.0.1", port=port)


def run_with_waitress(application: Flask) -> None:
    from waitress import serve
    port = get_server_port()

    print("=" * 60)
    print("Starting server with Waitress...")
    print("=" * 60)
    print("SERVER IS RUNNING!")
    print("Open your browser and go to:")
    print(f"http://127.0.0.1:{port}")
    print("=" * 60)
    print("Press Ctrl+C to stop the server")
    print("=" * 60)
    start_browser_thread()
    serve(application, host="127.0.0.1", port=port, threads=4)


if __name__ == "__main__":
    application = create_app()

    try:
        import waitress  # noqa: F401
        run_with_waitress(application)
    except ImportError as e:
        print(f"Waitress not found: {e}")
        print("Falling back to Flask development server...")
        run_with_flask(application)
    except Exception as e:
        print(f"Error starting Waitress server: {e}")
        print("Falling back to Flask development server...")
        run_with_flask(application)
