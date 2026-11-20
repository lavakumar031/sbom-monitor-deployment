"""Database settings read from the server environment."""

import os

from pymysql.cursors import DictCursor


DB_CONFIG = {
    "host": os.environ.get("SBOM_DB_HOST", "127.0.0.1"),
    "port": int(os.environ.get("SBOM_DB_PORT", "3306")),
    "user": os.environ.get("SBOM_DB_USER", "sbom_runner"),
    "password": os.environ.get("SBOM_DB_PASSWORD", ""),
    "database": os.environ.get("SBOM_DB_NAME", "sbom_monitoring_lavakumar"),
    "cursorclass": DictCursor,
    "autocommit": False,
}
