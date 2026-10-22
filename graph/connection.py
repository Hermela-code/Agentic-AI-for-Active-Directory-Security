"""
Neo4j Connection Manager
Component: Active Directory Knowledge Graph
"""

import os
import logging
from typing import Any, Dict, List, Optional

from neo4j import GraphDatabase, Driver
from neo4j.exceptions import ServiceUnavailable, AuthError

logger = logging.getLogger("ad_graph.connection")


class Neo4jConnection:
    """
    Thin wrapper around the official neo4j driver.

    Reads connection settings from environment variables so the same code
    works in local dev (docker-compose) and in CI, without hardcoding
    credentials anywhere in the codebase:

        NEO4J_URI       (default: bolt://localhost:7687)
        NEO4J_USER      (default: neo4j)
        NEO4J_PASSWORD  (required, no default - never commit this)
        NEO4J_DATABASE  (default: neo4j)
    """

    def __init__(
        self,
        uri: Optional[str] = None,
        user: Optional[str] = None,
        password: Optional[str] = None,
        database: Optional[str] = None,
    ):
        self.uri = uri or os.environ.get("NEO4J_URI", "bolt://localhost:7687")
        self.user = user or os.environ.get("NEO4J_USER", "neo4j")
        self.password = password or os.environ.get("NEO4J_PASSWORD")
        self.database = database or os.environ.get("NEO4J_DATABASE", "neo4j")

        if not self.password:
            raise ValueError(
                "NEO4J_PASSWORD is not set. Set it via environment variable or "
                ".env (never commit credentials - see SETUP.md rule #7)."
            )

        self._driver: Optional[Driver] = None

    def connect(self) -> "Neo4jConnection":
        """Establish and verify the driver connection. Call once at app startup."""
        self._driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
        try:
            self._driver.verify_connectivity()
            logger.info("Connected to Neo4j at %s (database=%s)", self.uri, self.database)
        except AuthError:
            logger.error("Neo4j authentication failed for user '%s'", self.user)
            raise
        except ServiceUnavailable:
            logger.error("Neo4j is unreachable at %s", self.uri)
            raise
        return self

    def close(self) -> None:
        if self._driver is not None:
            self._driver.close()
            self._driver = None

    def __enter__(self) -> "Neo4jConnection":
        return self.connect()

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def run_query(
        self, cypher: str, parameters: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Execute a single Cypher statement and return a list of plain dicts.
        Used for both writes (MERGE/CREATE) and reads (MATCH).
        """
        if self._driver is None:
            raise RuntimeError("Neo4jConnection.connect() must be called before run_query().")

        parameters = parameters or {}
        with self._driver.session(database=self.database) as session:
            result = session.run(cypher, parameters)
            return [record.data() for record in result]

    def run_write(self, cypher: str, parameters: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Execute a write transaction with automatic retry (managed transaction).
        Prefer this over run_query for MERGE/CREATE/DELETE statements.
        """
        if self._driver is None:
            raise RuntimeError("Neo4jConnection.connect() must be called before run_write().")

        parameters = parameters or {}

        def _tx_func(tx):
            result = tx.run(cypher, parameters)
            return [record.data() for record in result]

        with self._driver.session(database=self.database) as session:
            return {"records": session.execute_write(_tx_func)}

    def health_check(self) -> bool:
        """Lightweight check for the backend's /health endpoint to report graph DB status."""
        try:
            self.run_query("RETURN 1 AS ok")
            return True
        except Exception as exc:  # noqa: BLE001 - we want to report any failure, not crash
            logger.warning("Neo4j health check failed: %s", exc)
            return False
