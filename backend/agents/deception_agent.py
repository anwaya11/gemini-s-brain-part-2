"""
backend/agents/deception_agent.py

DeceptionAgent — routes confirmed attackers into the CHIMERA honeypot layer
and records the deception edge in the PostgreSQL graph topology.

Responsibilities:
  1. Analyse the MITRE technique from TriageAgent output and select the most
     appropriate decoy endpoint (deterministic, no LLM needed).
  2. Persist a ``redirected_to`` edge in the ``graph_edges`` table between
     the attacker IP node and the decoy node.
  3. Return a ``DeceptionResult`` with the chosen redirect path and the
     persisted graph edge metadata.

``graph_edges`` schema assumed:
    CREATE TABLE IF NOT EXISTS graph_edges (
        id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        source_node  TEXT NOT NULL,       -- e.g. "ip:198.51.100.42"
        target_node  TEXT NOT NULL,       -- e.g. "decoy:/decoy/db-admin"
        edge_type    TEXT NOT NULL,       -- e.g. "redirected_to"
        metadata     JSONB DEFAULT '{}',
        created_at   TIMESTAMPTZ DEFAULT now()
    );
"""

from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from backend.db.postgres import execute_query, record_decision_edge, init_db

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# MITRE technique → decoy path mapping
# ---------------------------------------------------------------------------

# Each entry: (regex pattern to match against the technique string, decoy path)
# Patterns are checked in order; first match wins.
_TECHNIQUE_DECOY_MAP: list[tuple[re.Pattern[str], str]] = [
    # SQL injection / database attacks
    (re.compile(r"sql.inject|T1190|exploit.public|database", re.I),       "/decoy/db-admin"),
    # Brute force / credential stuffing / password spraying
    (re.compile(r"brute.force|T1110|credential|password.spray|T1078", re.I), "/decoy/ssh-login"),
    # Privilege escalation / token theft / session hijack
    (re.compile(r"privilege.escal|T1068|T1134|token.theft|session.hijack", re.I), "/decoy/internal-api/token"),
    # Reconnaissance / scanning / discovery
    (re.compile(r"recon|T1595|T1046|T1082|scan|discovery", re.I),         "/decoy/health-internal"),
    # Config / secrets exfiltration
    (re.compile(r"T1552|credential.file|config|secret|unsecured", re.I),  "/decoy/config"),
    # Lateral movement / internal API abuse
    (re.compile(r"lateral|T1021|T1563|internal.api|remote.service", re.I), "/decoy/internal-api/users"),
    # Phishing / spear-phishing (C2 beaconing to internal endpoint)
    (re.compile(r"phish|T1566|T1071|C2|command.control", re.I),           "/decoy/internal-api/telemetry"),
    # XSS / injection (non-SQL)
    (re.compile(r"xss|T1059|script.inject|cross.site", re.I),             "/decoy/internal-api/render"),
]

_DEFAULT_DECOY_PATH = "/decoy/internal-api/status"


def _resolve_decoy_path(mitre_technique: str, attack_pattern: str) -> str:
    """
    Deterministically select the most appropriate decoy path for a given
    MITRE technique and free-form attack pattern string.
    """
    combined = f"{mitre_technique} {attack_pattern}"
    for pattern, path in _TECHNIQUE_DECOY_MAP:
        if pattern.search(combined):
            logger.debug("Decoy path resolved | technique=%s → path=%s", mitre_technique, path)
            return path
    logger.debug("Decoy path defaulted | technique=%s → %s", mitre_technique, _DEFAULT_DECOY_PATH)
    return _DEFAULT_DECOY_PATH


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class DeceptionResult:
    """Outcome of a single deception routing decision."""
    ip: str
    attack_pattern: str
    mitre_technique: str
    decoy_path: str
    edge_id: str
    graph_edge: dict[str, Any] = field(default_factory=dict)
    db_persisted: bool = False
    error: str | None = None


# ---------------------------------------------------------------------------
# Public agent class
# ---------------------------------------------------------------------------

class DeceptionAgent:
    """
    Routes confirmed attackers into the CHIMERA honeypot layer and records
    a ``redirected_to`` edge in the PostgreSQL graph topology.

    Usage::

        agent = DeceptionAgent()
        result = await agent.route_attacker(
            attack_pattern="SQL injection attempt on /api/users",
            ip="198.51.100.42",
            mitre_technique="T1190 – Exploit Public-Facing Application",
        )
        print(result.decoy_path)   # → "/decoy/db-admin"
        print(result.edge_id)      # → UUID of the persisted graph edge
    """

    # ------------------------------------------------------------------
    # Graph edge persistence
    # ------------------------------------------------------------------

    async def _ensure_graph_edges_table(self) -> None:
        """
        Create all tables if they don't exist yet via SQLAlchemy Base metadata.
        """
        try:
            await init_db()
        except Exception as e:
            logger.debug("_ensure_graph_edges_table note: %s", e)

    async def _persist_edge(
        self,
        edge_id: str,
        source_node: str,
        target_node: str,
        metadata: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Insert a ``redirected_to`` edge into ``graph_edges`` and ``decision_edges``.

        Returns the persisted edge record as a dict.
        """
        return await record_decision_edge(
            source_node=source_node,
            target_node=target_node,
            edge_type="redirected_to",
            agent_name="DeceptionAgent",
            reasoning=f"Attacker {metadata.get('attacker_ip')} routed to honeypot {metadata.get('decoy_path')}",
            metadata=metadata,
        )

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def route_attacker(
        self,
        attack_pattern: str,
        ip: str,
        mitre_technique: str = "",
    ) -> DeceptionResult:
        """
        Determine the best decoy path for the given attacker and record it.

        Parameters
        ----------
        attack_pattern:
            Free-form description of the observed attack (e.g.
            ``"SQL injection attempt on /api/users"``).
        ip:
            Attacker's source IP address.
        mitre_technique:
            MITRE ATT&CK technique string from TriageAgent output (e.g.
            ``"T1190 – Exploit Public-Facing Application"``).
            Falls back to pattern-matching on ``attack_pattern`` alone if empty.

        Returns
        -------
        DeceptionResult
            Contains ``decoy_path``, ``edge_id``, ``graph_edge`` record,
            and ``db_persisted`` flag.
        """
        logger.info(
            "DeceptionAgent.route_attacker | ip=%s | technique=%s | pattern=%.80s",
            ip,
            mitre_technique,
            attack_pattern,
        )

        # 1. Resolve decoy path (pure, no I/O)
        decoy_path = _resolve_decoy_path(mitre_technique, attack_pattern)

        # 2. Build graph node identifiers
        source_node = f"ip:{ip}"
        target_node = f"decoy:{decoy_path}"
        edge_id = str(uuid.uuid4())

        metadata: dict[str, Any] = {
            "attack_pattern": attack_pattern,
            "mitre_technique": mitre_technique,
            "attacker_ip": ip,
            "decoy_path": decoy_path,
        }

        # 3. Persist the graph edge
        result = DeceptionResult(
            ip=ip,
            attack_pattern=attack_pattern,
            mitre_technique=mitre_technique,
            decoy_path=decoy_path,
            edge_id=edge_id,
        )

        try:
            # Ensure table exists (idempotent DDL)
            await self._ensure_graph_edges_table()

            edge_record = await self._persist_edge(
                edge_id=edge_id,
                source_node=source_node,
                target_node=target_node,
                metadata=metadata,
            )
            result.graph_edge = edge_record
            result.db_persisted = True

            logger.info(
                "DeceptionAgent edge persisted | edge_id=%s | %s → %s",
                edge_id,
                source_node,
                target_node,
            )

        except Exception as exc:
            # DB failure must NOT block the deception redirect
            logger.error(
                "DeceptionAgent DB persist failed | edge_id=%s | error=%s",
                edge_id,
                exc,
            )
            result.error = str(exc)
            result.db_persisted = False

        return result
