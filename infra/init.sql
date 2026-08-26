-- Enable UUID generation extension if needed (gen_random_uuid is built-in in Postgres 13+)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================================
-- 1. INCIDENTS TABLE
-- Tracks security incidents, risk scores, confidence, and blast radius
-- ============================================================================
CREATE TABLE IF NOT EXISTS incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title VARCHAR(255) NOT NULL,
    description TEXT,
    status VARCHAR(50) NOT NULL DEFAULT 'OPEN', -- e.g. OPEN, INVESTIGATING, CONTAINED, RESOLVED, CLOSED
    severity VARCHAR(50) NOT NULL DEFAULT 'MEDIUM', -- e.g. LOW, MEDIUM, HIGH, CRITICAL
    risk_score DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    confidence DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    blast_radius JSONB NOT NULL DEFAULT '{}'::jsonb,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- 2. EVENTS TABLE
-- Stores raw telemetry, logs, and security events linked to incidents
-- ============================================================================
CREATE TABLE IF NOT EXISTS events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID REFERENCES incidents(id) ON DELETE SET NULL,
    event_type VARCHAR(100) NOT NULL,
    source VARCHAR(100) NOT NULL,
    severity VARCHAR(50) DEFAULT 'INFO',
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    raw_log TEXT,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- 3. ACTIONS TABLE
-- Tracks remediation actions and n8n playbooks execution
-- ============================================================================
CREATE TABLE IF NOT EXISTS actions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID REFERENCES incidents(id) ON DELETE CASCADE,
    playbook_name VARCHAR(255),
    action_type VARCHAR(100) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'PENDING', -- e.g. PENDING, RUNNING, SUCCESS, FAILED, CANCELLED
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    result JSONB NOT NULL DEFAULT '{}'::jsonb,
    executed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- 4. GRAPH NODES TABLE
-- Represents knowledge graph entities (IPs, Hosts, Users, Files, Threats)
-- ============================================================================
CREATE TABLE IF NOT EXISTS graph_nodes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID REFERENCES incidents(id) ON DELETE CASCADE,
    node_type VARCHAR(100) NOT NULL,
    label VARCHAR(255) NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- 5. GRAPH EDGES TABLE
-- Represents relationships between graph nodes for attack topology/investigation
-- ============================================================================
CREATE TABLE IF NOT EXISTS graph_edges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID REFERENCES incidents(id) ON DELETE CASCADE,
    source_id UUID NOT NULL,
    target_id UUID NOT NULL,
    edge_type VARCHAR(100) NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- 6. REPORTS TABLE
-- Stores incident summaries, post-mortems, and generated SOC reports
-- ============================================================================
CREATE TABLE IF NOT EXISTS reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID REFERENCES incidents(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    summary TEXT,
    content JSONB NOT NULL DEFAULT '{}'::jsonb,
    generated_by VARCHAR(100) DEFAULT 'SYSTEM',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- INDEXES
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_events_incident_id ON events(incident_id);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_risk_score ON incidents(risk_score);
CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents(created_at);
CREATE INDEX IF NOT EXISTS idx_actions_incident_id ON actions(incident_id);
CREATE INDEX IF NOT EXISTS idx_actions_status ON actions(status);
CREATE INDEX IF NOT EXISTS idx_graph_nodes_incident_id ON graph_nodes(incident_id);
CREATE INDEX IF NOT EXISTS idx_graph_edges_incident_id ON graph_edges(incident_id);
CREATE INDEX IF NOT EXISTS idx_reports_incident_id ON reports(incident_id);
