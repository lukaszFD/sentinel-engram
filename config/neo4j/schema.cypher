// ============================================================
// Sentinel Engram — Neo4j schema (constraints + indexes)
// ============================================================
// Applied by playbook 04.4 via cypher-shell. Idempotent (IF NOT EXISTS).
// Neo4j is a read-model of Synapse: every node is keyed by the same
// primary value Synapse uses, so the projection is a pure MERGE.
// ============================================================

CREATE CONSTRAINT domain_name IF NOT EXISTS FOR (d:Domain) REQUIRE d.name IS UNIQUE;
CREATE CONSTRAINT ip_addr IF NOT EXISTS FOR (i:IP) REQUIRE i.addr IS UNIQUE;
CREATE CONSTRAINT blocklist_slug IF NOT EXISTS FOR (b:Blocklist) REQUIRE b.slug IS UNIQUE;
CREATE CONSTRAINT malware_name IF NOT EXISTS FOR (m:MalwareFamily) REQUIRE m.name IS UNIQUE;
CREATE CONSTRAINT source_name IF NOT EXISTS FOR (s:Source) REQUIRE s.name IS UNIQUE;

CREATE INDEX domain_score IF NOT EXISTS FOR (d:Domain) ON (d.score);
CREATE INDEX domain_projected IF NOT EXISTS FOR (d:Domain) ON (d.projected_at);
CREATE INDEX ip_projected IF NOT EXISTS FOR (i:IP) ON (i.projected_at);
