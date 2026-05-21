-- WordPress BAZOOKA CVE Database Schema
CREATE TABLE IF NOT EXISTS cve_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL UNIQUE,
    component_type TEXT NOT NULL,  -- 'plugin', 'theme', 'core'
    component_slug TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    cvss_score REAL DEFAULT 0.0,
    cvss_vector TEXT,
    severity TEXT,  -- CRITICAL, HIGH, MEDIUM, LOW
    vuln_type TEXT,  -- RCE, SQLi, XSS, LFI, SSRF, PrivEsc, AuthBypass, InfoDisclosure
    affected_version_min TEXT,
    affected_version_max TEXT,
    fixed_version TEXT,
    poc_url TEXT,
    references_json TEXT,  -- JSON array of reference URLs
    published_date TEXT,
    source TEXT,  -- wordfence, patchstack, wpvulndb, nvd, manual
    date_added TEXT DEFAULT (datetime('now')),
    date_updated TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_cve_slug ON cve_entries(component_slug);
CREATE INDEX IF NOT EXISTS idx_cve_type ON cve_entries(component_type);
CREATE INDEX IF NOT EXISTS idx_cve_severity ON cve_entries(severity);
CREATE INDEX IF NOT EXISTS idx_cve_cvss ON cve_entries(cvss_score);

CREATE TABLE IF NOT EXISTS db_meta (
    key TEXT PRIMARY KEY,
    value TEXT
);
