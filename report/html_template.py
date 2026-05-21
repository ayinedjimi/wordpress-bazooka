"""HTML report template — PingCastle-style layout with Bootstrap 5, collapsible sections,
searchable/sortable tables, severity badges, and print-optimized output."""

HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="WordPress BAZOOKA Security Audit Report">
<meta name="author" content="WordPress BAZOOKA">
<title>BAZOOKA Report — {{ target_domain }}</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/bootstrap-table@1.23.5/dist/bootstrap-table.min.css" rel="stylesheet">
<style>
:root {
    --bz-primary: #5851DB;
    --bz-primary-hover: #6F69E7;
    --bz-primary-press: #4640B8;
    --bz-danger: #f12828;
    --bz-warning: #ff6a00;
    --bz-caution: #ffd800;
    --bz-success: #4CAF50;
    --bz-info: #0F82FF;
    --bz-dark: #1A172A;
    --bz-light: #F6F7F9;
    --bz-border: #EAE8E4;
}
body { font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; color: var(--bz-dark); background: #fff; }
a { color: var(--bz-primary); text-decoration: none !important; }
a:hover { color: var(--bz-primary-hover); }

/* Navbar */
.navbar-custom {
    background-color: var(--bz-dark);
    padding: 0.5rem 1.5rem;
    position: sticky; top: 0; z-index: 1030;
}
.navbar-custom .navbar-brand { color: #fa9c1a; font-weight: 700; font-size: 1.4rem; }
.navbar-custom .nav-link { color: rgba(255,255,255,0.85); font-size: 0.9rem; padding: 0.5rem 1rem; }
.navbar-custom .nav-link:hover { color: #fff; background: rgba(255,255,255,0.1); border-radius: 4px; }

/* Score cards */
.score-card { border-radius: 8px; padding: 1.5rem; text-align: center; color: #fff; }
.score-critical { background: var(--bz-danger); }
.score-high { background: var(--bz-warning); }
.score-medium { background: #E8A317; }
.score-low { background: var(--bz-caution); color: var(--bz-dark); }
.score-info { background: var(--bz-info); }
.score-good { background: var(--bz-success); }
.score-value { font-size: 2.5rem; font-weight: 700; }
.score-label { font-size: 0.85rem; text-transform: uppercase; letter-spacing: 1px; }

/* Section headers — PingCastle style */
.section-header-container {
    background-color: var(--bz-light);
    padding: 1rem 1.25rem;
    border: 1px solid var(--bz-border);
    margin-bottom: 0.625rem;
    margin-top: 1.5rem;
    cursor: pointer;
}
.section-header-container:hover { background-color: #EEEDEB; }
.sectionheader {
    color: var(--bz-dark) !important;
    text-decoration: underline !important;
    font-weight: 500;
    font-size: 1.25rem;
}

/* Severity badges */
.badge-critical { background-color: var(--bz-danger); color: #fff; }
.badge-high { background-color: var(--bz-warning); color: #fff; }
.badge-medium { background-color: #E8A317; color: #fff; }
.badge-low { background-color: var(--bz-caution); color: var(--bz-dark); }
.badge-info { background-color: var(--bz-info); color: #fff; }
.severity-badge { padding: 0.35em 0.65em; border-radius: 0.25rem; font-weight: 600; font-size: 0.8rem; }

/* Confidence badges */
.conf-confirmed { border-left: 4px solid var(--bz-success); }
.conf-likely { border-left: 4px solid var(--bz-caution); }
.conf-possible { border-left: 4px solid #ccc; }

/* Finding cards */
.finding-card {
    border: 1px solid var(--bz-border);
    border-radius: 6px;
    margin-bottom: 1rem;
    padding: 1.25rem;
}
.finding-card-critical { border-left: 5px solid var(--bz-danger); }
.finding-card-high { border-left: 5px solid var(--bz-warning); }
.finding-card-medium { border-left: 5px solid #E8A317; }
.finding-card-low { border-left: 5px solid var(--bz-caution); }
.finding-card-info { border-left: 5px solid var(--bz-info); }

/* Evidence blocks */
.evidence-block {
    background: #f8f9fa;
    border: 1px solid #dee2e6;
    border-radius: 4px;
    padding: 0.75rem;
    font-family: 'Consolas', 'Monaco', monospace;
    font-size: 0.85rem;
    white-space: pre-wrap;
    word-break: break-all;
    max-height: 300px;
    overflow-y: auto;
}

/* Compliance tags */
.compliance-tag {
    display: inline-block;
    padding: 0.15em 0.5em;
    border-radius: 3px;
    font-size: 0.75rem;
    margin-right: 0.25rem;
    background: #e9ecef;
    color: var(--bz-dark);
}

/* Charts area */
.chart-container { max-width: 400px; margin: 0 auto; }

/* Notification box */
.notif {
    border-radius: 2px;
    border-left: 4px solid var(--bz-info);
    background: #E5F2FF;
    padding: 1em;
    margin-bottom: 1rem;
}
.warn {
    border-radius: 2px;
    border-left: 4px solid #FFC700;
    background: #FFF9E5;
    padding: 1em;
    margin-bottom: 1rem;
}

/* Print */
@media print {
    .navbar-custom { display: none; }
    .no-print { display: none; }
    .section-header-container { break-inside: avoid; }
    .finding-card { break-inside: avoid; }
    body { font-size: 10pt; }
}
.pagebreak { page-break-before: always; }

/* Table customizations */
.table th { background-color: var(--bz-light); font-weight: 500; }
.fixed-table-toolbar .search input { border-radius: 4px; }
</style>
</head>
<body>

<!-- NAVBAR -->
<nav class="navbar navbar-custom navbar-expand-lg">
    <a class="navbar-brand" href="#">&#128163; BAZOOKA</a>
    <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navMenu">
        <span class="navbar-toggler-icon"></span>
    </button>
    <div class="collapse navbar-collapse" id="navMenu">
        <ul class="navbar-nav ms-auto">
            <li class="nav-item"><a class="nav-link" href="#summary">Resume</a></li>
            <li class="nav-item"><a class="nav-link" href="#findings-table">Vulnerabilites</a></li>
            <li class="nav-item"><a class="nav-link" href="#details">Details</a></li>
            <li class="nav-item"><a class="nav-link" href="#recon-data">Reconnaissance</a></li>
            <li class="nav-item"><a class="nav-link" href="#remediation">Remediation</a></li>
        </ul>
    </div>
</nav>

<div class="container-fluid" style="max-width: 1400px; padding: 2rem;">

<!-- HEADER -->
<div class="report-header mb-4">
    <h1 style="font-weight: 300;">Rapport d'Audit de Securite WordPress</h1>
    <div class="report-date" style="font-size:1.25rem; color: #666;">
        <strong>Cible :</strong> {{ target_url }}<br>
        <strong>Domaine :</strong> {{ target_domain }}<br>
        <strong>Date :</strong> {{ scan_date }}<br>
        <strong>Profil :</strong> {{ profile }}<br>
        {% if authorization_ref %}<strong>Ref. autorisation :</strong> {{ authorization_ref }}<br>{% endif %}
        <strong>Duree :</strong> {{ duration }} | <strong>Requetes :</strong> {{ total_requests }}
    </div>
</div>

<!-- DISCLAIMER -->
<div class="warn">
    <strong>CONFIDENTIEL</strong> — Ce rapport a ete produit dans le cadre d'un audit de securite autorise.
    Les tests ont ete realises conformement au perimetre defini. L'utilisation de cet outil en dehors
    d'un cadre legal autorise est strictement interdite.
</div>

<!-- SCORE CARDS -->
<a name="summary"></a>
<div class="section-header-container">
    <a class="sectionheader" data-bs-toggle="collapse" href="#panelSummary">Resume Executif</a>
</div>
<div class="collapse show" id="panelSummary">
    <div class="row g-3 mb-4">
        <div class="col-md-2">
            <div class="score-card {{ score_class }}">
                <div class="score-value">{{ max_cvss }}</div>
                <div class="score-label">Score Max</div>
            </div>
        </div>
        <div class="col-md-2">
            <div class="score-card score-critical">
                <div class="score-value">{{ counts.CRITICAL }}</div>
                <div class="score-label">Critiques</div>
            </div>
        </div>
        <div class="col-md-2">
            <div class="score-card score-high">
                <div class="score-value">{{ counts.HIGH }}</div>
                <div class="score-label">Hautes</div>
            </div>
        </div>
        <div class="col-md-2">
            <div class="score-card score-medium">
                <div class="score-value">{{ counts.MEDIUM }}</div>
                <div class="score-label">Moyennes</div>
            </div>
        </div>
        <div class="col-md-2">
            <div class="score-card score-low">
                <div class="score-value">{{ counts.LOW }}</div>
                <div class="score-label">Basses</div>
            </div>
        </div>
        <div class="col-md-2">
            <div class="score-card score-info">
                <div class="score-value">{{ counts.INFO }}</div>
                <div class="score-label">Info</div>
            </div>
        </div>
    </div>

    {% if wp_version %}
    <div class="notif">
        <strong>WordPress {{ wp_version }}</strong> detecte
        {% if waf %} | WAF: <strong>{{ waf }}</strong>{% endif %}
        {% if origin_ip %} | Origin IP: <strong>{{ origin_ip }}</strong>{% endif %}
        | Utilisateurs: <strong>{{ user_count }}</strong>
        | Plugins: <strong>{{ plugin_count }}</strong>
    </div>
    {% endif %}
</div>

<!-- FINDINGS TABLE -->
<a name="findings-table"></a>
<div class="section-header-container">
    <a class="sectionheader" data-bs-toggle="collapse" href="#panelFindings">Synthese des Vulnerabilites ({{ total_findings }})</a>
</div>
<div class="collapse show" id="panelFindings">
    <div class="table-responsive">
        <table class="table table-striped table-bordered"
            data-toggle="table"
            data-pagination="true"
            data-search="true"
            data-sortable="true"
            data-sort-name="cvss"
            data-sort-order="desc"
            data-page-list="[10,25,50,100,All]"
            data-page-size="25">
            <thead>
                <tr>
                    <th data-field="id" data-sortable="true">ID</th>
                    <th data-field="severity" data-sortable="true">Severite</th>
                    <th data-field="cvss" data-sortable="true">CVSS</th>
                    <th data-field="confidence" data-sortable="true">Confiance</th>
                    <th data-field="title" data-sortable="true">Titre</th>
                    <th data-field="module" data-sortable="true">Module</th>
                    <th data-field="compliance">Conformite</th>
                </tr>
            </thead>
            <tbody>
                {% for f in findings %}
                <tr>
                    <td><a href="#finding-{{ f.id }}">{{ f.id }}</a></td>
                    <td><span class="severity-badge badge-{{ f.severity.value|lower }}">{{ f.severity.value }}</span></td>
                    <td>{{ f.cvss_score }}</td>
                    <td>{{ f.confidence.value }}</td>
                    <td>{{ f.title }}</td>
                    <td><code>{{ f.module }}</code></td>
                    <td>
                        {% if f.compliance.owasp_2021 %}<span class="compliance-tag">{{ f.compliance.owasp_2021 }}</span>{% endif %}
                        {% if f.compliance.cwe %}<span class="compliance-tag">{{ f.compliance.cwe }}</span>{% endif %}
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</div>

<!-- DETAILED FINDINGS -->
<a name="details"></a>
<div class="section-header-container">
    <a class="sectionheader" data-bs-toggle="collapse" href="#panelDetails">Findings Detailles</a>
</div>
<div class="collapse show" id="panelDetails">
    {% for f in findings %}
    <a name="finding-{{ f.id }}"></a>
    <div class="finding-card finding-card-{{ f.severity.value|lower }} conf-{{ f.confidence.value }}">
        <div class="d-flex justify-content-between align-items-start mb-2">
            <div>
                <span class="severity-badge badge-{{ f.severity.value|lower }}">{{ f.severity.value }}</span>
                <strong style="margin-left: 0.5rem; font-size: 1.1rem;">{{ f.title }}</strong>
            </div>
            <div class="text-end">
                <span class="badge bg-dark">CVSS {{ f.cvss_score }}</span>
                <span class="badge bg-secondary">{{ f.confidence.value }}</span>
            </div>
        </div>

        <p class="text-justify">{{ f.description }}</p>

        {% if f.evidence.request %}
        <details class="mb-2">
            <summary><strong>Evidence</strong></summary>
            <div class="evidence-block mt-1">{{ f.evidence.request }}

{% if f.evidence.response_body_excerpt %}Response: {{ f.evidence.response_body_excerpt }}{% endif %}</div>
        </details>
        {% endif %}

        <div class="row mt-2">
            <div class="col-md-6">
                <strong>Impact :</strong>
                <p class="text-justify">{{ f.impact }}</p>
            </div>
            <div class="col-md-6">
                <strong>Remediation :</strong>
                <p class="text-justify">{{ f.remediation }}</p>
            </div>
        </div>

        <div>
            {% if f.compliance.owasp_2021 %}<span class="compliance-tag">OWASP: {{ f.compliance.owasp_2021 }}</span>{% endif %}
            {% if f.compliance.cwe %}<span class="compliance-tag">{{ f.compliance.cwe }}</span>{% endif %}
            {% if f.compliance.mitre_attack %}<span class="compliance-tag">MITRE: {{ f.compliance.mitre_attack }}</span>{% endif %}
            <span class="compliance-tag">Module: {{ f.module }}</span>
        </div>

        {% if f.references %}
        <div class="mt-2" style="font-size: 0.85rem;">
            <strong>References :</strong>
            {% for ref in f.references %}<a href="{{ ref }}" target="_blank">{{ ref }}</a> {% endfor %}
        </div>
        {% endif %}
    </div>
    {% endfor %}
</div>

<!-- RECONNAISSANCE DATA -->
<a name="recon-data"></a>
<div class="section-header-container">
    <a class="sectionheader" data-bs-toggle="collapse" href="#panelRecon">Donnees de Reconnaissance</a>
</div>
<div class="collapse" id="panelRecon">
    <div class="card-body">
        {% if dns_records %}
        <h5>DNS Records</h5>
        <div class="evidence-block">{{ dns_records }}</div>
        {% endif %}

        {% if users_data %}
        <h5 class="mt-3">Utilisateurs WordPress</h5>
        <div class="table-responsive">
            <table class="table table-sm table-striped table-bordered" data-toggle="table" data-search="true">
                <thead><tr><th>ID</th><th>Username</th><th>Display Name</th><th>Email</th><th>Methode</th></tr></thead>
                <tbody>
                {% for u in users_data %}
                <tr>
                    <td>{{ u.id }}</td>
                    <td><code>{{ u.username }}</code></td>
                    <td>{{ u.display_name }}</td>
                    <td>{{ u.email or '-' }}</td>
                    <td>{{ u.discovery_method }}</td>
                </tr>
                {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}

        {% if plugins_data %}
        <h5 class="mt-3">Plugins Detectes</h5>
        <div class="table-responsive">
            <table class="table table-sm table-striped table-bordered" data-toggle="table" data-search="true">
                <thead><tr><th>Slug</th><th>Version</th><th>Methode</th><th>CVEs</th></tr></thead>
                <tbody>
                {% for p in plugins_data %}
                <tr>
                    <td><code>{{ p.slug }}</code></td>
                    <td>{{ p.version or '?' }}</td>
                    <td>{{ p.discovery_method }}</td>
                    <td>{{ p.cves|length }}</td>
                </tr>
                {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}
    </div>
</div>

<!-- REMEDIATION PLAN -->
<a name="remediation"></a>
<div class="section-header-container">
    <a class="sectionheader" data-bs-toggle="collapse" href="#panelRemed">Plan de Remediation</a>
</div>
<div class="collapse show" id="panelRemed">
    <div class="notif">
        <strong>Priorite :</strong> Corriger d'abord les vulnerabilites CRITICAL, puis HIGH.
        Les corrections MEDIUM et LOW peuvent etre planifiees dans les sprints suivants.
    </div>
    <table class="table table-striped table-bordered">
        <thead>
            <tr><th>Priorite</th><th>Action</th><th>Findings</th></tr>
        </thead>
        <tbody>
            {% for r in remediation_plan %}
            <tr>
                <td><span class="severity-badge badge-{{ r.severity|lower }}">{{ r.severity|upper }}</span></td>
                <td>{{ r.action }}</td>
                <td>{{ r.finding_ids }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
</div>

<!-- FOOTER -->
<hr>
<div class="text-center text-muted" style="font-size: 0.85rem; padding: 1rem 0;">
    <strong>WordPress BAZOOKA</strong> v{{ bazooka_version }} — Rapport genere le {{ scan_date }}<br>
    {{ total_findings }} vulnerabilites | {{ total_requests }} requetes | Profil: {{ profile }}<br>
    <em>Genere automatiquement — Ne remplace pas l'expertise humaine.</em>
</div>

</div><!-- /container -->

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap-table@1.23.5/dist/bootstrap-table.min.js"></script>
<script>
$(function() { $('[data-toggle="table"]').bootstrapTable(); });
</script>
</body>
</html>"""
