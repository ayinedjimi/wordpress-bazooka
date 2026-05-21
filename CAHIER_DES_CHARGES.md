# WORDPRESS BAZOOKA - Cahier des Charges

## Outil automatise de pentest et audit de securite WordPress

**Version** : 2.0
**Date** : 31 mars 2026
**Auteur** : AYI NEDJIMI CONSULTANTS
**Statut** : Draft v2 — integre les revues par 4 IA specialisees

---

## Table des matieres

1. [Contexte et objectifs](#1-contexte-et-objectifs)
2. [Philosophie et positionnement](#2-philosophie-et-positionnement)
3. [Architecture technique](#3-architecture-technique)
4. [Modules fonctionnels](#4-modules-fonctionnels)
5. [Moteur de scoring et reporting](#5-moteur-de-scoring-et-reporting)
6. [Interface utilisateur (CLI)](#6-interface-utilisateur-cli)
7. [Gestion du loot et preuves](#7-gestion-du-loot-et-preuves)
8. [Chaines d'attaque automatisees](#8-chaines-dattaque-automatisees)
9. [Cadre juridique, ethique et RGPD](#9-cadre-juridique-ethique-et-rgpd)
10. [Contraintes et exigences non-fonctionnelles](#10-contraintes-et-exigences-non-fonctionnelles)
11. [Stack technique](#11-stack-technique)
12. [Strategie de test](#12-strategie-de-test)
13. [Risques projet](#13-risques-projet)
14. [Livrables et jalons](#14-livrables-et-jalons)
15. [Annexe A - Matrice des tests](#annexe-a---matrice-des-120-tests)
16. [Annexe B - Formats de sortie](#annexe-b---formats-de-sortie)
17. [Annexe C - Modele de donnees](#annexe-c---modele-de-donnees-pydantic)
18. [Annexe D - Structure du template DOCX](#annexe-d---structure-du-template-docx)

---

## 1. Contexte et objectifs

### 1.1 Constat terrain

Le pentest CYRIAS (mars 2026) a mobilise plus de **40 heures** de tests manuels repartis sur :
- 6 domaines WordPress
- 1 plage IP /24 (18 services decouverts)
- 950 fichiers collectes (398 MB)
- 145 vulnerabilites identifiees
- ~21 500 tentatives de brute-force
- Plus de 30 outils differents (nmap, wpscan, nuclei, sqlmap, curl, dig, etc.)

**Probleme** : 80% des actions sont repetitives et suivent un schema previsible. La valeur ajoutee du pentester reside dans l'interpretation des resultats et le chainage des attaques, pas dans l'execution sequentielle de commandes curl.

### 1.2 Objectif principal

Creer un outil **tout-en-un** qui automatise l'integralite du workflow de pentest WordPress, de la reconnaissance initiale a la generation du rapport final, en reproduisant fidelement les techniques qui ont fait leurs preuves sur le terrain.

### 1.3 Objectifs specifiques

| # | Objectif | Mesure de succes |
|---|----------|-----------------|
| O1a | Reduire le temps recon+enum de ~10h a < 5 min | Benchmark sur cible de test |
| O1b | Reduire le temps pentest complet de ~40h a < 1h (execution) + 2-4h (analyse humaine) | Benchmark sur cible de test |
| O2 | Zero faux negatif sur les vulns connues | Taux de detection >= 95% vs audit manuel |
| O3 | Rapport exploitable immediatement | Format DOCX/PDF/HTML/SARIF pret pour le client ou CI/CD |
| O4 | Fonctionner avec Python 3.11+ et pip | Dependances systeme (nmap, git) optionnelles avec fallback |
| O5 | Respecter le cadre legal | Scope file obligatoire, mode audit par defaut, RGPD-compliant |

### 1.4 Cibles utilisateurs

- Pentesters professionnels (audits mandates)
- Equipes securite internes (audit recurrent)
- Freelances WordPress (verification avant livraison)
- Bug bounty hunters (reconnaissance rapide)
- Equipes DevSecOps (integration CI/CD)

---

## 2. Philosophie et positionnement

### 2.1 Nom : WordPress BAZOOKA

> "Un seul tir, tous les angles couverts."

### 2.2 Ce que BAZOOKA est

- Un framework de pentest specialise WordPress
- Un enchaineur intelligent de tests (pas juste un scanner)
- Un collecteur de preuves structure avec chiffrement
- Un generateur de rapports professionnels multi-format
- Un outil extensible par modules et regles YAML

### 2.3 Ce que BAZOOKA n'est PAS

- Un remplacement de Burp Suite ou de l'expertise humaine
- Un outil d'exploitation automatique (pas de webshell auto-deploy)
- Un scanner generique (il connait WordPress en profondeur)
- Un outil offensif sans garde-fou (toujours un mode --dry-run)

### 2.4 Differenciateurs vs WPScan / Nuclei / etc.

| Critere | WPScan | Nuclei | BAZOOKA |
|---------|--------|--------|---------|
| Reconnaissance complete (DNS, WHOIS, CT, OSINT) | Non | Non | **Oui** |
| REST API deep enumeration (toutes routes core+plugins) | Basique | Non | **Complet** |
| GraphQL introspection | Non | Non | **Oui** |
| Chainage d'attaque automatique (rule engine YAML) | Non | Non | **Oui (7+ chaines)** |
| Detection CDN bypass / origin IP | Non | Non | **Oui** |
| CORS / SPF / DMARC analysis | Non | Non | **Oui** |
| Collecte structuree de loot (chiffre) | Non | Non | **Oui (par phase)** |
| Brute-force intelligent (CUPP + breach) | Non | Non | **Oui** |
| Rapport DOCX/PDF/SARIF/Markdown pret client | Non | Non | **Oui** |
| Mapping OWASP Top 10 / CWE / MITRE ATT&CK | Non | Partiel | **Complet** |
| Scan infrastructure adjacente (/24) | Non | Partiel | **Oui (SSL cert enum)** |
| Detection debug.log / backups / directory listing | Partiel | Partiel | **Complet** |
| Comparaison inter-scans (diff) | Non | Non | **Oui** |
| WordPress Multisite support | Partiel | Non | **Complet** |

---

## 3. Architecture technique

### 3.1 Architecture modulaire

```
wordpress-bazooka/
|
|-- bazooka.py                    # Point d'entree CLI principal
|-- pyproject.toml                # Packaging moderne (remplace setup.py)
|-- Dockerfile                    # Image officielle
|-- docker-compose.yml            # Stack de test (WP vulnerable inclus)
|-- LICENSE
|
|-- config/
|   |-- default.yaml              # Configuration par defaut
|   |-- scope.yaml.example        # Template de fichier scope
|   |-- profiles/                 # Profils d'audit
|   |   |-- quick.yaml
|   |   |-- standard.yaml
|   |   |-- aggressive.yaml
|   |   |-- bugbounty.yaml        # NOUVEAU : profil bug bounty (non-intrusif)
|   |-- wordlists/                # Wordlists embarquees
|       |-- wp_common_paths.txt
|       |-- wp_backup_extensions.txt
|       |-- wp_default_users.txt
|       |-- common_passwords_10k.txt
|
|-- signatures/                   # NOUVEAU : signatures externalisees en YAML
|   |-- plugins.yaml              # pattern → slug plugin
|   |-- themes.yaml               # pattern → slug theme
|   |-- waf.yaml                  # header pattern → nom WAF
|   |-- services.yaml             # fingerprint → service (Nextcloud, Vaultwarden, etc.)
|   |-- shortcodes.yaml           # shortcode → plugin associe
|
|-- core/
|   |-- __init__.py
|   |-- engine.py                 # Orchestrateur principal
|   |-- target.py                 # Objet cible (domaine, IP, infra)
|   |-- session.py                # Gestion HTTP (retry, proxy, UA, cache)
|   |-- cache.py                  # NOUVEAU : cache HTTP transparent (TTL par type)
|   |-- database.py               # NOUVEAU : backend SQLite (dedup, queries, resume)
|   |-- state.py                  # NOUVEAU : persistance etat scan pour resume
|   |-- scope.py                  # NOUVEAU : enforcement strict du perimetre
|   |-- chain.py                  # Moteur de chainage d'attaques (rule engine YAML)
|   |-- scorer.py                 # Moteur de scoring CVSS (via lib `cvss`)
|   |-- evidence.py               # Collecteur de preuves
|   |-- events.py                 # NOUVEAU : bus d'evenements pub/sub inter-modules
|   |-- context.py                # NOUVEAU : contexte de scan (resultats + confiance)
|   |-- registry.py               # NOUVEAU : registre et decouverte de modules
|   |-- signals.py                # NOUVEAU : gestion SIGINT/SIGTERM graceful
|   |-- crypto.py                 # NOUVEAU : chiffrement loot (age/GPG)
|
|-- modules/
|   |-- base.py                   # NOUVEAU : classe abstraite BazookaModule
|   |-- recon/                    # Phase 1 - Reconnaissance
|   |   |-- dns_enum.py
|   |   |-- whois_lookup.py
|   |   |-- ct_logs.py
|   |   |-- subdomain_enum.py
|   |   |-- cdn_detect.py
|   |   |-- origin_finder.py
|   |   |-- ssl_scan.py
|   |   |-- port_scan.py
|   |   |-- waf_detect.py
|   |   |-- headers_analysis.py
|   |   |-- spf_dmarc.py
|   |   |-- osint_emails.py
|   |   |-- breach_check.py
|   |   |-- sitemap_parser.py
|   |   |-- robots_parser.py
|   |   |-- technology_stack.py   # NOUVEAU : detection PHP version, serveur, etc.
|   |
|   |-- enum/                     # Phase 2 - Enumeration
|   |   |-- wp_content_detect.py  # NOUVEAU : detection repertoire wp-content custom
|   |   |-- wp_version.py
|   |   |-- wp_users.py
|   |   |-- wp_plugins.py
|   |   |-- wp_themes.py
|   |   |-- wp_multisite.py       # NOUVEAU : detection et enum WordPress Multisite
|   |   |-- wp_config_audit.py    # NOUVEAU : audit constantes wp-config (si fuitees)
|   |   |-- rest_api.py
|   |   |-- graphql_enum.py       # NOUVEAU : introspection WPGraphQL
|   |   |-- xmlrpc_methods.py
|   |   |-- woocommerce.py
|   |   |-- contact_forms.py
|   |   |-- media_enum.py
|   |   |-- path_fuzzer.py
|   |   |-- debug_log.py
|   |   |-- directory_listing.py
|   |   |-- backup_finder.py
|   |   |-- source_maps.py
|   |   |-- cron_jobs.py
|   |   |-- gravatar_reverse.py
|   |   |-- mu_plugins.py         # NOUVEAU : must-use plugins (backdoors)
|   |   |-- shortcode_parser.py   # NOUVEAU : detection plugins via shortcodes
|   |   |-- object_cache.py       # NOUVEAU : detection Redis/Memcached expose
|   |   |-- application_passwords.py # NOUVEAU : WP 5.6+ app passwords
|   |   |-- registration_check.py # NOUVEAU : inscription ouverte + role defaut
|   |
|   |-- vuln/                     # Phase 3 - Detection de vulnerabilites
|   |   |-- cve_matcher.py
|   |   |-- cors_check.py
|   |   |-- ssrf_xmlrpc.py
|   |   |-- sqli_scanner.py
|   |   |-- xss_scanner.py        # NOUVEAU : specification complete (voir 4.3)
|   |   |-- lfi_scanner.py        # NOUVEAU : specification complete
|   |   |-- rce_check.py          # NOUVEAU : specification complete
|   |   |-- idor_check.py         # NOUVEAU : specification complete
|   |   |-- csrf_check.py         # NOUVEAU : specification complete
|   |   |-- auth_bypass.py        # NOUVEAU : specification complete
|   |   |-- file_upload.py        # NOUVEAU : specification complete (SVG XXE, Phar)
|   |   |-- rate_limit.py
|   |   |-- security_headers.py
|   |   |-- ssl_tls_audit.py
|   |   |-- mod_rewrite_cve.py
|   |   |-- session_auth.py       # NOUVEAU : cookies, expiration, fixation
|   |   |-- host_header_injection.py # NOUVEAU : password reset poisoning
|   |   |-- honeypot_detect.py    # NOUVEAU : detection pots de miel
|   |   |-- misconfig_check.py    # NOUVEAU : erreurs de config non-CVE
|   |
|   |-- exploit/                  # Phase 4 - Exploitation (flag --pentest requis)
|   |   |-- xmlrpc_bruteforce.py
|   |   |-- wp_login_bruteforce.py
|   |   |-- pma_bruteforce.py
|   |   |-- ssrf_port_scan.py
|   |   |-- ssrf_internal.py
|   |   |-- origin_bypass.py
|   |   |-- git_dumper.py
|   |   |-- wordlist_generator.py
|   |   |-- authenticated_scan.py # NOUVEAU : tests post-compromission
|   |
|   |-- infra/                    # Phase 5 - Infrastructure adjacente
|   |   |-- network_scan.py
|   |   |-- ssl_cert_enum.py
|   |   |-- service_detect.py
|   |   |-- vhost_enum.py
|   |   |-- lateral_movement.py   # NOUVEAU : specification complete
|   |
|   |-- custom/                   # Modules tiers (decouverte auto)
|       |-- README.md
|
|-- cve_db/                       # NOUVEAU : base CVE SQLite (pas JSON)
|   |-- bazooka_cve.db            # SQLite : plugins, themes, core, CVE, CVSS, PoC
|   |-- sources.yaml              # Config des feeds (Wordfence, PatchStack, WPVulnDB, NVD)
|   |-- update.py                 # Script de mise a jour multi-sources
|
|-- report/
|   |-- __init__.py
|   |-- generator.py              # Orchestrateur de rapports
|   |-- exporters/                # NOUVEAU : exporteurs multi-format
|   |   |-- docx_exporter.py
|   |   |-- html_exporter.py
|   |   |-- json_exporter.py
|   |   |-- sarif_exporter.py     # NOUVEAU : GitHub Advanced Security
|   |   |-- markdown_exporter.py  # NOUVEAU : wikis, ticketing
|   |   |-- junit_exporter.py     # NOUVEAU : Jenkins/GitLab CI
|   |   |-- defectdojo_exporter.py # NOUVEAU : plateforme vuln management
|   |   |-- jira_exporter.py      # NOUVEAU : creation tickets auto
|   |-- templates/
|   |   |-- rapport_pentest.docx  # Template Word avec placeholders
|   |   |-- rapport_audit.html    # Template HTML Jinja2
|   |   |-- executive_summary.md  # Template resume executif
|   |   |-- disclaimer_fr.md      # NOUVEAU : clause de non-responsabilite FR
|   |   |-- disclaimer_en.md      # NOUVEAU : clause de non-responsabilite EN
|   |-- sections/
|   |   |-- recon_section.py
|   |   |-- enum_section.py
|   |   |-- vuln_section.py
|   |   |-- exploit_section.py
|   |   |-- remediation.py
|   |   |-- compliance.py         # NOUVEAU : mapping OWASP/CWE/PCI-DSS/MITRE
|   |   |-- diff_section.py       # NOUVEAU : comparaison inter-scans
|   |-- scoring.py
|   |-- charts.py                 # Graphiques (camembert, timeline, heatmap)
|   |-- chains_viz.py             # NOUVEAU : Mermaid.js / Graphviz pour chaines
|   |-- i18n/                     # NOUVEAU : traductions
|       |-- fr.yaml
|       |-- en.yaml
|
|-- loot/                         # Artefacts collectes (runtime)
|   |-- {target}/
|       |-- bazooka.db            # SQLite local du scan
|       |-- ...
|
|-- tests/                        # Tests (voir section 12)
|   |-- unit/
|   |   |-- test_recon.py
|   |   |-- test_enum.py
|   |   |-- test_vuln.py
|   |   |-- test_chain.py
|   |   |-- test_scorer.py
|   |   |-- test_session.py
|   |   |-- test_scope.py         # CRITIQUE : le scope ne doit jamais etre depasse
|   |   |-- test_registry.py
|   |-- integration/
|   |   |-- test_full_scan.py
|   |   |-- docker-compose.test.yml  # WP vulnerable pour tests
|   |-- fixtures/                 # Reponses HTTP mockees (golden files)
|   |-- conftest.py
```

### 3.2 Systeme de registre de modules (`core/registry.py`)

Chaque module implemente une interface standard pour la decouverte automatique :

```python
from abc import ABC, abstractmethod
from pydantic import BaseModel

class ModuleResult(BaseModel):
    findings: list[Finding]
    metadata: dict
    status: Literal["success", "partial", "failed", "skipped"]
    confidence: Literal["confirmed", "likely", "possible"]

class BazookaModule(ABC):
    name: str                      # Identifiant unique (ex: "recon.dns_enum")
    phase: str                     # recon | enum | vuln | exploit | infra
    description: str               # Description courte
    profiles: list[str]            # ["quick", "standard", "aggressive"]
    intrusive: bool                # Necessite --pentest ?
    dependencies: list[str]        # Modules requis avant celui-ci

    @abstractmethod
    async def run(self, target: Target, session: BazookaSession,
                  context: ScanContext) -> ModuleResult:
        """Execute le module et retourne les findings."""
        ...

    def should_run(self, context: ScanContext) -> bool:
        """Priorisation dynamique : decide si ce module est pertinent."""
        return True

# Decouverte automatique via scan du dossier modules/ + modules/custom/
# Les modules custom suivent la meme interface
```

### 3.3 Contexte de scan et communication inter-modules (`core/context.py`)

```python
class ScanContext:
    """
    Objet central qui accumule les resultats de tous les modules.
    Chaque donnee porte un niveau de confiance.
    Les modules en aval adaptent leur comportement en fonction.
    """
    target: Target
    findings: list[Finding]       # Tous les findings
    data: dict                    # Donnees partagees (users, plugins, origin_ip, etc.)
    confidence: dict[str, str]    # Confiance par cle de donnee
    events: EventBus              # Bus pub/sub pour reactions temps reel
    db: Database                  # Backend SQLite
    scope: ScopeEnforcer          # Verification perimetre avant chaque requete
    wp_content_path: str          # Chemin wp-content (detecte dynamiquement, defaut: /wp-content/)
```

### 3.4 Bus d'evenements (`core/events.py`)

```python
class EventBus:
    """
    Pattern pub/sub leger pour communication inter-modules.
    Le chain engine s'abonne aux evenements pour reagir en temps reel.

    Evenements :
    - "user_found"        → declenche gravatar_reverse, breach_check
    - "plugin_found"      → declenche cve_matcher
    - "origin_found"      → declenche origin_bypass
    - "ssrf_confirmed"    → declenche ssrf_port_scan
    - "credential_found"  → declenche authenticated_scan
    - "waf_detected"      → ajuste la strategie de session
    """
```

### 3.5 Pipeline d'execution

```
[CIBLE] + [SCOPE FILE]
   |
   v
Phase 0: BOOTSTRAP ─────────> Validation scope, detection wp-content custom, calibration 404
   |                           (sequentiel, ~5s)
   v
Phase 1: RECON ──────────────> DNS, WHOIS, CT, subdomains, CDN, origin, ports, WAF,
   |                           SPF/DMARC, OSINT, tech stack
   |                           (parallelise, ~30s)
   v
Phase 2: ENUM ───────────────> WP version, users, plugins, themes, REST API, GraphQL,
   |                           XML-RPC, Multisite, mu-plugins, shortcodes, debug.log,
   |                           backups, directory listing, media, source maps, app passwords
   |                           (parallelise, ~60s)
   v
Phase 3: VULN DETECT ────────> CVE match, CORS, SSRF, SQLi, XSS, LFI, RCE, IDOR, CSRF,
   |                           file upload, auth bypass, session, host header injection,
   |                           rate-limit, security headers, SSL/TLS, mod_rewrite, honeypot
   |                           (sequentiel sur findings, ~60s)
   v
Phase 4: EXPLOIT ────────────> Brute-force, SSRF interne, origin bypass, git dump,
   |  (--pentest only)         authenticated scan post-compromission
   |                           (controllable, throttled, ~variable)
   v
Phase 5: INFRA ──────────────> Scan /24, SSL cert enum, service detect, vhost, lateral map
   |  (--infra flag)           (parallelise, ~120s)
   v
[CHAIN ENGINE] ──────────────> Identification automatique des chaines d'attaque
   |                           (regles YAML + combinatoire dynamique)
   v
[SCORING] ───────────────────> CVSS v3.1 (lib cvss) + Temporal + Environmental
   |                           + score global hybride + mapping conformite
   v
[RAPPORT] ───────────────────> DOCX + HTML + JSON + SARIF + MD + terminal summary
```

### 3.6 Gestion des sessions HTTP (`core/session.py` + `core/cache.py`)

```python
class BazookaSession:
    """
    Session HTTP intelligente avec :
    - Retry automatique (429, 503, 500) avec backoff exponentiel + jitter
    - Rotation User-Agent (pool de 20 UA reels)
    - Support proxy SOCKS5 (Tor) et HTTP
    - Throttling configurable (req/sec) avec pools separes par categorie :
        - DNS : 50 concurrent (fast)
        - HTTP target : configurable (defaut 10 req/s)
        - HTTP infra : configurable (defaut 5 req/s)
    - Timeout adaptatif (court pour recon, long pour brute-force)
    - Logging de chaque requete pour evidence trail
    - Detection WAF automatique (ajuste la strategie)
    - DNS over HTTPS optionnel (--dns-doh) pour discretion
    """

class ResponseCache:
    """
    Cache HTTP transparent avec :
    - Deduplication : si 3 modules requetent /wp-json/wp/v2/users, 1 seule requete
    - TTL par type : recon = 24h, enum = 1h, vuln = pas de cache
    - Respect ETag/Last-Modified
    - Invalidation manuelle possible
    - Stockage SQLite (core/database.py)
    """
```

### 3.7 Gestion des signaux (`core/signals.py`)

| Signal | 1er appel | 2eme appel (< 3s) |
|--------|-----------|-------------------|
| SIGINT (Ctrl+C) | Termine la phase en cours, sauvegarde etat, affiche resume partiel | Arret immediat avec sauvegarde d'urgence |
| SIGTERM | Idem 1er SIGINT | Arret immediat |

### 3.8 Scope Enforcer (`core/scope.py`)

```yaml
# config/scope.yaml — OBLIGATOIRE pour --pentest
scope:
  authorization_ref: "CONTRAT-2026-042"   # Numero de contrat/lettre de mission
  pentester: "AYI NEDJIMI CONSULTANTS"
  client: "CYRIAS SAS"
  date_start: "2026-03-01"
  date_end: "2026-03-31"
  allowed_domains:
    - "cyrias.com"
    - "*.cyrias.com"
    - "comdhappy.bzh"
  allowed_ips:
    - "87.98.154.146"
    - "193.22.225.0/24"
  exclude:
    - "payment.cyrias.com"
  allow_private_ips: false
  respect_robots_txt: false    # En pentest, on ignore robots.txt
  max_depth: 5
```

Chaque requete HTTP passe par le scope enforcer **avant** d'etre envoyee. Si la cible est hors scope, la requete est bloquee et un warning est emis.

---

## 4. Modules fonctionnels

### 4.1 MODULE RECON - Reconnaissance passive et active

#### 4.1.1 DNS Enumeration (`dns_enum.py`)

| Test | Methode | Output |
|------|---------|--------|
| Records A, AAAA, MX, NS, TXT, SOA, CNAME | `dns.resolver` (dnspython) | JSON structured records |
| Zone transfer (AXFR) | `dns.query.xfr` | Full zone si autorise |
| SPF record parse | TXT record analysis | Mecanismes, includes, policy (~all vs -all) |
| DMARC record parse | `_dmarc.{domain}` TXT | Policy (none/quarantine/reject), rua, ruf |
| DKIM selector brute | Common selectors (default, google, k1, s1, etc.) | DKIM keys trouvees |
| CAA records | DNS CAA query | CAs autorisees (iodef, issue, issuewild) |
| DNSSEC validation | DS + DNSKEY records | Signe ou non, algorithme, zone walking possible si mal configure |
| DNS over HTTPS | Cloudflare/Google DoH (si --dns-doh) | Requetes invisibles pour l'ISP |

**Scoring automatique :**
- SPF `~all` (soft fail) = MEDIUM
- SPF absent = CRITICAL
- DMARC `p=none` = HIGH
- DMARC absent = CRITICAL
- DNSSEC absent = LOW
- CAA absent = LOW

#### 4.1.2 WHOIS & Registrar (`whois_lookup.py`)

| Test | Output |
|------|--------|
| WHOIS domaine | Registrar, dates creation/expiration, nameservers |
| WHOIS IP | ASN, netblock, organisation, pays |
| Reverse DNS (PTR) | Hostname d'hebergement (ex: cluster026.hosting.ovh.net) |

#### 4.1.3 Certificate Transparency (`ct_logs.py`)

| Test | Methode | Output |
|------|---------|--------|
| CT log search | crt.sh API (`?q=%.{domain}&output=json`) | Tous les certificats emis |
| Extraction sous-domaines | Parse CN + SAN de chaque cert | Liste unique de sous-domaines |
| Detection wildcard | Analyse des patterns | Wildcards identifies |
| Historique certificats | Dates d'emission | Timeline des changements d'infra |

#### 4.1.4 Decouverte de sous-domaines (`subdomain_enum.py`)

| Source | Methode |
|--------|---------|
| Certificate Transparency | crt.sh (cf. 4.1.3) |
| DNS brute-force | Wordlist (dev, staging, admin, mail, vpn, etc.) |
| DNS zone walking | NSEC/NSEC3 si DNSSEC mal configure (mode aggressive) |
| Scraping moteurs | Google dorks (`site:*.target.com`) |
| SecurityTrails / VirusTotal | API si cle configuree |
| Validation | Resolution DNS + HTTP probe sur chaque sous-domaine |

#### 4.1.5 CDN Detection & Origin Finder (`cdn_detect.py` + `origin_finder.py`)

| Test | Methode | Raison |
|------|---------|--------|
| Detection CDN | Headers (cf-ray, x-cache, x-cdn), ASN, CNAME | Savoir si on teste le CDN ou le vrai serveur |
| Origin IP discovery | DNS historique (SecurityTrails), headers leak, SPF includes, MX records | Bypass WAF/CDN pour atteindre le serveur reel |
| Origin validation | `curl -H "Host: target.com" http://{origin_ip}` | Confirmer que l'origin repond |
| CDN bypass test | Requetes directes sur origin IP | Tester si le WAF est contourne |
| IPv6 bypass | Tester si l'IPv6 pointe directement sur l'origin | CDN souvent configure uniquement en IPv4 |
| Header spoofing | X-Forwarded-For, X-Real-IP, CF-Connecting-IP | Certains backends font confiance a ces headers |

**Critique** : Sur CYRIAS, l'origin `87.98.154.146` servait le site complet en bypassant le CDN OVH et SecuPress.

#### 4.1.6 WAF Detection (`waf_detect.py`)

| Test | Methode |
|------|---------|
| Fingerprint WAF (30+ signatures) | Headers, codes erreur, pages custom |
| Test bypass payloads | XSS/SQLi benignes pour voir la reponse WAF |
| SecuPress specifique | Detection `.htpasswd` obfusque, custom login slug, 403 patterns |
| Wordfence specifique | `/wp-content/plugins/wordfence/`, rate-limit patterns |
| Detection ModSecurity | Headers `Server`, error page patterns |

**Signatures YAML externalisees** (`signatures/waf.yaml`) pour les WAF suivants :
SecuPress, Wordfence, Sucuri, Cloudflare, AWS WAF, Azure Front Door, Akamai, Imperva, FortiWeb, ModSecurity, OVH WAF, BunkerWeb, iThemes/Solid Security, MalCare, All In One Security.

#### 4.1.7 Analyse des headers HTTP (`headers_analysis.py`)

| Header | Check | Severite si absent/mauvais |
|--------|-------|---------------------------|
| Strict-Transport-Security | Presence, max-age >= 31536000, includeSubDomains | HIGH |
| Content-Security-Policy | Presence, pas de unsafe-inline/unsafe-eval | MEDIUM |
| X-Frame-Options | DENY ou SAMEORIGIN | MEDIUM |
| X-Content-Type-Options | nosniff | LOW |
| X-XSS-Protection | 1; mode=block (legacy) | LOW |
| Referrer-Policy | strict-origin-when-cross-origin | LOW |
| Permissions-Policy | Presence | LOW |
| Server | Version exposee (Apache/2.4.54) | MEDIUM |
| X-Powered-By | PHP version exposee | MEDIUM |
| Set-Cookie | HttpOnly, Secure, SameSite sur `wordpress_logged_in_*` | HIGH si absent |

#### 4.1.8 Technology Stack Detection (`technology_stack.py`) — NOUVEAU

| Donnee | Source |
|--------|--------|
| Serveur web (Apache, Nginx, LiteSpeed) | Header `Server` |
| Version PHP | `X-Powered-By`, erreurs 500, `/phpinfo.php` |
| Version MySQL/MariaDB | Erreurs SQL dans debug.log, pages d'erreur |
| OS serveur | Headers, TTL analysis, nmap OS detection |
| Panel hebergement | Patterns ISPConfig, cPanel, Plesk dans les paths |
| CDN provider | Headers specifiques, CNAME |

Mapper les versions aux CVEs connues (ex: Apache 2.4.49 → RCE path traversal).

#### 4.1.9 SSL/TLS Audit (`ssl_scan.py`)

| Test | Methode |
|------|---------|
| Protocoles supportes | TLS 1.0, 1.1, 1.2, 1.3 |
| Cipher suites | Faibles (RC4, DES, 3DES, export), preference serveur |
| Certificat | Validite, CN match, SAN, emetteur, date expiration |
| OCSP stapling | Presence |
| Heartbleed / POODLE / ROBOT | Tests specifiques |
| Certificate mismatch | CN ≠ domaine demande |

#### 4.1.10 Port Scan (`port_scan.py`)

| Test | Methode | Scope |
|------|---------|-------|
| Top 100 TCP | TCP connect scan (Python natif) | Cible principale |
| Full TCP (--full) | 1-65535 via TCP connect ou `python-nmap` si disponible | Sur demande |
| UDP top 20 | UDP probe (si nmap disponible) | Cible principale |
| Service detection | Banner grab sur ports ouverts | Automatique |

**Note** : Le SYN scan necessite `python-nmap` (dependance optionnelle). Le fallback TCP connect fonctionne sans aucune dependance systeme, conformement a l'objectif O4.

#### 4.1.11 OSINT Emails & Breaches (`osint_emails.py` + `breach_check.py`)

| Test | Source | Output |
|------|--------|--------|
| Gravatar hash reversal | SHA256 de l'email, lookup gravatar.com | Confirmation email + avatar |
| HIBP breach check | API haveibeenpwned.com/v3 | Nombre de fuites, noms, dates, types de donnees |
| HIBP Pwned Passwords | SHA1 k-anonymity API | Frequence du password dans les fuites |
| LeakCheck (optionnel) | API leakcheck.io | Details des fuites (nom, ville, DOB) |
| theHarvester integration | Email harvesting multi-source | Emails supplementaires |
| GitHub dorking | `"{domain}" password OR secret OR key` | Code expose |

**RGPD** : Les resultats HIBP/LeakCheck contiennent des donnees personnelles. Voir section 9.3 pour le traitement.

---

### 4.2 MODULE ENUM - Enumeration WordPress

#### 4.2.0 Phase Bootstrap : detection wp-content et calibration (`wp_content_detect.py`) — NOUVEAU

**Avant toute enumeration**, detecter le repertoire de contenu reel :

| Methode | Description |
|---------|-------------|
| HTML source | Liens CSS/JS vers `/wp-content/` ou chemin custom |
| readme.html | Presence confirme WP |
| REST API | `/wp-json/` response |
| Sitemap | Chemins dans les sitemaps |

**Calibration 404** : Envoyer une requete vers un chemin garanti inexistant (`/wp-content/plugins/zzz_nonexistent_12345/`) et comparer avec la reponse de reference. Un 403 different du 404 de reference = le repertoire **existe**.

Toutes les requetes subsequentes utilisent le `wp_content_path` dynamique.

#### 4.2.1 WordPress Core (`wp_version.py`)

| Methode de detection | Chemin / Pattern |
|---------------------|-----------------|
| Meta generator | `<meta name="generator" content="WordPress X.Y.Z">` |
| readme.html | `/readme.html` version string |
| RSS feed | `?v=X.Y.Z` dans les feeds |
| wp-links-opml.php | Version dans le header |
| REST API | `/wp-json/` → `namespaces`, `authentication` |
| CSS/JS versions | `?ver=X.Y.Z` dans les assets |
| install.php | `/wp-admin/install.php` (si pas installe) |
| upgrade.php | `/wp-admin/upgrade.php` response code |

#### 4.2.2 Enumeration des utilisateurs (`wp_users.py`)

| Methode | Chemin | Bypass potentiel |
|---------|--------|-----------------|
| REST API v2 | `/wp-json/wp/v2/users` | Standard, souvent accessible |
| REST API embed | `/wp-json/wp/v2/users?context=embed` | Moins de champs mais passe parfois |
| REST API _fields | `/wp-json/wp/v2/users?_fields=id,slug,email` | Leak de champs normalement filtres |
| Author archives | `/?author=1`, `/?author=2`, ... (1-20) | **Redirect 302 = info disclosure** |
| Author sitemap | `/wp-sitemap-users-1.xml` | Yoast/WP native sitemap |
| oEmbed | `/wp-json/oembed/1.0/embed?url={post_url}` | Expose l'auteur |
| RSS feed | Champ `<dc:creator>` | Toujours le slug auteur |
| Commentaires | Noms dans les commentaires publics | Si commentaires ouverts |
| Gravatar reverse | SHA256 hash → email | 3 emails trouves sur CYRIAS |
| Login error messages | `wp-login.php` avec username test | "Invalid username" vs "incorrect password" |
| BuddyPress/BuddyBoss | Profils publics, `/members/` | Souvent plus riche que l'API standard |

**Pour chaque user trouve :**
- ID, username, display_name, slug, avatar_url
- Extraction hash Gravatar → tentative reverse email
- Role si expose (via REST API context)
- `disclosure_method` : comment le user a ete trouve (pour le rapport)

#### 4.2.3 Enumeration des plugins (`wp_plugins.py`)

| Methode | Description |
|---------|-------------|
| Passive (HTML parse) | Scripts/CSS dans le HTML source (`{wp_content}/plugins/{slug}/`) |
| REST API namespaces | Chaque plugin REST expose un namespace (ex: `contact-form-7/v1`) |
| Shortcode parsing | Analyse des pages/posts pour `[contact-form-7]`, `[wpforms]`, etc. |
| Fichiers connus | `readme.txt`, `changelog.txt`, `style.css` de chaque plugin |
| Error pages (calibre) | `{wp_content}/plugins/{slug}/` → comparer avec 404 de reference |
| Wordlist brute | Top 1500 plugins WordPress (slug brute-force) |
| Source maps | `*.js.map` dans les assets charges |
| wp-cron analysis | Hooks cron enregistres (via REST si accessible) |

**Plugins a toujours tester specifiquement** (CVEs frequentes 2024-2026) :
Elementor, WPBakery, ACF, Duplicator, Wordfence, AIOS, Really Simple SSL, W3 Total Cache, WP Super Cache, Rank Math, Yoast, WPML, Contact Form 7, WooCommerce, Jetpack, WP File Manager, UpdraftPlus, Ninja Forms, WPForms, Gravity Forms, King Addons, Bricks Builder.

**Pour chaque plugin trouve :**
- Slug, version (readme.txt `Stable tag:` ou `Version:`)
- Lookup CVE dans la base SQLite (multi-sources)
- Flag si version vulnerable connue
- CVSS score de la CVE la plus critique

#### 4.2.4 Enumeration des themes (`wp_themes.py`)

| Methode | Description |
|---------|-------------|
| HTML source | Liens vers `{wp_content}/themes/{slug}/style.css` |
| style.css parse | `Theme Name:`, `Version:`, `Author:`, `Template:` (parent) |
| REST API | `/wp-json/wp/v2/themes` (si accessible) |
| Wordlist brute | Top 500 themes WordPress |

#### 4.2.5 WordPress Multisite Detection (`wp_multisite.py`) — NOUVEAU

| Test | Methode |
|------|---------|
| `/wp-signup.php` | HTTP 200 = Multisite avec inscription ouverte |
| REST API response | `is_multisite` dans certaines configs |
| Sous-sites enumeration | Via sitemaps, REST API, links dans le HTML |
| Network admin | `/wp-admin/network/` (401 attendu, 200 = exposed) |
| Domain mapping | Tester si d'autres domaines pointent vers la meme IP |

#### 4.2.6 REST API Deep Enumeration (`rest_api.py`)

| Endpoint | Donnees collectees |
|----------|--------------------|
| `/wp-json/` | Toutes les routes, namespaces, authentication methods |
| `/wp-json/wp/v2/posts` | Articles publics (titre, contenu, auteur, date) |
| `/wp-json/wp/v2/pages` | Pages publiques (contenu complet) |
| `/wp-json/wp/v2/media` | Fichiers media (URLs, metadata, MIME type) → flag PDFs |
| `/wp-json/wp/v2/categories` | Taxonomies |
| `/wp-json/wp/v2/tags` | Tags |
| `/wp-json/wp/v2/comments` | Commentaires (noms, emails si exposes) |
| `/wp-json/wp/v2/users` | Utilisateurs (cf. 4.2.2) |
| `/wp-json/wp/v2/types` | Post types enregistres (custom post types) |
| `/wp-json/wp/v2/statuses` | Statuts de publication |
| `/wp-json/wp/v2/taxonomies` | Toutes les taxonomies |
| `/wp-json/wp/v2/search` | Recherche full-text |
| `/wp-json/wp/v2/settings` | Parametres (401 attendu, noter si 200) |
| `/wp-json/wp/v2/posts?status=draft` | Brouillons (401 attendu, noter si 200 = **CRITICAL**) |
| `/wp-json/wp/v2/posts?status=private` | Articles prives (idem) |
| `/wp-json/wp/v2/block-renderer/` | Gutenberg block renderer (SSRF/RCE potentiel) |

**Specifique plugins :**

| Plugin | Endpoint | Criticite |
|--------|----------|-----------|
| Contact Form 7 | `/wp-json/contact-form-7/v1/contact-forms` | HIGH |
| WooCommerce | `/wc/v3/products`, `/wc/v3/orders`, `/wc/v3/customers` | CRITICAL |
| WooCommerce Store | `/wc/store/v1/products`, `/wc/store/v1/cart` | HIGH |
| Jetpack | `/jetpack/v4/connection/status` | MEDIUM |
| Yoast SEO | `?rest_route=/yoast/v1/` | LOW |
| WPML | `/wpml/v1/languages` | LOW |
| Kleo/BuddyPress | `/kleo/v1/`, search endpoint | MEDIUM |
| WPBakery | Frontend editor JS, shortcodes | MEDIUM |
| Elementor | `/elementor/v1/` | MEDIUM |
| ACF | `/acf/v3/` | MEDIUM |
| Dokan | `/dokan/v1/stores`, `/dokan/v1/orders` | HIGH (marketplace IDOR) |

**Pagination automatique** : suivre les headers `X-WP-Total` et `X-WP-TotalPages`.

**Detection automatique de plugins via namespaces** : parser la liste des namespaces dans `/wp-json/` et mapper vers les plugins connus.

#### 4.2.7 GraphQL Introspection (`graphql_enum.py`) — NOUVEAU

| Test | Methode |
|------|---------|
| Detection | `POST /graphql` avec `{ __schema { types { name } } }` |
| Introspection complete | Telecharger le schema complet (types, queries, mutations) |
| Field suggestions | Exploiter les erreurs "Did you mean...?" pour enumerer |
| Auth bypass | Tester si des mutations (createUser, updatePost) sont accessibles sans auth |
| Comparaison REST | Le schema GraphQL est souvent plus riche que l'API REST |

#### 4.2.8 XML-RPC Analysis (`xmlrpc_methods.py`)

| Test | Payload |
|------|---------|
| Detection | `POST /xmlrpc.php` avec `system.listMethods` |
| Methodes dangereuses | `system.multicall`, `wp.getUsersBlogs`, `wp.uploadFile`, `pingback.ping` |
| Nombre de methodes | Compter les methodes exposees (80 = mauvais signe) |
| Multicall amplification | Test avec 1 multicall de 2 appels → mesurer si amplifie |

#### 4.2.9 Fichiers sensibles et backups (`debug_log.py` + `backup_finder.py` + `directory_listing.py`)

| Chemin | Ce qu'on cherche | Criticite si trouve |
|--------|-----------------|---------------------|
| `{wp_content}/debug.log` | Errors PHP, paths serveur, DB names, credentials | HIGH-CRITICAL |
| `{wp_content}/uploads/` | Directory listing (Apache) | HIGH |
| `{wp_content}/updraft/` | Repertoire UpdraftPlus backups | CRITICAL |
| `{wp_content}/ai1wm-backups/` | All-in-One WP Migration | CRITICAL |
| `{wp_content}/backups-dup-lite/` | Duplicator | CRITICAL |
| `{wp_content}/backup-db/` | WP-DB-Backup | CRITICAL |
| `{wp_content}/mu-plugins/` | Must-use plugins (backdoors) | HIGH |
| `{wp_content}/object-cache.php` | Redis/Memcached expose | HIGH |
| `/.git/HEAD` | Repo Git expose | CRITICAL |
| `/.git/config` | Config Git (remote, credentials) | CRITICAL |
| `/.env` | Variables d'environnement (DB pass, API keys) | CRITICAL |
| `/.wp-env.json` | Config de dev avec credentials | CRITICAL |
| `/.htpasswd` | Hashes Apache htpasswd | HIGH |
| `/wp-config.php~` | Backup editeur | CRITICAL |
| `/wp-config.php.bak` | Backup manuel | CRITICAL |
| `/wp-config.php.old` | Backup ancien | CRITICAL |
| `/wp-config.php.save` | Backup nano/vim | CRITICAL |
| `/wp-config.php.swp` | Swap vim | CRITICAL |
| `/wp-config.php.txt` | Renomme en texte | CRITICAL |
| `/wp-config-sample.php` | Template (info version) | LOW |
| `/phpinfo.php` | Info PHP completes | HIGH |
| `{wp_content}/uploads/phpinfo.php` | phpinfo uploade puis oublie | HIGH |
| `/phpmyadmin/` | Panel phpMyAdmin | CRITICAL |
| `/adminer.php` | Adminer DB manager | CRITICAL |
| `/readme.html` | Version WP | LOW |
| `/license.txt` | Confirme WP | LOW |
| `/xmlrpc.php` | XML-RPC actif | MEDIUM |
| `/wp-cron.php` | Cron public | LOW |
| `/wp-admin/install.php` | Installation non finalisee | CRITICAL |

**Pour debug.log** : telecharger en streaming (chunked, limite par `--max-download-size` defaut 10 MB) et rechercher :
- `user_pass`, `$P$` (phpass hashes), `password`, `passwd`
- `SMTP`, `auth_cookie`, `secret_key`, `DB_PASSWORD`, `DB_USER`, `DB_HOST`
- Cles AWS (`AKIA`), GCP (`AIza`), JWT (`eyJ`), tokens API
- Paths serveur (`/var/www/`, `/home/`)
- Noms de DB, prefixes de tables
- Noms d'utilisateurs DB

#### 4.2.10 wp-config.php Constants Audit (`wp_config_audit.py`) — NOUVEAU

Si wp-config.php fuite (via debug.log, .git dump, backup), analyser :

| Constante | Check | Severite |
|-----------|-------|----------|
| `DISALLOW_FILE_EDIT` | false ou absent | HIGH |
| `DISALLOW_UNFILTERED_HTML` | absent | MEDIUM |
| `WP_DEBUG` | true en production | HIGH |
| `WP_DEBUG_LOG` | true en production | HIGH |
| `WP_DEBUG_DISPLAY` | true en production | MEDIUM |
| `WP_AUTO_UPDATE_CORE` | false | MEDIUM |
| `AUTH_KEY`, `SECURE_AUTH_KEY`, etc. | Valeurs par defaut "put your unique phrase here" | CRITICAL |
| `DB_HOST` | Expose = information disclosure | MEDIUM |
| `$table_prefix` | `wp_` par defaut | LOW |

#### 4.2.11 Application Passwords (`application_passwords.py`) — NOUVEAU

| Test | Methode |
|------|---------|
| Detection feature | Tester `/wp-json/wp/v2/users/me/application-passwords` |
| Reponse 200 | Liste des app passwords = CRITICAL si non authentifie |
| Reponse 401 | Normal, feature activee mais protegee |
| Reponse 404 | Feature desactivee |

#### 4.2.12 Registration Check (`registration_check.py`) — NOUVEAU

| Test | Methode |
|------|---------|
| `/wp-login.php?action=register` | HTTP 200 = inscription ouverte |
| Role par defaut | Si inscription ouverte, quel role est assigne ? |
| `/wp-json/wp/v2/users` POST | Tester si la creation d'utilisateur est possible sans auth |

#### 4.2.13 Source Maps Detection (`source_maps.py`)

| Test | Methode |
|------|---------|
| Headers | `SourceMap:` ou `X-SourceMap:` |
| Commentaires JS | `//# sourceMappingURL=` en fin de fichier |
| Brute-force | `{script}.js.map` pour chaque JS charge |
| Analyse | Parser le .map → extraire les fichiers sources originaux |

---

### 4.3 MODULE VULN - Detection de vulnerabilites

#### 4.3.1 CVE Matcher (`cve_matcher.py`)

Pour chaque plugin/theme/core avec version identifiee :
1. Lookup dans la base CVE SQLite (mise a jour via `bazooka update-db`)
2. Sources : **Wordfence Intelligence** (API publique), **PatchStack**, WPVulnDB, NVD
3. Retourner : CVE ID, CVSS score, type, version affectee, PoC reference, date publication
4. Flag "non patche" si aucune version fixee n'existe

**La base est versionnee** : chaque scan enregistre la version de la base CVE utilisee dans `scan_meta.json`.

**Mise a jour** : `bazooka update-db` fetche depuis toutes les sources configurees, merge dans SQLite, et affiche les nouvelles CVEs ajoutees.

#### 4.3.2 CORS Misconfiguration (`cors_check.py`)

| Test | Payload |
|------|---------|
| Origin reflection | Envoyer `Origin: https://evil.com` → verifier si reflete |
| Null origin | `Origin: null` → verifier si accepte |
| Credentials | Verifier `Access-Control-Allow-Credentials: true` |
| Methods | Lister `Access-Control-Allow-Methods` |
| Headers | Lister `Access-Control-Allow-Headers` (X-WP-Nonce ?) |
| Pre-flight | Envoyer OPTIONS avec origin malveillant |
| Sous-domaine | `Origin: https://evil.target.com` → verifier |
| HTTP downgrade | `Origin: http://target.com` (pas HTTPS) → verifier |

**Scoring :**
- Origin reflete + Credentials: true = **CRITICAL**
- Origin reflete sans Credentials = HIGH
- Null origin accepte = HIGH
- Origins specifiques mais larges = MEDIUM

#### 4.3.3 SSRF via XML-RPC Pingback (`ssrf_xmlrpc.py`)

| Test | Payload |
|------|---------|
| SSRF basique | `pingback.ping` avec URL interne `http://127.0.0.1` |
| Protocol handlers | `file://`, `gopher://`, `dict://`, `ftp://` |
| Port scan interne | SSRF vers `http://127.0.0.1:{port}` (top 20 ports) |
| Cross-network | SSRF vers IPs du meme /24 |
| Cloud metadata | `http://169.254.169.254/latest/meta-data/` (AWS/GCP/Azure) |
| Timing analysis | Mesurer delta temps pour determiner ports ouverts/fermes |

#### 4.3.4 SQL Injection (`sqli_scanner.py`)

| Vecteur | Parametres testes |
|---------|-------------------|
| Search | `/?s={payload}` |
| Admin AJAX | `/wp-admin/admin-ajax.php?action={action}&{param}={payload}` |
| REST API filters | `/wp-json/wp/v2/posts?filter[{param}]={payload}` |
| WooCommerce | `/wp-json/wc/v3/products?search={payload}` |

**Payloads (20 payloads par vecteur)** :
- Error-based : `'`, `"`, `' OR 1=1--`, `" OR ""="`, `1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--`
- Time-based blind : `' OR SLEEP(3)--`, `1' AND BENCHMARK(5000000,MD5('test'))--`
- UNION-based : `' UNION SELECT 1,2,3--`, `' UNION SELECT NULL,@@version,NULL--`
- Adaptes MySQL/MariaDB (types de quotes, commentaires `--`, `#`, `/* */`)

**Detection** : pattern matching sur les reponses (erreurs MySQL/MariaDB), timing delta > 2s pour blind.
**Faux positifs connus** : certains WAF retournent 500 sur les quotes simples (pas une SQLi).

#### 4.3.5 XSS Scanner (`xss_scanner.py`) — SPECIFIE

| Vecteur | Methode |
|---------|---------|
| Reflected XSS search | `/?s=<script>alert(1)</script>` et variantes |
| Reflected XSS params | Test sur chaque parametre GET/POST detecte dans l'enum |
| Stored XSS commentaires | Si commentaires ouverts, soumettre payload et verifier reflexion |
| DOM XSS | Analyse statique des JS charges (sources → sinks) |

**Payloads (15 payloads)** :
- `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`, `<svg onload=alert(1)>`
- Event handlers : `" onfocus="alert(1)" autofocus="`, `' onmouseover='alert(1)'`
- Encodages : `%3Cscript%3E`, `&#x3C;script&#x3E;`, `javascript:alert(1)`
- Bypass WAF : `<scr<script>ipt>`, `<SCRIPT>`, polyglots

**Detection** : verifier si le payload apparait non-encode dans la reponse HTML. Parser le DOM (BeautifulSoup) pour confirmer l'execution potentielle.

**Faux positifs** : un payload reflete dans un attribut `value=""` entre quotes n'est pas exploitable sans echappement.

#### 4.3.6 LFI Scanner (`lfi_scanner.py`) — SPECIFIE

| Vecteur | Payloads |
|---------|----------|
| Plugins avec parametre file/path | `?file=../../../etc/passwd`, `?file=....//....//etc/passwd` |
| Themes Kleo (CVE connues) | `?template=../../../wp-config.php` |
| PHP wrappers | `php://filter/convert.base64-encode/resource=wp-config.php` |
| Null byte (legacy) | `../../../etc/passwd%00` (PHP < 5.3) |
| Double encoding | `..%252f..%252f..%252fetc/passwd` |

**Detection** : presence de `root:x:0:0` (passwd), `DB_PASSWORD` (wp-config), ou contenu base64 decodable.

**Scope** : tester uniquement sur les plugins detectes avec parametres de fichier connus. Pas de brute-force de parametres.

#### 4.3.7 RCE Check (`rce_check.py`) — SPECIFIE

| Vecteur | Methode |
|---------|---------|
| CVEs RCE connues | Pour chaque plugin CVE type RCE, envoyer le PoC safe (callback DNS/HTTP) |
| PHP deserialization | Tester `phar://` via upload si file upload detecte |
| SSTI (Twig/WPML) | `{{7*7}}` dans les champs texte → verifier si `49` apparait |
| Command injection | `; id` et `` `id` `` dans les parametres suspects |
| wp-file-manager connector | `POST /wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php` |

**Mode safe** : les PoC ne deploient jamais de webshell. Utiliser un callback OOB (Burp Collaborator, interact.sh, ou un serveur DNS propre) pour confirmer l'execution.

#### 4.3.8 IDOR Check (`idor_check.py`) — SPECIFIE

| Vecteur | Methode |
|---------|---------|
| WooCommerce orders | `/wp-json/wc/v3/orders/{id}` pour id=1-100 |
| WooCommerce customers | `/wp-json/wc/v3/customers/{id}` |
| Dokan stores/orders | `/wp-json/dokan/v1/stores/{id}`, `/dokan/v1/orders/{id}` |
| User profile access | `/wp-json/wp/v2/users/{id}?context=edit` |
| Media access | `/wp-json/wp/v2/media/{id}` pour medias non-publics |

**Detection** : HTTP 200 avec contenu ≠ reponse par defaut = IDOR confirme. HTTP 401/403 = protege.

#### 4.3.9 CSRF Check (`csrf_check.py`) — SPECIFIE

| Test | Methode |
|------|---------|
| Nonce validation | Soumettre des actions admin-ajax sans `_wpnonce` → verifier si accepte |
| Nonce previsible | Analyser les nonces exposes dans le HTML (patterns, entropie) |
| Cookie SameSite | Verifier `SameSite=Lax` ou `Strict` sur les cookies de session |
| Formulaires publics | Verifier la presence de tokens CSRF sur les formulaires (CF7, WPForms, etc.) |

#### 4.3.10 Auth Bypass (`auth_bypass.py`) — SPECIFIE

| Test | Methode |
|------|---------|
| REST API sans auth | Tester `?context=edit` sur tous les endpoints (devrait retourner 401) |
| Plugin-specific | CVE-2024-56000 K Elements : `/wp-admin/admin-ajax.php?action=kleo_fb_initialise&email={email}` |
| Application Passwords | Tester si des endpoints authentifies acceptent des app passwords faibles |
| OAuth/OpenID | Si detecte, tester `/wp-json/openid-connect/` endpoints |
| JWT weakness | Si JWT Auth plugin, tester avec secret faible ou `alg: none` |

#### 4.3.11 File Upload Vulnerabilities (`file_upload.py`) — SPECIFIE

| Test | Methode |
|------|---------|
| SVG XXE | Upload SVG avec entity injection (`<!ENTITY xxe SYSTEM "file:///etc/passwd">`) |
| Phar deserialization | Upload `.phar` via formulaires media |
| Extension bypass | `.php.jpg`, `.phtml`, `.php5`, double extension |
| MIME type bypass | Content-Type spoof (`image/jpeg` pour un `.php`) |
| wp-file-manager | Connector elFinder (CVE-2020-25213) |

**Mode safe** : ne pas uploader de webshell. Utiliser un fichier PHP inoffensif (`<?php echo "bazooka_test"; ?>`) ou un SVG avec callback DNS.

#### 4.3.12 Session & Authentication Audit (`session_auth.py`) — NOUVEAU

| Test | Methode |
|------|---------|
| Cookie flags | Verifier HttpOnly, Secure, SameSite sur `wordpress_logged_in_*` |
| Session expiration | Tester si les sessions expirent (via cookie `Max-Age` / `Expires`) |
| Session fixation | Tester si un cookie fixe est accepte apres login |
| Password policy | Tester si des mots de passe faibles sont acceptes (si registration ouverte) |
| Password reset token | Analyser l'entropie du token de reinitialisation |

#### 4.3.13 Host Header Injection (`host_header_injection.py`) — NOUVEAU

| Test | Methode |
|------|---------|
| Password reset poisoning | `POST /wp-login.php?action=lostpassword` avec `Host: evil.com` |
| X-Forwarded-Host | Envoyer `X-Forwarded-Host: evil.com` → verifier dans la reponse |
| Cache poisoning | Si CDN, tester si le Host header influence le contenu cache |

#### 4.3.14 Honeypot Detection (`honeypot_detect.py`) — NOUVEAU

| Heuristique | Description |
|-------------|-------------|
| Temps de reponse uniforme | Vrai WP varie (100-500ms), honeypot repond en ~200ms constant |
| Champs caches dans login | Formulaire avec champs invisibles = trap |
| Entropie des reponses | Vrai WP genere du contenu dynamique, honeypot = templates |
| Plugins impossibles | Combinaisons de plugins incompatibles |

**Si honeypot detecte** : alerte dans le rapport + arreter les tests intrusifs.

#### 4.3.15 Misconfiguration Check (`misconfig_check.py`) — NOUVEAU

Vulnerabilites non-CVE issues d'erreurs de configuration :

| Check | Condition | Severite |
|-------|-----------|----------|
| Plugin securite mal configure | Wordfence installe mais XML-RPC non bloque | HIGH |
| Cache plugin expose | `/wp-content/cache/` accessible | MEDIUM |
| Cron public exploitable | `/wp-cron.php` accessible → timing attack / DoS | LOW |
| wp-mail-smtp debug | Logs SMTP dans debug.log | HIGH |
| Elementor debug data | Data-attributes avec infos sensibles dans le HTML | MEDIUM |

**Classification** : les findings de type `misconfiguration` sont separes des CVE dans le rapport.

#### 4.3.16 Rate Limiting Check (`rate_limit.py`)

| Endpoint | Test |
|----------|------|
| `/wp-login.php` | 20 tentatives rapides → compte les 429/403/bannissements |
| `/xmlrpc.php` | 10 multicalls → mesurer throttling |
| `/wp-json/` | 50 requetes/sec → mesurer degradation |
| Custom login (SecuPress) | Detecter et tester le slug custom |

**Output** : requetes/sec toleres, presence de ban IP, duree du ban, type de protection.

#### 4.3.17 mod_rewrite CVE-2024-38474 (`mod_rewrite_cve.py`)

| Test | Payload |
|------|---------|
| Path confusion | `/wp-config.php%3f` → detecter 302 redirect |
| .htpasswd access | `/.htpasswd%3f` |
| .env access | `/.env%3f` |
| Double encode | `%253f` variantes |
| Discovery | Analyser la destination du redirect (nouveau domaine ?) |

#### 4.3.18 Security Headers Check (`security_headers.py`)

Cf. section 4.1.7 pour la liste des headers. Ce module produit un finding par header manquant/mal configure.

#### 4.3.19 SSL/TLS Vulnerabilities (`ssl_tls_audit.py`)

Cf. section 4.1.9. Ce module produit des findings pour : TLS 1.0/1.1 actif, ciphers faibles, certificat expire, Heartbleed, POODLE.

---

### 4.4 MODULE EXPLOIT - Exploitation (mode --pentest uniquement)

> **IMPORTANT** : Ce module est desactive par defaut. Il requiert le flag `--pentest`, un `--scope-file`, et une confirmation. Chaque action est loggee avec timestamp, methode, cible et resultat.

> **--pentest-simulate** : Affiche les chaines qui seraient executees, le nombre de requetes estimees, et le temps estime — sans rien envoyer.

#### 4.4.1 Brute-force XML-RPC (`xmlrpc_bruteforce.py`)

| Feature | Detail |
|---------|--------|
| Amplification multicall | N passwords par requete (configurable, defaut: 100) |
| Users | Automatique (issus de l'enumeration) |
| Wordlists | Embarquee (10k) + CUPP-generated + breach-derived |
| Throttle | Configurable (defaut: 2 req/sec) |
| Detection WAF | Stop automatique si 403/429 persistant |
| Resume | Sauvegarde progression, reprise possible |
| Safe mode | `--safe-exploit` : tester seulement 5 credentials et extrapoler |

#### 4.4.2 Generateur de wordlists intelligent (`wordlist_generator.py`)

Basee sur les donnees OSINT collectees en phase 1 :

| Source | Mutations generees |
|--------|--------------------|
| Prenom + Nom | `alexia`, `tanguy`, `Alexia2020`, `alexia123`, `AlexiaTanguy!` |
| Nom de domaine | `cyrias`, `Cyrias2026`, `cyrias!`, `cyrias@2026` |
| Nom entreprise | `comdhappy`, `ComDHappy1`, `comdhappy!` |
| Ville / Pays | Issues OSINT (breach data: city, country) |
| Date de naissance | Issues OSINT (DOB → `ddmmyyyy`, `YYYY`, etc.) |
| Patterns annee | `{base}2024`, `{base}2025`, `{base}2026`, `{base}!` |
| L33t speak | `@lex1a`, `cyr1@s`, etc. |
| Keyboard walks | `azerty`, `qwerty`, et variantes |
| Top passwords | `Password1`, `Azerty123`, `Admin2026`, etc. |
| Patterns 2025-2026 | Mutations basees sur les patterns de fuites recentes |

#### 4.4.3 Brute-force phpMyAdmin (`pma_bruteforce.py`)

| Feature | Detail |
|---------|--------|
| Detection auto | Si phpMyAdmin decouvert en phase enum |
| Token CSRF | Extraction automatique du token depuis la page login |
| Users | `root` + DB user (issu de debug.log) + patterns ISPConfig |
| Session management | Gestion cookie `phpMyAdmin` + renouvellement session |

#### 4.4.4 SSRF Port Scanner interne (`ssrf_port_scan.py`)

| Feature | Detail |
|---------|--------|
| Declencheur | Si SSRF XML-RPC confirme en phase vuln |
| Cibles | Localhost + IPs du /24 (issues de recon) |
| Ports | Top 20 (22, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200, etc.) |
| Detection | Timing-based + error-based |
| Cloud metadata | AWS/GCP/Azure metadata endpoints |

#### 4.4.5 Origin Bypass Exploitation (`origin_bypass.py`)

| Feature | Detail |
|---------|--------|
| Declencheur | Si origin IP decouverte en phase recon |
| Tests | Toutes les requetes de phases 2-3 refaites via origin (bypass WAF) |
| PHPSESSID | Detection leak cookie de session |
| Host header | Injection de differents Host headers |

#### 4.4.6 Git Dumper (`git_dumper.py`)

| Feature | Detail |
|---------|--------|
| Declencheur | Si `/.git/HEAD` retourne 200 ou taille suspecte en 403 |
| Download | Reconstruction incrementale du repo (.git/objects, packs, refs) |
| Analyse | `git log`, `git diff`, recherche de secrets dans l'historique |
| Secrets | Regex pour DB_PASSWORD, AUTH_KEY, API keys, tokens, AWS AKIA, JWT |

#### 4.4.7 Authenticated Scan (`authenticated_scan.py`) — NOUVEAU

| Feature | Detail |
|---------|--------|
| Declencheur | Si une credential est trouvee (brute-force reussi) |
| Flag | `--reuse-session` pour continuer avec le cookie obtenu |
| Tests | Refaire TOUS les tests enum + vuln en mode authentifie |
| Findings supplementaires | REST API `?context=edit`, plugins admin, upload capabilities |
| Marquage rapport | "Tests authentifies realises avec credentials decouvertes" |

---

### 4.5 MODULE INFRA - Infrastructure adjacente

#### 4.5.1 Network Range Scan (`network_scan.py`)

| Feature | Detail |
|---------|--------|
| Scope | /24 du serveur cible (ou range custom, valide par scope.yaml) |
| Methode | TCP connect sur ports 80, 443, 8080, 8443 |
| Detection | Service fingerprint via banner + headers |

#### 4.5.2 SSL Certificate Enumeration (`ssl_cert_enum.py`)

Pour chaque IP du range avec port 443 ouvert :

| Donnee extraite | Utilite |
|-----------------|---------|
| CN (Common Name) | Decouverte de nouveaux domaines |
| SAN (Subject Alt Names) | Domaines supplementaires |
| Issuer | Type de certificat (Let's Encrypt, self-signed, etc.) |
| Dates validite | Certificat expire = service abandonne |

#### 4.5.3 Service Detection (`service_detect.py`)

Services identifies via `signatures/services.yaml` :
WordPress, Nextcloud, Vaultwarden/Bitwarden, phpMyAdmin, Wazo/Asterisk, BunkerWeb, Adminer, Grafana, Portainer, GitLab, Redmine, Matomo, Jenkins, SonarQube.

#### 4.5.4 Virtual Host Enumeration (`vhost_enum.py`)

| Methode | Detail |
|---------|--------|
| Brute-force Host header | Envoyer differents `Host:` sur une meme IP |
| Domaines connus | Tester tous les domaines trouves (CT, DNS) sur chaque IP |
| Wildcard detection | Comparer taille reponse default vs Host specifique |
| Status codes | 200 vs 301 vs 401 vs 403 = differents niveaux d'acces |

#### 4.5.5 Lateral Movement Map (`lateral_movement.py`) — SPECIFIE

| Analyse | Description |
|---------|-------------|
| Credential reuse | Memes emails/usernames sur plusieurs services |
| Shared infrastructure | Services sur meme IP/sous-reseau sans segmentation |
| Multi-tenant risks | ISPConfig/cPanel avec plusieurs clients sur un serveur |
| Cross-service SSRF | Si SSRF confirmee, pivoter vers services internes decouverts |

**Output** : graphe de relations entre les services decouverts + evaluation du risque de mouvement lateral.

---

## 5. Moteur de scoring et reporting

### 5.1 Scoring CVSS v3.1

Utiliser la bibliotheque Python `cvss` (pip) pour le calcul. Ne pas reimplementer.

Chaque finding recoit :
- **Base Score** : calcule via le vecteur CVSS standard
- **Temporal Score** : ajuste selon la maturite de l'exploit et la disponibilite du patch
- **Environmental Score** : ajuste selon le contexte client (si fourni)

| Metrique temporelle | Valeurs |
|---------------------|---------|
| Exploit Code Maturity (E) | Not Defined / Unproven / PoC / Functional / High |
| Remediation Level (RL) | Not Defined / Official Fix / Temporary Fix / Workaround / Unavailable |
| Report Confidence (RC) | Not Defined / Unknown / Reasonable / Confirmed |

### 5.2 Score de risque global (modele hybride)

```
Score de gravite maximale = max(CVSS individuels) * facteur_exposition * facteur_chainabilite
Score de surface d'attaque = nombre_findings_ponderes / seuil_normalisation

Score Global = 0.7 * gravite_max + 0.3 * surface_attaque
```

| Facteur | Valeurs |
|---------|---------|
| facteur_exposition | Internet sans WAF = 1.0, avec WAF = 0.8, interne = 0.5 |
| facteur_chainabilite | Dynamique selon l'impact terminal de la chaine |
| facteur_exploitabilite | PoC publique simple = 1.3, necessite modifications = 1.0, pas de PoC = 0.7 |

**Chainabilite dynamique** : calculee par le chain engine — une chaine menant a un acces DB (`CHAIN-B`) a un facteur superieur a une chaine de brute-force (`CHAIN-A`).

### 5.3 Niveau de confiance par finding

| Niveau | Critere | Exemple |
|--------|---------|---------|
| `confirmed` | Reponse HTTP 200 avec contenu attendu | debug.log accessible avec contenu |
| `likely` | 403 avec taille suspecte ≠ 404 reference | .git/config retourne 403 de 4707 bytes |
| `possible` | Timing suspect, redirect, ou reponse ambigue | SSRF timing delta 0.3s |

Le rapport filtre par defaut les findings `possible` (affichables via `--show-all`).

### 5.4 Classification des severites

| Score CVSS | Severite | Couleur rapport |
|------------|----------|-----------------|
| 9.0 - 10.0 | CRITIQUE | Rouge fonce |
| 7.0 - 8.9 | HAUTE | Rouge |
| 4.0 - 6.9 | MOYENNE | Orange |
| 0.1 - 3.9 | BASSE | Jaune |
| 0.0 | INFO | Bleu |

### 5.5 Mapping de conformite

Chaque finding est automatiquement mappe vers :

| Referentiel | Exemple |
|-------------|---------|
| OWASP Top 10 (2021) | A01:2021 - Broken Access Control |
| CWE | CWE-346 (Origin Validation Error) |
| MITRE ATT&CK | T1189 - Drive-by Compromise |
| PCI-DSS v4 (si applicable) | 6.5.8 (Improper Access Control) |

### 5.6 Remediations automatiques

Chaque vulnerabilite inclut une remediation standard :

| Type de vuln | Remediation type |
|--------------|-----------------|
| Plugin CVE | "Mettre a jour {plugin} vers la version {fixed_version}" |
| REST API expose | "Ajouter `add_filter('rest_authentication_errors', ...)` ou restreindre" |
| debug.log expose | "Desactiver WP_DEBUG, supprimer le fichier, bloquer via .htaccess" |
| CORS wildcard | "Configurer des origines specifiques, ne jamais refleter l'origine" |
| SPF ~all | "Changer ~all en -all (hard fail)" |
| DMARC p=none | "Passer a p=quarantine puis p=reject apres monitoring" |
| XML-RPC expose | "Desactiver XML-RPC ou restreindre les methodes" |
| Directory listing | "Ajouter `Options -Indexes` dans .htaccess" |
| Headers manquants | Snippet .htaccess/nginx pour chaque header |
| Misconfiguration | Guide specifique (ex: constantes wp-config.php a ajouter) |

---

## 6. Interface utilisateur (CLI)

### 6.1 Commandes principales

```bash
# Audit standard (non-intrusif)
bazooka scan https://target.com

# Audit rapide (recon + enum seulement)
bazooka scan https://target.com --profile quick

# Pentest complet (avec exploitation, scope obligatoire)
bazooka scan https://target.com --pentest --scope-file scope.yaml

# Simuler un pentest sans rien envoyer
bazooka scan https://target.com --pentest --pentest-simulate

# Scan infrastructure adjacente
bazooka scan https://target.com --infra --range 193.22.225.0/24

# Scan via proxy Tor
bazooka scan https://target.com --proxy socks5://127.0.0.1:9050

# Scan avec origin bypass
bazooka scan https://target.com --origin 87.98.154.146

# Mode bug bounty (non-intrusif strict)
bazooka scan https://target.com --profile bugbounty

# Mode hors-ligne (base CVE locale uniquement)
bazooka scan https://target.com --offline

# Uniquement un module specifique
bazooka recon https://target.com
bazooka enum https://target.com
bazooka vuln https://target.com
bazooka exploit https://target.com --pentest --scope-file scope.yaml

# Mise a jour base CVE (multi-sources)
bazooka update-db

# Generer le rapport depuis un scan precedent
bazooka report ./loot/target.com/ --format docx --lang fr

# Reprendre un scan interrompu
bazooka resume ./loot/target.com/

# Comparer deux scans (avant/apres remediation)
bazooka compare ./loot/target.com/2026-03-01/ ./loot/target.com/2026-03-31/

# Verifier les prerequis et dependances
bazooka doctor

# Wizard interactif pour debutants
bazooka wizard

# Benchmark vs cible de test
bazooka benchmark --target https://test-wp.local/
```

### 6.2 Options globales

| Flag | Description | Defaut |
|------|-------------|--------|
| `--profile` | Profil d'audit (quick/standard/aggressive/bugbounty) | standard |
| `--pentest` | Active le module exploit | false |
| `--pentest-simulate` | Simule sans envoyer de requetes | false |
| `--scope-file` | Fichier scope YAML (obligatoire pour --pentest) | aucun |
| `--authorization-ref` | Reference autorisation (incluse dans le rapport) | aucun |
| `--confirm` | Mode confirmation (each/batch/none) | each |
| `--infra` | Active le scan infrastructure | false |
| `--range` | Plage IP pour le scan infra | /24 auto |
| `--proxy` | Proxy HTTP/SOCKS5 | aucun |
| `--origin` | IP origin (bypass CDN) | auto-detect |
| `--output` | Repertoire de sortie | `./loot/{target}/` |
| `--format` | Format rapport (docx/html/json/sarif/md/junit/all) | all |
| `--lang` | Langue du rapport (fr/en) | fr |
| `--threads` | Nombre de threads | 10 |
| `--rate-limit` | Requetes par seconde max | 10 |
| `--timeout` | Timeout HTTP en secondes | 10 |
| `--max-download-size` | Taille max telechargement (debug.log, etc.) | 10 MB |
| `--ua` | User-Agent custom | rotation auto |
| `--dns-doh` | Utiliser DNS over HTTPS | false |
| `--offline` | Pas d'APIs externes | false |
| `--encrypt-loot` | Chiffrer le dossier loot (age/GPG) | false |
| `--screenshots` | Capturer des screenshots (playwright) | false |
| `--reuse-session` | Tests authentifies si credential trouvee | false |
| `--safe-exploit` | Exploits en mode safe (5 tentatives max) | false |
| `--no-color` | Desactiver les couleurs terminal | false |
| `--verbose` / `-v` | Niveau de verbosity (1-3) | 1 |
| `--explain` | Afficher la logique de detection pour chaque finding | false |
| `--show-all` | Inclure les findings `possible` (basse confiance) | false |
| `--quiet` / `-q` | Seulement les findings critiques | false |
| `--dry-run` | Afficher les tests sans les executer | false |
| `--api-keys` | Fichier de cles API | `~/.bazooka/keys.yaml` |

**Stockage securise des cles API** : supporte les variables d'environnement (`BAZOOKA_HIBP_KEY`, etc.), le fichier YAML, et le `keyring` systeme.

### 6.3 Affichage terminal temps reel

```
 WORDPRESS BAZOOKA v1.0
 Target: https://cyrias.com | Scope: CONTRAT-2026-042
 Profile: standard | Threads: 10 | Rate: 10 req/s

 [BOOTSTRAP] wp-content: /wp-content/ | 404 calibrated | Scope OK

 [RECON] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% (16/16 checks)
   DNS: 12 records | WHOIS: OVHcloud | CDN: OVH CDN detected
   Origin: 87.98.154.146 (CONFIRMED)
   WAF: SecuPress Pro | Tech: Apache 2.4.54, PHP 8.1
   SPF: ~all (SOFT FAIL)  DMARC: p=quarantine
   Subdomains: 3 found | Emails: 3 found | Breaches: 8

 [ENUM] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% (22/22 checks)
   WP 6.7.0 | Theme: Kleo 5.1.2 | Plugins: 31 | Multisite: No
   Users: 5 | REST API: 222 routes | GraphQL: Not found
   XML-RPC: 80 methods (multicall ACTIVE)
   debug.log: NOT FOUND | Backups: updraft/ (403=exists)

 [VULN] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% (19/19 checks)

   CRITICAL [confirmed] CVE-2024-6386 WPML SSTI RCE (9.9) → A03:Injection
   CRITICAL [confirmed] CORS wildcard + credentials (9.1) → A01:Access Control
   CRITICAL [confirmed] DMARC p=none comdhappy.bzh (8.5) → A07:Auth Failures
   HIGH     [likely]    .git/ detected (403, 4707 bytes) → A05:Misconfiguration
   HIGH     [confirmed] Origin bypass, no WAF (8.2) → A05:Misconfiguration
   ...

 [CHAINS] 7 attack chains identified
   Chain A: User enum → breach → XML-RPC brute (impact: admin access)
   Chain B: Origin → .git → wp-config → DB (impact: full compromise)

 [SCORE] Global risk: 9.2/10 (gravite: 9.9, surface: 8.1)
   CRITICAL: 27 | HIGH: 45 | MEDIUM: 34 | LOW: 21 | INFO: 19

 [REPORT] Generated:
   ./loot/cyrias.com/RAPPORT_BAZOOKA.docx (fr)
   ./loot/cyrias.com/RAPPORT_BAZOOKA.html
   ./loot/cyrias.com/findings.json
   ./loot/cyrias.com/findings.sarif

 Completed in 3m 42s | 1,247 requests | CVE DB: 2026-03-31
```

---

## 7. Gestion du loot et preuves

### 7.1 Structure de sortie

```
loot/{target}/
|-- scan_meta.json              # Metadata (cf. 7.3)
|-- bazooka.db                  # SQLite : tous les findings, dedup, queries
|-- recon/
|   |-- dns_records.json
|   |-- whois.json
|   |-- ct_logs.json
|   |-- subdomains.json
|   |-- origin.json
|   |-- waf.json
|   |-- headers.json
|   |-- ssl.json
|   |-- ports.json
|   |-- spf_dmarc.json
|   |-- tech_stack.json
|   |-- osint_emails.json
|   |-- breaches.json
|-- enum/
|   |-- wp_version.json
|   |-- users.json
|   |-- plugins.json
|   |-- themes.json
|   |-- rest_api/
|   |-- graphql_schema.json
|   |-- xmlrpc_methods.json
|   |-- debug_log/
|   |-- backups.json
|   |-- directory_listings/
|   |-- source_maps/
|-- vuln/
|   |-- findings.json           # Tous les findings avec confiance + mapping
|   |-- cve_matches.json
|   |-- cors.json
|   |-- ...
|-- exploit/                    # Seulement en mode --pentest
|-- infra/                      # Seulement avec --infra
|-- evidence/
|   |-- screenshots/            # Si --screenshots
|   |-- http_log.jsonl          # Log HTTP (rotation a 100 MB)
|   |-- request_responses/      # Requetes/reponses brutes des findings
|-- chains.json
|-- scoring.json
|-- compliance.json             # Mapping OWASP/CWE/MITRE/PCI-DSS
|-- RAPPORT_BAZOOKA.docx
|-- RAPPORT_BAZOOKA.html
|-- findings.json
|-- findings.sarif
```

### 7.2 Format des findings

```json
{
  "id": "VULN-CORS-001",
  "title": "CORS Wildcard avec Credentials sur cyrias.com",
  "severity": "CRITICAL",
  "cvss_score": 9.1,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
  "cvss_temporal": "E:F/RL:U/RC:C",
  "confidence": "confirmed",
  "false_positive_potential": "low",
  "category": "Access Control",
  "type": "misconfiguration",
  "description": "Le serveur reflete n'importe quelle origine...",
  "evidence": {
    "request": "GET /wp-json/wp/v2/users HTTP/1.1\nHost: cyrias.com\nOrigin: https://evil.com",
    "response_headers": { "...": "..." },
    "screenshot": null,
    "file": "evidence/request_responses/cors_001.txt"
  },
  "impact": "Equivalent a un CSRF universel via CORS.",
  "remediation": "Configurer des origines specifiques...",
  "compliance": {
    "owasp_2021": "A01:2021 - Broken Access Control",
    "cwe": "CWE-346",
    "mitre_attack": "T1189 - Drive-by Compromise",
    "pci_dss_v4": "6.5.8"
  },
  "references": [
    "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"
  ],
  "chain_ids": ["CHAIN-A", "CHAIN-F"],
  "phase": "vuln",
  "module": "vuln.cors_check",
  "disclosure_method": "active_test",
  "timestamp": "2026-03-31T14:32:00Z"
}
```

### 7.3 Metadata du scan (`scan_meta.json`)

```json
{
  "bazooka_version": "1.0.0",
  "schema_version": "2.0",
  "cve_db_version": "2026-03-31",
  "target": "https://cyrias.com",
  "scope_file": "scope.yaml",
  "authorization_ref": "CONTRAT-2026-042",
  "profile": "standard",
  "start_time": "2026-03-31T14:28:00Z",
  "end_time": "2026-03-31T14:31:42Z",
  "total_requests": 1247,
  "modules_executed": 57,
  "modules_skipped": 7,
  "modules_failed": 0
}
```

**Migration** : `bazooka migrate-loot ./loot/` convertit les anciens resultats vers le nouveau schema.

### 7.4 Chiffrement du loot

Option `--encrypt-loot` :
- Chiffrement AES-256-GCM via `age` (ou GPG en fallback)
- Cle derivee du mot de passe utilisateur ou cle SSH agent
- Purge automatique optionnelle : `--auto-purge 7d` (suppression securisee apres N jours)
- Les fichiers sensibles (breaches.json, users.json, bruteforce_results.json) sont prioritairement chiffres

### 7.5 Gestion de la taille des logs HTTP

- `http_log.jsonl` : rotation automatique a 100 MB
- Flag `--no-http-log` pour desactiver
- Le rapport ne conserve que les requetes liees aux findings dans l'annexe technique

---

## 8. Chaines d'attaque automatisees

### 8.1 Rule engine YAML

Au-dela des 7 chaines pre-definies, un DSL YAML permet de definir des regles de chainage dynamiques :

```yaml
# config/chain_rules.yaml
rules:
  - name: "Brute-force amplifie"
    conditions:
      - finding: "enum.wp_users"
        min_count: 1
      - finding: "enum.xmlrpc_methods"
        has_method: "system.multicall"
      - finding: "vuln.rate_limit"
        result: "no_protection"
    actions:
      - trigger: "exploit.xmlrpc_bruteforce"
      - trigger: "exploit.wordlist_generator"
    impact: "admin_access"

  - name: "Custom plugin RCE"
    conditions:
      - finding: "vuln.cve_matcher"
        cvss_min: 9.0
        type: "RCE"
        confidence: "confirmed"
    actions:
      - trigger: "exploit.rce_exploit"
    impact: "full_compromise"
```

Ce format permet a l'utilisateur ou la communaute d'ajouter des regles sans modifier le code.

### 8.2 Chaines pre-definies (issues du pentest CYRIAS)

| ID | Nom | Etapes | Condition | Impact terminal |
|----|-----|--------|-----------|-----------------|
| CHAIN-A | Brute-force amplifie | Users → Gravatar → breach → CUPP → XML-RPC multicall | Users + multicall + no rate-limit | Admin access |
| CHAIN-B | Git dump | CDN bypass → origin → .git/ → git-dumper → secrets | .git detecte + origin | Full DB compromise |
| CHAIN-C | Backup UpdraftPlus | /updraft/ → CVE-2022-0633 → download → extract | updraft/ existe | Full compromise |
| CHAIN-D | Env/Htpasswd pivot | .env → mod_rewrite CVE → .htpasswd → crack → dev → prod | .env + .htpasswd | Prod access |
| CHAIN-E | Infrastructure pivot | Meme admin N sites → credential reuse → lateral | Meme user/email multi-domaines | Multi-site compromise |
| CHAIN-F | CORS exploitation | CORS wildcard → craft JS → voler nonce → CRUD REST API | CORS reflete + credentials | Admin actions |
| CHAIN-G | Plugin RCE | Version vulnerable → PoC → execution code | CVE CVSS >= 9.0 confirmed | Full compromise |

### 8.3 Visualisation des chaines

**Terminal** : arbre ASCII avec `rich`
**HTML** : diagrammes interactifs Mermaid.js
**DOCX** : graphe statique genere par `graphviz` / `networkx`

### 8.4 Chaines cross-target (v2.0)

En mode multi-target, detecter les pivots entre cibles :
- Memes emails (via Gravatar)
- Memes cookies de session
- Memes credentials exposees
- Infrastructure partagee (meme IP, meme /24)

---

## 9. Cadre juridique, ethique et RGPD

### 9.1 Scope enforcement

- Le flag `--pentest` EXIGE un `--scope-file` valide
- Chaque requete HTTP passe par le `ScopeEnforcer` avant envoi
- Toute requete hors scope est bloquee avec log + warning
- Le fichier scope inclut les references d'autorisation

### 9.2 Tracabilite et consentement

- Le rapport inclut une page "Portee et autorisation" avec :
  - Reference contrat/lettre de mission (`--authorization-ref`)
  - Liste des domaines/IPs autorises
  - Dates du test
  - Pentester identifie
- Chaque requete HTTP est loggee avec timestamp dans `http_log.jsonl`
- Hash SHA256 du scope file inclus dans les metadata du scan

### 9.3 RGPD et donnees personnelles

Les modules OSINT (HIBP, LeakCheck, Gravatar) manipulent des **donnees a caractere personnel**. Regles :

| Donnee | Traitement | Duree retention |
|--------|-----------|-----------------|
| Emails decouverts | Hasher dans le rapport par defaut (`a***@domain.com`), flag `--reveal-data` pour afficher en clair | Duree du scan + rapport |
| Resultats de fuites (HIBP) | Stockes dans le loot chiffre si `--encrypt-loot` | Purge automatique `--auto-purge` |
| Mots de passe de fuites | JAMAIS stockes en clair — uniquement hashes SHA1 (HIBP k-anonymity) | Pas de retention |
| DOB, ville, nom complet (LeakCheck) | Stockes uniquement si pertinents pour la wordlist | Purge avec le loot |

**Avertissement** : avant toute requete HIBP/LeakCheck, BAZOOKA affiche un avertissement et demande confirmation (sauf en mode `--confirm=none`).

### 9.4 Disclaimer automatique

Chaque rapport genere inclut un disclaimer legal en en-tete :

> *Ce rapport a ete produit dans le cadre d'un audit de securite autorise (ref: {authorization_ref}). Les tests ont ete realises conformement au perimetre defini et ne constituent pas une autorisation de reproduction. L'utilisation de cet outil en dehors d'un cadre legal autorise est strictement interdite.*

### 9.5 Mode bug bounty (`--profile bugbounty`)

Desactive automatiquement :
- Tout brute-force
- Port scans
- Telechargement de fichiers sensibles (debug.log, backups)
- Requetes paralleles agressives (rate-limit a 2 req/s)
- SSRF exploitation
- Module infra complet

### 9.6 Clause de non-responsabilite

L'outil inclut une licence avec clause d'usage ethique :
> *WordPress BAZOOKA est destine exclusivement a des tests de securite autorises. L'auteur decline toute responsabilite en cas d'utilisation malveillante ou non autorisee.*

---

## 10. Contraintes et exigences non-fonctionnelles

### 10.1 Performance

| Metrique | Cible |
|----------|-------|
| Scan quick (recon + enum) | < 60 secondes |
| Scan standard (recon + enum + vuln) | < 5 minutes sur connexion 100 Mbps |
| Pentest complet (avec brute-force) | < 1 heure (execution) |
| Memoire RAM | < 500 MB |
| Disk (loot) | < 100 MB par cible (hors media) |
| Parallelisme | 10 threads par defaut, configurable 1-50 |
| Re-scan (avec cache) | ~50% plus rapide (DNS, WHOIS, CT caches) |

### 10.2 Fiabilite

| Exigence | Detail |
|----------|--------|
| Reprise sur interruption | Etat SQLite atomique, `bazooka resume` |
| Gestion timeout | Retry intelligent (3 tentatives, backoff + jitter) |
| Gestion rate-limit | Detection auto + throttle adaptatif |
| Gestion WAF | Detection + adaptation strategie (UA, timing, paths) |
| Zero crash | Try/except granulaire, un module fail ne bloque pas les autres |
| Signal handling | Ctrl+C graceful (sauvegarde etat) |
| Erreur partielle | Le contexte note `confidence: partial` si un module echoue |

### 10.3 Portabilite

| Plateforme | Support |
|------------|---------|
| Linux (Kali, Ubuntu, Debian) | Complet |
| Windows 10/11 (natif + WSL) | Complet |
| macOS | Complet |
| Docker | Image officielle des v0.1 |
| Python | 3.11+ requis |

### 10.4 Extensibilite

| Feature | Detail |
|---------|--------|
| Modules custom | `modules/custom/` avec decouverte auto via `BazookaModule` |
| Signatures YAML | `signatures/*.yaml` pour plugins, themes, WAF, services |
| Regles de chainage YAML | `config/chain_rules.yaml` personnalisable |
| Templates rapport | Templates DOCX/HTML personnalisables |
| Base CVE | Multi-sources configurables dans `cve_db/sources.yaml` |
| Hooks pre/post phase | Callbacks configurables dans YAML |
| i18n | Fichiers de traduction `report/i18n/{lang}.yaml` |
| Webhooks | Notifications Slack/Discord sur findings CRITICAL |

---

## 11. Stack technique

### 11.1 Langage et frameworks

| Composant | Technologie | Raison |
|-----------|-------------|--------|
| Langage | **Python 3.11+** | Ecosysteme securite, async, cross-platform |
| HTTP | `httpx` (async) | HTTP/2, connection pooling, proxy support |
| DNS | `dnspython` | Resolution DNS programmatique |
| CLI | `typer` + `rich` | Interface CLI moderne avec couleurs |
| Concurrence | `asyncio` + `ThreadPoolExecutor` | IO-bound (HTTP) + CPU-bound (hashing) |
| Parsing HTML | `beautifulsoup4` + `lxml` | Parse DOM WordPress |
| Base de donnees | `sqlite3` + `SQLAlchemy` (async) | Loot, dedup, queries, resume |
| CVSS | `cvss` (pip) | Calcul CVSS v3.1 base/temporal/environmental |
| Rapport DOCX | `python-docx` | Generation Word |
| Rapport HTML | `jinja2` | Templates HTML |
| Graphiques | `matplotlib` + `networkx` | Camemberts + graphes chaines d'attaque |
| Visualisation chaines | `graphviz` (optionnel) | Diagrammes dans le DOCX |
| YAML config | `pyyaml` | Configuration, signatures, regles |
| Modeles de donnees | `pydantic` v2 | Validation stricte des findings et configs |
| SSL | `ssl` + `cryptography` | Analyse certificats |
| Hashing | `hashlib` | SHA1 (HIBP), SHA256 (Gravatar), PBKDF2 |
| Chiffrement loot | `age` (pyage) ou `gnupg` | Chiffrement AES-256-GCM |
| Screenshots | `playwright` (optionnel) | Captures d'ecran des pages vulnerables |
| Packaging | `pyproject.toml` + `hatch` | Standard moderne (pas setup.py) |

### 11.2 Dependances externes optionnelles

| Outil | Utilisation | Fallback sans |
|-------|-------------|---------------|
| nmap / python-nmap | SYN scan, UDP scan, OS detection | TCP connect scan natif Python |
| git | Git dumper reconstruction | Module desactive |
| sqlmap | SQLi avancee (integration API) | SQLi basique integree |
| playwright | Screenshots des pages vulnerables | Pas de screenshots |
| graphviz | Diagrammes chaines d'attaque dans DOCX | ASCII art dans DOCX |

### 11.3 APIs externes (optionnelles, avec cle)

| API | Utilisation | Gratuite | Fallback offline |
|-----|-------------|----------|-----------------|
| Wordfence Intelligence | CVE WordPress temps reel | Oui (API publique) | Base locale SQLite |
| PatchStack | CVE WordPress | Freemium | Base locale |
| WPVulnDB | CVE WordPress | Freemium | Base locale |
| NVD | CVE generales | Gratuit | Base locale |
| HIBP v3 | Breach check | Payant | Skip |
| HIBP Pwned Passwords | Password check | Gratuit | Skip |
| crt.sh | Certificate Transparency | Gratuit | Skip |
| SecurityTrails | DNS historique, origin IP | Freemium | Skip |
| Shodan | Service detection | Freemium | Skip |
| VirusTotal | Sous-domaines | Freemium | Skip |

---

## 12. Strategie de test

### 12.1 Tests unitaires

| Categorie | Couverture cible | Framework |
|-----------|-----------------|-----------|
| Modules recon | > 80% | pytest + responses (mock HTTP) |
| Modules enum | > 80% | pytest + responses |
| Modules vuln | > 80% | pytest + responses |
| Chain engine | > 90% | pytest |
| Scorer | > 90% | pytest |
| Session/cache | > 80% | pytest + responses |
| Scope enforcer | **100%** | pytest (CRITIQUE : ne doit jamais etre depasse) |
| Registry | > 80% | pytest |

### 12.2 Tests d'integration

- **Environnement** : Docker Compose avec WordPress vulnerable (plugins CVE connus, debug.log actif, .git expose, REST API ouverte)
- **Golden files** : corpus de reponses HTTP sauvegardees pour tests de regression
- **Scenarios** : scan complet d'un site de test, verification que tous les findings attendus sont trouves

### 12.3 CI/CD

- GitHub Actions avec matrice Python 3.11 / 3.12 / 3.13
- Lint : `ruff`
- Type check : `mypy`
- Tests : `pytest --cov`
- Build Docker : test de l'image

---

## 13. Risques projet

| Risque | Impact | Mitigation |
|--------|--------|-----------|
| API tierces indisponibles (crt.sh down, HIBP timeout) | Recon incomplete | Mode `--offline` + cache persistant + retry |
| Evolution WordPress casse des tests | Faux negatifs | Tests d'integration reguliers, monitoring des changelogs WP |
| Faux positifs erode la confiance | Rapport peu fiable | Champ `confidence` + `false_positive_potential` sur chaque finding |
| Volume CVE (11k+ en 2025, en hausse) | Base obsolete | `bazooka update-db` automatisable (cron) + multi-sources |
| Utilisation malveillante | Legal + reputation | Scope obligatoire, disclaimer, licence ethique, logging complet |
| Dependance Python unique | Portabilite limitee | Docker image officielle |
| Complexite du chain engine | Bugs de logique | Tests unitaires > 90% + scenarios de regression |

---

## 14. Livrables et jalons

### 14.1 MVP (v0.1) - Milestone 1

| Module | Contenu |
|--------|---------|
| CLI | `bazooka scan {url}` + `bazooka doctor` + `bazooka update-db` |
| Core | Engine, session, cache, scope enforcer, SQLite backend, signal handler |
| Recon | DNS, headers, WAF detect, SPF/DMARC, tech stack |
| Enum | wp-content detect, WP version, users, plugins, themes, REST API, XML-RPC, debug.log, backups |
| Vuln | CVE matcher (SQLite multi-sources), CORS, security headers, rate-limit |
| Report | JSON + SARIF + terminal summary |
| Loot | Structure organisee + SQLite |
| Docker | Dockerfile + docker-compose.yml (outil + WP test) |
| Tests | Unitaires > 80% + 1 integration test |

### 14.2 v0.5 - Milestone 2

| Module | Contenu |
|--------|---------|
| Recon complet | CT logs, subdomains, origin finder, SSL, port scan, OSINT emails, breaches |
| Enum complet | REST API deep, GraphQL, WooCommerce, CF7, media, source maps, directory listing, Multisite, mu-plugins, shortcodes, wp-config audit, app passwords, registration |
| Vuln complet | SSRF XML-RPC, SQLi, XSS, LFI, mod_rewrite CVE, session auth, host header injection, honeypot, misconfig |
| Report | HTML interactif + DOCX + Markdown |
| Chains | Rule engine YAML + 7 chaines pre-definies |
| Compare | `bazooka compare` inter-scans |
| Conformite | Mapping OWASP / CWE / MITRE ATT&CK |

### 14.3 v1.0 - Milestone 3

| Module | Contenu |
|--------|---------|
| Vuln complet | RCE, IDOR, CSRF, auth bypass, file upload |
| Exploit | Brute-force XML-RPC/login/phpMyAdmin, wordlist generator, SSRF port scan, origin bypass, git dumper, authenticated scan |
| Infra | Network scan, SSL cert enum, service detect, vhost, lateral movement |
| Report complet | DOCX pro avec remediations, graphiques, conformite, chaines Graphviz, resume executif, annexes |
| CLI complet | Wizard, benchmark, tous les flags |
| i18n | FR + EN |
| Chiffrement | `--encrypt-loot` |
| Profiles | quick / standard / aggressive / bugbounty |

### 14.4 v2.0 - Futur

| Feature | Description |
|---------|-------------|
| Mode CI/CD | Integration GitHub Actions / GitLab CI pour audit recurrent |
| API REST | Lancer des scans via API HTTP (pour dashboards) |
| Dashboard web | Mini-dashboard local temps reel (WebSocket + vis.js) |
| AI-assisted analysis | LLM local (Ollama) pour resumer findings, proposer chaines, analyser code source |
| Multi-target | Scanner N sites WordPress en parallele |
| Mode agent distribue | Master/worker pour tres grands perimetres |
| Export avance | DefectDojo, Jira, STIX 2.1 |
| Alerting | Webhook Slack/Discord/SIEM (syslog CEF) |
| Cross-target chains | Pivots entre cibles en multi-target |
| Self-update | `bazooka self-update` |

---

## Annexe A - Matrice des 120 tests

### Matrice complete

| # | Module | Test | Intrusif | quick | standard | aggressive | bugbounty |
|---|--------|------|----------|-------|----------|------------|-----------|
| 1 | recon | DNS A/AAAA/MX/NS/TXT/SOA/CAA | Non | X | X | X | X |
| 2 | recon | WHOIS domaine | Non | X | X | X | X |
| 3 | recon | WHOIS IP | Non | | X | X | |
| 4 | recon | Certificate Transparency | Non | | X | X | X |
| 5 | recon | Sous-domaines (CT) | Non | | X | X | X |
| 6 | recon | Sous-domaines (brute) | Non | | | X | |
| 7 | recon | DNS zone walking (DNSSEC) | Non | | | X | |
| 8 | recon | CDN detection | Non | X | X | X | X |
| 9 | recon | Origin IP discovery | Non | | X | X | X |
| 10 | recon | Origin validation | Non | | X | X | |
| 11 | recon | IPv6 bypass | Non | | | X | |
| 12 | recon | WAF detection (30+ signatures) | Non | X | X | X | X |
| 13 | recon | Headers HTTP | Non | X | X | X | X |
| 14 | recon | SPF analysis | Non | X | X | X | X |
| 15 | recon | DMARC analysis | Non | X | X | X | X |
| 16 | recon | SSL/TLS audit | Non | | X | X | X |
| 17 | recon | Port scan (top 100) | Non | | X | X | |
| 18 | recon | Port scan (full) | Non | | | X | |
| 19 | recon | Technology stack | Non | X | X | X | X |
| 20 | recon | OSINT emails | Non | | X | X | X |
| 21 | recon | Breach check (HIBP) | Non | | X | X | |
| 22 | recon | Sitemap parse | Non | X | X | X | X |
| 23 | recon | Robots.txt parse | Non | X | X | X | X |
| 24 | enum | wp-content path detect | Non | X | X | X | X |
| 25 | enum | 404 calibration | Non | X | X | X | X |
| 26 | enum | WP version detect | Non | X | X | X | X |
| 27 | enum | User enumeration (REST) | Non | X | X | X | X |
| 28 | enum | User enumeration (author) | Non | | X | X | |
| 29 | enum | User enumeration (sitemap) | Non | | X | X | X |
| 30 | enum | User enumeration (_fields leak) | Non | | X | X | X |
| 31 | enum | Gravatar reverse | Non | | X | X | |
| 32 | enum | Plugin enumeration (passive) | Non | X | X | X | X |
| 33 | enum | Plugin enumeration (active) | Non | | X | X | X |
| 34 | enum | Plugin enumeration (brute 1500) | Non | | | X | |
| 35 | enum | Shortcode parser | Non | | X | X | |
| 36 | enum | Theme detection | Non | X | X | X | X |
| 37 | enum | Multisite detection | Non | | X | X | X |
| 38 | enum | REST API routes | Non | X | X | X | X |
| 39 | enum | REST API posts | Non | | X | X | X |
| 40 | enum | REST API pages | Non | | X | X | X |
| 41 | enum | REST API media | Non | | X | X | X |
| 42 | enum | REST API categories/tags | Non | | X | X | |
| 43 | enum | REST API comments | Non | | X | X | |
| 44 | enum | REST API drafts/private | Non | | X | X | X |
| 45 | enum | REST API settings | Non | | X | X | X |
| 46 | enum | REST API block-renderer | Non | | | X | |
| 47 | enum | GraphQL introspection | Non | | X | X | X |
| 48 | enum | GraphQL field suggestions | Non | | | X | |
| 49 | enum | WooCommerce routes | Non | | X | X | X |
| 50 | enum | Contact Form 7 | Non | | X | X | X |
| 51 | enum | XML-RPC methods | Non | X | X | X | X |
| 52 | enum | XML-RPC multicall check | Non | | X | X | |
| 53 | enum | debug.log | Non | X | X | X | X |
| 54 | enum | debug.log credential search | Non | | X | X | |
| 55 | enum | Directory listing uploads | Non | X | X | X | X |
| 56 | enum | Backup paths (25 chemins) | Non | X | X | X | X |
| 57 | enum | wp-config backups | Non | | X | X | |
| 58 | enum | .git detection | Non | X | X | X | X |
| 59 | enum | .env / .wp-env.json detection | Non | X | X | X | X |
| 60 | enum | phpMyAdmin / adminer detection | Non | | X | X | |
| 61 | enum | Source maps | Non | | X | X | X |
| 62 | enum | wp-cron analysis | Non | | X | X | |
| 63 | enum | mu-plugins scan | Non | | X | X | |
| 64 | enum | Object cache (Redis/Memcached) | Non | | X | X | |
| 65 | enum | Application passwords | Non | | X | X | X |
| 66 | enum | Registration check | Non | | X | X | X |
| 67 | enum | wp-config constants audit | Non | | X | X | |
| 68 | vuln | CVE matcher (plugins) | Non | X | X | X | X |
| 69 | vuln | CVE matcher (themes) | Non | X | X | X | X |
| 70 | vuln | CVE matcher (core) | Non | X | X | X | X |
| 71 | vuln | CVE matcher (server) | Non | | X | X | X |
| 72 | vuln | CORS misconfiguration | Non | X | X | X | X |
| 73 | vuln | CORS with credentials | Non | X | X | X | X |
| 74 | vuln | SSRF XML-RPC (basic) | Non | | X | X | |
| 75 | vuln | SSRF protocols | Non | | | X | |
| 76 | vuln | SSRF cloud metadata | Non | | X | X | |
| 77 | vuln | SQLi search param | Non | | X | X | |
| 78 | vuln | SQLi admin-ajax | Non | | | X | |
| 79 | vuln | XSS reflected search | Non | | X | X | |
| 80 | vuln | XSS reflected params | Non | | | X | |
| 81 | vuln | LFI plugin-specific | Non | | | X | |
| 82 | vuln | RCE CVE-specific PoC safe | Non | | | X | |
| 83 | vuln | IDOR WooCommerce | Non | | | X | |
| 84 | vuln | IDOR user/media | Non | | | X | |
| 85 | vuln | CSRF nonce validation | Non | | X | X | |
| 86 | vuln | Auth bypass REST API | Non | | X | X | X |
| 87 | vuln | Auth bypass plugin-specific | Non | | | X | |
| 88 | vuln | File upload SVG XXE | Non | | | X | |
| 89 | vuln | File upload extension bypass | Non | | | X | |
| 90 | vuln | Session/cookie audit | Non | | X | X | X |
| 91 | vuln | Host header injection | Non | | X | X | |
| 92 | vuln | Honeypot detection | Non | | X | X | X |
| 93 | vuln | Misconfiguration checks | Non | | X | X | X |
| 94 | vuln | Rate-limit wp-login | Faible | | X | X | |
| 95 | vuln | Rate-limit XML-RPC | Faible | | X | X | |
| 96 | vuln | Rate-limit REST API | Faible | | | X | |
| 97 | vuln | Security headers check | Non | X | X | X | X |
| 98 | vuln | SSL/TLS vulns | Non | | X | X | X |
| 99 | vuln | mod_rewrite CVE-2024-38474 | Non | | X | X | |
| 100 | exploit | XML-RPC brute-force | **Oui** | | | X | |
| 101 | exploit | wp-login brute-force | **Oui** | | | X | |
| 102 | exploit | phpMyAdmin brute-force | **Oui** | | | X | |
| 103 | exploit | Wordlist generation (CUPP) | Non | | | X | |
| 104 | exploit | SSRF internal port scan | **Oui** | | | X | |
| 105 | exploit | SSRF cross-network | **Oui** | | | X | |
| 106 | exploit | Origin bypass full test | Faible | | | X | |
| 107 | exploit | Git dump | Faible | | | X | |
| 108 | exploit | Authenticated scan | **Oui** | | | X | |
| 109 | infra | Network /24 scan | Non | | | X | |
| 110 | infra | SSL cert enumeration | Non | | | X | |
| 111 | infra | Service fingerprint | Non | | | X | |
| 112 | infra | VHost enumeration | Faible | | | X | |
| 113 | infra | Lateral movement map | Non | | | X | |
| 114 | chain | Attack chain detection | Non | X | X | X | X |
| 115 | chain | YAML rule engine | Non | | X | X | |
| 116 | report | Rapport generation | Non | X | X | X | X |
| 117 | report | Compliance mapping | Non | X | X | X | X |
| 118 | report | Chain visualization | Non | | X | X | |
| 119 | report | Diff (si baseline fournie) | Non | | X | X | |
| 120 | report | Screenshot capture | Non | | | X | |

**Total** : 120 tests | quick: 33 | standard: 84 | aggressive: 120 | bugbounty: 52

---

## Annexe B - Formats de sortie

### B.1 JSON (findings.json)
Structure complete de tous les findings (cf. section 7.2). Machine-readable.

### B.2 SARIF (findings.sarif) — NOUVEAU
Static Analysis Results Interchange Format pour integration native :
- GitHub Advanced Security (Code Scanning)
- GitLab Security Dashboard
- Azure DevOps

### B.3 JUnit (findings.junit.xml) — NOUVEAU
Pour integration Jenkins / GitLab CI. Code de retour non-zero si findings >= seuil configurable.

### B.4 Markdown (RAPPORT_BAZOOKA.md) — NOUVEAU
Pour wikis internes, GitLab/GitHub Issues, Confluence. Meme structure que DOCX.

### B.5 DOCX (rapport client)
Cf. Annexe D pour la structure detaillee.

### B.6 HTML (rapport interactif)
Rapport HTML single-file avec :
- Navigation sidebar cliquable
- Filtrage par severite et confiance
- Code blocks avec coloration syntaxique
- Graphiques SVG inline + diagrammes Mermaid.js
- Mode impression propre

### B.7 Terminal summary
Sortie coloree avec `rich` : progress bars, tableaux, couleurs par severite, arbre des chaines.

---

## Annexe C - Modele de donnees (Pydantic)

```python
from pydantic import BaseModel
from typing import Optional, Literal
from datetime import datetime

class Evidence(BaseModel):
    request: str
    response_status: int
    response_headers: dict[str, str]
    response_body_excerpt: Optional[str] = None
    screenshot: Optional[str] = None
    file: Optional[str] = None

class Compliance(BaseModel):
    owasp_2021: Optional[str] = None     # "A01:2021 - Broken Access Control"
    cwe: Optional[str] = None            # "CWE-346"
    mitre_attack: Optional[str] = None   # "T1189"
    pci_dss_v4: Optional[str] = None     # "6.5.8"

class Finding(BaseModel):
    id: str                              # "VULN-CORS-001"
    title: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    cvss_score: float
    cvss_vector: str
    cvss_temporal: Optional[str] = None
    confidence: Literal["confirmed", "likely", "possible"]
    false_positive_potential: Literal["low", "medium", "high"]
    category: str                        # "Access Control", "Injection", etc.
    type: Literal["cve", "misconfiguration", "information_disclosure", "design_flaw"]
    description: str
    evidence: Evidence
    impact: str
    remediation: str
    compliance: Compliance
    references: list[str]
    chain_ids: list[str] = []
    phase: str
    module: str                          # "vuln.cors_check"
    disclosure_method: str               # "passive", "active_test", "redirect"
    timestamp: datetime
    tags: list[str] = []                 # Pour filtrage

class ScanMeta(BaseModel):
    bazooka_version: str
    schema_version: str = "2.0"
    cve_db_version: str
    target: str
    scope_file: Optional[str] = None
    authorization_ref: Optional[str] = None
    profile: str
    start_time: datetime
    end_time: Optional[datetime] = None
    total_requests: int = 0
    modules_executed: int = 0
    modules_skipped: int = 0
    modules_failed: int = 0
```

---

## Annexe D - Structure du template DOCX

| Section | Style Word | Contenu | Placeholders |
|---------|-----------|---------|-------------|
| Page de garde | Custom | Logo, nom client, date, "CONFIDENTIEL" | `{{CLIENT_NAME}}`, `{{DATE}}`, `{{AUTHORIZATION_REF}}` |
| Disclaimer | Normal (italic) | Clause de non-responsabilite (cf. 9.4) | `{{DISCLAIMER}}` |
| Sommaire | TOC | Genere automatiquement | Auto |
| Resume executif | Heading 1 | Score global, top 5 vulns, recommandation critique, 1 page | `{{EXECUTIVE_SUMMARY}}`, `{{RISK_SCORE}}`, `{{SEVERITY_CHART}}` |
| Methodologie | Heading 1 | OWASP Testing Guide v4, PTES, outils, profil utilise | `{{METHODOLOGY}}`, `{{TOOLS_USED}}` |
| Scope | Heading 1 | Domaines, IPs, dates, pentester, reference autorisation | `{{SCOPE_TABLE}}` |
| Synthese des vulns | Heading 1 | Tableau avec ID, severite, CVSS, titre, confiance, statut | `{{FINDINGS_SUMMARY_TABLE}}` |
| Conformite | Heading 1 | Matrice OWASP Top 10, heatmap par categorie | `{{OWASP_MATRIX}}`, `{{CWE_TABLE}}` |
| Findings detailles | Heading 2 (par finding) | Description, evidence, impact, remediation, references | `{{FINDING_DETAIL}}` x N |
| Chaines d'attaque | Heading 1 | Schema visuel (Graphviz) + description narrative | `{{CHAIN_DIAGRAMS}}` |
| Plan de remediation | Heading 1 | Tableau priorise : quick wins → court terme → long terme | `{{REMEDIATION_PLAN}}` |
| Annexes techniques | Heading 1 | Logs pertinents, configurations recommandees | `{{TECHNICAL_APPENDIX}}` |

---

*Document genere le 31 mars 2026 — WordPress BAZOOKA v2.0 Specification*
*Base sur le pentest CYRIAS (mars 2026) — 145 vulnerabilites, 950 fichiers, 398 MB*
*Integre les revues de 4 IA specialisees — 120 tests, 5 phases, 18 sections*
