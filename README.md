<h1 align="center">
  WordPress BAZOOKA
</h1>

<p align="center">
  <b>Automated WordPress Penetration Testing & Security Audit Framework</b><br>
  <i>Un seul tir, tous les angles couverts.</i>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.11+-blue.svg" />
  <img src="https://img.shields.io/badge/license-MIT-green.svg" />
  <img src="https://img.shields.io/badge/status-active-success.svg" />
  <img src="https://img.shields.io/badge/CVE_sources-wpvulnerability.net-orange.svg" />
</p>

---

## English

WordPress BAZOOKA is a full-stack automated security framework for WordPress that combines reconnaissance, enumeration, vulnerability scanning, exploit-class checks and infrastructure analysis into a single fast workflow. It ships with both a CLI and a real-time web GUI.

### Why BAZOOKA

- **40× faster than WPScan** on real targets — our scan completes in 2 min on average where WPScan takes 96 min, while producing **more CVE matches** (we use the free wpvulnerability.net feed, no API token required).
- **0 false positive WPScan typically reports** (WPScan can confuse users / themes / authors with plugin slugs — BAZOOKA does not).
- **Detects CVE on plugins, WordPress core, and infrastructure** (Apache, nginx, PHP, MySQL, MariaDB, Redis, Memcached) — most scanners do plugins only.
- **Multi-vector user enumeration** (REST API, `?author=N` brute, oEmbed, sitemap) and passive plugin discovery that does not depend on aggressive bruteforce wordlists.
- **Report-ready**: HTML, DOCX and JSON output with OWASP / CWE / MITRE mapping.

### Features

| Phase | Modules |
|---|---|
| **Recon** | DNS / DMARC / SPF, WAF detection, SSL/TLS, headers, WHOIS, CT logs, robots.txt, technology stack, subdomain enum, wayback, Google dorking |
| **Enum** | WP version, users (4 vectors), plugins (passive + meta + wordlist), themes, REST API, XML-RPC, backup finder, debug log, config audit, dev tools (Search-Replace-DB, Adminer, phpMyAdmin…) |
| **Vuln** | CORS, security headers, CVE matching (plugins + core + infra via wpvulnerability.net live feed), SQLi, XSS, SSRF, mod_rewrite path confusion, rate limit, CSRF, IDOR, auth bypass, REST API exposure, open ports |
| **Exploit** | XML-RPC bruteforce, wordlist generator, origin bypass, Git dumper, API key extraction |
| **Infra** | Network scan, SSL cert enum, service detect, lateral movement hints |

### Quickstart

```bash
pip install -e .
bazooka scan https://your-target.com
```

Profiles: `quick` (~25s), `standard` (~2min), `aggressive` (~3min, full plugin bruteforce).

### Web GUI

```bash
python run_gui.py
# opens http://localhost:8666
```

Real-time scan progress with per-module status, animated activity bar, finding stream, and one-click HTML/DOCX/JSON report.

### Architecture

```
core/         engine, session, models (Pydantic)
modules/      recon/ enum/ vuln/ exploit/ infra/
cve_db/       seed SQLite + wpvulnerability.net live integration
report/       HTML/DOCX/JSON generators
gui/          FastAPI + WebSocket live GUI
data/         wordlists, priority plugins, sensitive paths
testlab/      Docker WP lab for benchmarking
```

### Output Example

```
[SCORE] Max CVSS: 9.8/10
  CRITICAL: 18 | HIGH: 20 | MEDIUM: 172 | LOW: 6 | INFO: 37
 Completed in 208s | 1207 requests sent
 Plugins: 29 detected | CVE matched: 144 | Users: admin, Editor
```

### Related projects

- **[wordpress-vulnerable-lab](https://github.com/AYI-NEDJIMI/wordpress-vulnerable-lab)** — the companion Docker lab packing 30+ vulnerable WordPress plugins with documented CVE ground truth.
- **[ayinedjimi-consultants.fr](https://ayinedjimi-consultants.fr)** — WordPress security guides, hardening checklists and consulting.

### License

MIT. By [Ayi NEDJIMI](https://ayinedjimi-consultants.fr).

---

## Français

WordPress BAZOOKA est un framework d'audit de sécurité automatisé pour WordPress combinant en un seul workflow reconnaissance, énumération, scan de vulnérabilités, checks exploit et analyse infrastructure. Il fournit une CLI et une GUI web temps réel.

### Pourquoi BAZOOKA

- **40× plus rapide que WPScan** sur cibles réelles — notre scan finit en 2 min en moyenne là où WPScan met 96 min, avec **plus de CVE détectées** (on utilise le feed gratuit wpvulnerability.net, sans token).
- **0 faux positif que WPScan rapporte** (WPScan confond parfois utilisateurs / thèmes / auteurs avec des slugs plugins — pas BAZOOKA).
- **Détecte les CVE sur plugins, core WordPress, ET infrastructure** (Apache, nginx, PHP, MySQL, MariaDB, Redis, Memcached) — la plupart des scanners ne font que les plugins.
- **Énumération users multi-vecteur** (REST API, brute `?author=N`, oEmbed, sitemap) et détection plugins passive ne dépendant pas du brute-force agressif.
- **Reports prêts pour rendu** : HTML, DOCX et JSON avec mapping OWASP / CWE / MITRE.

### Démarrage rapide

```bash
pip install -e .
bazooka scan https://ta-cible.com
```

Profils : `quick` (~25s), `standard` (~2min), `aggressive` (~3min, brute-force plugins complet).

### Interface Web

```bash
python run_gui.py
# ouvre http://localhost:8666
```

### Benchmark vs WPScan / Nuclei

| Métrique | BAZOOKA aggressive | WPScan (free) | Nuclei |
|---|---|---|---|
| Plugins légitimes détectés | 14 | 12 (15 - 3 FP) | 0 |
| Utilisateurs détectés | ✅ | ❌ | n/a |
| CVE plugins matchés | ✅ 3 (live wpvulnerability.net) | ❌ 0 (token requis) | 0 |
| Durée | **2 min 25s** | 96 min | 30 s (mais 0 finding) |
| Requêtes | 1 129 | 153 078 | ~ |
| Faux positifs | 0 | 3 | n/a |

### Lab de test

Le repo **[wordpress-vulnerable-lab](https://github.com/AYI-NEDJIMI/wordpress-vulnerable-lab)** (séparé) fournit un environnement Docker WordPress volontairement vulnérable avec **30+ plugins** CVE 2023-2025 préinstallés pour benchmarker des scanners. Ground truth documentée, idéal pour formation, CTF et benchmark de scanner.

### Ressources complémentaires

Guides et ressources WordPress security : **[ayinedjimi-consultants.fr](https://ayinedjimi-consultants.fr)**

- Guide de sécurisation WordPress
- Checklist de durcissement
- Audit & conseil sécurité WordPress

### Licence

MIT. Par [Ayi NEDJIMI](https://ayinedjimi-consultants.fr).
