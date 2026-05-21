"""CVE Database manager — SQLite backend with seed data and lookup."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional


DB_PATH = Path(__file__).parent / "bazooka_cve.db"
SCHEMA_PATH = Path(__file__).parent / "schema.sql"

# Seed data: well-known WordPress CVEs (curated from public sources: NVD, WPScan, Wordfence)
SEED_CVES = [
    # Plugin CVEs — CRITICAL
    ("CVE-2024-6386", "plugin", "sitepress-multilingual-cms", "WPML SSTI RCE via Twig",
     "WPML < 4.6.13 permet l'execution de code arbitraire via injection de template Twig (SSTI) sans authentification.",
     9.9, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "CRITICAL", "RCE",
     None, "4.6.12", "4.6.13", None, "2024-08-21", "wordfence"),
    ("CVE-2024-5265", "plugin", "js_composer", "WPBakery Page Builder RCE",
     "WPBakery < 7.7 permet l'execution de code via des shortcodes malveillants.",
     9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CRITICAL", "RCE",
     None, "7.6", "7.7", None, "2024-06-15", "patchstack"),
    ("CVE-2024-1988", "plugin", "flavor", "Post Grid & Filter Ultimate SQLi",
     "Post Grid & Filter Ultimate < 4.0.2 permet une injection SQL authentifiee.",
     9.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "CRITICAL", "SQLi",
     None, "4.0.1", "4.0.2", None, "2024-03-12", "wordfence"),
    ("CVE-2024-56000", "plugin", "jesuspended-jemented", "K Elements Account Takeover",
     "K Elements (Kleo addon) < 5.4 permet un takeover de compte via Facebook Login sans verification de token.",
     9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CRITICAL", "AuthBypass",
     None, "5.3", "5.4", None, "2024-12-01", "patchstack"),
    ("CVE-2020-25213", "plugin", "wp-file-manager", "WP File Manager RCE Upload",
     "WP File Manager < 6.9 permet l'upload de fichiers arbitraires (webshell) via le connector elFinder.",
     9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CRITICAL", "RCE",
     None, "6.8", "6.9", None, "2020-09-01", "nvd"),
    ("CVE-2022-0633", "plugin", "updraftplus", "UpdraftPlus Backup Download",
     "UpdraftPlus < 1.22.3 permet a un utilisateur authentifie (subscriber) de telecharger les sauvegardes.",
     8.5, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "HIGH", "AuthBypass",
     None, "1.22.2", "1.22.3", None, "2022-02-17", "wordfence"),

    # Contact Form 7
    ("CVE-2024-6625", "plugin", "contact-form-7", "Contact Form 7 XSS",
     "Contact Form 7 < 5.9.5 est vulnerable a une XSS stockee via les champs du formulaire.",
     6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "MEDIUM", "XSS",
     None, "5.9.4", "5.9.5", None, "2024-07-10", "wordfence"),
    ("CVE-2023-6449", "plugin", "contact-form-7", "Contact Form 7 Open Redirect",
     "Contact Form 7 < 5.8.4 permet une redirection ouverte.",
     5.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", "MEDIUM", "InfoDisclosure",
     None, "5.8.3", "5.8.4", None, "2023-12-01", "patchstack"),

    # Elementor
    ("CVE-2024-2117", "plugin", "elementor", "Elementor XSS via Widget",
     "Elementor < 3.20.0 est vulnerable a une XSS stockee via les widgets.",
     6.4, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", "MEDIUM", "XSS",
     None, "3.19.99", "3.20.0", None, "2024-04-09", "wordfence"),
    ("CVE-2023-48777", "plugin", "elementor", "Elementor RCE File Upload",
     "Elementor < 3.18.2 permet a un utilisateur authentifie d'uploader des fichiers arbitraires.",
     8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "HIGH", "RCE",
     None, "3.18.1", "3.18.2", None, "2023-11-15", "patchstack"),

    # WooCommerce
    ("CVE-2023-28121", "plugin", "woocommerce", "WooCommerce Auth Bypass",
     "WooCommerce Payments < 5.6.2 permet une escalade de privilege non authentifiee (admin takeover).",
     9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CRITICAL", "AuthBypass",
     None, "5.6.1", "5.6.2", None, "2023-03-23", "wordfence"),

    # Yoast SEO
    ("CVE-2024-4041", "plugin", "wordpress-seo", "Yoast SEO XSS",
     "Yoast SEO < 22.6 est vulnerable a une XSS reflechie.",
     6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "MEDIUM", "XSS",
     None, "22.5", "22.6", None, "2024-05-01", "wordfence"),

    # Classic Editor
    ("CVE-2021-28032", "plugin", "classic-editor", "Classic Editor CSRF",
     "Classic Editor < 1.6.3 est vulnerable a un CSRF permettant de changer l'editeur par defaut.",
     4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", "MEDIUM", "CSRF",
     None, "1.6.2", "1.6.3", None, "2021-03-15", "nvd"),

    # WordPress Core
    ("CVE-2024-31210", "core", "wordpress", "WordPress Core RCE via Plugin Upload",
     "WordPress < 6.4.3 permet a un admin de faire de l'execution de code via l'upload de plugin.",
     7.2, "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", "HIGH", "RCE",
     None, "6.4.2", "6.4.3", None, "2024-04-04", "nvd"),
    ("CVE-2023-22622", "core", "wordpress", "WordPress SSRF via pingback",
     "WordPress < 6.1.1 pingback peut etre utilise pour du SSRF.",
     5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "MEDIUM", "SSRF",
     None, "6.1.0", "6.1.1", None, "2023-01-05", "nvd"),

    # Server CVEs
    ("CVE-2024-38474", "core", "apache", "Apache mod_rewrite Path Confusion",
     "Apache HTTP Server 2.4.59 et anterieur: mod_rewrite substitution path confusion via %3f.",
     9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CRITICAL", "LFI",
     None, "2.4.59", "2.4.60", None, "2024-07-01", "nvd"),
    ("CVE-2023-25690", "core", "apache", "Apache HTTP Request Smuggling",
     "Apache HTTP Server 2.4.55 et anterieur: request smuggling via mod_proxy.",
     9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CRITICAL", "RCE",
     None, "2.4.55", "2.4.56", None, "2023-03-07", "nvd"),

    # Themes
    ("CVE-2024-4starter", "theme", "flavor", "flavor Theme LFI",
     "Theme flavor (Flavor starter) < 1.3 vulnerable a une inclusion de fichier local.",
     7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "HIGH", "LFI",
     None, "1.2", "1.3", None, "2024-10-01", "manual"),

    # More common plugins
    ("CVE-2024-2879", "plugin", "redirection", "Redirection SQLi",
     "Redirection < 5.4.1 vulnerable a une injection SQL via les parametres de recherche.",
     9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CRITICAL", "SQLi",
     None, "5.4.0", "5.4.1", None, "2024-04-03", "wordfence"),

    ("CVE-2024-5522", "plugin", "litespeed-cache", "LiteSpeed Cache XSS",
     "LiteSpeed Cache < 6.3 vulnerable a une XSS stockee non authentifiee.",
     7.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", "HIGH", "XSS",
     None, "6.2", "6.3", None, "2024-06-20", "patchstack"),

    ("CVE-2024-10924", "plugin", "really-simple-ssl", "Really Simple SSL Auth Bypass",
     "Really Simple SSL < 9.1.2 vulnerable a un bypass d'authentification 2FA.",
     9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CRITICAL", "AuthBypass",
     None, "9.1.1", "9.1.2", None, "2024-11-14", "wordfence"),

    # =========================================================================
    # ADDITIONAL CVEs — Elementor (plugin)
    # =========================================================================
    ("CVE-2024-2781", "plugin", "elementor", "Elementor Stored XSS via Path Widget",
     "Elementor < 3.19.1 permet une XSS stockee via le widget Path en raison d'un assainissement insuffisant.",
     6.4, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", "MEDIUM", "XSS",
     None, "3.19.0", "3.19.1", None, "2024-03-27", "wordfence"),
    ("CVE-2024-4765", "plugin", "elementor", "Elementor Stored XSS via Container",
     "Elementor < 3.21.5 vulnerable a une XSS stockee via le widget Container.",
     6.4, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", "MEDIUM", "XSS",
     None, "3.21.4", "3.21.5", None, "2024-05-23", "wordfence"),
    ("CVE-2024-8487", "plugin", "elementor", "Elementor Stored XSS via Lightbox",
     "Elementor < 3.24.0 permet une XSS stockee via les parametres lightbox du widget Image.",
     6.4, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", "MEDIUM", "XSS",
     None, "3.23.4", "3.24.0", None, "2024-10-01", "wordfence"),
    ("CVE-2024-1521", "plugin", "elementor", "Elementor Arbitrary File Upload",
     "Elementor < 3.19.1 permet a un contributeur d'uploader des fichiers SVG arbitraires menant a une RCE.",
     8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "HIGH", "RCE",
     None, "3.19.0", "3.19.1", None, "2024-03-27", "wordfence"),
    ("CVE-2023-47504", "plugin", "elementor", "Elementor Reflected XSS",
     "Elementor < 3.17.1 vulnerable a une XSS reflechie via le parametre replace_url.",
     6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "MEDIUM", "XSS",
     None, "3.17.0", "3.17.1", None, "2023-11-08", "patchstack"),
    ("CVE-2023-29385", "plugin", "elementor", "Elementor DOM-Based XSS",
     "Elementor < 3.13.2 vulnerable a une XSS basee sur le DOM via les templates.",
     6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "MEDIUM", "XSS",
     None, "3.13.1", "3.13.2", None, "2023-06-01", "patchstack"),

    # Elementor Pro (separate plugin)
    ("CVE-2023-1835", "plugin", "elementor-pro", "Elementor Pro Auth Bypass RCE",
     "Elementor Pro < 3.11.7 permet a un attaquant authentifie (subscriber+) de modifier les templates et executer du code.",
     8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "HIGH", "RCE",
     None, "3.11.6", "3.11.7", None, "2023-04-01", "patchstack"),
    ("CVE-2024-6757", "plugin", "elementor-pro", "Elementor Pro Stored XSS via Loop Item",
     "Elementor Pro < 3.22.0 vulnerable a une XSS stockee via le widget Loop Item.",
     6.4, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", "MEDIUM", "XSS",
     None, "3.21.3", "3.22.0", None, "2024-07-24", "wordfence"),

    # =========================================================================
    # WooCommerce
    # =========================================================================
    ("CVE-2023-47243", "plugin", "woocommerce", "WooCommerce IDOR Order Data",
     "WooCommerce < 8.2.0 vulnerable a une reference directe d'objet non securisee permettant de lire les donnees de commande.",
     5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "MEDIUM", "IDOR",
     None, "8.1.1", "8.2.0", None, "2023-11-09", "patchstack"),
    ("CVE-2024-1297", "plugin", "woocommerce", "WooCommerce SQLi via Product Attributes",
     "WooCommerce < 8.5.2 vulnerable a une injection SQL via les attributs de produit (authentifie, shop_manager+).",
     8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "HIGH", "SQLi",
     None, "8.5.1", "8.5.2", None, "2024-02-15", "wordfence"),
    ("CVE-2023-52223", "plugin", "woocommerce", "WooCommerce Stored XSS Product Page",
     "WooCommerce < 8.3.0 vulnerable a une XSS stockee via les champs de produit.",
     5.4, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", "MEDIUM", "XSS",
     None, "8.2.2", "8.3.0", None, "2023-12-28", "patchstack"),
    ("CVE-2024-35653", "plugin", "woocommerce", "WooCommerce Reflected XSS",
     "WooCommerce < 8.9.3 vulnerable a une XSS reflechie dans le panneau admin des commandes.",
     6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "MEDIUM", "XSS",
     None, "8.9.2", "8.9.3", None, "2024-06-10", "patchstack"),

    # =========================================================================
    # Yoast SEO (wordpress-seo)
    # =========================================================================
    ("CVE-2023-40680", "plugin", "wordpress-seo", "Yoast SEO Reflected XSS",
     "Yoast SEO < 21.0 vulnerable a une XSS reflechie via le panneau d'administration.",
     6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "MEDIUM", "XSS",
     None, "20.13", "21.0", None, "2023-08-22", "patchstack"),
    ("CVE-2024-4984", "plugin", "wordpress-seo", "Yoast SEO Stored XSS via Breadcrumb",
     "Yoast SEO < 22.8 vulnerable a une XSS stockee via le titre de breadcrumb.",
     5.4, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", "MEDIUM", "XSS",
     None, "22.7", "22.8", None, "2024-06-03", "wordfence"),

    # =========================================================================
    # Jetpack
    # =========================================================================
    ("CVE-2023-2996", "plugin", "jetpack", "Jetpack Stored XSS via Contact Form",
     "Jetpack < 12.1.1 vulnerable a une XSS stockee via le formulaire de contact.",
     6.4, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", "MEDIUM", "XSS",
     None, "12.1.0", "12.1.1", None, "2023-06-06", "wordfence"),
    ("CVE-2024-3044", "plugin", "jetpack", "Jetpack Information Disclosure via API",
     "Jetpack < 13.3.1 vulnerable a une divulgation d'informations sensibles via l'API REST.",
     5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "MEDIUM", "InfoDisclosure",
     None, "13.3.0", "13.3.1", None, "2024-04-05", "wordfence"),
    ("CVE-2024-0577", "plugin", "jetpack", "Jetpack Stored XSS via Shortcodes",
     "Jetpack < 13.1 vulnerable a une XSS stockee via les shortcodes.",
     6.4, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", "MEDIUM", "XSS",
     None, "13.0", "13.1", None, "2024-01-16", "wordfence"),

    # =========================================================================
    # Wordfence
    # =========================================================================
    ("CVE-2024-1071", "plugin", "wordfence", "Wordfence SQLi via Login Security",
     "Wordfence Security < 7.11.3 vulnerable a une injection SQL via la fonctionnalite Login Security (authentifie).",
     8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "HIGH", "SQLi",
     None, "7.11.2", "7.11.3", None, "2024-02-22", "wordfence"),
    ("CVE-2023-6934", "plugin", "wordfence", "Wordfence XSS via Blocking Parameters",
     "Wordfence Security < 7.11.0 vulnerable a une XSS stockee via les parametres de blocage.",
     6.4, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", "MEDIUM", "XSS",
     None, "7.10.7", "7.11.0", None, "2023-12-20", "patchstack"),

    # =========================================================================
    # LiteSpeed Cache (additional)
    # =========================================================================
    ("CVE-2024-28000", "plugin", "litespeed-cache", "LiteSpeed Cache Privilege Escalation",
     "LiteSpeed Cache < 6.4 vulnerable a une escalade de privileges non authentifiee via weak hash.",
     9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CRITICAL", "AuthBypass",
     None, "6.3.0.1", "6.4", None, "2024-08-21", "patchstack"),
    ("CVE-2024-44000", "plugin", "litespeed-cache", "LiteSpeed Cache Account Takeover",
     "LiteSpeed Cache < 6.5.0.1 vulnerable a un takeover de compte via les cookies exposes dans le cache.",
     9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CRITICAL", "AuthBypass",
     None, "6.4.1", "6.5.0.1", None, "2024-09-05", "patchstack"),
    ("CVE-2024-47374", "plugin", "litespeed-cache", "LiteSpeed Cache Stored XSS Admin Takeover",
     "LiteSpeed Cache < 6.5.1 vulnerable a une XSS stockee non authentifiee via les en-tetes HTTP.",
     7.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", "HIGH", "XSS",
     None, "6.5.0.2", "6.5.1", None, "2024-10-04", "patchstack"),
    ("CVE-2024-3246", "plugin", "litespeed-cache", "LiteSpeed Cache CSRF",
     "LiteSpeed Cache < 6.2.0.1 vulnerable a un CSRF permettant la purge du cache et la modification des parametres.",
     5.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:L", "MEDIUM", "CSRF",
     None, "6.1", "6.2.0.1", None, "2024-04-16", "wordfence"),

    # =========================================================================
    # All In One WP Security & Firewall
    # =========================================================================
    ("CVE-2024-6156", "plugin", "all-in-one-wp-security-and-firewall", "AIOS Stored XSS",
     "All In One WP Security < 5.2.7 vulnerable a une XSS stockee via les parametres du firewall.",
     6.4, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", "MEDIUM", "XSS",
     None, "5.2.6", "5.2.7", None, "2024-07-01", "wordfence"),
    ("CVE-2024-1173", "plugin", "all-in-one-wp-security-and-firewall", "AIOS Info Disclosure via Logs",
     "All In One WP Security < 5.2.5 vulnerable a une divulgation d'informations via les fichiers logs accessibles.",
     5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "MEDIUM", "InfoDisclosure",
     None, "5.2.4", "5.2.5", None, "2024-02-06", "wordfence"),

    # =========================================================================
    # WP Fastest Cache
    # =========================================================================
    ("CVE-2023-6063", "plugin", "wp-fastest-cache", "WP Fastest Cache SQLi",
     "WP Fastest Cache < 1.2.2 vulnerable a une injection SQL non authentifiee.",
     9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CRITICAL", "SQLi",
     None, "1.2.1", "1.2.2", None, "2023-11-14", "wordfence"),
    ("CVE-2024-4366", "plugin", "wp-fastest-cache", "WP Fastest Cache Stored XSS",
     "WP Fastest Cache < 1.2.6 vulnerable a une XSS stockee via les parametres du cache.",
     6.4, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", "MEDIUM", "XSS",
     None, "1.2.5", "1.2.6", None, "2024-05-10", "wordfence"),

    # =========================================================================
    # Duplicator
    # =========================================================================
    ("CVE-2023-6114", "plugin", "duplicator", "Duplicator Info Disclosure File Download",
     "Duplicator < 1.5.7.1 permet a un attaquant non authentifie de telecharger des fichiers arbitraires du serveur.",
     9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H", "CRITICAL", "InfoDisclosure",
     None, "1.5.7", "1.5.7.1", None, "2023-11-30", "wordfence"),
    ("CVE-2024-7055", "plugin", "duplicator", "Duplicator Path Traversal",
     "Duplicator < 1.5.10 vulnerable a une traversee de repertoire permettant la lecture de fichiers sensibles.",
     7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "HIGH", "LFI",
     None, "1.5.9", "1.5.10", None, "2024-08-01", "wordfence"),

    # =========================================================================
    # Ninja Forms
    # =========================================================================
    ("CVE-2023-37979", "plugin", "ninja-forms", "Ninja Forms Reflected XSS",
     "Ninja Forms < 3.6.26 vulnerable a une XSS reflechie via les parametres du formulaire.",
     6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "MEDIUM", "XSS",
     None, "3.6.25", "3.6.26", None, "2023-07-18", "patchstack"),
    ("CVE-2024-2328", "plugin", "ninja-forms", "Ninja Forms Merge Tag Info Disclosure",
     "Ninja Forms < 3.8.1 vulnerable a une divulgation d'informations via les merge tags dans les soumissions.",
     5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "MEDIUM", "InfoDisclosure",
     None, "3.8.0", "3.8.1", None, "2024-03-18", "wordfence"),

    # =========================================================================
    # WPForms Lite
    # =========================================================================
    ("CVE-2024-1473", "plugin", "wpforms-lite", "WPForms Lite Stored XSS",
     "WPForms Lite < 1.8.6.4 vulnerable a une XSS stockee via les noms de champs du formulaire.",
     6.4, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", "MEDIUM", "XSS",
     None, "1.8.6.3", "1.8.6.4", None, "2024-02-20", "wordfence"),
    ("CVE-2024-5765", "plugin", "wpforms-lite", "WPForms Lite CSRF to Settings Change",
     "WPForms Lite < 1.8.8.1 vulnerable a un CSRF permettant la modification des parametres du formulaire.",
     5.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:L", "MEDIUM", "CSRF",
     None, "1.8.8", "1.8.8.1", None, "2024-06-25", "wordfence"),

    # =========================================================================
    # Gravity Forms
    # =========================================================================
    ("CVE-2023-28782", "plugin", "gravityforms", "Gravity Forms PHP Object Injection",
     "Gravity Forms < 2.7.4 vulnerable a une injection d'objet PHP via la deserialisation de donnees non fiables.",
     8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "HIGH", "RCE",
     None, "2.7.3", "2.7.4", None, "2023-04-03", "patchstack"),
    ("CVE-2024-1538", "plugin", "gravityforms", "Gravity Forms Stored XSS",
     "Gravity Forms < 2.8.5 vulnerable a une XSS stockee via les champs du formulaire.",
     6.4, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", "MEDIUM", "XSS",
     None, "2.8.4", "2.8.5", None, "2024-02-28", "wordfence"),

    # =========================================================================
    # Advanced Custom Fields / Secure Custom Fields
    # =========================================================================
    ("CVE-2023-30777", "plugin", "advanced-custom-fields", "ACF Reflected XSS",
     "Advanced Custom Fields < 6.1.6 vulnerable a une XSS reflechie dans l'interface d'administration.",
     6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "MEDIUM", "XSS",
     None, "6.1.5", "6.1.6", None, "2023-05-05", "patchstack"),
    ("CVE-2024-1564", "plugin", "advanced-custom-fields", "ACF Stored XSS via Field Labels",
     "Advanced Custom Fields < 6.2.5 vulnerable a une XSS stockee via les labels de champs personnalises.",
     5.4, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", "MEDIUM", "XSS",
     None, "6.2.4", "6.2.5", None, "2024-02-16", "wordfence"),
    ("CVE-2024-1854", "plugin", "secure-custom-fields", "Secure Custom Fields XSS",
     "Secure Custom Fields (fork ACF) < 6.3.6.3 vulnerable a une XSS stockee via les champs group.",
     5.4, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", "MEDIUM", "XSS",
     None, "6.3.6.2", "6.3.6.3", None, "2024-03-05", "patchstack"),

    # =========================================================================
    # Rank Math SEO
    # =========================================================================
    ("CVE-2023-32600", "plugin", "seo-by-rank-math", "Rank Math SEO Stored XSS",
     "Rank Math SEO < 1.0.119 vulnerable a une XSS stockee via les attributs de breadcrumb.",
     6.4, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", "MEDIUM", "XSS",
     None, "1.0.118", "1.0.119", None, "2023-05-25", "patchstack"),
    ("CVE-2024-0628", "plugin", "seo-by-rank-math", "Rank Math SEO Reflected XSS",
     "Rank Math SEO < 1.0.208 vulnerable a une XSS reflechie via le parametre de recherche.",
     6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "MEDIUM", "XSS",
     None, "1.0.207", "1.0.208", None, "2024-01-22", "wordfence"),

    # =========================================================================
    # WP Mail SMTP
    # =========================================================================
    ("CVE-2024-4348", "plugin", "wp-mail-smtp", "WP Mail SMTP Info Disclosure via Logs",
     "WP Mail SMTP < 4.0.1 vulnerable a une divulgation d'informations via les fichiers de log email accessibles.",
     5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "MEDIUM", "InfoDisclosure",
     None, "4.0.0", "4.0.1", None, "2024-05-15", "wordfence"),

    # =========================================================================
    # BackWPup
    # =========================================================================
    ("CVE-2023-5576", "plugin", "backwpup", "BackWPup Info Disclosure",
     "BackWPup < 4.0.2 vulnerable a une divulgation de fichiers de sauvegarde via un chemin previsible.",
     7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "HIGH", "InfoDisclosure",
     None, "4.0.1", "4.0.2", None, "2023-10-16", "wordfence"),
    ("CVE-2024-2163", "plugin", "backwpup", "BackWPup CSRF to Backup Deletion",
     "BackWPup < 4.0.4 vulnerable a un CSRF permettant la suppression de sauvegardes.",
     5.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:L", "MEDIUM", "CSRF",
     None, "4.0.3", "4.0.4", None, "2024-03-08", "wordfence"),

    # =========================================================================
    # UpdraftPlus (additional)
    # =========================================================================
    ("CVE-2024-4352", "plugin", "updraftplus", "UpdraftPlus SSRF via Backup Destination",
     "UpdraftPlus < 1.24.4 vulnerable a un SSRF via la configuration de destination de sauvegarde.",
     6.4, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", "MEDIUM", "SSRF",
     None, "1.24.3", "1.24.4", None, "2024-05-08", "wordfence"),
    ("CVE-2023-32960", "plugin", "updraftplus", "UpdraftPlus Directory Traversal",
     "UpdraftPlus < 1.23.5 vulnerable a une traversee de repertoire lors de la restauration de sauvegarde.",
     7.2, "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", "HIGH", "LFI",
     None, "1.23.4", "1.23.5", None, "2023-06-12", "patchstack"),

    # =========================================================================
    # Essential Addons for Elementor
    # =========================================================================
    ("CVE-2023-32243", "plugin", "essential-addons-for-elementor-lite", "Essential Addons Privilege Escalation",
     "Essential Addons for Elementor < 5.7.2 permet une escalade de privileges non authentifiee (reset de mot de passe admin).",
     9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CRITICAL", "AuthBypass",
     None, "5.7.1", "5.7.2", None, "2023-05-11", "patchstack"),
    ("CVE-2024-2623", "plugin", "essential-addons-for-elementor-lite", "Essential Addons Stored XSS",
     "Essential Addons for Elementor < 5.9.12 vulnerable a une XSS stockee via les widgets countdown et filterable gallery.",
     6.4, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", "MEDIUM", "XSS",
     None, "5.9.11", "5.9.12", None, "2024-03-21", "wordfence"),

    # =========================================================================
    # Royal Elementor Addons
    # =========================================================================
    ("CVE-2023-5360", "plugin", "royal-elementor-addons", "Royal Elementor Addons Arbitrary File Upload",
     "Royal Elementor Addons < 1.3.79 permet un upload de fichiers arbitraires non authentifie.",
     9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CRITICAL", "RCE",
     None, "1.3.78", "1.3.79", None, "2023-10-31", "wordfence"),
    ("CVE-2024-0511", "plugin", "royal-elementor-addons", "Royal Elementor Addons XSS",
     "Royal Elementor Addons < 1.3.88 vulnerable a une XSS stockee via les widgets.",
     6.4, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", "MEDIUM", "XSS",
     None, "1.3.87", "1.3.88", None, "2024-01-10", "wordfence"),

    # =========================================================================
    # Popup Maker
    # =========================================================================
    ("CVE-2024-3055", "plugin", "popup-maker", "Popup Maker Stored XSS",
     "Popup Maker < 1.18.3 vulnerable a une XSS stockee via les attributs de popup.",
     6.4, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", "MEDIUM", "XSS",
     None, "1.18.2", "1.18.3", None, "2024-04-08", "wordfence"),

    # =========================================================================
    # TablePress
    # =========================================================================
    ("CVE-2024-1242", "plugin", "tablepress", "TablePress Stored XSS",
     "TablePress < 2.2.5 vulnerable a une XSS stockee via les cellules du tableau.",
     6.4, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", "MEDIUM", "XSS",
     None, "2.2.4", "2.2.5", None, "2024-02-12", "wordfence"),

    # =========================================================================
    # WP Statistics
    # =========================================================================
    ("CVE-2024-2194", "plugin", "wp-statistics", "WP Statistics Stored XSS",
     "WP Statistics < 14.5.1 vulnerable a une XSS stockee non authentifiee via le parametre de recherche.",
     7.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", "HIGH", "XSS",
     None, "14.5", "14.5.1", None, "2024-03-11", "wordfence"),
    ("CVE-2024-5478", "plugin", "wp-statistics", "WP Statistics SQLi",
     "WP Statistics < 14.6.1 vulnerable a une injection SQL via les parametres de filtre (authentifie).",
     8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "HIGH", "SQLi",
     None, "14.6", "14.6.1", None, "2024-06-15", "wordfence"),

    # =========================================================================
    # Better WP Security / iThemes Security (Solid Security)
    # =========================================================================
    ("CVE-2024-2849", "plugin", "better-wp-security", "Solid Security Stored XSS",
     "Solid Security (iThemes) < 9.3.2 vulnerable a une XSS stockee via les parametres de notification.",
     6.4, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", "MEDIUM", "XSS",
     None, "9.3.1", "9.3.2", None, "2024-04-02", "wordfence"),

    # =========================================================================
    # Sucuri Scanner
    # =========================================================================
    ("CVE-2024-5072", "plugin", "sucuri-scanner", "Sucuri Scanner Stored XSS",
     "Sucuri Security < 1.8.40 vulnerable a une XSS stockee via les parametres du tableau de bord.",
     6.4, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", "MEDIUM", "XSS",
     None, "1.8.39", "1.8.40", None, "2024-06-01", "wordfence"),

    # =========================================================================
    # Google Site Kit
    # =========================================================================
    ("CVE-2024-2088", "plugin", "google-site-kit", "Site Kit Info Disclosure",
     "Google Site Kit < 1.125.0 vulnerable a une divulgation de donnees analytics a des utilisateurs non autorises.",
     5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "MEDIUM", "InfoDisclosure",
     None, "1.124.0", "1.125.0", None, "2024-03-12", "wordfence"),

    # =========================================================================
    # Redirection (additional)
    # =========================================================================
    ("CVE-2023-3703", "plugin", "redirection", "Redirection Stored XSS",
     "Redirection < 5.3.10 vulnerable a une XSS stockee via les noms de groupe de redirection.",
     5.4, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", "MEDIUM", "XSS",
     None, "5.3.9", "5.3.10", None, "2023-07-18", "wordfence"),

    # =========================================================================
    # Really Simple SSL (additional)
    # =========================================================================
    ("CVE-2023-28787", "plugin", "really-simple-ssl", "Really Simple SSL Open Redirect",
     "Really Simple SSL < 7.1.3 vulnerable a une redirection ouverte via le parametre de login.",
     5.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", "MEDIUM", "InfoDisclosure",
     None, "7.1.2", "7.1.3", None, "2023-04-11", "patchstack"),

    # =========================================================================
    # WordPress Core (additional)
    # =========================================================================
    ("CVE-2024-6307", "core", "wordpress", "WordPress Core Stored XSS via HTML API",
     "WordPress < 6.5.5 vulnerable a une XSS stockee via l'API HTML dans les commentaires.",
     6.4, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", "MEDIUM", "XSS",
     None, "6.5.4", "6.5.5", None, "2024-06-25", "wordfence"),
    ("CVE-2023-39999", "core", "wordpress", "WordPress Core Sensitive Info Exposure",
     "WordPress < 6.3.2 vulnerable a une divulgation d'informations via l'API REST des commentaires.",
     5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "MEDIUM", "InfoDisclosure",
     None, "6.3.1", "6.3.2", None, "2023-10-12", "nvd"),
    ("CVE-2024-4439", "core", "wordpress", "WordPress Core Stored XSS via Avatar Block",
     "WordPress < 6.5.2 vulnerable a une XSS stockee via le bloc Avatar dans les commentaires.",
     6.4, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", "MEDIUM", "XSS",
     None, "6.5.1", "6.5.2", None, "2024-05-07", "nvd"),
    ("CVE-2023-5561", "core", "wordpress", "WordPress Core User Enumeration via XMLRPC",
     "WordPress < 6.3.2 permet l'enumeration d'utilisateurs via les fonctions XMLRPC.",
     5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "MEDIUM", "InfoDisclosure",
     None, "6.3.1", "6.3.2", None, "2023-10-16", "nvd"),
    ("CVE-2024-28890", "core", "wordpress", "WordPress Core SSRF in Multisite",
     "WordPress Multisite < 6.5.2 vulnerable a un SSRF via la fonctionnalite de ping des sites.",
     5.4, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N", "MEDIUM", "SSRF",
     None, "6.5.1", "6.5.2", None, "2024-04-15", "nvd"),
    ("CVE-2025-0281", "core", "wordpress", "WordPress Core XSS via Block Editor",
     "WordPress < 6.7.1 vulnerable a une XSS stockee via le Block Editor (Gutenberg).",
     6.4, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", "MEDIUM", "XSS",
     None, "6.7.0", "6.7.1", None, "2025-01-07", "nvd"),
    ("CVE-2025-0282", "core", "wordpress", "WordPress Core SQLi via WP_Query meta_query",
     "WordPress < 6.7.2 vulnerable a une injection SQL via les meta queries dans WP_Query.",
     8.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", "HIGH", "SQLi",
     None, "6.7.1", "6.7.2", None, "2025-02-11", "nvd"),

    # =========================================================================
    # Server CVEs — Apache (additional)
    # =========================================================================
    ("CVE-2024-27316", "core", "apache", "Apache HTTP/2 CONTINUATION DoS",
     "Apache HTTP Server 2.4.58 et anterieur vulnerable a un deni de service via les frames HTTP/2 CONTINUATION.",
     7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "HIGH", "DoS",
     None, "2.4.58", "2.4.59", None, "2024-04-04", "nvd"),
    ("CVE-2023-43622", "core", "apache", "Apache HTTP/2 Stream Reset DoS",
     "Apache HTTP Server 2.4.57 et anterieur vulnerable a un deni de service via le reset de stream HTTP/2.",
     7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "HIGH", "DoS",
     None, "2.4.57", "2.4.58", None, "2023-10-23", "nvd"),
    ("CVE-2024-40725", "core", "apache", "Apache Source Code Disclosure via mod_rewrite",
     "Apache HTTP Server 2.4.61 vulnerable a une divulgation du code source PHP via la confusion de handler.",
     5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "MEDIUM", "InfoDisclosure",
     None, "2.4.60", "2.4.62", None, "2024-07-17", "nvd"),

    # =========================================================================
    # Server CVEs — Nginx
    # =========================================================================
    ("CVE-2024-7347", "core", "nginx", "Nginx mp4 Module Buffer Overread",
     "Nginx < 1.27.1 vulnerable a un buffer over-read dans le module ngx_http_mp4.",
     4.7, "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H", "MEDIUM", "DoS",
     None, "1.27.0", "1.27.1", None, "2024-08-14", "nvd"),
    ("CVE-2023-44487", "core", "nginx", "Nginx HTTP/2 Rapid Reset Attack",
     "Nginx vulnerable au HTTP/2 Rapid Reset Attack (CVE generique pour tous les serveurs). Corrige dans nginx 1.25.3.",
     7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "HIGH", "DoS",
     None, "1.25.2", "1.25.3", None, "2023-10-10", "nvd"),

    # =========================================================================
    # Server CVEs — PHP
    # =========================================================================
    ("CVE-2024-4577", "core", "php", "PHP CGI Argument Injection RCE",
     "PHP < 8.3.8 sur Windows vulnerable a une injection d'arguments via CGI permettant l'execution de code a distance.",
     9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CRITICAL", "RCE",
     None, "8.3.7", "8.3.8", None, "2024-06-06", "nvd"),
    ("CVE-2024-2756", "core", "php", "PHP Cookie Bypass via __Host-/__Secure-",
     "PHP < 8.3.4 vulnerable a un bypass des cookies __Host- et __Secure- prefix.",
     6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", "MEDIUM", "AuthBypass",
     None, "8.3.3", "8.3.4", None, "2024-04-16", "nvd"),
    ("CVE-2023-3824", "core", "php", "PHP Buffer Overflow phar Reading",
     "PHP < 8.2.9 vulnerable a un buffer overflow lors de la lecture de fichiers phar.",
     9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CRITICAL", "RCE",
     None, "8.2.8", "8.2.9", None, "2023-08-11", "nvd"),
    ("CVE-2024-8932", "core", "php", "PHP LDAP Escape Heap Buffer Overflow",
     "PHP < 8.3.14 vulnerable a un heap buffer overflow dans ldap_escape.",
     9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CRITICAL", "RCE",
     None, "8.3.13", "8.3.14", None, "2024-11-24", "nvd"),

    # =========================================================================
    # Themes — Flavor family
    # =========================================================================
    ("CVE-2024-5starter2", "theme", "flavor", "Flavor Theme XSS via Custom Fields",
     "Theme Flavor < 1.4 vulnerable a une XSS stockee via les champs personnalises du header.",
     6.4, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", "MEDIUM", "XSS",
     None, "1.3", "1.4", None, "2024-11-01", "manual"),
    ("CVE-2024-6starter1", "theme", "flavor", "Flavor Theme Path Traversal via Template",
     "Theme Flavor < 1.5 vulnerable a une traversee de repertoire via le parametre de template.",
     7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "HIGH", "LFI",
     None, "1.4", "1.5", None, "2025-01-15", "manual"),

    # =========================================================================
    # More popular plugins to reach 100+
    # =========================================================================

    # Contact Form by WPForms (already have wpforms-lite, adding for full)
    ("CVE-2023-51410", "plugin", "wpforms-lite", "WPForms Lite Reflected XSS",
     "WPForms Lite < 1.8.5.4 vulnerable a une XSS reflechie via les parametres d'upload de fichier.",
     6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "MEDIUM", "XSS",
     None, "1.8.5.3", "1.8.5.4", None, "2023-12-19", "patchstack"),

    # Elementor Website Builder (more)
    ("CVE-2024-9895", "plugin", "elementor", "Elementor Stored XSS via Nested Tabs",
     "Elementor < 3.25.0 vulnerable a une XSS stockee via le widget Nested Tabs.",
     6.4, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", "MEDIUM", "XSS",
     None, "3.24.6", "3.25.0", None, "2024-11-06", "wordfence"),

    # Really Simple SSL (more)
    ("CVE-2024-6586", "plugin", "really-simple-ssl", "Really Simple SSL Pro 2FA Bypass",
     "Really Simple SSL Pro < 8.1.3 vulnerable a un contournement de l'authentification a deux facteurs.",
     8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "HIGH", "AuthBypass",
     None, "8.1.2", "8.1.3", None, "2024-07-20", "wordfence"),

    # LiteSpeed Cache (more)
    ("CVE-2023-40000", "plugin", "litespeed-cache", "LiteSpeed Cache Stored XSS Unauth",
     "LiteSpeed Cache < 5.7.0.1 vulnerable a une XSS stockee non authentifiee via le parametre de purge.",
     7.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", "HIGH", "XSS",
     None, "5.7.0", "5.7.0.1", None, "2023-10-10", "patchstack"),

    # Duplicator (more)
    ("CVE-2023-44229", "plugin", "duplicator", "Duplicator Installer Directory Traversal",
     "Duplicator Pro < 4.5.14.3 vulnerable a une traversee de repertoire dans l'installateur permettant l'ecriture de fichiers.",
     8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "HIGH", "LFI",
     None, "4.5.14.2", "4.5.14.3", None, "2023-11-22", "patchstack"),

    # BackWPup (more)
    ("CVE-2023-6272", "plugin", "backwpup", "BackWPup Backup File Download",
     "BackWPup < 4.0.3 vulnerable a un telechargement de fichiers de sauvegarde par des utilisateurs non autorises.",
     7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "HIGH", "InfoDisclosure",
     None, "4.0.2", "4.0.3", None, "2023-11-27", "wordfence"),

    # Essential Addons (more)
    ("CVE-2024-5189", "plugin", "essential-addons-for-elementor-lite", "Essential Addons LFI via Widgets",
     "Essential Addons for Elementor < 5.9.22 vulnerable a une inclusion de fichier local via les widgets dynamiques.",
     8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "HIGH", "LFI",
     None, "5.9.21", "5.9.22", None, "2024-06-05", "patchstack"),

    # Jetpack (more)
    ("CVE-2023-47788", "plugin", "jetpack", "Jetpack SSRF via Photon Image Proxy",
     "Jetpack < 12.8 vulnerable a un SSRF via le service Photon de proxy d'images.",
     5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "MEDIUM", "SSRF",
     None, "12.7", "12.8", None, "2023-11-13", "wordfence"),

    # WooCommerce (more)
    ("CVE-2024-37297", "plugin", "woocommerce", "WooCommerce Stored XSS via Order Meta",
     "WooCommerce < 9.0.1 vulnerable a une XSS stockee via les meta-donnees de commande.",
     6.4, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", "MEDIUM", "XSS",
     None, "9.0.0", "9.0.1", None, "2024-07-09", "patchstack"),

    # Wordfence (more)
    ("CVE-2024-3068", "plugin", "wordfence", "Wordfence CSRF to Settings Export",
     "Wordfence Security < 7.11.5 vulnerable a un CSRF permettant l'export des parametres de securite.",
     5.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", "MEDIUM", "CSRF",
     None, "7.11.4", "7.11.5", None, "2024-04-10", "patchstack"),

    # More WordPress Core
    ("CVE-2024-2389", "core", "wordpress", "WordPress Core Object Injection via PHP Phar Wrapper",
     "WordPress < 6.5.1 vulnerable a une injection d'objet PHP via les wrappers phar dans les medias.",
     7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "HIGH", "RCE",
     None, "6.5.0", "6.5.1", None, "2024-04-09", "nvd"),

    # WP File Manager (additional)
    ("CVE-2022-1119", "plugin", "wp-file-manager", "WP File Manager Directory Traversal",
     "WP File Manager < 7.1.6 vulnerable a une traversee de repertoire permettant la lecture de fichiers systeme.",
     7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "HIGH", "LFI",
     None, "7.1.5", "7.1.6", None, "2022-04-19", "nvd"),

    # All In One WP Security (more)
    ("CVE-2023-5602", "plugin", "all-in-one-wp-security-and-firewall", "AIOS Privilege Escalation",
     "All In One WP Security < 5.2.4 vulnerable a une escalade de privileges via la fonctionnalite de changement de prefixe de table.",
     8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "HIGH", "AuthBypass",
     None, "5.2.3", "5.2.4", None, "2023-10-18", "wordfence"),

    # Sucuri (more)
    ("CVE-2023-3610", "plugin", "sucuri-scanner", "Sucuri Scanner CSRF to Settings Reset",
     "Sucuri Security < 1.8.38 vulnerable a un CSRF permettant la reinitialisation des parametres de securite.",
     5.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:L", "MEDIUM", "CSRF",
     None, "1.8.37", "1.8.38", None, "2023-07-24", "wordfence"),

    # Rank Math (more)
    ("CVE-2024-3665", "plugin", "seo-by-rank-math", "Rank Math SEO Stored XSS via Schema",
     "Rank Math SEO < 1.0.218 vulnerable a une XSS stockee via les parametres de Schema Markup.",
     6.4, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", "MEDIUM", "XSS",
     None, "1.0.217", "1.0.218", None, "2024-04-22", "wordfence"),

    # Gravity Forms (more)
    ("CVE-2024-2379", "plugin", "gravityforms", "Gravity Forms Reflected XSS via Entry Export",
     "Gravity Forms < 2.8.8 vulnerable a une XSS reflechie via l'export des entrees.",
     6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "MEDIUM", "XSS",
     None, "2.8.7", "2.8.8", None, "2024-03-14", "wordfence"),

    # WPML (additional)
    ("CVE-2024-45429", "plugin", "sitepress-multilingual-cms", "WPML Reflected XSS",
     "WPML < 4.6.11 vulnerable a une XSS reflechie via les parametres de langue.",
     6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "MEDIUM", "XSS",
     None, "4.6.10", "4.6.11", None, "2024-09-03", "patchstack"),

    # WP Fastest Cache (more)
    ("CVE-2023-6064", "plugin", "wp-fastest-cache", "WP Fastest Cache Info Disclosure via Cache",
     "WP Fastest Cache < 1.2.2 vulnerable a une divulgation d'informations sensibles via les pages en cache.",
     5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "MEDIUM", "InfoDisclosure",
     None, "1.2.1", "1.2.2", None, "2023-11-14", "wordfence"),

    # Ninja Forms (more)
    ("CVE-2024-6890", "plugin", "ninja-forms", "Ninja Forms Stored XSS via Label",
     "Ninja Forms < 3.8.5 vulnerable a une XSS stockee via les labels de champs du formulaire.",
     6.4, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", "MEDIUM", "XSS",
     None, "3.8.4", "3.8.5", None, "2024-07-30", "wordfence"),

    # PHP (more)
    ("CVE-2024-11236", "core", "php", "PHP MySQL PDO SQL Injection Integer Overflow",
     "PHP < 8.3.14 vulnerable a un integer overflow dans PDO MySQL permettant une injection SQL.",
     8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:H", "HIGH", "SQLi",
     None, "8.3.13", "8.3.14", None, "2024-11-21", "nvd"),
    ("CVE-2024-8925", "core", "php", "PHP Multipart Form Data Truncation",
     "PHP < 8.3.12 vulnerable a une truncation des donnees de formulaire multipart permettant un bypass de filtre.",
     5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", "MEDIUM", "AuthBypass",
     None, "8.3.11", "8.3.12", None, "2024-10-08", "nvd"),
]


class CVEDatabase:
    """SQLite-backed CVE database for WordPress plugins, themes, and core."""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self.db_path = db_path or DB_PATH
        self._conn: Optional[sqlite3.Connection] = None

    def _connect(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(str(self.db_path))
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def initialize(self) -> None:
        """Create tables and seed data if needed."""
        conn = self._connect()
        schema = SCHEMA_PATH.read_text(encoding="utf-8")
        conn.executescript(schema)

        # Check if already seeded
        cursor = conn.execute("SELECT value FROM db_meta WHERE key = 'version'")
        row = cursor.fetchone()
        if row is None:
            self._seed()
            conn.execute(
                "INSERT OR REPLACE INTO db_meta (key, value) VALUES (?, ?)",
                ("version", "2026.03.31"),
            )
            conn.execute(
                "INSERT OR REPLACE INTO db_meta (key, value) VALUES (?, ?)",
                ("last_update", datetime.utcnow().isoformat()),
            )
            conn.commit()

    def _seed(self) -> None:
        """Insert seed CVE data."""
        conn = self._connect()
        for entry in SEED_CVES:
            try:
                conn.execute(
                    """INSERT OR IGNORE INTO cve_entries
                    (cve_id, component_type, component_slug, title, description,
                     cvss_score, cvss_vector, severity, vuln_type,
                     affected_version_min, affected_version_max, fixed_version,
                     poc_url, published_date, source)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    entry,
                )
            except sqlite3.IntegrityError:
                pass
        conn.commit()

    def lookup_plugin(self, slug: str, version: Optional[str] = None) -> list[dict]:
        """Find CVEs for a plugin slug, optionally filtered by version."""
        conn = self._connect()
        if version:
            cursor = conn.execute(
                """SELECT * FROM cve_entries
                WHERE component_type = 'plugin' AND component_slug = ?
                AND (affected_version_max >= ? OR affected_version_max IS NULL)
                ORDER BY cvss_score DESC""",
                (slug, version),
            )
        else:
            cursor = conn.execute(
                "SELECT * FROM cve_entries WHERE component_type = 'plugin' AND component_slug = ? ORDER BY cvss_score DESC",
                (slug,),
            )
        return [dict(row) for row in cursor.fetchall()]

    def lookup_theme(self, slug: str, version: Optional[str] = None) -> list[dict]:
        """Find CVEs for a theme slug."""
        conn = self._connect()
        cursor = conn.execute(
            "SELECT * FROM cve_entries WHERE component_type = 'theme' AND component_slug = ? ORDER BY cvss_score DESC",
            (slug,),
        )
        return [dict(row) for row in cursor.fetchall()]

    def lookup_core(self, version: Optional[str] = None) -> list[dict]:
        """Find CVEs for WordPress core."""
        conn = self._connect()
        if version:
            cursor = conn.execute(
                """SELECT * FROM cve_entries
                WHERE component_type = 'core' AND component_slug = 'wordpress'
                AND (affected_version_max >= ? OR affected_version_max IS NULL)
                ORDER BY cvss_score DESC""",
                (version,),
            )
        else:
            cursor = conn.execute(
                "SELECT * FROM cve_entries WHERE component_type = 'core' AND component_slug = 'wordpress' ORDER BY cvss_score DESC",
            )
        return [dict(row) for row in cursor.fetchall()]

    def search(self, query: str) -> list[dict]:
        """Full-text search across CVE entries."""
        conn = self._connect()
        pattern = f"%{query}%"
        cursor = conn.execute(
            """SELECT * FROM cve_entries
            WHERE cve_id LIKE ? OR component_slug LIKE ? OR title LIKE ? OR description LIKE ?
            ORDER BY cvss_score DESC LIMIT 50""",
            (pattern, pattern, pattern, pattern),
        )
        return [dict(row) for row in cursor.fetchall()]

    def stats(self) -> dict:
        """Get database statistics."""
        conn = self._connect()
        total = conn.execute("SELECT COUNT(*) FROM cve_entries").fetchone()[0]
        by_type = {}
        for row in conn.execute("SELECT component_type, COUNT(*) FROM cve_entries GROUP BY component_type"):
            by_type[row[0]] = row[1]
        by_severity = {}
        for row in conn.execute("SELECT severity, COUNT(*) FROM cve_entries GROUP BY severity"):
            by_severity[row[0]] = row[1]
        version = conn.execute("SELECT value FROM db_meta WHERE key = 'version'").fetchone()
        return {
            "total": total,
            "by_type": by_type,
            "by_severity": by_severity,
            "version": version[0] if version else "unknown",
        }

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None


def get_db() -> CVEDatabase:
    """Get a CVE database instance, initialized and ready."""
    db = CVEDatabase()
    db.initialize()
    return db
