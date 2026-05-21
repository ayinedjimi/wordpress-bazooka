"""Tests that ALL modules load correctly and have valid attributes."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.engine import ScanEngine


def test_all_modules_load_aggressive():
    """All modules in aggressive profile must load without import errors."""
    engine = ScanEngine("https://test.com", profile="aggressive", pentest=True, infra=True)
    engine.discover_modules()
    total = sum(len(m) for m in engine._modules.values())
    assert total >= 40, f"Expected >= 40 modules in aggressive, got {total}"


def test_all_modules_have_name():
    engine = ScanEngine("https://test.com", profile="aggressive", pentest=True, infra=True)
    engine.discover_modules()
    for phase, mods in engine._modules.items():
        for mod in mods:
            assert mod.name, f"Module in {phase} has no name"
            assert "." in mod.name, f"Module name {mod.name} should be phase.module_name"


def test_all_modules_have_phase():
    engine = ScanEngine("https://test.com", profile="aggressive", pentest=True, infra=True)
    engine.discover_modules()
    for phase, mods in engine._modules.items():
        for mod in mods:
            assert mod.phase == phase, f"Module {mod.name} has phase={mod.phase} but is in {phase}"


def test_all_modules_have_description():
    engine = ScanEngine("https://test.com", profile="aggressive", pentest=True, infra=True)
    engine.discover_modules()
    for phase, mods in engine._modules.items():
        for mod in mods:
            assert mod.description, f"Module {mod.name} has no description"


def test_all_modules_have_profiles():
    engine = ScanEngine("https://test.com", profile="aggressive", pentest=True, infra=True)
    engine.discover_modules()
    for phase, mods in engine._modules.items():
        for mod in mods:
            assert mod.profiles, f"Module {mod.name} has no profiles"
            assert isinstance(mod.profiles, list)


def test_exploit_modules_are_intrusive():
    engine = ScanEngine("https://test.com", profile="aggressive", pentest=True, infra=True)
    engine.discover_modules()
    for mod in engine._modules.get("exploit", []):
        # wordlist_generator is not intrusive, others should be
        non_intrusive_exploits = ["wordlist", "origin_bypass", "git_dumper", "api_key", "cors_exploit", "woocommerce_idor", "wp_cron_dos"]
        if not any(skip in mod.name for skip in non_intrusive_exploits):
            assert mod.intrusive is True, f"Exploit module {mod.name} should be intrusive"


def test_quick_profile_no_intrusive():
    engine = ScanEngine("https://test.com", profile="quick")
    engine.discover_modules()
    for phase, mods in engine._modules.items():
        for mod in mods:
            assert mod.intrusive is False, f"Quick profile should not include intrusive module {mod.name}"


def test_bugbounty_profile_exists():
    engine = ScanEngine("https://test.com", profile="bugbounty")
    engine.discover_modules()
    total = sum(len(m) for m in engine._modules.values())
    assert total >= 5, f"Bugbounty profile should have modules, got {total}"
    # Should not have exploit modules
    assert len(engine._modules.get("exploit", [])) == 0, "Bugbounty should not have exploit modules"


def test_standard_more_than_quick():
    e_quick = ScanEngine("https://test.com", profile="quick")
    e_quick.discover_modules()
    e_std = ScanEngine("https://test.com", profile="standard")
    e_std.discover_modules()
    total_quick = sum(len(m) for m in e_quick._modules.values())
    total_std = sum(len(m) for m in e_std._modules.values())
    assert total_std > total_quick, f"Standard ({total_std}) should have more modules than quick ({total_quick})"
