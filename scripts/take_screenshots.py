"""Take screenshots of the BAZOOKA GUI scanning the DVWP lab.

Requires: GUI running on :8666 and DVWP lab running on :31337.
Output: docs/screenshots/*.png
"""

import asyncio
import sys
import time
from pathlib import Path

import httpx
from playwright.async_api import async_playwright

OUT = Path(__file__).parent.parent / "docs" / "screenshots"
OUT.mkdir(parents=True, exist_ok=True)


async def main() -> None:
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(viewport={"width": 1440, "height": 900},
                                            device_scale_factor=2)
        page = await context.new_page()

        # 1. Dashboard
        await page.goto("http://localhost:8666/", wait_until="networkidle")
        await asyncio.sleep(1)
        await page.screenshot(path=str(OUT / "01-dashboard.png"), full_page=True)
        print("OK 01-dashboard")

        # 2. Start a scan against DVWP
        await page.fill('input[name="url"]', "http://localhost:31337")
        await page.select_option('select[name="profile"]', "standard")
        await page.click('button[type="submit"]')
        await page.wait_for_url("**/scan/**", timeout=10000)
        await asyncio.sleep(8)  # wait scan to populate findings
        await page.screenshot(path=str(OUT / "02-scan-running.png"), full_page=True)
        print("OK 02-scan-running")

        # 3. Wait for scan complete
        try:
            await page.wait_for_selector("#actionsArea:not([style*='display: none'])",
                                        state="visible", timeout=180000)
        except Exception:
            pass
        await asyncio.sleep(2)
        await page.screenshot(path=str(OUT / "03-scan-complete.png"), full_page=True)
        print("OK 03-scan-complete")

        # 4. Report view
        report_link = await page.get_attribute("#reportLink", "href")
        if report_link:
            full = f"http://localhost:8666{report_link}" if report_link.startswith("/") else report_link
            await page.goto(full, wait_until="networkidle")
            await asyncio.sleep(1)
            await page.screenshot(path=str(OUT / "04-report.png"), full_page=False)
            print("OK 04-report (above fold)")
            # Full report
            await page.screenshot(path=str(OUT / "05-report-full.png"), full_page=True)
            print("OK 05-report-full")

        await browser.close()


if __name__ == "__main__":
    asyncio.run(main())
