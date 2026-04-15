"""One-shot screenshot capture for blog/marketing assets.

Captures two screenshots of the running frontend:
  1. Empty / idle state
  2. Malicious-verdict state using the public EICAR SHA-256 test hash

Requires:
  - The backend running on http://127.0.0.1:8765 (make serve)
  - The frontend running on http://localhost:5173 (make ui-dev)
  - playwright + chromium installed (python -m pip install playwright
    && python -m playwright install chromium)

Outputs go to: Blogs/images/menagos-ioc-mcp/ (one level up from the repo)
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

# EICAR test file SHA-256, the de-facto industry-standard benign malware test
# signature. Safe to publish, triggers a real "malicious" verdict on VirusTotal.
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

FRONTEND_URL = "http://localhost:5173/"
OUT_DIR = Path(__file__).resolve().parents[2] / "Blogs" / "images" / "menagos-ioc-mcp"

VIEWPORT = {"width": 1400, "height": 1100}


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as p:
        browser = p.chromium.launch()
        context = browser.new_context(
            viewport=VIEWPORT,
            device_scale_factor=2,  # retina-quality PNG
        )
        page = context.new_page()

        # --- 1. Empty state ---
        page.goto(FRONTEND_URL, wait_until="networkidle")
        page.wait_for_selector("text=Results appear here", timeout=5000)
        # Make sure the search bar isn't focused (so no caret flicker) by
        # clicking the hero headline area.
        page.click("h1")
        time.sleep(0.3)
        empty_path = OUT_DIR / "menagos-ioc-mcp-empty-state.png"
        page.screenshot(path=str(empty_path), full_page=True)
        print(f"wrote {empty_path}")

        # --- 2. Malicious verdict (EICAR hash) ---
        page.fill('input[type="text"]', EICAR_SHA256)
        page.click('button[type="submit"]')
        # Wait for verdict badge to appear.
        page.wait_for_selector(".text-3xl", timeout=15000)
        # Let the score bar finish its CSS transition.
        time.sleep(0.9)

        # Mask the hash: apply CSS blur to the large verdict heading (h2) and
        # to the text inside the search input. We don't want to publish the
        # raw hash even though EICAR is globally known, keeps the screenshot
        # generic for anyone repurposing the asset.
        page.add_style_tag(
            content="""
            h2 {
              filter: blur(8px) !important;
              user-select: none;
            }
            input[type="text"] {
              -webkit-text-security: disc !important;
              text-security: disc !important;
              filter: blur(4px) !important;
            }
            """
        )
        time.sleep(0.3)

        malicious_path = OUT_DIR / "menagos-ioc-mcp-malicious-verdict.png"
        page.screenshot(path=str(malicious_path), full_page=True)
        print(f"wrote {malicious_path}")

        browser.close()

    print(f"\nDone. {OUT_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
