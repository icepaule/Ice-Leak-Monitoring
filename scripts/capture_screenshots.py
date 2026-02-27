#!/usr/bin/env python3
"""Capture blurred screenshots of all Ice-Leak-Monitor pages via Playwright.

Usage:
    pip install playwright
    playwright install chromium
    python scripts/capture_screenshots.py [--base-url http://localhost:8084]

Saves screenshots to:
    - docs/screenshots/
    - /root/icepaule.github.io/assets/images/ice-leak-monitoring/
"""

import argparse
import shutil
from pathlib import Path

from playwright.sync_api import sync_playwright, Page

BASE_URL = "http://localhost:8084"

# Output directories
DOCS_DIR = Path(__file__).resolve().parent.parent / "docs" / "screenshots"
PAGES_DIR = Path("/root/icepaule.github.io/assets/images/ice-leak-monitoring")

# CSS selectors to blur per page
BLUR_RULES: dict[str, list[str]] = {
    "dashboard": [
        # Repo names in log and activity feed
        ".log-entry",
        ".activity-text",
    ],
    "keywords": [
        # Keyword terms in table
        "table tbody td:first-child",
        "table tbody td code",
    ],
    "repos": [
        # Repo full_name, Owner, Description, Keywords
        "table tbody td:nth-child(1)",  # Repo name
        "table tbody td:nth-child(2)",  # Owner
        "table tbody td:nth-child(3)",  # Description (if present)
        ".keyword-badges",
        ".repo-name",
        ".repo-link",
        ".repo-owner",
        ".repo-description",
        ".repo-keywords",
    ],
    "findings": [
        # Repo-Name, Detektor, Snippet, Keywords
        "table tbody td:nth-child(2)",  # Repo name
        "table tbody td:nth-child(4)",  # Detector
        "table tbody td:nth-child(5)",  # Snippet / file path
        ".keyword-badges",
        ".finding-snippet",
        ".finding-repo",
    ],
    "settings": [
        # E-Mail address field
        "#email-recipients",
    ],
    "settings_prompt": [
        # Nothing to blur - prompt is generic
    ],
    "scans": [
        # Nothing to blur
    ],
    "repo_detail": [
        # Repo-Name, Keywords, file paths, URL
        "h1",
        ".repo-url",
        ".repo-link",
        ".keyword-badges",
        ".keyword-badge",
        "table tbody td code",  # File paths
        ".repo-keywords",
        ".repo-owner",
        ".repo-description",
        ".match-files",
    ],
}


def inject_blur(page: Page, selectors: list[str]) -> None:
    """Inject CSS blur filter on given selectors."""
    if not selectors:
        return
    css_rules = []
    for sel in selectors:
        css_rules.append(f"{sel} {{ filter: blur(8px) !important; }}")
    combined = "\n".join(css_rules)
    page.evaluate(f"""() => {{
        const style = document.createElement('style');
        style.textContent = `{combined}`;
        document.head.appendChild(style);
    }}""")
    # Give browser a moment to apply styles
    page.wait_for_timeout(300)


def capture_page(
    page: Page,
    url: str,
    name: str,
    selectors: list[str],
    scroll_to_bottom: bool = False,
    full_page: bool = True,
) -> Path:
    """Navigate to URL, apply blur, capture screenshot."""
    page.goto(url, wait_until="networkidle")
    page.wait_for_timeout(500)

    if scroll_to_bottom:
        page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
        page.wait_for_timeout(500)

    inject_blur(page, selectors)

    tmp = DOCS_DIR / f"{name}.png"
    page.screenshot(path=str(tmp), full_page=full_page)
    print(f"  Captured: {name}.png")
    return tmp


def main():
    parser = argparse.ArgumentParser(description="Capture blurred screenshots")
    parser.add_argument("--base-url", default=BASE_URL, help="Base URL of the app")
    args = parser.parse_args()
    base = args.base_url.rstrip("/")

    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    PAGES_DIR.mkdir(parents=True, exist_ok=True)

    screenshots: list[tuple[str, Path]] = []

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        ctx = browser.new_context(
            viewport={"width": 1440, "height": 900},
            device_scale_factor=2,
        )
        page = ctx.new_page()

        # 1. Dashboard
        path = capture_page(page, f"{base}/", "dashboard", BLUR_RULES["dashboard"])
        screenshots.append(("dashboard", path))

        # 2. Keywords
        path = capture_page(page, f"{base}/keywords", "keywords", BLUR_RULES["keywords"])
        screenshots.append(("keywords", path))

        # 3. Repos
        path = capture_page(page, f"{base}/repos", "repos", BLUR_RULES["repos"])
        screenshots.append(("repos", path))

        # 4. Findings
        path = capture_page(page, f"{base}/findings", "findings", BLUR_RULES["findings"])
        screenshots.append(("findings", path))

        # 5. Settings (email section visible)
        path = capture_page(page, f"{base}/settings", "settings", BLUR_RULES["settings"])
        screenshots.append(("settings", path))

        # 6. Settings prompt (scroll down)
        path = capture_page(
            page, f"{base}/settings", "settings_prompt",
            BLUR_RULES["settings_prompt"], scroll_to_bottom=True,
        )
        screenshots.append(("settings_prompt", path))

        # 7. Scans
        path = capture_page(page, f"{base}/scans", "scans", BLUR_RULES["scans"])
        screenshots.append(("scans", path))

        # 8. Repo detail (first repo)
        path = capture_page(page, f"{base}/repos/1", "repo_detail", BLUR_RULES["repo_detail"])
        screenshots.append(("repo_detail", path))

        browser.close()

    # Copy to GitHub Pages directory
    print(f"\nCopying to {PAGES_DIR}:")
    for name, src in screenshots:
        dst = PAGES_DIR / f"{name}.png"
        shutil.copy2(str(src), str(dst))
        print(f"  {dst}")

    print(f"\nDone! {len(screenshots)} screenshots captured.")


if __name__ == "__main__":
    main()
