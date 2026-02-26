"""CrossLinked OSINT module - LinkedIn person search."""

import logging
import subprocess
import tempfile
import os
import csv

logger = logging.getLogger(__name__)


def run_crosslinked(company_name: str, timeout: int = 120) -> list[dict]:
    """Run CrossLinked to find employees on LinkedIn.
    Returns [{"name": "...", "title": "...", "url": "..."}]."""
    persons = []

    try:
        with tempfile.TemporaryDirectory(prefix="crosslinked_") as tmpdir:
            outfile = os.path.join(tmpdir, "results.csv")
            result = subprocess.run(
                [
                    "crosslinked",
                    "-f", "{first}.{last}@{company}.com",
                    company_name,
                    "-o", outfile,
                ],
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=tmpdir,
            )

            # CrossLinked outputs a CSV with name, title, url columns
            if os.path.isfile(outfile):
                with open(outfile, newline="", encoding="utf-8", errors="replace") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        name = row.get("name", row.get("Name", "")).strip()
                        if name:
                            persons.append({
                                "name": name,
                                "title": row.get("title", row.get("Title", "")).strip(),
                                "url": row.get("url", row.get("URL", "")).strip(),
                            })

        logger.info("CrossLinked for '%s': %d persons found", company_name, len(persons))

    except FileNotFoundError:
        logger.warning("crosslinked binary not found, skipping")
    except subprocess.TimeoutExpired:
        logger.warning("CrossLinked timeout for '%s'", company_name)
    except Exception:
        logger.exception("CrossLinked error for '%s'", company_name)

    return persons
