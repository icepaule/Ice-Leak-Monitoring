"""theHarvester OSINT module - E-Mails, hosts, IPs."""

import json
import logging
import subprocess
import tempfile
import os

logger = logging.getLogger(__name__)

SOURCES = "baidu,bing,duckduckgo,yahoo,crtsh,dnsdumpster,hackertarget"


def run_theharvester(domain: str, timeout: int = 180) -> dict:
    """Run theHarvester against a domain.
    Returns {"emails": [], "hosts": [], "ips": []}."""
    results = {"emails": [], "hosts": [], "ips": []}

    try:
        with tempfile.TemporaryDirectory(prefix="harvester_") as tmpdir:
            outfile = os.path.join(tmpdir, "results")
            result = subprocess.run(
                [
                    "theHarvester",
                    "-d", domain,
                    "-b", SOURCES,
                    "-f", outfile,
                ],
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            # theHarvester writes JSON output to <outfile>.json
            json_path = outfile + ".json"
            if os.path.isfile(json_path):
                with open(json_path) as f:
                    data = json.load(f)

                results["emails"] = list(set(data.get("emails", [])))
                results["hosts"] = list(set(data.get("hosts", [])))
                results["ips"] = list(set(data.get("ips", [])))
            else:
                # Parse stdout as fallback
                _parse_stdout(result.stdout, results)

        total = len(results["emails"]) + len(results["hosts"]) + len(results["ips"])
        logger.info("theHarvester for '%s': %d results", domain, total)

    except FileNotFoundError:
        logger.warning("theHarvester binary not found, skipping")
    except subprocess.TimeoutExpired:
        logger.warning("theHarvester timeout for '%s'", domain)
    except Exception:
        logger.exception("theHarvester error for '%s'", domain)

    return results


def _parse_stdout(stdout: str, results: dict):
    """Fallback parser for theHarvester stdout output."""
    section = None
    for line in stdout.splitlines():
        line = line.strip()
        if "Emails found" in line:
            section = "emails"
            continue
        elif "Hosts found" in line:
            section = "hosts"
            continue
        elif "IPs found" in line:
            section = "ips"
            continue
        elif line.startswith("[") or line.startswith("*") or not line:
            continue

        if section and line:
            if line not in results[section]:
                results[section].append(line)
