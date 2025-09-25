import logging
from typing import Dict, Any
import requests

logger = logging.getLogger(__name__)

def cve_search(config: Dict[str, Any], cve: str) -> str:
    """Search for CVE details from NIST database."""
    try:
        # Input validation
        if not cve or not cve.strip():
            return "Please provide a valid CVE ID."
        
        cve = cve.strip().upper()
        
        # Validate CVE format (strict check)
        import re
        cve_pattern = r'^CVE-\d{4}-\d{4,}$'
        if not re.match(cve_pattern, cve):
            return "Invalid CVE format. Please provide a CVE ID like CVE-2021-44228."

        r = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}", timeout=config["request_timeout"])
        r.raise_for_status()
        data = r.json()
        if not data.get("vulnerabilities"):
            return f"No vulnerability found for {cve}."

        vuln = data["vulnerabilities"][0]["cve"]
        vuln_name = vuln.get("cisaVulnerabilityName", "N/A")
        vuln_description = vuln["descriptions"][0]["value"] if vuln["descriptions"] else "No description available."
        vuln_references = vuln.get("references", [])
        reference_url = vuln_references[0]["url"] if vuln_references else "No references available."

        return (
            f"```{vuln_name}```\n"
            f"```{vuln_description}```\n"
            f"```{reference_url}```"
        )
    except requests.RequestException as e:
        logger.error(f"Error fetching CVE data for {cve}: {e}")
        return f"Sorry, there was an error fetching CVE information for {cve}."
    except (KeyError, IndexError) as e:
        logger.error(f"Error parsing CVE data for {cve}: {e}")
        return f"Sorry, there was an error processing CVE information for {cve}."
    except Exception as e:
        logger.error(f"Unexpected error in cve_search for {cve}: {e}")
        return "An unexpected error occurred while searching for the CVE."


def package_cve_search(config: Dict[str, Any], package: str) -> str:
    """Search for package vulnerabilities from NIST database."""
    try:
        # Input validation and sanitization
        if not package or not package.strip():
            return "Please provide a valid package name."

        package = package.strip()
        
        # Limit package name length to prevent abuse
        max_package_length = config.get("max_package_length", 100)
        if len(package) > max_package_length:
            return f"Package name too long. Please limit to {max_package_length} characters."
        
        # Basic sanitization - remove potentially dangerous characters
        import re
        if not re.match(r'^[a-zA-Z0-9._-]+$', package):
            return "Invalid package name. Only alphanumeric characters, dots, underscores, and hyphens are allowed."
        r = requests.get(
            f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={package}",
            timeout=config["request_timeout"]
        )
        r.raise_for_status()
        data = r.json()
        vulnerabilities = data.get("vulnerabilities", [])

        if not vulnerabilities:
            return f"No vulnerabilities found for package '{package}'."

        # Limit results to avoid flooding
        max_results = config["max_cve_results"]
        results = vulnerabilities[:max_results]
        s = ""
        for entry in results:
            cve_id = entry["cve"]["id"]
            description = entry["cve"]["descriptions"][0]["value"] if entry["cve"]["descriptions"] else "No description available."
            s += f"```{cve_id}\n{description}```\n\n"

        if len(vulnerabilities) > max_results:
            s += f"... and {len(vulnerabilities) - max_results} more results. Please refine your search."

        return s
    except requests.RequestException as e:
        logger.error(f"Error fetching package CVE data for {package}: {e}")
        return f"Sorry, there was an error fetching CVE information for package '{package}'."
    except (KeyError, IndexError) as e:
        logger.error(f"Error parsing package CVE data for {package}: {e}")
        return f"Sorry, there was an error processing CVE information for package '{package}'."
    except Exception as e:
        logger.error(f"Unexpected error in package_cve_search for {package}: {e}")
        return "An unexpected error occurred while searching for package CVEs."
