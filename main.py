import argparse
import json
import logging
import sys
from typing import Dict, List, Tuple

try:
    import requests
    from bs4 import BeautifulSoup
    import yaml
except ImportError as e:
    print(f"Error importing dependencies: {e}. Please install them (e.g., pip install requests beautifulsoup4 pyyaml)")
    sys.exit(1)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse() -> argparse.ArgumentParser:
    """Sets up the argument parser for the CLI tool."""
    parser = argparse.ArgumentParser(
        description="vac-VulnRemediationPathfinder: Suggests remediation paths for aggregated vulnerabilities based on dependency analysis."
    )
    parser.add_argument(
        "--vulnerability_report",
        type=str,
        required=True,
        help="Path to the vulnerability report file (JSON or YAML).",
    )
    parser.add_argument(
        "--dependency_graph",
        type=str,
        required=True,
        help="Path to the software dependency graph file (e.g., SBOM - JSON or YAML).",
    )
    parser.add_argument(
        "--output",
        type=str,
        help="Path to the output file for remediation suggestions (JSON).",
    )
    parser.add_argument(
        "--aggregate_data",
        action="store_true",
        help="Flag to enable aggregation of vulnerability data from NIST NVD.",
    )
    parser.add_argument(
        "--nvd_api_key",
        type=str,
        help="NIST NVD API key (required if aggregate_data is enabled).",
    )
    
    return parser


def load_data(file_path: str) -> Dict:
    """Loads data from a JSON or YAML file."""
    try:
        with open(file_path, "r") as f:
            if file_path.lower().endswith(".json"):
                return json.load(f)
            elif file_path.lower().endswith(".yaml") or file_path.lower().endswith(".yml"):
                return yaml.safe_load(f)
            else:
                raise ValueError("Unsupported file format.  Must be JSON or YAML.")
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        raise
    except json.JSONDecodeError:
        logging.error(f"Error decoding JSON from: {file_path}")
        raise
    except yaml.YAMLError as e:
        logging.error(f"Error decoding YAML from: {file_path}: {e}")
        raise
    except Exception as e:
        logging.error(f"Error loading data from {file_path}: {e}")
        raise


def aggregate_vulnerability_data(nvd_api_key: str = None, cve_ids: List[str] = None) -> List[Dict]:
    """
    Queries the NVD API once per supplied CVE ID and reads the CVSS
    score from the v2 metrics structure.
    """
    vulnerabilities = []
    if not nvd_api_key:
        logging.warning("NVD API key not provided. Skipping NIST NVD data aggregation.")
        return vulnerabilities
    headers = {"apiKey": nvd_api_key}
    for cve_id in (cve_ids or []):
        try:
            response = requests.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                headers=headers, params={"cveId": cve_id}, timeout=10)
            if response.status_code != 200:
                logging.error(f"Failed to fetch data from NIST NVD for {cve_id}: Status code {response.status_code}")
                continue
            nvd_data = response.json()
            for item in nvd_data.get("vulnerabilities", []):
                cve_data = item["cve"]
                cvss_score = None
                metrics = cve_data.get("metrics") or {}
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    entries = metrics.get(key) or []
                    if entries:
                        cvss_score = (entries[0].get("cvssData") or {}).get("baseScore")
                        if cvss_score is not None:
                            break
                entry = {
                    "cve_id": cve_data["id"],
                    "description": cve_data["descriptions"][0]["value"] if cve_data.get("descriptions") else "No Description",
                    "cvssv3": cvss_score,
                    "source": "NIST NVD",
                }
                for field in ("fixed_version", "target_version"):
                    if cve_data.get(field):
                        entry[field] = cve_data[field]
                vulnerabilities.append(entry)
        except requests.exceptions.RequestException as e:
            logging.error(f"Error fetching data from NIST NVD for {cve_id}: {e}")
        except Exception as e:
            logging.error(f"Error processing NVD data for {cve_id}: {e}")
    return vulnerabilities


def correlate_vulnerabilities(
    vulnerability_report: Dict, aggregated_vulnerabilities: List[Dict]
) -> List[Dict]:
    """Correlates vulnerabilities from the report with aggregated data."""
    correlated_vulnerabilities = []
    if not aggregated_vulnerabilities:
        # Default mode: correlate the report entries directly; the
        # dependency analysis below works from the report itself.
        return [dict(vuln) for vuln in vulnerability_report.get("vulnerabilities", []) if vuln.get("cve_id")]
    for vuln in vulnerability_report.get("vulnerabilities", []):
        cve_id = vuln.get("cve_id")
        if cve_id:
            for agg_vuln in aggregated_vulnerabilities:
                if agg_vuln["cve_id"] == cve_id:
                    correlated_vuln = vuln.copy()  # Create a copy to avoid modifying original
                    correlated_vuln["additional_info"] = agg_vuln
                    correlated_vulnerabilities.append(correlated_vuln)
                    break  # Stop searching after the first match
    return correlated_vulnerabilities


def resolve_fixed_version(vuln: Dict):
    """Resolves a target version from the report entry or its aggregated record, or None."""
    for source in (vuln, vuln.get("additional_info") or {}):
        for field in ("fixed_version", "target_version", "fixedVersion"):
            value = source.get(field)
            if value:
                return str(value)
    return None

def analyze_dependencies(
    dependency_graph: Dict, correlated_vulnerabilities: List[Dict]
) -> Dict:
    """Analyzes dependencies and suggests remediation paths."""
    remediation_suggestions = {}
    dependencies = dependency_graph.get("dependencies", {})
    all_listed = set()
    for deps in dependencies.values():
        all_listed.update(deps or [])
    # The application roots are the graph keys that no other package lists.
    roots = [name for name in dependencies if name not in all_listed]
    if not roots and dependencies:
        roots = [next(iter(dependencies))]
    direct = set()
    for root in roots:
        direct.update(dependencies.get(root) or [])

    for vuln in correlated_vulnerabilities:
        cve_id = vuln.get("cve_id")
        affected_package = vuln.get("affected_package")
        if not affected_package or not cve_id:
            continue
        version = resolve_fixed_version(vuln)
        if version:
            version_text = f"to version {version} or later"
        else:
            version_text = "to a fixed version (no version could be resolved from the report or aggregated data, so check the vendor advisory for the first fixed release)"
        if affected_package in direct:
            remediation_suggestions[cve_id] = {
                "affected_package": affected_package,
                "suggestion": f"Upgrade direct dependency {affected_package} {version_text} to address CVE: {cve_id}",
            }
            continue
        for package, deps in dependencies.items():
            if package in roots:
                continue
            if affected_package in (deps or []):
                remediation_suggestions[cve_id] = {
                    "affected_package": affected_package,
                    "suggestion": f"Upgrade transitive dependency {affected_package} {version_text} to address CVE: {cve_id} by upgrading the dependency that brings it in: {package}",
                }
                break
    return remediation_suggestions


def save_output(data: Dict, output_path: str) -> None:
    """Saves the output data to a JSON file."""
    try:
        with open(output_path, "w") as f:
            json.dump(data, f, indent=4)
        logging.info(f"Output saved to: {output_path}")
    except Exception as e:
        logging.error(f"Error saving output to {output_path}: {e}")
        raise


def main():
    """Main function to orchestrate the vulnerability remediation pathfinder."""
    parser = setup_argparse()
    args = parser.parse_args()

    if args.output:
        from pathlib import Path as _Path
        out_resolved = _Path(args.output).resolve()
        for input_path in (args.vulnerability_report, args.dependency_graph):
            if out_resolved == _Path(input_path).resolve():
                logging.error(f"Output file {args.output} resolves to an input file ({input_path}); refusing to overwrite it.")
                sys.exit(1)
    try:
        # Load data from files
        vulnerability_report = load_data(args.vulnerability_report)
        dependency_graph = load_data(args.dependency_graph)

        # Aggregate vulnerability data if requested
        aggregated_vulnerabilities = []
        if args.aggregate_data:
            if not args.nvd_api_key:
                logging.error("NVD API key is required when aggregating data. Please provide it using --nvd_api_key.")
                sys.exit(1)
            report_cve_ids = [v.get("cve_id") for v in vulnerability_report.get("vulnerabilities", []) if isinstance(v, dict) and v.get("cve_id")]
            aggregated_vulnerabilities = aggregate_vulnerability_data(args.nvd_api_key, report_cve_ids)

        # Correlate vulnerabilities
        # Without aggregation the aggregated list is empty and this correlation can only ever
        # be empty too. The default run prints an empty object and exits 0.
        correlated_vulnerabilities = correlate_vulnerabilities(
            vulnerability_report, aggregated_vulnerabilities
        )

        # Analyze dependencies and suggest remediation paths
        remediation_suggestions = analyze_dependencies(
            dependency_graph, correlated_vulnerabilities
        )

        # Save output to file or print to console
        if args.output:
            save_output(remediation_suggestions, args.output)
        else:
            print(json.dumps(remediation_suggestions, indent=4))

    except FileNotFoundError:
        print("One or more input files not found.  Check the file paths.")
        sys.exit(1)
    except ValueError as e:
        print(f"Invalid input: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        print("An unexpected error occurred. See the logs for details.")
        sys.exit(1)


if __name__ == "__main__":
    main()

# Example Usage:
# python main.py --vulnerability_report vulnerability_report.json --dependency_graph dependency_graph.json --output remediation_suggestions.json
# python main.py --vulnerability_report vulnerability_report.yaml --dependency_graph dependency_graph.yaml --aggregate_data --nvd_api_key YOUR_NVD_API_KEY

# Example vulnerability_report.json:
# {
#   "vulnerabilities": [
#     {
#       "cve_id": "CVE-2023-12345",
#       "affected_package": "requests"
#     },
#     {
#       "cve_id": "CVE-2023-67890",
#       "affected_package": "urllib3"
#     }
#   ]
# }

# Example dependency_graph.json:
# {
#   "dependencies": {
#     "my_app": ["requests", "beautifulsoup4"],
#     "beautifulsoup4": ["urllib3"]
#   }
# }

# Example vulnerability_report.yaml:
# vulnerabilities:
#   - cve_id: CVE-2023-12345
#     affected_package: requests
#   - cve_id: CVE-2023-67890
#     affected_package: urllib3

# Example dependency_graph.yaml:
# dependencies:
#   my_app:
#     - requests
#     - beautifulsoup4
#   beautifulsoup4:
#     - urllib3