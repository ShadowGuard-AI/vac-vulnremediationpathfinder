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
        help="Flag to enable aggregation of vulnerability data from external sources (NIST NVD, Exploit-DB).",
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


def aggregate_vulnerability_data(nvd_api_key: str = None) -> List[Dict]:
    """
    Aggregates vulnerability data from external sources (NIST NVD, Exploit-DB).
    This is a simplified example.  In a real implementation, you would:
    1.  Implement robust error handling for network requests.
    2.  Implement rate limiting to avoid being blocked by APIs.
    3.  Handle API pagination for large datasets.
    4.  Implement more sophisticated data extraction and parsing.
    """
    vulnerabilities = []

    # NIST NVD (Example - simplified)
    if nvd_api_key:
        try:
            # Replace with actual NVD API endpoint and parameters
            nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"  # Example endpoint, needs proper parameters
            headers = {"apiKey": nvd_api_key}
            response = requests.get(nvd_url, headers=headers, timeout=10)

            if response.status_code == 200:
                nvd_data = response.json()
                if "vulnerabilities" in nvd_data:
                    for item in nvd_data["vulnerabilities"]:
                        cve_data = item["cve"]
                        vulnerabilities.append({
                            "cve_id": cve_data["id"],
                            "description": cve_data["descriptions"][0]["value"] if cve_data["descriptions"] else "No Description",
                            "cvssv3": cve_data.get("cvssV3", {}).get("baseScore"), #Optional field, hence the get
                            "source": "NIST NVD",
                        })
                else:
                    logging.warning("No 'vulnerabilities' found in NVD data.")

            else:
                logging.error(f"Failed to fetch data from NIST NVD: Status code {response.status_code}")
        except requests.exceptions.RequestException as e:
            logging.error(f"Error fetching data from NIST NVD: {e}")
        except json.JSONDecodeError:
            logging.error("Error decoding JSON from NIST NVD response.")
        except Exception as e:
            logging.error(f"Error processing data from NIST NVD: {e}")

    else:
        logging.warning("NVD API key not provided. Skipping NIST NVD data aggregation.")

    # Exploit-DB (Example - scraping - very basic, not recommended for production)
    try:
        # NOTE: Web scraping is fragile and can break easily.  Use APIs where available.
        exploitdb_url = "https://www.exploit-db.com/"  # Example URL
        response = requests.get(exploitdb_url, timeout=10)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

        soup = BeautifulSoup(response.content, "html.parser")
        # Example: Find all links to exploits (this is highly dependent on the website's structure)
        # This is a placeholder and needs to be adapted to the actual website structure
        # exploit_links = soup.find_all("a", href=lambda href: href and "/exploits/" in href)
        # for link in exploit_links:
        #     exploit_url = link["href"]
        #     vulnerabilities.append({
        #         "cve_id": "N/A",  # Exploit-DB might not always have CVEs
        #         "description": f"Exploit found: {exploit_url}",
        #         "source": "Exploit-DB",
        #     })
        logging.info("Exploit-DB scraping is placeholder - needs implementation based on website structure")
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching data from Exploit-DB: {e}")
    except Exception as e:
        logging.error(f"Error processing data from Exploit-DB: {e}")

    return vulnerabilities


def correlate_vulnerabilities(
    vulnerability_report: Dict, aggregated_vulnerabilities: List[Dict]
) -> List[Dict]:
    """Correlates vulnerabilities from the report with aggregated data."""
    correlated_vulnerabilities = []
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


def analyze_dependencies(
    dependency_graph: Dict, correlated_vulnerabilities: List[Dict]
) -> Dict:
    """Analyzes dependencies and suggests remediation paths."""
    remediation_suggestions = {}
    for vuln in correlated_vulnerabilities:
        cve_id = vuln.get("cve_id")
        affected_package = vuln.get("affected_package")  # Assuming package name is in vulnerability report

        if affected_package:
            for package, dependencies in dependency_graph.get("dependencies", {}).items():
                if package == affected_package:
                    # Suggest upgrading the affected package
                    new_version = get_latest_version(package)  # Placeholder - implement version fetching
                    remediation_suggestions[cve_id] = {
                        "affected_package": affected_package,
                        "suggestion": f"Upgrade {affected_package} to version {new_version} or later to address CVE: {cve_id}",
                    }
                    break
                else: # Check transitive dependencies
                    for dep in dependencies:
                         if dep == affected_package:
                            new_version = get_latest_version(affected_package)
                            remediation_suggestions[cve_id] = {
                                "affected_package": affected_package,
                                "suggestion": f"Upgrade transitive dependency {affected_package} to version {new_version} or later to address CVE: {cve_id} by upgrading the top-level dependency: {package}",
                            }
                            break # Stop searching transitive deps for current package.

    return remediation_suggestions


def get_latest_version(package_name: str) -> str:
    """Placeholder function to fetch the latest version of a package."""
    # In a real implementation, this would query a package registry (e.g., PyPI for Python)
    # For example, using the `requests` library to query the PyPI API:
    # https://pypi.org/pypi/<package_name>/json
    # This is just a placeholder. Replace with actual implementation.
    return "latest"  # Placeholder


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
            aggregated_vulnerabilities = aggregate_vulnerability_data(args.nvd_api_key)

        # Correlate vulnerabilities
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