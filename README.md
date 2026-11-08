# vac-VulnRemediationPathfinder

A CLI tool that suggests remediation paths for vulnerabilities based on dependency analysis. It takes a vulnerability report (JSON/YAML) and a software dependency graph (e.g., from a SBOM) as input. In the default mode it works from the report and the graph directly: a package in the application's own dependency list is treated as a direct dependency, and a package that only appears under another dependency is treated as transitive. Each suggestion names the resolved fixed version from the report entry when one is present, and otherwise states that no version could be resolved. If the same CVE affects several packages, the first suggestion keeps the plain CVE ID as its output key and later ones are keyed as `CVE-ID [package]`, so no suggestion is overwritten. A vulnerability whose package does not appear in the dependency graph still gets a suggestion, marked as undetermined direct or transitive status. Report entries that are not objects are skipped with a warning, and a report or graph that is not a JSON or YAML object is rejected as invalid input. With `--aggregate_data`, it also queries the NIST NVD API once per report CVE ID and reads the CVSS base score from the first available metrics family, in the order CVSS v3.1, CVSS v3.0, then CVSS v2. It does not fetch Exploit-DB and does not perform active scanning.

## Install
`git clone https://github.com/ShadowGuard-AI/vac-vulnremediationpathfinder.git`

## Usage
`python3 main.py --vulnerability_report vulnerability_report.json --dependency_graph dependency_graph.json`

## Parameters
- `-h`: Show help message and exit
- `--vulnerability_report`: Path to the vulnerability report file (JSON or YAML).
- `--dependency_graph`: Path to the software dependency graph file (e.g., SBOM - JSON or YAML).
- `--output`: Path to the output file for remediation suggestions (JSON). It must not resolve to either input file.
- `--aggregate_data`: Aggregate vulnerability data from NIST NVD.
- `--nvd_api_key`: NIST NVD API key (required if aggregate_data is enabled).

## License
MIT License. See LICENSE.
