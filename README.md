# vac-VulnRemediationPathfinder

A CLI tool that suggests remediation paths for vulnerabilities based on dependency analysis. It takes a vulnerability report (JSON/YAML) and a software dependency graph (e.g., from a SBOM) as input. In the default mode it works from the report and the graph directly: a package in the application's own dependency list is treated as a direct dependency, and a package that only appears under another dependency is treated as transitive. Each suggestion names the resolved fixed version from the report entry when one is present, and otherwise states that no version could be resolved. With `--aggregate_data`, it also queries the NIST NVD API once per report CVE ID and reads the CVSS score from the v2 metrics structure. It does not fetch Exploit-DB and does not perform active scanning.

## Install
`git clone https://github.com/ShadowGuard-AI/vac-vulnremediationpathfinder`

## Usage
`python main.py --vulnerability_report vulnerability_report.json --dependency_graph dependency_graph.json`

## Parameters
- `-h`: Show help message and exit
- `--vulnerability_report`: Path to the vulnerability report file (JSON or YAML).
- `--dependency_graph`: Path to the software dependency graph file (e.g., SBOM - JSON or YAML).
- `--output`: Path to the output file for remediation suggestions (JSON). It must not resolve to either input file.
- `--aggregate_data`: Aggregate vulnerability data from NIST NVD.
- `--nvd_api_key`: NIST NVD API key (required if aggregate_data is enabled).

## License
Copyright (c) ShadowGuard-AI
