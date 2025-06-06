# vac-VulnRemediationPathfinder
A CLI tool that suggests remediation paths for aggregated vulnerabilities based on dependency analysis. It takes a vulnerability report (JSON/YAML) and a software dependency graph (e.g., from a SBOM) as input. It then identifies potential remediation strategies, such as upgrading a specific library or applying a patch, that address multiple vulnerabilities simultaneously based on the dependency relationships. - Focused on Aggregates vulnerability data from multiple sources (e.g., NIST NVD, Exploit-DB, local vulnerability databases) and correlates them based on common vulnerabilities and exposures (CVEs). Provides a consolidated view of potential weaknesses in a system.  The tool focuses on fetching, parsing, and correlating vulnerability data, not active scanning.

## Install
`git clone https://github.com/ShadowStrikeHQ/vac-vulnremediationpathfinder`

## Usage
`./vac-vulnremediationpathfinder [params]`

## Parameters
- `-h`: Show help message and exit
- `--vulnerability_report`: No description provided
- `--dependency_graph`: No description provided
- `--output`: No description provided
- `--aggregate_data`: No description provided
- `--nvd_api_key`: No description provided

## License
Copyright (c) ShadowStrikeHQ
