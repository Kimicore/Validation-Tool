import json
import sys
import argparse
import ipaddress
import subprocess
import shutil
import platform
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


def load_report(file_path):
    """Load the prioritization report from a JSON file."""

    with open(file_path, "r", encoding="utf-8") as file:
        data = json.load(file)

    return data


def validate_asset_structure(asset):
    """Check whether an asset contains the required sections and fields."""

    errors = []

    required_asset_fields = [
        "asset_id",
        "asset_enrichment",
        "risk_scoring_engine",
        "prioritization"
    ]

    for field in required_asset_fields:
        if field not in asset:
            errors.append(f"Missing asset field: {field}")

    if "asset_enrichment" in asset:
        required_enrichment_fields = [
            "asset_id",
            "subdomain_name",
            "ip_address",
            "dns_whois_data",
            "tech_fingerprint",
            "screenshot_and_title",
            "ssl_tls_info",
            "cloud_cdn_hosting_info",
            "historical_data_and_reputation"
        ]

        for field in required_enrichment_fields:
            if field not in asset["asset_enrichment"]:
                errors.append(f"Missing enrichment field: {field}")

    if "risk_scoring_engine" in asset:
        required_risk_fields = [
            "exposure_internet_facing",
            "criticality_business_impact",
            "technology_risk",
            "known_cves",
            "threat_intel_matches",
            "misconfiguration_signals",
            "overall_risk_score"
        ]

        for field in required_risk_fields:
            if field not in asset["risk_scoring_engine"]:
                errors.append(f"Missing risk field: {field}")

    return errors

def validate_asset_values(asset):
    """Validate the actual values contained within an asset."""

    errors = []

    asset_id = asset.get("asset_id")

    if not isinstance(asset_id, str) or not asset_id.strip():
        errors.append("asset_id must be a non-empty string")

    enrichment = asset.get("asset_enrichment", {})

    subdomain = enrichment.get("subdomain_name")

    if not isinstance(subdomain, str) or not subdomain.strip():
        errors.append("subdomain_name must be a non-empty string")

    ip_address = enrichment.get("ip_address")

    if ip_address:
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            errors.append(f"Invalid IP address: {ip_address}")
    else:
        errors.append("ip_address is empty or missing")

    risk = asset.get("risk_scoring_engine", {})

    risk_fields = [
        "exposure_internet_facing",
        "criticality_business_impact",
        "technology_risk",
        "overall_risk_score"
    ]

    for field in risk_fields:
        value = risk.get(field)

        if not isinstance(value, (int, float)):
            errors.append(f"{field} must be a number")

        elif not 0 <= value <= 1:
            errors.append(f"{field} must be between 0 and 1")

    return errors

def find_tool(tool_name):
    """Locate an external security tool safely, across Windows/Linux/macOS."""

    is_windows = platform.system() == "Windows"
    exe_suffix = ".exe" if is_windows else ""

    # 1. Prefer Go-installed ProjectDiscovery tools.
    if tool_name in {"httpx", "naabu"}:
        try:
            gopath = subprocess.run(
                ["go", "env", "GOPATH"],
                capture_output=True,
                text=True,
                check=True
            ).stdout.strip()

            if gopath:
                candidate = Path(gopath) / "bin" / f"{tool_name}{exe_suffix}"

                if candidate.exists():
                    return str(candidate)

        except (subprocess.SubprocessError, FileNotFoundError):
            pass

    # 2. Fall back to PATH.
    path = shutil.which(tool_name)

    if path:
        return path

    # 3. Common Nmap installation locations, per OS.
    if tool_name == "nmap":
        if is_windows:
            common_paths = [
                Path(r"C:\Program Files (x86)\Nmap\nmap.exe"),
                Path(r"C:\Program Files\Nmap\nmap.exe")
            ]
        else:
            common_paths = [
                Path("/usr/bin/nmap"),
                Path("/usr/local/bin/nmap"),
                Path("/opt/homebrew/bin/nmap")
            ]

        for candidate in common_paths:
            if candidate.exists():
                return str(candidate)

    raise FileNotFoundError(
        f"{tool_name} was not found. "
        f"Install it and make sure it is available on the system."
    )

def run_nuclei_scan(nuclei_path, urls, asset_id):
    """Run targeted Nuclei validation against confirmed reachable URLs."""

    findings = []

    if not urls:
        return findings

    url_file = BASE_DIR / "output" / f"{asset_id}_nuclei_targets.txt"

    try:
        with open(url_file, "w", encoding="utf-8") as file:
            for url in urls:
                file.write(url + "\n")


        output = subprocess.run(
            [
                str(nuclei_path),
                "-l", str(url_file),
                "-tags", "tomcat,apache,java,exposures",
                "-severity", "medium,high,critical",
                "-jsonl",
                "-silent"
            ],
            capture_output=True,
            text=True,
            timeout=120
        )

        seen = set()

        for line in output.stdout.splitlines():
            if not line.strip():
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            template_id = data.get("template-id")
            matched_at = data.get("matched-at") or data.get("host")

            key = (template_id, matched_at)

            if key in seen:
                continue

            seen.add(key)

            findings.append({
                "template_id": template_id,
                "name": data.get("info", {}).get("name"),
                "severity": data.get("info", {}).get("severity"),
                "matched_at": matched_at
            })

    except subprocess.TimeoutExpired:
        print("  [!] Nuclei validation timed out.")

    except Exception as error:
        print(f"  [!] Nuclei error: {error}")

    finally:
        url_file.unlink(missing_ok=True)

    return findings

def validate_asset(asset):
    """Validate whether the asset is alive and identify open ports."""

    enrichment = asset.get("asset_enrichment", {})
    risk = asset.get("risk_scoring_engine", {})

    known_cves_raw = risk.get("known_cves", {})
    known_cves = known_cves_raw.get("matches", []) if isinstance(known_cves_raw, dict) else []
    if not isinstance(known_cves, list):
        known_cves = []

    misconfig_raw = risk.get("misconfiguration_signals", {})
    misconfigurations = misconfig_raw.get("findings", []) if isinstance(misconfig_raw, dict) else []
    if not isinstance(misconfigurations, list):
        misconfigurations = []

    subdomain = enrichment.get("subdomain_name")

    result = {
        "asset_id": asset.get("asset_id"),
        "subdomain": subdomain,
        "ip_address": enrichment.get("ip_address"),
        "alive": False,
        "ports": [],
        "services": [],
        "technology": [],
        "screenshot": None,
        "title": None,
        "vulnerabilities": [],
        "prioritized_cves": [],
        "prioritized_misconfigurations": [],
        "validated_misconfigurations": [],
        "validated_cves": [],
        "nuclei_findings": [],
        "validation_verdict": "inconclusive",
        "error": None,
        "expert_review": {
            "status": "pending",
            "decision": None,
            "notes": "",
            "evidence_reviewed": [],
        }
    }

    result["prioritized_cves"] = [cve.get("id") for cve in known_cves if isinstance(cve, dict)]
    result["prioritized_misconfigurations"] = misconfigurations

    try:
        httpx_path = find_tool("httpx")
        naabu_path = find_tool("naabu")
        nmap_path = find_tool("nmap")
        nuclei_path = find_tool("nuclei")
    except FileNotFoundError as error:
        result["error"] = f"Required tool missing: {error}"
        print(f"  [!] {result['error']} — skipping validation for {subdomain}")
        return result




    print(f"  [*] Running httpx on {subdomain}...")


    try:
        output = subprocess.run(
    [
            str(httpx_path),
            "-silent",
            "-tech-detect",
            "-json",
            "-u",
            f"https://{subdomain}"
    ],
            capture_output=True,
            text=True
        )

        if output.stdout.strip():
            result["alive"] = True

            httpx_data = json.loads(output.stdout.strip())

            result["technology"] = httpx_data.get("tech", [])
            result["services"] = [httpx_data.get("webserver")] if httpx_data.get("webserver") else []

    except Exception as error:
        print(f"httpx error: {error}")

    print(f"  [*] Running naabu on {subdomain}...")

    try:
        output = subprocess.run(
            [
                str(naabu_path),
                "-host",
                subdomain,
                "-silent"
            ],
            capture_output=True,
            text=True
        )

        for line in output.stdout.splitlines():
            if ":" in line:
                port = line.rsplit(":", 1)[1].strip()

                if not port.isdigit():
                    continue

                port = int(port)

                if port not in result["ports"]:
                    result["ports"].append(port)

    except Exception as error:
        print(f"naabu error: {error}")

    print(f"  [*] Running nmap service detection on {subdomain}...")

    if result["ports"]:
        try:
            output = subprocess.run(
                [
                    str(nmap_path),
                    "-sV",
                    "-p",
                    ",".join(map(str, result["ports"])),
                    subdomain
                ],
                capture_output=True,
                text=True
            )

            for line in output.stdout.splitlines():
                if "/tcp" in line and "open" in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        service = " ".join(parts[3:])
                        if service not in result["services"]:
                            result["services"].append(service)

        except Exception as error:
            print(f"nmap error: {error}")

    else:
        print("  [*] No open ports found; skipping nmap.")

    for cve in known_cves:
        description = cve.get("description", "").lower()
        service_evidence = " ".join(result["services"]).lower()

        technology_match = any(
            tech.lower() in description
            for tech in result["technology"]
        )

        service_match = any(
            word in description
            for word in ["tomcat", "apache", "java", "jsp"]
            if word in service_evidence
        )

        if technology_match or service_match:
            status = "needs_version_check"
            reason = "Technology/service matches, but exact version is unknown"
        else:
            status = "not_applicable"
            reason = "No detected technology/service match"

        result["validated_cves"].append({
            "cve": cve.get("id"),
            "status": status,
            "reason": reason,
            "severity": cve.get("severity")
        })

    print(f"  [*] Validating prioritized URLs for {subdomain}...")

    try:
        urls = []

        for finding in misconfigurations:
            if "https://" in finding:
                url = "https://" + finding.split("https://", 1)[1]
                urls.append((finding, url))

        if urls:
            url_file = BASE_DIR / "output" / f"{asset.get('asset_id')}_urls.txt"

            with open(url_file, "w", encoding="utf-8") as file:
                for _, url in urls:
                    file.write(url + "\n")

            output = subprocess.run(
                [
                    str(httpx_path),
                    "-silent",
                    "-json",
                    "-follow-redirects",
                    "-l",
                    str(url_file)
                ],
                capture_output=True,
                text=True,
                timeout=60
            )
            url_file.unlink(missing_ok=True)

            results = {}

            for line in output.stdout.splitlines():
                if not line.strip():
                    continue

                data = json.loads(line)
                results[data.get("url")] = data

            for finding, url in urls:
                data = results.get(url)

                if data is None:
                    status = "no_response"
                else:
                    status_code = data.get("status_code")

                    if status_code is not None and 200 <= status_code < 400:
                        status = "confirmed_reachable"
                    else:
                        status = "confirmed_error_response"

                result["validated_misconfigurations"].append({
                    "finding": finding,
                    "status": status,
                    "url": url,
                    "status_code": data.get("status_code") if data else None,
                    "title": data.get("title") if data else None
                })

            retry_targets = [
                item for item in result["validated_misconfigurations"]
                if item["status"] == "no_response"
            ]

            if retry_targets:
                print(f"  [*] Retrying {len(retry_targets)} no_response URL(s) individually...")

            for item in retry_targets:
                try:
                    retry_output = subprocess.run(
                        [
                            str(httpx_path),
                            "-silent",
                            "-json",
                            "-follow-redirects",
                            "-u",
                            item["url"]
                        ],
                        capture_output=True,
                        text=True,
                        timeout=15
                    )

                    if retry_output.stdout.strip():
                        retry_data = json.loads(retry_output.stdout.strip().splitlines()[0])
                        status_code = retry_data.get("status_code")

                        if status_code is not None and 200 <= status_code < 400:
                            item["status"] = "confirmed_reachable"
                        else:
                            item["status"] = "confirmed_error_response"

                        item["status_code"] = status_code
                        item["title"] = retry_data.get("title")
                    else:
                        item["status"] = "confirmed_unreachable"

                except subprocess.TimeoutExpired:
                    item["status"] = "confirmed_unreachable"

                except Exception:
                    pass

    except subprocess.TimeoutExpired:
        print(f"misconfiguration validation timed out for {subdomain}")
        result["validated_misconfigurations"] = "timeout"

    except Exception as error:
        print(f"misconfiguration validation error: {error}")

    if isinstance(result["validated_misconfigurations"], list):

        confirmed_urls = [
            item["url"]
            for item in result["validated_misconfigurations"]
            if item["status"] == "confirmed_reachable"
        ]

        print(f"  [*] Running nuclei on {len(confirmed_urls)} confirmed URL(s) for {subdomain}...")

        result["nuclei_findings"] = run_nuclei_scan(
            nuclei_path,
            confirmed_urls,
            asset.get("asset_id")
        )

    if not result["alive"]:
        result["validation_verdict"] = "inconclusive"
    elif result["nuclei_findings"]:
        result["validation_verdict"] = "confirmed"
    elif isinstance(result["validated_misconfigurations"], list) and any(
        item["status"] == "confirmed_reachable" for item in result["validated_misconfigurations"]
    ):
        result["validation_verdict"] = "needs_review"
    elif any(item["status"] == "needs_version_check" for item in result["validated_cves"]):
        result["validation_verdict"] = "needs_review"
    else:
        result["validation_verdict"] = "not_applicable"

    return result



def print_validation_result(result):
    print("\n" + "=" * 60)
    print(f"ASSET: {result['subdomain']}")
    print("=" * 60)

    print(f"Alive:       {result['alive']}")
    print(f"IP Address:  {result['ip_address']}")
    print(f"Ports:       {', '.join(map(str, result['ports']))}")
    print(f"Technology:  {', '.join(result['technology'])}")
    print(f"Services:    {', '.join(result['services'])}")

    print("\nValidated Misconfigurations:")


    if isinstance(result["validated_misconfigurations"], list):
        for item in result["validated_misconfigurations"]:
            print(f"  [{item['status']}] [{item['status_code']}] {item['url']}")
    else:
        print(f"  {result['validated_misconfigurations']}")

    print("\nNuclei Findings:")
    if result["nuclei_findings"]:
        for finding in result["nuclei_findings"]:
            print(f"  [{finding['severity']}] {finding['template_id']} @ {finding['matched_at']}")
    else:
        print("  None")

    needs_check = [item for item in result["validated_cves"] if item["status"] == "needs_version_check"]
    not_applicable_count = len(result["validated_cves"]) - len(needs_check)

    print(f"\nCVE Validation: {len(needs_check)} need version check, {not_applicable_count} not applicable")
    for item in needs_check:
        print(f"  {item['cve']}: needs_version_check")

    print(f"\nValidation Verdict: {result['validation_verdict']}")

    print("\nExpert Review:")
    print(f"  Status: {result['expert_review']['status']}")

def save_validation_report(results, output_path):
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(results, file, indent=4)

    print(f"\nValidation report saved to: {output_path}")


def main():
    parser = argparse.ArgumentParser(description="ASM Validation stage")
    parser.add_argument("input", type=Path, help="Path to prioritization report JSON")
    parser.add_argument(
        "-o", "--output",
        type=Path,
        default=BASE_DIR / "output" / "validation_report.json",
        help="Path to write validation_report.json (default: output/validation_report.json)"
    )
    args = parser.parse_args()

    if not args.input.exists():
        print(f"Error: File not found: {args.input}")
        return

    data = load_report(args.input)

    print("Report loaded successfully.")
    print("Data type:", type(data))
    print("Top-level keys:", list(data.keys()))

    assets = data["assets"]

    print("\nTotal assets:", len(assets))

    print("\n" + "=" * 60)
    print("STARTING ASSET STRUCTURE VALIDATION")
    print("=" * 60)

    validation_results = []

    for asset in assets:

        asset_id = asset.get("asset_id", "UNKNOWN")

        structure_errors = validate_asset_structure(asset)
        value_errors = validate_asset_values(asset)

        errors = structure_errors + value_errors

        print("\nAsset:", asset_id)

        if not errors:
            print("Status: VALID")

            try:
                validation_result = validate_asset(asset)
                validation_results.append(validation_result)
                print_validation_result(validation_result)
            except Exception as error:
                print(f"  [!] Unexpected error validating asset {asset_id}: {error}")
                validation_results.append({
                    "asset_id": asset_id,
                    "error": str(error),
                    "validation_verdict": "inconclusive"
                })
        else:
            print("Status: INVALID")

            for error in errors:
                print("-", error)

    save_validation_report(validation_results, args.output)


if __name__ == "__main__":
    main()