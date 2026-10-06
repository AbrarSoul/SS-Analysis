"""
NVD fallback for the FINAL dataset's Step 4, for cases where GitHub's
Advisory API returned no record for an otherwise-real CVE -- identical
procedure and rationale to curate_step4b_nvd_fallback.py (see that script's
docstring), pointed at the final batch's results file instead of the
pilot's.
"""
import json
import ssl
import time
import urllib.request
import urllib.error
from pathlib import Path

import certifi

DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "morefixes_v4"
RESULTS_FILE = DATA_DIR / "step4_advisory_results_topup12.json"

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"

_SSL_CONTEXT = ssl.create_default_context(cafile=certifi.where())


def fetch_nvd(cve_id: str) -> dict:
    try:
        req = urllib.request.Request(NVD_URL.format(cve_id=cve_id),
                                      headers={"User-Agent": "research-dataset-curation/1.0"})
        with urllib.request.urlopen(req, timeout=20, context=_SSL_CONTEXT) as resp:
            data = json.loads(resp.read())
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return {"found": False}
        cve = vulns[0]["cve"]
        weaknesses = []
        for w in cve.get("weaknesses", []):
            for d in w.get("description", []):
                if d.get("lang") == "en":
                    weaknesses.append(d.get("value"))
        return {
            "found": True,
            "status": cve.get("vulnStatus"),
            "description": next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), ""),
            "cwe_ids_from_nvd": weaknesses,
            "published": cve.get("published"),
        }
    except urllib.error.HTTPError as e:
        return {"found": False, "http_error": e.code}
    except Exception as e:
        return {"found": False, "error": str(e)}


def main():
    results = json.loads(RESULTS_FILE.read_text())

    no_advisory_cases = {
        case_id: v for case_id, v in results.items()
        if "nvd_fallback" not in v and all("error" in a or not a.get("advisories") for a in v["advisories_by_cve"].values())
    }
    print(f"Cases needing NVD fallback: {len(no_advisory_cases)}")

    for i, (case_id, v) in enumerate(no_advisory_cases.items(), 1):
        nvd_by_cve = {}
        for cve_id in v["cve_ids"]:
            print(f"[{i}/{len(no_advisory_cases)}] {case_id} -> {cve_id}")
            nvd_by_cve[cve_id] = fetch_nvd(cve_id)
            time.sleep(6)  # conservative pacing, well under NVD's unauthenticated limit
        results[case_id]["nvd_fallback"] = nvd_by_cve
        results[case_id]["nvd_confirmed_real_cve"] = any(
            r.get("found") for r in nvd_by_cve.values()
        )
        RESULTS_FILE.write_text(json.dumps(results, indent=2))

    confirmed = sum(1 for case_id in no_advisory_cases if results[case_id]["nvd_confirmed_real_cve"])
    print()
    print(f"Confirmed as real CVEs via NVD: {confirmed} / {len(no_advisory_cases)}")
    print(f"Updated {RESULTS_FILE}")


if __name__ == "__main__":
    main()
