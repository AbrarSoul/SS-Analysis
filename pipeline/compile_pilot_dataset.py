"""
Compiles the 40 manually-verified pilot cases (Section 8 Step 4's actual
read-the-diff-against-the-advisory pass, done directly, not scripted) into
the design doc's Section 10 benchmark/ structure: one directory per case
with metadata.json/patch.diff/vulnerable_source/patched_source, plus
manifest.jsonl, inclusion_log.csv, and exclusion_log.csv at the benchmark/
root.

Earlier-stage exclusions (Step 1 language/CVE-matching, Step 2 dedup, Step 3
repo/commit resolution) are already fully logged under data/morefixes_v4/
(target_language_candidates.txt, dedup_exclusions.csv, step3_results.csv).
This script's exclusion_log.csv covers specifically the Step 4 manual-
verification-stage rejections -- cases that passed every earlier automated
stage but were rejected on actually reading the diff against its advisory.
"""
import csv
import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STEP3_DIR = ROOT / "benchmark" / "step3_repo_states"
STEP4_RESULTS = json.loads((ROOT / "data" / "morefixes_v4" / "step4_advisory_results.json").read_text())
CASES_OUT = ROOT / "benchmark" / "cases"
CASES_OUT.mkdir(parents=True, exist_ok=True)

# (case_id, language) -- the 40 manually verified during this session.
SELECTED = [
    # Python
    ("github.com_1Panel-dev_MaxKB_38c4cfecd065293ede0437f6fa76cf0116591d25", "python"),
    ("github.com_ComposioHQ_composio_ed82fb45dc9fbd7f07c535c72bada871c158ae5f", "python"),
    ("github.com_CyrilleB79_NVDA-Dev-Test-Toolbox_21a0544432b08971b5d18320e8256be12c610bea", "python"),
    ("github.com_FederatedAI_FATE_6feccf6d752184a6f9365d56a76fe627983e7139", "python"),
    ("github.com_inducer_relate_555f0efb1c5bd7531c07cd73724d7e566a81f620", "python"),
    ("github.com_lintsinghua_DeepAudit_b2a3b26579d3fdbab5236ae12ed67ae2313175fd", "python"),
    ("github.com_llamastack_llama-stack_b709bd77b6c1fad68a30a4888baa6f2337eaef6f", "python"),
    ("github.com_parisneo_lollms-webui_6d07c8a0dd0a15cc060becc73fda9fe8e788eb23", "python"),
    ("github.com_scottcwang_openssh_key_parser_26e0a471e9fdb23e635bc3014cf4cbd2323a08d3", "python"),
    ("github.com_projectdiscovery_interactsh_6a0cb98b16636a98712729f3d23e34d8bf7260e7", "python"),
    # Java
    ("github.com_FasterXML_jackson-databind_3d97153944f7de9c19c1b3637b33d3cf1fbbe4d7", "java"),
    ("github.com_HtmlUnit_htmlunit_940dc7fd8af9f46ca448c1e548b8f6d064a64290", "java"),
    ("github.com_KnowageLabs_Knowage-Server_f7d0362f737e1b0db1cc9cc95b1236d62d83dd0c", "java"),
    ("github.com_ManyDesigns_Portofino_94653cb357806c9cf24d8d294e6afea33f8f0775", "java"),
    ("github.com_apache_felix-dev_87513ea3533fdb79d9e2b251410bf2bfbd63941e", "java"),
    ("github.com_apache_kylin_e373c64c96a54a7abfe4bccb82e8feb60db04749", "java"),
    ("github.com_apache_spark_cf59b1f51c16301f689b4e0f17ba4dbd140e1b19", "java"),
    ("github.com_jenkinsci_gitlab-oauth-plugin_695ce63fddb3567cf8d87339ddc1fa3b67ae2db8", "java"),
    ("github.com_joniles_mpxj_8002802890dfdc8bc74259f37e053e15b827eea0", "java"),
    ("github.com_spring-projects_spring-security-samples_4e3bec904a5467db28ea33e25ac9d90524b53d66", "java"),
    # JavaScript
    ("github.com_Countly_countly-server_2bfa1ee1fa46e9bb007cf8687ad197ab9c604999", "javascript"),
    ("github.com_GSConnect_gnome-shell-extension-gsconnect_a38246deec0af50ae218cdc51db32cdd7eb145e3", "javascript"),
    ("github.com_InternalError503_forget-it_adf0c7fd59b9c935b4fd675c556265620124999c", "javascript"),
    ("github.com_KartikTalwar_gmail.js_a83436f499f9c01b04280af945a5a81137b6baf1", "javascript"),
    ("github.com_Mintplex-Labs_anything-llm_94ed62d320df1a06c229e4bc3ee09c2cb5111b33", "javascript"),
    ("github.com_NodeBB_NodeBB_48d143921753914da45926cca6370a92ed0c46b8", "javascript"),
    ("github.com_ether_etherpad-lite_9d4e5f6e35153129377206ef545d4965afae627d", "javascript"),
    ("github.com_kanaka_noVNC_ad941faddead705cd611921730054767a0b32dcd", "javascript"),
    ("github.com_micromatch_braces_abdafb0cae1e0c00f184abbadc692f4eaa98f451", "javascript"),
    ("github.com_mongodb_js-bson_bd61c45157c53a1698ff23770160cf4783e9ea4a", "javascript"),
    # TypeScript
    ("github.com_Dokploy_dokploy_61cf426615a4aa095b150362526aa52f2d1ea115", "typescript"),
    ("github.com_Eugeny_tabby_1c077147acd0a6ec9f8ee80d83a3e9688fbb9444", "typescript"),
    ("github.com_JstnMcBrd_dectalk-tts_3600d8ac156f27da553ac4ead46d16989a350105", "typescript"),
    ("github.com_OneUptime_oneuptime_07bc6d4edde7397ea6b88f889c065ec392052ab4", "typescript"),
    ("github.com_OpenSlides_openslides-auth-service_70c1aa9f5e1db59ec120ecce98d1c1169350a4ee", "typescript"),
    ("github.com_awwaiid_mcp-server-taskwarrior_1ee3d282debfa0a99afeb41d22c4b2fd5a3148f2", "typescript"),
    ("github.com_edmundhung_conform_4819d51b5a53fd5486fc85c17cdc148eb160e3de", "typescript"),
    ("github.com_enchant97_note-mark_a0997facb82f85bfb8c0d497606d89e7d150e182", "typescript"),
    ("github.com_genieacs_genieacs_7f295beeecc1c1f14308a93c82413bb334045af6", "typescript"),
    ("github.com_jasonraimondi_url-to-png_e4eaeca6493b21cd515b582fd6c0af09ede54507", "typescript"),
]

# Step 4 manual-verification rejections: (case_id, reason)
STEP4_REJECTIONS = [
    ("github.com_AkshuDev_PheonixAppAPI_0937419e323f5ea9013d43dc1b82fef9d7e05044",
     "Advisory describes an exposed encoding/decoding map; diff only edits error-message strings and one method rename. No correspondence between diff and advisory."),
    ("github.com_hyperledger_indy-node_55056f22c83b7c3520488b615e1577e0f895d75a",
     "Single recognized-language file selected was a test file (test_nym_auth_rules.py); the actual production authorization fix (nym_handler.py, per the advisory's own implementation notes) is not in this diff."),
    ("github.com_apache_lucene-solr_0d21b900975b7048d2e925d852aeacb9bdc6766c",
     "Confirmed by automated refactor-only heuristic AND manual read: diff only edits a Javadoc comment, no functional change. Not the real XXE fix."),
    ("github.com_Mintplex-Labs_anything-llm_e287fab56089cf8fcea9ba579a3ecdeca0daa313",
     "Advisory describes username enumeration via different error messages; diff only adds a trailing period to an already-identical error string in two places. Does not address enumeration logic."),
    ("github.com_brokercap_Bifrost_63da5c8eb7eb21639ea7ac199fe10b5e07b03a8a",
     "Advisory describes a server-side authentication bypass (missing header check); diff fixes an unrelated client-side JS variable-name bug in an AJAX success callback (data.status -> callbackData.status)."),
    ("github.com_mattermost_mattermost_613bb616cd62c584a606919e6978688e7b87d81e",
     "Advisory describes missing permission validation when deleting Boards comments; diff only changes a React useEffect dependency array in an unrelated user-profile component. No correspondence."),
]


def load_source_lang_extension(language: str) -> str:
    return {"python": "py", "java": "java", "javascript": "js", "typescript": "ts"}[language]


def main():
    manifest_path = ROOT / "benchmark" / "manifest.jsonl"
    inclusion_log_path = ROOT / "benchmark" / "inclusion_log.csv"
    exclusion_log_path = ROOT / "benchmark" / "exclusion_log.csv"

    manifest_lines = []
    inclusion_rows = []

    for i, (case_id, language) in enumerate(SELECTED, 1):
        case_number = f"CASE-{i:04d}"
        src_dir = STEP3_DIR / case_id
        metadata = json.loads((src_dir / "metadata.json").read_text())

        dest_dir = CASES_OUT / case_number
        dest_dir.mkdir(exist_ok=True)

        ext = load_source_lang_extension(language)
        shutil.copy(src_dir / "vulnerable_source", dest_dir / f"vulnerable_source.{ext}")
        shutil.copy(src_dir / "patched_source", dest_dir / f"patched_source.{ext}")
        shutil.copy(src_dir / "patch.diff", dest_dir / "patch.diff")

        step4 = STEP4_RESULTS.get(case_id, {})
        advisory_source = None
        for cve, adv in step4.get("advisories_by_cve", {}).items():
            if adv.get("advisories"):
                advisory_source = "github"
                break
        if advisory_source is None and step4.get("nvd_confirmed_real_cve"):
            advisory_source = "nvd"

        case_metadata = {
            "case_id": case_number,
            "original_patch_filename": case_id + ".patch",
            "cve_id": metadata["cve_ids"][0] if metadata["cve_ids"] else None,
            "cve_ids_all": metadata["cve_ids"],
            "cwe_ids": metadata["cwe_ids"],
            "language": language,
            "repository": metadata["repository"],
            "repository_url": metadata["repository_url"],
            "vulnerable_commit": metadata["vulnerable_commit"],
            "fixed_commit": metadata["fixed_commit"],
            "changed_file": metadata["changed_file"],
            "patch_path": f"cases/{case_number}/patch.diff",
            "vulnerable_code_path": f"cases/{case_number}/vulnerable_source.{ext}",
            "patched_code_path": f"cases/{case_number}/patched_source.{ext}",
            "semgrep_representability": "supported",
            "advisory_source": advisory_source,
            "advisory_confidence_score": metadata.get("max_score"),
            "verification_method": "manual: diff read against real advisory text, Section 8 Step 4 criteria",
            "split": "pilot",
        }
        (dest_dir / "metadata.json").write_text(json.dumps(case_metadata, indent=2))

        manifest_lines.append(json.dumps(case_metadata))
        inclusion_rows.append({
            "case_id": case_number,
            "cve_id": case_metadata["cve_id"],
            "language": language,
            "repository": metadata["repository"],
            "advisory_source": advisory_source,
            "verification_date": "2026-09-19",
        })

    manifest_path.write_text("\n".join(manifest_lines) + "\n")

    with open(inclusion_log_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(inclusion_rows[0].keys()))
        writer.writeheader()
        writer.writerows(inclusion_rows)

    with open(exclusion_log_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["case_id", "stage", "reason"])
        for case_id, reason in STEP4_REJECTIONS:
            writer.writerow([case_id, "step4_manual_verification", reason])
        writer.writerow(["(see data/morefixes_v4/dedup_exclusions.csv)", "step2_dedup",
                          "70 same-commit-different-representation exclusions, earlier stage"])
        writer.writerow(["(see data/morefixes_v4/step3_results.csv)", "step3_repo_state",
                          "4 excluded (inaccessible repo / file not modified), 15 flagged as merge commits, earlier stage"])

    print(f"Compiled {len(SELECTED)} pilot cases -> {CASES_OUT}")
    print(f"Manifest -> {manifest_path}")
    print(f"Inclusion log -> {inclusion_log_path}")
    print(f"Exclusion log -> {exclusion_log_path}")


if __name__ == "__main__":
    main()
