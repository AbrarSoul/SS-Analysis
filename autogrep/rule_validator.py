import subprocess
from pathlib import Path
import json
import tempfile
from patch_processor import PatchInfo
from config import Config
import yaml
import git
from typing import Optional, Tuple, List
import logging

_EXT_BY_LANGUAGE = {"python": "py", "java": "java", "javascript": "js", "typescript": "ts"}
_BENCH_CASES_DIR = Path(__file__).resolve().parent.parent / "benchmark" / "cases"


def _curated_file_paths(patch_info: PatchInfo):
    """For a curated case (patch_info.case_id set): the standalone vulnerable/patched files Step 3/7
    curation already extracted, at benchmark/cases/CASE-XXXX/{vulnerable_source,patched_source}.<ext> --
    the same content a git checkout of the parent/fixed commit would have produced for the one file every
    curated case touches (verified: all 340 pilot+final cases have exactly one changed file), without
    needing a clone. See git_manager.py's prepare_repo() for why this exists."""
    ext = _EXT_BY_LANGUAGE[patch_info.file_changes[0].language]
    case_dir = _BENCH_CASES_DIR / patch_info.case_id
    return case_dir / f"vulnerable_source.{ext}", case_dir / f"patched_source.{ext}"


class RuleValidator:
    def __init__(self, config: Config):
        self.config = config

    def check_existing_rules(self, patch_info: PatchInfo, repo_path: Path, existing_rules: List[dict]) -> Tuple[bool, Optional[str]]:
        """
        Check if any existing rules can already detect the vulnerability.
        
        Args:
            patch_info: Information about the patch
            repo_path: Path to the repository
            existing_rules: List of existing rules for the same language
            
        Returns:
            Tuple[bool, Optional[str]]: 
                - Boolean indicating if vulnerability is already detectable
                - ID of the matching rule if found, None otherwise
        """
        try:
            # Curated case: use the standalone extracted files, no clone/checkout needed. See
            # _curated_file_paths() / git_manager.prepare_repo() for why.
            if patch_info.case_id is not None:
                vuln_files, fixed_files = [_curated_file_paths(patch_info)[0]], [_curated_file_paths(patch_info)[1]]
            else:
                repo = git.Repo(repo_path)
                parent_commit = repo.commit(patch_info.commit_id).parents[0]
                repo.git.checkout(parent_commit)
                vuln_files = [repo_path / fc.file_path for fc in patch_info.file_changes]

            # Create temporary rule file with all existing rules
            with tempfile.NamedTemporaryFile('w', suffix='.yml', delete=False) as tf:
                yaml.dump({"rules": existing_rules}, tf)
                rule_file = tf.name

            try:
                # Test vulnerable version
                vuln_results = []
                for target_file in vuln_files:
                    if not target_file.exists():
                        continue

                    results, error = self._run_semgrep(rule_file, str(target_file))
                    if error:
                        continue
                    vuln_results.extend(results)

                # If no rules detect the vulnerable version, we need a new rule
                if not vuln_results:
                    return False, None

                # Check fixed version (fixed_files already set above for a curated case)
                if patch_info.case_id is None:
                    repo.git.checkout(patch_info.commit_id)
                    fixed_files = [repo_path / fc.file_path for fc in patch_info.file_changes]
                fixed_results = []

                for target_file in fixed_files:
                    if not target_file.exists():
                        continue

                    results, error = self._run_semgrep(rule_file, str(target_file))
                    if error:
                        continue
                    fixed_results.extend(results)
                
                # If any rule detects vulnerability in vulnerable version but not in fixed version,
                # we don't need a new rule
                detecting_rules = set()
                for result in vuln_results:
                    rule_id = result.get('check_id')
                    if rule_id and not any(r.get('check_id') == rule_id for r in fixed_results):
                        detecting_rules.add(rule_id)
                
                if detecting_rules:
                    return True, next(iter(detecting_rules))  # Return first detecting rule ID
                
                return False, None
                
            finally:
                # Clean up temporary rule file
                try:
                    Path(rule_file).unlink()
                except Exception as e:
                    logging.warning(f"Failed to delete temporary rule file: {e}")
                    
        except Exception as e:
            logging.error(f"Error checking existing rules: {e}", exc_info=True)
            return False, None
        
    def _run_semgrep(self, rule_file: str, target_path: str) -> Tuple[list, Optional[str]]:
        """Run semgrep with better error classification."""
        try:
            result = subprocess.run(
                ["semgrep", "--config", rule_file, "--json", target_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Try to parse JSON output regardless of return code
            try:
                if result.stdout:
                    output = json.loads(result.stdout)
                    results = output.get("results", [])
                    errors = output.get("errors", [])
                    
                    # Process errors if any. Deliberately a deny-list, not an
                    # allow-list: only target-file parsing problems (the file
                    # itself couldn't be parsed -- not the rule's fault) are
                    # safe to silently skip. Every other error type is
                    # surfaced by default. An earlier allow-list version of
                    # this function only recognized specific error-type
                    # strings as "real" errors, which meant any error type it
                    # didn't already know about (discovered case: Semgrep's
                    # own "Rule parse error" for an invalid metavariable) fell
                    # through and was silently treated as "0 results, no
                    # error" -- indistinguishable from a valid rule that
                    # legitimately found nothing. See
                    # Research_Log/Model_Failure_Root_Cause_Analysis.md.
                    if errors:
                        for error in errors:
                            if isinstance(error, dict):
                                error_type = error.get('type', '')
                                if any(t in error_type for t in ['ParseError', 'SyntaxError', 'TokenError']):
                                    logging.warning(f"Skipping file due to parse error: {error.get('long_msg', '')}")
                                    return [], None  # target-file parse error -- safe to skip
                                return [], error.get('long_msg') or error.get('short_msg') or str(error)
                            return [], str(error)

                    return results, None
                    
                return [], None  # No output but no error either
                
            except json.JSONDecodeError:
                if "Parse error" in result.stderr or "Syntax error" in result.stderr:
                    logging.warning(f"Skipping file due to parse error: {result.stderr}")
                    return [], None
                return [], f"Failed to parse semgrep output: {result.stderr}"
                
        except subprocess.TimeoutExpired:
            return [], "Semgrep process timed out"
        except Exception as e:
            return [], f"Error running semgrep: {str(e)}"

    def validate_rule(self, rule: dict, patch_info: PatchInfo, repo_path: Path) -> Tuple[bool, Optional[str]]:
        """Validate a generated rule using semgrep with improved error handling."""
        rule_file = None
        try:
            with tempfile.NamedTemporaryFile('w', suffix='.yml', delete=False) as tf:
                yaml.dump({"rules": [rule]}, tf)
                rule_file = tf.name
            
            # Curated case: use the standalone extracted files, no clone/checkout needed. See
            # _curated_file_paths() / git_manager.prepare_repo() for why.
            if patch_info.case_id is not None:
                vuln_path, fixed_path = _curated_file_paths(patch_info)
                vuln_files, fixed_files = [vuln_path], [fixed_path]
            else:
                repo = git.Repo(repo_path)
                parent_commit = repo.commit(patch_info.commit_id).parents[0]
                repo.git.checkout(parent_commit)
                vuln_files = [repo_path / fc.file_path for fc in patch_info.file_changes]

            # Test all files in vulnerable version
            vuln_results = []
            skip_count = 0
            for target_file in vuln_files:
                if not target_file.exists():
                    return False, f"Target file not found: {target_file}"

                results, error = self._run_semgrep(rule_file, str(target_file))
                if error:
                    # If it's a rule error, propagate it up
                    return False, error
                elif results is None:
                    # Skip this file but continue with others
                    skip_count += 1
                    continue
                vuln_results.extend(results)

            # If all files were skipped, skip this patch
            if skip_count == len(vuln_files):
                return False, "Skipped all files due to parsing errors"

            # Check fixed version (fixed_files already set above for a curated case)
            if patch_info.case_id is None:
                repo.git.checkout(patch_info.commit_id)
                fixed_files = [repo_path / fc.file_path for fc in patch_info.file_changes]

            # Test all files in fixed version
            fixed_results = []
            for target_file in fixed_files:
                if not target_file.exists():
                    return False, f"Target file not found after checkout: {target_file}"

                results, error = self._run_semgrep(rule_file, str(target_file))
                if error:
                    return False, error
                elif results is None:
                    continue  # Skip this file
                fixed_results.extend(results)
            
            # Rule is valid if it detects vulnerability in parent commit but not in fixed commit
            is_valid = len(vuln_results) > 0 and len(fixed_results) == 0
            
            if not is_valid:
                if len(vuln_results) == 0:
                    error_msg = "Rule failed to detect vulnerability in original version"
                elif len(fixed_results) > 0:
                    error_msg = "Rule incorrectly detected vulnerability in fixed version"
                else:
                    error_msg = "Rule validation failed for unknown reason"
                return False, error_msg
                
            return True, None
            
        except git.exc.GitCommandError as e:
            return False, f"Git error during validation: {str(e)}"
        except Exception as e:
            return False, f"Validation error: {str(e)}"
        finally:
            if rule_file:
                try:
                    Path(rule_file).unlink()
                except Exception as e:
                    logging.warning(f"Failed to delete temporary rule file: {e}")