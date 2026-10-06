import git
import os
import shutil
import signal
import threading
from pathlib import Path
from config import Config
from patch_processor import PatchInfo
from typing import Optional
import logging
import subprocess

class GitManager:
    # Process-wide, keyed by shared-clone-relative repo path, so concurrent
    # threads (this project parallelizes model runs across GPU hosts) never
    # race on "does the shared clone exist yet, if not create it" for the
    # same repository. Not scoped to one GitManager instance since each
    # model run builds its own instance but they all share the same
    # underlying shared_repos_cache_dir on disk.
    _clone_locks: dict = {}
    _clone_locks_guard = threading.Lock()

    def __init__(self, config: Config):
        self.config = config
        self._check_git_installation()
        # Abort a git network operation (clone/fetch) if its transfer rate
        # stays below ~1KB/s for 60+ consecutive seconds, instead of hanging
        # indefinitely. Found live during Phase 4 curation: cloning a large
        # repository (liferay/liferay-portal) stalled completely partway
        # through -- 0% CPU, zero size growth, no error -- and sat hung for
        # 45+ minutes, blocking the entire sequential Step 3 run with no way
        # to recover automatically. Same category of gap as the earlier
        # missing OpenAI-client timeout (Config.request_timeout_seconds),
        # just for git instead of the LLM API. setdefault so an operator's
        # own environment setting, if any, isn't silently overridden.
        os.environ.setdefault("GIT_HTTP_LOW_SPEED_LIMIT", "1000")
        os.environ.setdefault("GIT_HTTP_LOW_SPEED_TIME", "60")

    def _check_git_installation(self):
        """Check if git is installed and accessible."""
        try:
            subprocess.run(["git", "--version"],
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,
                         check=True)
        except subprocess.CalledProcessError:
            raise RuntimeError("Git command failed. Please ensure Git is installed and in your PATH.")
        except FileNotFoundError:
            raise RuntimeError("Git is not installed or not found in PATH. Please install Git first.")

    def _sanitize_repo_path(self, owner: str, name: str) -> str:
        """Create a safe repository directory name."""
        return f"{owner}_{name}".replace('/', '_').replace('\\', '_')

    @classmethod
    def _get_clone_lock(cls, safe_path: str) -> threading.Lock:
        with cls._clone_locks_guard:
            if safe_path not in cls._clone_locks:
                cls._clone_locks[safe_path] = threading.Lock()
            return cls._clone_locks[safe_path]

    # Hard wall-clock cap on a single clone attempt. The GIT_HTTP_LOW_SPEED_*
    # env vars set in __init__ only catch a genuinely STALLED transfer
    # (near-zero throughput); a repository that's just enormous and clones
    # steadily the whole time (observed live: liferay/liferay-portal, which
    # still hadn't finished after 45+ minutes) would never trip that and
    # could block the entire sequential curation run indefinitely on its
    # own. A shallow/depth-limited clone isn't a safe alternative fix here --
    # this pipeline checks out arbitrary historical commits by hash
    # (Section 8 Step 3), which a shallow clone may not even contain.
    CLONE_TIMEOUT_SECONDS = 300

    def _clone_or_fetch(self, repo_url_owner: str, repo_url_name: str, dest_path: Path) -> git.Repo:
        """Clone dest_path if it doesn't exist yet (HTTPS, falling back to
        SSH), otherwise fetch updates into the existing clone. Shared by
        both the legacy (per-run clone) and shared-cache (per-repo clone)
        paths below -- identical logic, different destination.

        Clones via a direct subprocess.run(..., timeout=...) rather than
        GitPython's clone_from(), specifically so a hard wall-clock timeout
        can be enforced -- GitPython's own clone_from() has no timeout
        parameter, which is exactly how the liferay-portal case above went
        unbounded. On timeout, any partial clone directory is removed and a
        git.exc.GitCommandError is raised, so callers (prepare_repo()) treat
        it exactly like an inaccessible repository -- excluded and logged,
        not retried forever."""
        if not dest_path.exists():
            logging.info(f"Cloning repository: {repo_url_owner}/{repo_url_name}")
            repo_url = f"https://github.com/{repo_url_owner}/{repo_url_name}"
            try:
                self._run_clone(repo_url, dest_path)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                if dest_path.exists():
                    shutil.rmtree(dest_path)
                if isinstance(e, subprocess.TimeoutExpired):
                    logging.warning(f"Clone of {repo_url_owner}/{repo_url_name} exceeded "
                                     f"{self.CLONE_TIMEOUT_SECONDS}s, aborting and trying SSH...")
                else:
                    logging.info("HTTPS clone failed, trying SSH...")
                repo_url = f"git@github.com:{repo_url_owner}/{repo_url_name}.git"
                try:
                    self._run_clone(repo_url, dest_path)
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e2:
                    if dest_path.exists():
                        shutil.rmtree(dest_path)
                    raise git.exc.GitCommandError(
                        ["git", "clone", repo_url], 1,
                        f"clone failed via both HTTPS and SSH (last error: {e2})")
            repo = git.Repo(dest_path)
        else:
            logging.info(f"Using cached repository at {dest_path}")
            repo = git.Repo(dest_path)
            try:
                repo.remote().fetch()
            except git.exc.GitCommandError as e:
                logging.warning(f"Failed to fetch updates: {e}")
        return repo

    def _run_clone(self, repo_url: str, dest_path: Path) -> None:
        """Runs `git clone` in its own process group so a timeout can kill
        the WHOLE tree, not just the immediate child. git itself spawns a
        grandchild (git-remote-https) to do the actual network transfer --
        subprocess.run(timeout=...)'s default kill() only reaches the direct
        child, which is exactly how an earlier clone attempt on this same
        pipeline left an orphaned git-remote-https running independently in
        the background for 45+ minutes after its "parent" was killed."""
        proc = subprocess.Popen(
            ["git", "clone", "--", repo_url, str(dest_path)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            start_new_session=True,
        )
        try:
            _, stderr = proc.communicate(timeout=self.CLONE_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            proc.wait()
            raise subprocess.TimeoutExpired(proc.args, self.CLONE_TIMEOUT_SECONDS)
        if proc.returncode != 0:
            raise subprocess.CalledProcessError(proc.returncode, proc.args, stderr=stderr)

    @staticmethod
    def _commit_or_fetch_by_sha(repo: git.Repo, commit_id: str):
        """Resolve commit_id; if a normal clone lacks it (e.g. a fix that lives only on a pull-request branch,
        as with hand-curated CASE-0078), fetch it by SHA from origin -- GitHub serves any reachable commit.
        Added for the final benchmark after the Step 2 pipeline test found such a case."""
        try:
            return repo.commit(commit_id)
        except (git.exc.BadName, git.exc.BadObject, ValueError):  # GitPython raises ValueError for an unresolved full SHA
            logging.info(f"Commit {commit_id} not in clone; trying fetch by SHA")
            repo.git.fetch("origin", commit_id)
            return repo.commit(commit_id)

    def prepare_repo(self, patch_info: PatchInfo) -> Optional[Path]:
        """Clone or update repository and check out the relevant commits.

        Curated cases (patch_info.case_id set, i.e. built via pipeline/case_loader.py) skip cloning entirely:
        rule_validator.py reads their vulnerable/patched content directly from the standalone
        benchmark/cases/CASE-XXXX/{vulnerable_source,patched_source} files that Step 3/7 curation already
        extracted, rather than checking out a real git repository. Across the 300 final cases that would
        otherwise mean cloning 258 repositories (~48GB locally, measured) for content already sitting on
        disk in exactly the form needed. Returns a synthetic, non-existent marker path -- callers only need
        it to be truthy (main.py's `if not repo_path: ... return None` check) and it is never dereferenced
        by rule_validator for a curated case; reset_repo()/cleanup_repo() also naturally no-op on a path
        that doesn't exist. The raw-.patch-file flow (case_id is None) is completely unaffected -- this
        branch is skipped entirely for it. Decided in Section 30 preregistration audit, Implementation Log
        Section 12.24.
        """
        if patch_info.case_id is not None:
            return Path(f"<curated-case:{patch_info.case_id}>")

        safe_path = self._sanitize_repo_path(patch_info.repo_owner, patch_info.repo_name)

        if self.config.shared_repos_cache_dir is None:
            repo_path = self.config.repos_cache_dir / safe_path
            try:
                repo = self._clone_or_fetch(patch_info.repo_owner, patch_info.repo_name, repo_path)
                commit = self._commit_or_fetch_by_sha(repo, patch_info.commit_id)
                logging.info(f"Found commit: {commit.hexsha}")
                return repo_path
            except git.exc.BadName:
                logging.error(f"Commit {patch_info.commit_id} not found in repository")
                return None
            except Exception as e:
                logging.error(f"Error preparing repository: {str(e)}", exc_info=True)
                if repo_path.exists():
                    shutil.rmtree(repo_path)
                return None

        shared_clone_path = self.config.shared_repos_cache_dir / safe_path
        worktree_path = self.config.repos_cache_dir / safe_path

        lock = self._get_clone_lock(safe_path)
        try:
            with lock:
                shared_repo = self._clone_or_fetch(patch_info.repo_owner, patch_info.repo_name, shared_clone_path)
                commit = self._commit_or_fetch_by_sha(shared_repo, patch_info.commit_id)
                logging.info(f"Found commit: {commit.hexsha}")
        except git.exc.BadName:
            logging.error(f"Commit {patch_info.commit_id} not found in repository")
            return None
        except Exception as e:
            logging.error(f"Error preparing shared repository clone: {str(e)}", exc_info=True)
            if shared_clone_path.exists():
                shutil.rmtree(shared_clone_path)
            return None

        if worktree_path.exists():
            # Reused across multiple cases from the same repo within this
            # same run -- rule_validator checks it out to whatever commit
            # each case needs, same as it always has on a plain clone.
            return worktree_path

        try:
            worktree_path.parent.mkdir(parents=True, exist_ok=True)
            # --detach: this worktree is never on a branch, so many worktrees
            # of the same repo (one per concurrent model run) can coexist --
            # git only refuses two worktrees on the same *branch* at once.
            shared_repo.git.worktree('add', '--detach', str(worktree_path), patch_info.commit_id)
            return worktree_path
        except git.exc.GitCommandError as e:
            logging.error(f"Error creating worktree for {patch_info.repo_owner}/{patch_info.repo_name}: {e}",
                          exc_info=True)
            return None

    def reset_repo(self, repo_path: Path) -> bool:
        """Reset repository (or worktree) to clean state, discarding all local changes."""
        try:
            repo = git.Repo(repo_path)
            repo.git.reset('--hard')  # Reset any staged changes
            repo.git.clean('-fd')     # Remove untracked files and directories
            return True
        except Exception as e:
            logging.error(f"Error resetting repository: {e}")
            return False

    def cleanup_repo(self, repo_path: Path):
        """Clean up a repository (or worktree) directory if needed.

        For a worktree, a plain rmtree leaves a stale admin entry in the
        shared clone's .git/worktrees/ metadata that can make a future
        `git worktree add` at the same path fail -- so worktrees are removed
        via `git worktree remove`, with a fallback to prune's cleanup if
        the directory was already gone/corrupted."""
        if not repo_path.exists():
            return
        if self.config.shared_repos_cache_dir is not None:
            safe_path = repo_path.name
            shared_clone_path = self.config.shared_repos_cache_dir / safe_path
            if shared_clone_path.exists():
                try:
                    git.Repo(shared_clone_path).git.worktree('remove', '--force', str(repo_path))
                    return
                except Exception as e:
                    logging.warning(f"git worktree remove failed for {repo_path}, falling back to rmtree: {e}")
                    try:
                        git.Repo(shared_clone_path).git.worktree('prune')
                    except Exception:
                        pass
        try:
            shutil.rmtree(repo_path)
        except Exception as e:
            logging.error(f"Error cleaning up repository: {e}")