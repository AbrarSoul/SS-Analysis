"""
Section 9 ground-truth test bundle: CASE-0124
(aws/sagemaker-python-sdk, save_retrive/.../save/utils.py
capture_dependencies, CVE-2024-34073, CWE-78 OS command injection).

Core vulnerable mechanism: `capture_dependencies(requirements_path)` builds
a shell command line with an f-string,
`f"pigar gen -f {Path(requirements_path)} {os.getcwd()}"`, and runs it with
`os.system(command)`. The path is interpolated into a string parsed by
/bin/sh, so a path such as `req.txt; touch /tmp/pwned` (or one containing
`$(...)`, backticks or `&&`) executes arbitrary commands. The upstream fix
builds an argv list and runs it with `subprocess.run(command, check=True,
capture_output=True)` (no shell).

Every variant is the FULL real file with capture_dependencies replaced. It
has no in-file callers (it is called from other modules), so the renamed
variant renames the declaration only.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0124"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original

HDR = "def capture_dependencies(requirements_path: str):\n"
s = original.index(HDR)
e = original.index("\n\n\ndef capture_optimization_metadata", s) + 1
BLOCK = original[s:e]
CMD = '''    command = f"pigar gen -f {Path(requirements_path)} {os.getcwd()}"
    logging.info("Running command %s", command)

    os.system(command)
'''
assert original.count(HDR) == 1 and BLOCK.count(CMD) == 1
assert original.count("capture_dependencies(") == 1 and "subprocess" not in original


def build(new_block, extra_import=None):
    assert new_block != BLOCK
    out = original[:s] + new_block + original[e:]
    if extra_import:
        assert out.count("import os\n") == 1
        out = out.replace("import os\n", "import os\n" + extra_import + "\n")
    return out


# --- Variant 1: renamed vulnerable variant ---
b = BLOCK.replace("def capture_dependencies(", "def record_requirements(")
b = b.replace("requirements_path", "output_file")          # unique identifier, also inside the f-string
b = b.replace('with open(output_file, "w") as f:', 'with open(output_file, "w") as handle:').replace("f.write(", "handle.write(")
b = b.replace("sagemaker_dependency", "pinned_line")
# `command` -> `shell_line`, but never inside the log format string "Running command %s"
out = []
for line in b.split("\n"):
    parts = re.split(r'("(?:[^"\\]|\\.)*")', line)
    for i in range(0, len(parts), 2):
        parts[i] = re.sub(r"(?<![.\w])command(?![\w])", "shell_line", parts[i])
    out.append("".join(parts))
b = "\n".join(out)
assert 'shell_line = f"pigar gen -f {Path(output_file)} {os.getcwd()}"' in b
assert 'logging.info("Running command %s", shell_line)' in b and "os.system(shell_line)" in b
assert "handle.write(pinned_line)" in b
(CASE_DIR / "variant_vulnerable_01.py").write_text(build(b))

# --- Variant 2: structurally changed vulnerable variant ---
# Argument list joined back into one shell string: still handed to /bin/sh.
b = BLOCK.replace(CMD, '''    parts = ["pigar", "gen", "-f", str(Path(requirements_path)), os.getcwd()]
    command = " ".join(parts)
    logging.info("Running command %s", command)

    os.system(command)
''')
assert b != BLOCK and "os.system(command)" in b
(CASE_DIR / "variant_vulnerable_02.py").write_text(build(b))

# --- Variant 3: transformed safe variant ---
# argv-based os.spawnvp (no shell at all); upstream uses subprocess.run.
b = BLOCK.replace(CMD, '''    argv = ["pigar", "gen", "-f", str(Path(requirements_path)), os.getcwd()]
    logging.info("Running command: %s", " ".join(argv))

    os.spawnvp(os.P_WAIT, "pigar", argv)
''')
safe_source = build(b)
assert "os.system" not in safe_source
(CASE_DIR / "variant_safe_01.py").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
benign_source = '''import os


def run_build(jobs: int) -> int:
    """Same "f-string command handed to os.system" shape, but the only
    interpolated value goes through int(), so it can contain nothing except
    an optional sign and digits (anything else raises ValueError before a
    shell is ever involved), and everything else in the command is a
    constant. No caller-controlled text can reach the shell."""
    command = f"make -j {int(jobs)}"
    return os.system(command)
'''
assert "int(jobs)" in benign_source
(CASE_DIR / "benign_lookalike.py").write_text(benign_source)
print("Wrote 4 new samples for CASE-0124.")
