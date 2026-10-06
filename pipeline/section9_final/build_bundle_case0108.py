"""
Section 9 ground-truth test bundle: CASE-0108
(apache/openmeetings, InvitationForm, CVE-2023-28326, CWE-306 missing
authorization for a critical function).

Core vulnerable mechanism: `updateButtons()` enables the "Generate
invitation link" button whenever exactly ONE recipient is selected
(`setEnabled(recpnts.size() == 1)`), regardless of who that recipient is.
Any logged-in user can therefore generate an invitation/login link for an
arbitrary other user's account. The upstream fix enables it only when the
single recipient is the current user or a CONTACT-type user.

Every variant is the FULL real file with updateButtons replaced. It is a
`protected` (overridable) method with one in-file call site (inside a
lambda in onInitialize), which the renamed variant also renames.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0108"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

HDR = "\tprotected void updateButtons(AjaxRequestTarget target) {\n"
s = original.index(HDR)
e = original.index("\n\t}\n", s) + len("\n\t}\n")
BLOCK = original[s:e]
CALL = "updateButtons(target);"
GEN_LINE = "\t\t\t\t, dialog.getGenerate().setEnabled(recpnts.size() == 1)\n"
assert original.count(HDR) == 1 and original.count(CALL) == 1 and BLOCK.count(GEN_LINE) == 1
assert original.count("updateButtons(") == 2 and "import org.apache.openmeetings.db.entity.user.User.Type;" in original


def build(new_block, new_call=None):
    assert new_block != BLOCK
    out = original[:s] + new_block + original[e:]
    if new_call:
        assert out.count(CALL) == 1
        out = out.replace(CALL, new_call)
    return out


def rename_outside_strings(text, pairs):
    out = []
    for line in text.split("\n"):
        if line.lstrip().startswith("//"):
            out.append(line)
            continue
        parts = re.split(r'("(?:[^"\\]|\\.)*")', line)
        for i in range(0, len(parts), 2):
            for old, new in pairs:
                parts[i] = re.sub(r"\b%s\b" % old, new, parts[i])
        out.append("".join(parts))
    return "\n".join(out)


# --- Variant 1: renamed vulnerable variant ---
b = BLOCK.replace("updateButtons(", "refreshActionButtons(")
b = rename_outside_strings(b, (("target", "ajaxTarget"), ("recpnts", "selectedUsers")))
assert "selectedUsers.size() == 1" in b and "refreshActionButtons(AjaxRequestTarget ajaxTarget)" in b
(CASE_DIR / "variant_vulnerable_01.java").write_text(build(b, "refreshActionButtons(target);"))

# --- Variant 2: structurally changed vulnerable variant ---
b = BLOCK.replace(
    "\t\ttarget.add(\n\t\t\t\tdialog.getSend().setEnabled(!recpnts.isEmpty())\n" + GEN_LINE + "\t\t\t\t);\n",
    "\t\tfinal boolean canSend = !recpnts.isEmpty();\n"
    "\t\tfinal boolean canGenerate = recpnts.size() == 1;\n"
    "\t\ttarget.add(dialog.getSend().setEnabled(canSend), dialog.getGenerate().setEnabled(canGenerate));\n")
assert b != BLOCK and "canGenerate = recpnts.size() == 1" in b
(CASE_DIR / "variant_vulnerable_02.java").write_text(build(b))

# --- Variant 3: transformed safe variant ---
# Same authorization rule as upstream (single recipient must be the current
# user or a CONTACT) expressed as a stream allMatch, reusing the already
# imported `Type`.
b = BLOCK.replace(
    "\t\ttarget.add(\n",
    "\t\tboolean generateEnabled = recpnts.size() == 1\n"
    "\t\t\t\t&& recpnts.stream().allMatch(u -> getUserId().equals(u.getId()) || Type.CONTACT == u.getType());\n"
    "\t\ttarget.add(\n").replace(GEN_LINE, "\t\t\t\t, dialog.getGenerate().setEnabled(generateEnabled)\n")
assert b != BLOCK and "recpnts.size() == 1)" not in b and "setEnabled(generateEnabled)" in b
(CASE_DIR / "variant_safe_01.java").write_text(build(b))

# --- Variant 4: benign structural look-alike ---
benign_source = '''import java.util.Collection;

public class RecipientPreviewButton {

    public interface Toggle {
        void setEnabled(boolean on);
    }

    /**
     * Same "enable when exactly one is selected" shape, but the enabled action
     * is a read-only preview of display names the current user has already
     * selected from a list they can already see. It generates no link or
     * token and grants no access, so it needs no authorization check.
     */
    public void updatePreview(Collection<String> selectedDisplayNames, Toggle previewButton) {
        previewButton.setEnabled(selectedDisplayNames.size() == 1);
    }
}
'''
assert "generate" not in benign_source.lower().replace("generates no", "")
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0108.")
