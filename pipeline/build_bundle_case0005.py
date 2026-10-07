"""
Section 9 ground-truth test bundle: CASE-0005
(inducer/relate, CVE-2026-42197, CWE-79 -- stored/reflected XSS).

Core vulnerable mechanism: get_user() builds an <a> tag by %-formatting a
template string with obj.user.get_full_name() (user-controlled) and wraps
the whole result in mark_safe(), which disables Django's autoescaping.
Since the interpolated value is never escaped, a crafted full name
containing HTML/JS breaks out into the admin page markup.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent / "benchmark" / "cases" / "CASE-0005"
original = (CASE_DIR / "vulnerable_source.py").read_text()

VULNERABLE_BLOCK = '''    def get_user(self, obj):
        from django.conf import settings
        from django.urls import reverse
        from django.utils.html import mark_safe

        return mark_safe(string_concat(
                "<a href='%(link)s'>", "%(user_fullname)s",
                "</a>"
                ) % {
                    "link": reverse(
                        "admin:{}_change".format(
                            settings.AUTH_USER_MODEL.replace(".", "_").lower()),
                        args=(obj.user.id,)),
                    "user_fullname": obj.user.get_full_name(
                        force_verbose_blank=True),
                    })'''
assert VULNERABLE_BLOCK in original, "vulnerable block not found verbatim"

LIST_DISPLAY_REF = '            "get_user",\n'
assert LIST_DISPLAY_REF in original

# --- Variant 1: renamed vulnerable variant ---
# Rename get_user -> get_user_display_link (definition + its list_display
# string reference), obj -> participation, and the dict keys link/
# user_fullname -> profile_link/display_name. Same exact vulnerability.
RENAMED_BLOCK = '''    def get_user_display_link(self, participation):
        from django.conf import settings
        from django.urls import reverse
        from django.utils.html import mark_safe

        return mark_safe(string_concat(
                "<a href='%(profile_link)s'>", "%(display_name)s",
                "</a>"
                ) % {
                    "profile_link": reverse(
                        "admin:{}_change".format(
                            settings.AUTH_USER_MODEL.replace(".", "_").lower()),
                        args=(participation.user.id,)),
                    "display_name": participation.user.get_full_name(
                        force_verbose_blank=True),
                    })'''
renamed_source = original.replace(VULNERABLE_BLOCK, RENAMED_BLOCK)
renamed_source = renamed_source.replace(LIST_DISPLAY_REF, '            "get_user_display_link",\n')
assert "def get_user(self" not in renamed_source
assert "get_user_display_link" in renamed_source
(CASE_DIR / "variant_vulnerable_01.py").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: intermediate variables. Same exact vulnerability (mark_safe
# wrapping an unescaped user-controlled full name), no renaming.
STRUCTURAL_BLOCK = '''    def get_user(self, obj):
        from django.conf import settings
        from django.urls import reverse
        from django.utils.html import mark_safe

        link_template = string_concat(
                "<a href='%(link)s'>", "%(user_fullname)s",
                "</a>")
        substitutions = {
            "link": reverse(
                "admin:{}_change".format(
                    settings.AUTH_USER_MODEL.replace(".", "_").lower()),
                args=(obj.user.id,)),
            "user_fullname": obj.user.get_full_name(
                force_verbose_blank=True),
        }
        return mark_safe(link_template % substitutions)'''
structural_source = original.replace(VULNERABLE_BLOCK, STRUCTURAL_BLOCK)
assert structural_source != original
assert "link_template" in structural_source and "substitutions" in structural_source
(CASE_DIR / "variant_vulnerable_02.py").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same security property as the real fix (the untrusted full name is
# escaped before being embedded in markup) but implemented via explicit
# escape() + an f-string, not format_html() -- a materially different,
# equally valid Django idiom, not byte-identical to the real patch.
SAFE_BLOCK = '''    def get_user(self, obj):
        from django.conf import settings
        from django.urls import reverse
        from django.utils.html import escape, mark_safe

        profile_url = reverse(
                "admin:{}_change".format(
                    settings.AUTH_USER_MODEL.replace(".", "_").lower()),
                args=(obj.user.id,))
        safe_fullname = escape(obj.user.get_full_name(force_verbose_blank=True))
        return mark_safe(f"<a href='{profile_url}'>{safe_fullname}</a>")'''
safe_source = original.replace(VULNERABLE_BLOCK, SAFE_BLOCK)
assert safe_source != original
assert "escape(obj.user.get_full_name" in safe_source
(CASE_DIR / "variant_safe_01.py").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
# Built on the safe implementation above. Adds a method that also calls
# mark_safe(), the same "risky" API surface, but on a fully static, hardcoded
# HTML string -- no user-controlled text is ever interpolated, so this is
# genuinely safe regardless of what any user's data contains.
BENIGN_ADDITION = '''
    def get_status_icon(self, obj):
        """Renders a static status icon.

        The markup is a hardcoded literal, so mark_safe() here never
        exposes untrusted or user-controlled text into the page, unlike
        the unescaped full-name interpolation this class replaces.
        """
        from django.utils.html import mark_safe
        return mark_safe("<span class='status-icon status-ok'></span>")
'''
anchor = "    def get_user(self, obj):"
benign_source = safe_source.replace(anchor, BENIGN_ADDITION.strip("\n") + "\n\n" + anchor, 1)
assert benign_source != safe_source
assert "get_status_icon" in benign_source
(CASE_DIR / "benign_lookalike.py").write_text(benign_source)

print("Wrote 4 new samples for CASE-0005.")
