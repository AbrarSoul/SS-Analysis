"""
Section 9 ground-truth test bundle: CASE-0242
(open-webui/open-webui, backend/open_webui/utils/pdf_generator.py
PDFGenerator._build_html_message, CVE-2026-45347, CWE-918 server-side
request forgery through HTML injected into a PDF export).

Core vulnerable mechanism: the chat-export feature builds an HTML document from the
chat's messages and its title with f-strings and hands it to `FPDF.write_html`.
`_build_html_message` puts `role`, `model`, the timestamp and `content`
into the markup unescaped, and `_generate_html_body` does the same with the chat
title. A message (or title) containing `<img src="http://internal-host/...">`
therefore becomes a real image element and fpdf2 fetches the URL from the
server while rendering the PDF: the attacker chooses the request the server makes
(internal services, cloud metadata endpoints) and can also break the layout with other
tags. The upstream fix wraps the values in `html.escape`.

Sibling sites: the same interpolation exists in `_generate_html_body` for
`self.form_data.title`; the upstream patch escapes it too (it is part of the same
diff), so the safe variant escapes all five interpolated values and the
vulnerable variants leave both methods unescaped.

Measured caveat, kept in the manifest notes: `escape(message.get("content", ""))`
raises for a non-string content (for example null), while the safe variant
converts through a helper that treats None as empty text.

Verification: each full file is imported as a module with `open_webui.*` stubbed
(a temporary css file for STATIC_DIR) and `markdown` stubbed; the REAL fpdf2 2.8.8
`FPDF.write_html` renders the html produced by `_build_html_message` and
`_generate_html_body` (core Helvetica font instead of the NotoSans fonts, which are not
available) while a local HTTP server on 127.0.0.1 records whether it was asked for
`/leak.png`.

Every variant is the FULL real file. The two methods are called by
generate_chat_pdf, so their names and signatures are kept; the renamed variant
renames locals.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0242"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


MSG = '''        role = message.get("role", "user")
        content = message.get("content", "")
        timestamp = message.get("timestamp")

        model = message.get("model") if role == "assistant" else ""

        date_str = self.format_timestamp(timestamp) if timestamp else ""
'''
assert original.count(MSG) == 1
TITLE = '''        return f"""
        <html>
            <head>
                <meta name="viewport" content="width=device-width, initial-scale=1.0" />
            </head>
            <body>
            <div>
                <div>
                    <h2>{self.form_data.title}</h2>
'''
assert original.count(TITLE) == 1

# --- Variant 1: renamed vulnerable variant ---
import re

s = original.index("    def _build_html_message(")
e = original.index("    def _generate_html_body(")
seg = original[s:e]
for a, b in (("html_message", "rendered"), ("date_str", "when_text"), ("timestamp", "sent_at")):
    # whole identifiers only; the message.get("timestamp") key and the method names stay
    seg = re.sub(r"(?<![\w\"])%s\b(?!\")" % a, b, seg)
assert "def _build_html_message(" in seg and 'message.get("timestamp")' in seg and "self.format_timestamp(sent_at)" in seg
v1 = original[:s] + seg + original[e:]
(CASE_DIR / "variant_vulnerable_01.py").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
BODY = '''        content = content.replace("\\n", "<br/>")
        html_message = f"""
            <div>
                <div>
                    <h4>
                        <strong>{role.title()}</strong>
                        <span style="font-size: 12px;">{model}</span>
                    </h4>
                    <div> {date_str} </div>
                </div>
                <br/>
                <br/>

                <div>
                    {content}
                </div>
            </div>
            <br/>
          """
        return html_message
'''
assert original.count(BODY) == 1
v2 = swap(original, BODY, '''        content = content.replace("\\n", "<br/>")
        return self._message_markup(role, model, date_str, content)

    @staticmethod
    def _message_markup(role: str, model: str, date_str: str, content: str) -> str:
        return f"""
            <div>
                <div>
                    <h4>
                        <strong>{role.title()}</strong>
                        <span style="font-size: 12px;">{model}</span>
                    </h4>
                    <div> {date_str} </div>
                </div>
                <br/>
                <br/>

                <div>
                    {content}
                </div>
            </div>
            <br/>
          """
''')
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant ---
v3 = swap(original, "from typing import Dict, Any, List\n", "from typing import Dict, Any, List\nfrom html import escape\n")
v3 = swap(v3, "class PDFGenerator:\n", '''def _esc(value: Any) -> str:
    """HTML-escape any value; None becomes empty text."""
    return "" if value is None else escape(str(value))


class PDFGenerator:
''')
v3 = swap(v3, MSG, '''        role = _esc(message.get("role", "user"))
        content = _esc(message.get("content", ""))
        timestamp = message.get("timestamp")

        model = _esc(message.get("model")) if role == "assistant" else ""

        date_str = _esc(self.format_timestamp(timestamp)) if timestamp else ""
''')
v3 = swap(v3, TITLE, '''        title = _esc(self.form_data.title)
        return f"""
        <html>
            <head>
                <meta name="viewport" content="width=device-width, initial-scale=1.0" />
            </head>
            <body>
            <div>
                <div>
                    <h2>{title}</h2>
''')
(CASE_DIR / "variant_safe_01.py").write_text(v3)

BENIGN = '''"""Standalone example of the same shape: build a small HTML snippet from
server-generated numbers only (an export footer), so nothing user-controlled reaches
the markup."""
from datetime import datetime


def footer_html(page: int, total: int) -> str:
    stamp = datetime.now().strftime("%Y-%m-%d")
    return f"<div>Page {int(page)} of {int(total)} - exported {stamp}</div>"
'''
(CASE_DIR / "benign_lookalike.py").write_text(BENIGN)
