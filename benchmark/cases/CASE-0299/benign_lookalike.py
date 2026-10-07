"""
Standalone example of the same shape: assemble a command from a template
and a value, but run it WITHOUT a shell (argument list), so the value is one
literal argv item and metacharacters are inert.
"""
import subprocess


def open_with(template_argv, url):
    return subprocess.run(list(template_argv) + [url], check=False)
