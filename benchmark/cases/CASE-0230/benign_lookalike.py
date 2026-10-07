"""Standalone example of the same shape: render a fixed, package-owned
template with data only; the template source never comes from a user."""
import jinja2

_TEMPLATE = jinja2.Environment(loader=jinja2.BaseLoader()).from_string(
    "<h1>{{ title }}</h1><p>{{ body }}</p>"
)


def render_banner(title, body):
    return _TEMPLATE.render(title=title, body=body)
