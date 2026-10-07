from jinja2 import Environment


def render_status_banner(service_name, uptime_seconds):
    """Uses a plain Environment, but the template text is a fixed
    developer-written constant; callers supply only data values, never
    template source, so no attacker-controlled template is ever compiled."""
    env = Environment(autoescape=True)
    template = env.from_string("{{ name }} has been up for {{ seconds }}s")
    return template.render(name=service_name, seconds=uptime_seconds)
