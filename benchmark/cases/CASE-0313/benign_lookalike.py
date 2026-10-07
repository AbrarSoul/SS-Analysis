"""Report registry: a class that publishes only read-only entry points in its own RPC-style table."""


class ReportHandler(object):
    """Internal report model; nothing that changes state is ever published."""

    def __init__(self):
        self._rpc = {}
        self._rpc.update({
            'render': False,
            'list_templates': False,
            'export_pdf': False,
        })
        self._constraints = []

    def render(self, template, values):
        return template.format(**values)

    def list_templates(self):
        return ['invoice', 'statement']
