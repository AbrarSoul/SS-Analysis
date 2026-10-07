"""
Standalone example of the same shape: filter which of the ACCOUNT'S OWN
locally-queued reminders get dispatched as desktop notifications by matching
a label the account itself set (never data a remote party controls), so a
label mismatch is a UX filter, not a security boundary.
"""


class ReminderNotifier:

    def __init__(self, active_label):
        self.active_label = active_label
        self.fired = []

    def _handle_reminder_due(self, reminder):
        if reminder['label'] == self.active_label:
            self.fired.append(reminder)
