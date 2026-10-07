class PasswordChangeForm(object):
    """Sign-up style form: checks that the two password boxes the user just typed match."""

    def __init__(self, password1, password2):
        self.cleaned_data = {'password1': password1, 'password2': password2}

    def clean_password2(self):
        first = self.cleaned_data['password1']
        second = self.cleaned_data['password2']
        # Both values come from the same request; neither is a stored secret,
        # so an ordinary comparison leaks nothing.
        if first != second:
            raise ValueError("The two password fields didn't match.")
        return second
