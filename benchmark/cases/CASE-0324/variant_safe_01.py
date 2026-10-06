from django import forms
from django.utils.crypto import constant_time_compare
from django.utils.translation import ugettext as _
from django.utils.translation import ugettext_lazy


class PasswordViewRestrictionForm(forms.Form):
    password = forms.CharField(label=ugettext_lazy("Password"), widget=forms.PasswordInput)
    return_url = forms.CharField(widget=forms.HiddenInput)

    def __init__(self, *args, **kwargs):
        self.restriction = kwargs.pop('instance')
        super().__init__(*args, **kwargs)

    def _matches(self, candidate):
        return constant_time_compare(candidate, self.restriction.password)

    def clean_password(self):
        data = self.cleaned_data['password']
        if not self._matches(data):
            raise forms.ValidationError(_("The password you have entered is not correct. Please try again."))

        return data
