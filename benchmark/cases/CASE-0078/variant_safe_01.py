class FlaskSessionCaptcha:
    def validate(self, form_key="captcha", value=None):
        """
        Validate a captcha answer (taken from request.form) against the answer saved in the session.
        Returns always true if CAPTCHA_ENABLE is set to False. Otherwise return true only if it is the correct answer.
        """
        if not self.enabled:
            return True

        session_value = session.get('captcha_answer')
        if not session_value:
            return False

        if not value and form_key in request.form:
            value = request.form[form_key].strip()

        # invalidate the answer to stop new tries on the same challenge.
        session['captcha_answer'] = None
        return bool(value and value == session_value)
