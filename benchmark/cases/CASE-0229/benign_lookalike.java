package org.mitre.oauth2.web;

import java.util.Map;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * Standalone example of the same shape: a form-backed page whose object is a
 * plain display preferences bean that is SUPPOSED to be filled from request
 * parameters; no security decision depends on any of its fields.
 */
@Controller
public class DisplayPreferencesController {

	public static class DisplayPreferences {
		private String theme = "light";
		public String getTheme() { return theme; }
		public void setTheme(String theme) { this.theme = theme; }
	}

	@RequestMapping("/preferences")
	public String show(Map<String, Object> model, @ModelAttribute("prefs") DisplayPreferences prefs) {
		model.put("theme", prefs.getTheme());
		return "preferences";
	}
}
