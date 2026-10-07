const PUBLIC_FIELDS = ["appName", "logoUrl", "supportEmail"];

/**
 * Same "res.success({ msg, data }) with the stored settings" shape, but the
 * response is built by picking an explicit allow-list of PUBLIC branding
 * fields, so no secret (password, API key, token) can ever be in it -- new
 * secret fields added to the settings document later are excluded by
 * default.
 */
export const getPublicBranding = (settingsService, stringService) => async (req, res) => {
	const stored = await settingsService.getDBSettings();
	const data = {};
	for (const field of PUBLIC_FIELDS) {
		if (typeof stored[field] !== "undefined") {
			data[field] = stored[field];
		}
	}
	return res.success({ msg: stringService.getPublicBranding, data });
};
