import { updateAppSettingsBodyValidation } from "../validation/joi.js";
import { handleValidationError, handleError } from "./controllerUtils.js";

const SERVICE_NAME = "SettingsController";

const SECRET_KEY_PATTERN = /password|apikey|secret|token/i;

const maskSecrets = (settings) => {
	const masked = {};
	for (const [key, value] of Object.entries(settings || {})) {
		masked[key] = SECRET_KEY_PATTERN.test(key) && typeof value !== "undefined" ? "********" : value;
	}
	return masked;
};

class SettingsController {
	constructor(db, settingsService, stringService) {
		this.db = db;
		this.settingsService = settingsService;
		this.stringService = stringService;
	}

	getAppSettings = async (req, res, next) => {
		const dbSettings = await this.settingsService.getDBSettings();
		const sanitizedSettings = maskSecrets(dbSettings);
		return res.success({
			msg: this.stringService.getAppSettings,
			data: sanitizedSettings,
		});
	};

	updateAppSettings = async (req, res, next) => {
		try {
			await updateAppSettingsBodyValidation.validateAsync(req.body);
		} catch (error) {
			next(handleValidationError(error, SERVICE_NAME));
			return;
		}

		try {
			await this.db.updateAppSettings(req.body);
			const updatedSettings = maskSecrets(await this.settingsService.reloadSettings());
			delete updatedSettings.jwtSecret;
			return res.success({
				msg: this.stringService.updateAppSettings,
				data: updatedSettings,
			});
		} catch (error) {
			next(handleError(error, SERVICE_NAME, "updateAppSettings"));
		}
	};
}

export default SettingsController;
