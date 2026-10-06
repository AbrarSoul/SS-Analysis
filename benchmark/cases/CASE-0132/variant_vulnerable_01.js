import { updateAppSettingsBodyValidation } from "../validation/joi.js";
import { handleValidationError, handleError } from "./controllerUtils.js";

const SERVICE_NAME = "SettingsController";

class SettingsController {
	constructor(db, settingsService, stringService) {
		this.db = db;
		this.settingsService = settingsService;
		this.stringService = stringService;
	}

	loadSettings = async (request, response, next) => {
		const stored = await this.settingsService.getDBSettings();
		const visible = { ...stored };
		if (typeof visible.pagespeedApiKey !== "undefined") {
			visible.pagespeedApiKey = "********";
		}
		return response.success({
			msg: this.stringService.getAppSettings,
			data: visible,
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
			const updatedSettings = { ...(await this.settingsService.reloadSettings()) };
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
