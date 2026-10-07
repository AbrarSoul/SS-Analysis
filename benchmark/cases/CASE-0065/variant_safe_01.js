Auth.verifyToken = async function (token, done) {
	const { tokens = [] } = await meta.settings.get('core.api');
	const tokenMap = new Map();
	tokens.forEach(cur => tokenMap.set(cur.token, cur.uid));

	const uid = tokenMap.get(token);

	if (uid !== undefined) {
		if (parseInt(uid, 10) > 0) {
			done(null, {
				uid: uid,
			});
		} else {
			done(null, {
				master: true,
			});
		}
	} else {
		done(false);
	}
}
