// Standalone example of the same shape as the fixed SRI-trust check (verify
// a claimed value against an independently-established allow-list; treat an
// unknown key as unverifiable rather than adopting the claim) but over a
// purely local, non-adversarial lookup table with no untrusted input.

/**
 * @param {Map<string, string>} knownUnits
 * @param {string} itemName
 * @param {string} claimedUnit
 * @returns {{ok: boolean, reason?: string}}
 */
export const checkDisplayUnit = (knownUnits, itemName, claimedUnit) => {
	if (!knownUnits.has(itemName)) {
		return { ok: false, reason: `no configured unit for "${itemName}"` }
	}
	const expected = knownUnits.get(itemName)
	if (expected !== claimedUnit) {
		return { ok: false, reason: `unit mismatch for "${itemName}"` }
	}
	return { ok: true }
}
