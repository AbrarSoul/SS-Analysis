function buildSafeSetDateCommand(datetime) {
  const parsed = new Date(datetime)
  if (isNaN(parsed.getTime())) {
    throw new Error('Invalid datetime received: ' + String(datetime).substring(0, 50))
  }
  const pad = n => String(n).padStart(2, '0')
  const safeDateStr =
    `${parsed.getUTCFullYear()}-${pad(parsed.getUTCMonth() + 1)}-${pad(parsed.getUTCDate())} ` +
    `${pad(parsed.getUTCHours())}:${pad(parsed.getUTCMinutes())}:${pad(parsed.getUTCSeconds())}`
  // safeDateStr is built ENTIRELY from validated numeric fields -- no
  // substring of the original attacker-influenced string ever appears
  // in the returned command.
  return `date -u -s "${safeDateStr}"`
}

module.exports = { buildSafeSetDateCommand }
