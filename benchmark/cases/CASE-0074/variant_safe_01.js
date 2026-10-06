const path = require('path')

function pathForApplicationData(req, appid, version, isUser, dirForApplicationData, configPath) {
  const candidatePath = path.normalize(
    path.join(dirForApplicationData(req, appid, isUser), `${version}.json`)
  )
  const relative = path.relative(configPath, candidatePath)
  const escapesConfigDir = relative.startsWith('..') || path.isAbsolute(relative)
  if (escapesConfigDir) {
    throw new Error('Invalid path: outside configuration directory')
  }
  return candidatePath
}

module.exports = { pathForApplicationData }
