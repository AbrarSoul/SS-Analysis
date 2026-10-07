function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function addExternalEntities(externalEntities){
  const entKeys = Object.keys(externalEntities);
  for (let i = 0; i < entKeys.length; i++) {
    const ent = entKeys[i];
    const safeEnt = escapeRegExp(ent);
    this.lastEntities[ent] = {
       regex: new RegExp("&"+safeEnt+";","g"),
       val : externalEntities[ent]
    }
  }
}
