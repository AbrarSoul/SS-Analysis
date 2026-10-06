export function selfTestMimeParser() {
  // Only ever exercised against these two fixed literal strings at
  // module load time -- never receives external/attacker-supplied
  // input, so the nested-quantifier regex below has no exploitable
  // pathological-input surface despite its structural resemblance to
  // extractImageFromDataUrl()'s vulnerable pattern.
  var samples = ["data:image/png;charset=utf-8;", "data:image/jpeg;"];
  return samples.map(function (sample) {
    return /^data:(\w*\/\w*);*(charset=[\w=-]*)*;*$/.exec(sample);
  });
}
