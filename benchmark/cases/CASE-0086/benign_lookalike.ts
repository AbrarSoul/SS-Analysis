/**
 * Same FROM/JOIN keyword scan as a table-reference extractor, but used only
 * to label a query in a metrics counter. Missing a comma-joined table here
 * only makes a dashboard label less complete; no authorization decision
 * depends on the result.
 */
export function tablesForMetricsLabel(sql: string): string {
  const refPattern = /\b(?:FROM|INTO|UPDATE|TABLE|JOIN)\s+["`[]?([A-Za-z_][A-Za-z0-9_]{0,63})["`\]]?/gi;
  const names = new Set<string>();
  for (const match of sql.matchAll(refPattern)) names.add(match[1]);
  return [...names].sort().join('+') || 'unknown';
}
