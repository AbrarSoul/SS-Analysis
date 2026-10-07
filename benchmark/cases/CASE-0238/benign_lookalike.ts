// Standalone example of the same shape: a CSV export whose columns are
// server-generated numbers only, so no cell can start with a formula character.
import Papaparse from 'papaparse';

export function exportCounters(counters: Record<string, number>): string {
    const rows = Object.entries(counters).map(([name, count]) => ({ name: name.replace(/[^a-z0-9_]/gi, '_'), count }));
    return Papaparse.unparse({ fields: ['name', 'count'], data: rows });
}
