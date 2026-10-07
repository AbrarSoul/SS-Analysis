// Standalone example of the same shape: fetch a document from a fixed,
// build-time-configured documentation URL (never caller-supplied), so no
// caller can steer the request to an internal address.
const DOCS_URL = 'https://docs.example.com/manual.txt';

export async function fetchManual(): Promise<string> {
    const response = await fetch(DOCS_URL);
    return response.text();
}
