// Standalone example of the same shape: map a URL path to a file for a fixed,
// server-defined list of documentation pages, never an arbitrary client path.
import path from 'path';

const PAGES: Record<string, string> = {
    '/': 'index.html',
    '/help': 'help.html',
};

export function pageFile(publicDir: string, pathname: string): string | undefined {
    const name = PAGES[pathname];
    return name ? path.join(publicDir, name) : undefined;
}
