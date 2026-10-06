import path from 'path';

const ASSET_FILES: Record<string, string> = {
    logo: 'img/logo.png',
    favicon: 'img/favicon.ico',
};

/**
 * Same path.join(base, x) + startsWith(base) shape, but the relative part
 * comes only from a fixed table of developer-written constants keyed by a
 * whitelisted name; no request-supplied path (and no user-writable
 * directory that could contain a symlink) is ever involved.
 */
export const resolveBundledAsset = (base: string, name: string): string => {
    const relative = ASSET_FILES[name];
    if (relative === undefined) {
        throw new Error('Unknown asset');
    }
    const fullPath = path.join(base, relative);
    if (!fullPath.startsWith(base)) {
        throw new Error('Invalid path');
    }
    return fullPath;
};
