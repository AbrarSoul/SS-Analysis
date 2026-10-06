import * as fs from 'fs-extra';
// eslint-disable-next-line import/no-unresolved
import { load as loadResEdit } from 'resedit/cjs';
import { Win32MetadataOptions } from './types';
import { FileRecord } from '@electron/asar';

export type ExeMetadata = {
  productVersion?: string;
  fileVersion?: string;
  legalCopyright?: string;
  productName?: string;
  iconPath?: string;
  asarIntegrity?: Record<string, Pick<FileRecord['integrity'], 'algorithm' | 'hash'>>;
  win32Metadata?: Win32MetadataOptions;
}

type ParsedVersionNumerics = [number, number, number, number];

/**
 * Parse a version string in the format a.b.c.d with each component being optional
 * but if present must be an integer. Matches the impl in rcedit for compat
 */
function parseVersionString(str: string): ParsedVersionNumerics {
  const parts = str.split('.');
  if (parts.length === 0 || parts.length > 4) {
    throw new Error(`Incorrectly formatted version string: "${str}". Should have at least one and at most four components`);
  }
  return parts.map((part) => {
    const parsed = parseInt(part, 10);
    if (isNaN(parsed)) {
      throw new Error(`Incorrectly formatted version string: "${str}". Component "${part}" could not be parsed as an integer`);
    }
    return parsed;
  }) as ParsedVersionNumerics;
}

// Ref: https://learn.microsoft.com/en-us/windows/win32/menurc/resource-types
const RT_MANIFEST_TYPE = 24;

export async function resedit(exeFile: string, opts: ExeMetadata) {
  const resEditLib = await loadResEdit();

  const rawBytes = await fs.readFile(exeFile);
  const pe = resEditLib.NtExecutable.from(rawBytes);
  const resources = resEditLib.NtExecutableResource.from(pe);

  if (opts.iconPath) {
    // Icon Info
    const existingIconGroups = resEditLib.Resource.IconGroupEntry.fromEntries(resources.entries);
    if (existingIconGroups.length !== 1) {
      throw new Error('Failed to parse win32 executable resources, failed to locate existing icon group');
    }
    const iconFile = resEditLib.Data.IconFile.from(await fs.readFile(opts.iconPath));
    resEditLib.Resource.IconGroupEntry.replaceIconsForResource(
      resources.entries,
      existingIconGroups[0].id,
      existingIconGroups[0].lang,
      iconFile.icons.map((item) => item.data)
    );
  }

  // Manifest
  if (opts.win32Metadata?.['application-manifest'] || opts.win32Metadata?.['requested-execution-level']) {
    if (opts.win32Metadata?.['application-manifest'] && opts.win32Metadata?.['requested-execution-level']) {
      throw new Error('application-manifest and requested-execution-level are mutually exclusive, only provide one');
    }

    const manifests = resources.entries.filter(e => e.type === RT_MANIFEST_TYPE);
    if (manifests.length !== 1) {
      throw new Error('Failed to parse win32 executable resources, failed to locate existing manifest');
    }
    const manifestEntry = manifests[0];
    if (opts.win32Metadata?.['application-manifest']) {
      manifestEntry.bin = (await fs.readFile(opts.win32Metadata?.['application-manifest'])).buffer;
    } else if (opts.win32Metadata?.['requested-execution-level']) {
      // This implementation matches what rcedit used to do, in theory we can be Smarter
      // and use an actual XML parser, but for now let's match the old impl
      const currentManifestContent = Buffer.from(manifestEntry.bin).toString('utf-8');
      const newContent = currentManifestContent.replace(
        /(<requestedExecutionLevel level=")asInvoker(" uiAccess="false"\/>)/g,
        `$1${opts.win32Metadata?.['requested-execution-level']}$2`
      );
      manifestEntry.bin = Buffer.from(newContent, 'utf-8');
    }
  }

  // Version Info
  const versionInfo = resEditLib.Resource.VersionInfo.fromEntries(resources.entries);
  if (versionInfo.length !== 1) {
    throw new Error('Failed to parse win32 executable resources, failed to locate existing version info');
  }
  if (opts.fileVersion) versionInfo[0].setFileVersion(...parseVersionString(opts.fileVersion));
  if (opts.productVersion) versionInfo[0].setProductVersion(...parseVersionString(opts.productVersion));
  const languageInfo = versionInfo[0].getAllLanguagesForStringValues();
  if (languageInfo.length !== 1) {
    throw new Error('Failed to parse win32 executable resources, failed to locate existing language info');
  }
  // Empty strings retain original value
  const newStrings: Record<string, string> = {
    CompanyName: opts.win32Metadata?.CompanyName || '',
    FileDescription: opts.win32Metadata?.FileDescription || '',
    FileVersion: opts.fileVersion || '',
    InternalName: opts.win32Metadata?.InternalName || '',
    LegalCopyright: opts.legalCopyright || '',
    OriginalFilename: opts.win32Metadata?.OriginalFilename || '',
    ProductName: opts.productName || '',
    ProductVersion: opts.productVersion || '',
  };
  for (const key of Object.keys(newStrings)) {
    if (!newStrings[key]) delete newStrings[key];
  }
  versionInfo[0].setStringValues(languageInfo[0], newStrings);

  // Output version info
  versionInfo[0].outputToResourceEntries(resources.entries);

  // Asar Integrity
  if (opts.asarIntegrity) {
    resources.entries.push({
      type: 'Integrity',
      id: 'ElectronAsar',
      bin: Buffer.from(JSON.stringify(opts.asarIntegrity)).buffer,
      lang: languageInfo[0].lang,
      codepage: languageInfo[0].codepage,
    });
  }

  resources.outputResource(pe);

  await fs.writeFile(exeFile, Buffer.from(pe.generate()));
}
