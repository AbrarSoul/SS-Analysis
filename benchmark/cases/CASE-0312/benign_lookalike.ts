/* Settings form parser: maps known form field names onto a Map, never onto an object. */

const KNOWN_FIELDS = ['name', 'email', 'locale'] as const;

export function readProfileForm(formData: FormData): Map<string, string> {
  const profile = new Map<string, string>();

  for (const [key, value] of formData.entries()) {
    const field = key.split(/[\.\[\]]/).filter(Boolean).join('.');
    if ((KNOWN_FIELDS as readonly string[]).includes(field) && typeof value === 'string') {
      profile.set(field, value);
    }
  }

  return profile;
}
