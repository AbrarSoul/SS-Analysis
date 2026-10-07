/* eslint-disable @typescript-eslint/no-non-null-assertion */

const isIndexKey = (str: string) => /^\d+$/.test(str);

function assignPath(
  target: Record<string, any>,
  segments: readonly string[],
  value: unknown,
): void {
  if (segments.length > 1) {
    const rest = [...segments];
    const head = rest.shift()!;
    const following = rest[0]!;

    if (!target[head]) {
      target[head] = isIndexKey(following) ? [] : {};
    } else if (Array.isArray(target[head]) && !isIndexKey(following)) {
      target[head] = Object.fromEntries(Object.entries(target[head]));
    }

    assignPath(target[head], rest, value);

    return;
  }
  const leaf = segments[0]!;
  if (target[leaf] === undefined) {
    target[leaf] = value;
  } else if (Array.isArray(target[leaf])) {
    target[leaf].push(value);
  } else {
    target[leaf] = [target[leaf], value];
  }
}

export function formDataToObject(formData: FormData) {
  const target: Record<string, unknown> = {};

  for (const [head, value] of formData.entries()) {
    const segs = head.split(/[\.\[\]]/).filter(Boolean);
    assignPath(target, segs, value);
  }

  return target;
}
