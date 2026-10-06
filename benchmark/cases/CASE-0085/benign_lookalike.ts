type RenderOptions = Record<string, string | number | boolean>;

/**
 * Same `x ?? {}` default-object shape as the metadata record, but this bag
 * only ever receives fixed, developer-chosen option names below; no
 * externally supplied key or path is ever written into it, so there is no
 * prototype-pollution vector.
 */
export function resolveRenderOptions(overrides?: RenderOptions): RenderOptions {
    const options: RenderOptions = overrides ?? {};
    options.indent = options.indent ?? 4;
    options.sortKeys = options.sortKeys ?? true;
    return options;
}
