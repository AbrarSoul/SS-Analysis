const NAV_LINKS = { docs: "/docs", help: "/help", status: "/status" };

/**
 * Same "setAttribute('href', value)" DOM-anchor sink, but the value is one of
 * a fixed set of developer-written site-relative paths looked up by own-key,
 * never request or user text, so nothing untrusted reaches the sink.
 */
export function setNavLink(anchor, key) {
  const target = Object.prototype.hasOwnProperty.call(NAV_LINKS, key) ? NAV_LINKS[key] : "/";
  anchor.setAttribute("href", target);
  return anchor;
}
