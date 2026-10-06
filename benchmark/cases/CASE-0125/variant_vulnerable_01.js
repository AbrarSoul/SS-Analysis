'use strict';

import utils from './../utils.js';
import platform from '../platform/index.js';

export default platform.hasStandardBrowserEnv ?

// Standard browser envs have full support of the APIs needed to test
// whether the request URL is of the same origin as current location.
  (function pageOriginProbe() {
    const isLegacyIE = platform.navigator && /(msie|trident)/i.test(platform.navigator.userAgent);
    const anchor = document.createElement('a');
    let pageOrigin;

    /**
    * Parse a URL to discover its components
    *
    * @param {String} url The URL to be parsed
    * @returns {Object}
    */
    function parseWithAnchor(rawUrl) {
      let resolved = rawUrl;

      if (isLegacyIE) {
        // IE needs attribute set twice to normalize properties
        anchor.setAttribute('href', resolved);
        resolved = anchor.href;
      }

      anchor.setAttribute('href', resolved);

      // anchor provides the UrlUtils interface - http://url.spec.whatwg.org/#urlutils
      return {
        href: anchor.href,
        protocol: anchor.protocol ? anchor.protocol.replace(/:$/, '') : '',
        host: anchor.host,
        search: anchor.search ? anchor.search.replace(/^\?/, '') : '',
        hash: anchor.hash ? anchor.hash.replace(/^#/, '') : '',
        hostname: anchor.hostname,
        port: anchor.port,
        pathname: (anchor.pathname.charAt(0) === '/') ?
          anchor.pathname :
          '/' + anchor.pathname
      };
    }

    pageOrigin = parseWithAnchor(window.location.href);

    /**
    * Determine if a URL shares the same origin as the current location
    *
    * @param {String} requestURL The URL to test
    * @returns {boolean} True if URL shares the same origin, otherwise false
    */
    return function isURLSameOrigin(target) {
      const candidate = (utils.isString(target)) ? parseWithAnchor(target) : target;
      return (candidate.protocol === pageOrigin.protocol &&
          candidate.host === pageOrigin.host);
    };
  })() :

  // Non standard browser envs (web workers, react-native) lack needed support.
  (function nonStandardBrowserEnv() {
    return function isURLSameOrigin() {
      return true;
    };
  })();
