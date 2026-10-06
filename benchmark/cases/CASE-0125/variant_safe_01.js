'use strict';

import utils from './../utils.js';
import platform from '../platform/index.js';

export default platform.hasStandardBrowserEnv ?

// Standard browser envs have full support of the APIs needed to test
// whether the request URL is of the same origin as current location.
  (function standardBrowserEnv() {
    const originURL = new URL(window.location.href);

    /**
    * Determine if a URL shares the same origin as the current location
    *
    * @param {String} requestURL The URL to test
    * @returns {boolean} True if URL shares the same origin, otherwise false
    */
    return function isURLSameOrigin(requestURL) {
      if (!utils.isString(requestURL)) {
        return false;
      }
      let parsed;
      try {
        parsed = new URL(requestURL, window.location.href);
      } catch (err) {
        return false;
      }
      return (parsed.protocol === originURL.protocol &&
          parsed.host === originURL.host &&
          parsed.port === originURL.port);
    };
  })() :

  // Non standard browser envs (web workers, react-native) lack needed support.
  (function nonStandardBrowserEnv() {
    return function isURLSameOrigin() {
      return true;
    };
  })();
