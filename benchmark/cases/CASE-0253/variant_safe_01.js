/**
 * @license
 * ====================================================================
 * Copyright (c) 2013 Youssef Beddad, youssef.beddad@gmail.com
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 * ====================================================================
 */

import { jsPDF } from "../jspdf.js";

/**
 * jsPDF JavaScript plugin
 *
 * @name javascript
 * @module
 */
(function(jsPDFAPI) {
  "use strict";
  /**
   * @name addJS
   * @function
   * @param {string} javascript The javascript to be embedded into the PDF-file.
   * @returns {jsPDF}
   */
  jsPDFAPI.addJS = function(javascript) {
    // per-call state: nothing is shared between documents or between addJS calls
    var state = { namesObj: undefined, jsObj: undefined, text: javascript };
    this.internal.events.subscribe("postPutResources", function() {
      state.namesObj = this.internal.newObject();
      this.internal.out("<<");
      this.internal.out("/Names [(EmbeddedJS) " + (state.namesObj + 1) + " 0 R]");
      this.internal.out(">>");
      this.internal.out("endobj");

      state.jsObj = this.internal.newObject();
      this.internal.out("<<");
      this.internal.out("/S /JavaScript");
      this.internal.out("/JS (" + state.text + ")");
      this.internal.out(">>");
      this.internal.out("endobj");
    });
    this.internal.events.subscribe("putCatalog", function() {
      if (state.namesObj !== undefined && state.jsObj !== undefined) {
        this.internal.out("/Names <</JavaScript " + state.namesObj + " 0 R>>");
      }
    });
    return this;
  };
})(jsPDF.API);
