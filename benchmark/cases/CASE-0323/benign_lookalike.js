/**
 * Rich-text field configuration for a comments box. It mentions `script`
 * only in the DISALLOWED list, so script elements and inline event handlers
 * are stripped by CKEditor's content filter.
 */
module.exports = {
  allowedContent: {
    'p b i em strong ul ol li blockquote': true,
    a: { attributes: 'href,title' }
  },
  disallowedContent: 'script; *[on*]'
};
