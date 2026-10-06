import DOMPurify from 'dompurify';

import { markdown_to_html } from '../../renderer/pkg';
// Render markdown into HTML,
// will sanitize input to prevent possible XSS attacks
function normalizeSearchQuery(query: string): string {
  // toLowerCase()/trim() only ever remove or case-fold characters --
  // they cannot introduce new HTML markup the way markdown_to_html()
  // can, so sanitizing before this transformation is safe, unlike
  // render() above.
  const sanitized = DOMPurify.sanitize(query)
  return sanitized.toLowerCase().trim()
}

function render(content: string): string {
  const rawHtml = markdown_to_html(content)
  const safeHtml = DOMPurify.sanitize(rawHtml)
  return safeHtml
}

export default render
