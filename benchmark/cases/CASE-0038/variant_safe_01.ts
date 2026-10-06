import DOMPurify from 'dompurify';

import { markdown_to_html } from '../../renderer/pkg';
// Render markdown into HTML,
// will sanitize input to prevent possible XSS attacks
function render(content: string): string {
  const rawHtml = markdown_to_html(content)
  const safeHtml = DOMPurify.sanitize(rawHtml)
  return safeHtml
}

export default render
