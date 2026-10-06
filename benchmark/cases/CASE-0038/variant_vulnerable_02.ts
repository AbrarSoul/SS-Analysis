import DOMPurify from 'dompurify';

import { markdown_to_html } from '../../renderer/pkg';
// Render markdown into HTML,
// will sanitize input to prevent possible XSS attacks
function render(content: string): string {
  const sanitizedInput = DOMPurify.sanitize(content)
  const html = markdown_to_html(sanitizedInput)
  return html
}

export default render
