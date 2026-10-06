import DOMPurify from 'dompurify';

import { markdown_to_html } from '../../renderer/pkg';
// Render markdown into HTML,
// will sanitize input to prevent possible XSS attacks
function renderMarkdown(markdownSource: string): string {
  markdownSource = DOMPurify.sanitize(markdownSource)
  return markdown_to_html(markdownSource)
}

export default renderMarkdown
