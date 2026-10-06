"use strict";

// Removes the LITERAL suffix ".md" from an imported file name. Using a string pattern here is intentional:
// the text to remove is a fixed literal, not a character class.
function stripMarkdownExtension(fileName) {
    return fileName.replace('.md', '');
}

module.exports = { stripMarkdownExtension };
