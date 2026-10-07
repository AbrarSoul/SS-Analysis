// Standalone example of the same shape: check that an invoice number appears
// somewhere in a list of printed line items for a UI highlight -- a
// presentational match, not a payment-authorization check.
export function highlightInvoice(lines: string[], invoiceNo: string): boolean {
    return lines.some((line) => line.includes(invoiceNo));
}
