"""
Section 9 ground-truth test bundle: CASE-0290
(solana-labs/solana-pay, core/src/validateTransfer.ts validateTransfer /
validateSystemTransfer / validateSPLTokenTransfer, CVE-2022-35917,
CWE-670 always-incorrect control flow implementation).

Core vulnerable mechanism: `validateTransfer` is the merchant-side check
that an on-chain transaction really is the Solana Pay payment for an order.
It (1) checks the recipient balance increased by at least `amount`, (2)
checks each expected `reference` public key appears ANYWHERE in the
transaction's account list, and (3) never checks `memo` at all (`// FIXME:
add memo check`). A payment does not have to be the transfer that was
asked for: an attacker can craft a transaction whose accounts merely
INCLUDE the order's reference key (e.g. as an unrelated account of a second
instruction) while the real transfer instruction carries no reference, or
attach a different/absent memo, and the merchant treats the order as paid;
references are also not bound to the transfer instruction, so a reference
harvested from someone else's public payment can be replayed. The upstream
fix requires the FIRST instruction to be the transfer (system transfer, or
SPL `transfer`/`transferChecked`), requires its extra account keys to match
the expected references exactly (same count, same order), and when a memo
is requested requires the SECOND instruction to be a memo-program
instruction whose data equals the memo.

Sibling sites: the same weakness is in both the system-transfer and
SPL-token branches; the fix (and this bundle's safe variant, built from the
real patched file) covers both, plus the memo check in `validateTransfer`.

Verification: each full file is transpiled (Node `stripTypeScriptTypes`),
its imports converted to `require` calls against REAL `@solana/web3.js`,
`@solana/spl-token` and `bignumber.js` (only the project-local
`./constants` (the real MEMO_PROGRAM_ID) and `./types` are stubbed), and
`validateTransfer` is run for real over REAL `Transaction`/`Message` objects
built with `SystemProgram.transfer` and a memo instruction, served through a
fake `connection.getTransaction`. Three system-transfer scenarios: (a) an
honest payment (reference as an extra key on the transfer, correct memo)
must be accepted by every variant; (b) a forged payment whose transfer
carries NO reference key but whose memo instruction lists the reference as
an account must be REJECTED by a correct validator; (c) a payment with a
WRONG memo must be REJECTED.

Every variant is the FULL real file. `validateTransfer` is the package's
exported API; names/signatures are kept.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0290"
original = (CASE_DIR / "vulnerable_source.ts").read_text()
patched = (CASE_DIR / "patched_source.ts").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant ---
v1 = original
for a, b in (("preAmount", "balanceBefore"), ("postAmount", "balanceAfter"), ("recipientATA", "recipientTokenAccount"), ("accountIndex", "recipientIndex")):
    import re
    v1 = re.sub(r"\b%s\b" % a, b, v1)
assert v1 != original
(CASE_DIR / "variant_vulnerable_01.ts").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
REF = '''    if (reference) {
        if (!Array.isArray(reference)) {
            reference = [reference];
        }

        for (const pubkey of reference) {
            if (!message.accountKeys.some((accountKey) => accountKey.equals(pubkey)))
                throw new ValidateTransferError('reference not found');
        }
    }

    // FIXME: add memo check
'''
assert original.count(REF) == 1
v2 = swap(original, REF, '''    if (reference) {
        assertReferencesPresent(message, Array.isArray(reference) ? reference : [reference]);
    }

    // FIXME: add memo check
''')
v2 = swap(v2, "async function validateSystemTransfer(", '''function assertReferencesPresent(message: Message, references: PublicKey[]): void {
    for (const pubkey of references) {
        if (!message.accountKeys.some((accountKey) => accountKey.equals(pubkey)))
            throw new ValidateTransferError('reference not found');
    }
}

async function validateSystemTransfer(''')
v2 = swap(v2, "    Message,\n    TransactionResponse,", "    Message,\n    PublicKey,\n    TransactionResponse,")
(CASE_DIR / "variant_vulnerable_02.ts").write_text(v2)

# --- Variant 3: transformed safe variant (real patched file, memo check extracted) ---
MEMO = '''    if (memo) {
        // Check that the second instruction is a memo instruction with the expected memo.
        const transaction = Transaction.populate(message);
        const instruction = transaction.instructions[1];
        if (!instruction) throw new ValidateTransferError('missing memo instruction');
        if (!instruction.programId.equals(MEMO_PROGRAM_ID)) throw new ValidateTransferError('invalid memo program');
        if (!instruction.data.equals(Buffer.from(memo, 'utf8'))) throw new ValidateTransferError('invalid memo');
    }
'''
assert patched.count(MEMO) == 1
v3 = swap(patched, MEMO, '''    if (memo) assertMemoInstruction(message, memo);
''')
v3 = swap(v3, "async function validateSystemTransfer(", '''function assertMemoInstruction(message: Message, memo: string): void {
    // The second instruction must be a memo-program instruction carrying exactly the expected memo.
    const instruction = Transaction.populate(message).instructions[1];
    if (!instruction) throw new ValidateTransferError('missing memo instruction');
    if (!instruction.programId.equals(MEMO_PROGRAM_ID)) throw new ValidateTransferError('invalid memo program');
    if (!instruction.data.equals(Buffer.from(memo, 'utf8'))) throw new ValidateTransferError('invalid memo');
}

async function validateSystemTransfer(''')
(CASE_DIR / "variant_safe_01.ts").write_text(v3)

(CASE_DIR / "benign_lookalike.ts").write_text('''// Standalone example of the same shape: check that an invoice number appears
// somewhere in a list of printed line items for a UI highlight -- a
// presentational match, not a payment-authorization check.
export function highlightInvoice(lines: string[], invoiceNo: string): boolean {
    return lines.some((line) => line.includes(invoiceNo));
}
''')
