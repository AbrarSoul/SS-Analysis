"""
Section 9 ground-truth test bundle: CASE-0131
(bitcoinj/bitcoinj, script/ScriptExecution.correctlySpends 7-argument
overload, CVE-2026-44714, CWE-347 improper verification of a cryptographic
signature).

Core vulnerable mechanism: the P2WPKH and P2PKH fast paths decode a
signature and a public key FROM THE SPENDER (`witness.getPush(1)` /
`chunks.get(1).data`) and verify that the signature is valid for that key,
but never check that the key's HASH160 equals the hash committed in the
output's scriptPubKey. Anyone can therefore spend any P2PKH/P2WPKH output by
signing with their own key and supplying their own public key. The upstream
fix compares the provided key's hash160 with the required hash in both
branches (and builds the P2WPKH scriptCode from the required hash).

Every variant is the FULL real file with the 7-argument correctlySpends
overload replaced. It has no in-file callers (the 5-argument overloads are
different methods), so the renamed variant renames this overload only and
keeps the recursive call to the 5-argument overload unchanged.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0131"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

HDR = ("    public static void correctlySpends(Script script, Transaction txContainingThis, int scriptSigIndex,\n"
       "                                       @Nullable TransactionWitness witness, @Nullable Coin value,\n"
       "                                       Script scriptPubKey, Set<VerifyFlag> verifyFlags) throws ScriptException {\n")
s = original.index(HDR)
e = original.index("\n    }\n", s) + len("\n    }\n")
BLOCK = original[s:e]
assert original.count(HDR) == 1
P2WPKH_KEY = "            ECKey pubkey = ECKey.fromPublicOnly(witness.getPush(1));\n"
P2PKH_KEY = "            ECKey pubkey = ECKey.fromPublicOnly(Objects.requireNonNull(chunks.get(1).data));\n"
VERIFY_TAIL = '''            boolean validSig = pubkey.verify(sigHash, signature);
            if (!validSig)
                throw new ScriptException(ScriptError.SCRIPT_ERR_CHECKSIGVERIFY, "Invalid signature");
'''
assert BLOCK.count(P2WPKH_KEY) == 1 and BLOCK.count(P2PKH_KEY) == 1 and BLOCK.count(VERIFY_TAIL) == 3
assert "extractHashFromP2WH" not in original and "extractHashFromP2PKH" not in original


def build(new_block, extra_after=None):
    assert new_block != BLOCK
    return original[:s] + new_block + (extra_after or "") + original[e:]


def rename_outside_strings(text, pairs):
    out = []
    for line in text.split("\n"):
        if line.lstrip().startswith("//"):
            out.append(line)
            continue
        parts = re.split(r"""('(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")""", line)
        for i in range(0, len(parts), 2):
            for name, new in pairs:
                parts[i] = re.sub(r"(?<![.\w$])%s(?![\w$])" % re.escape(name), new, parts[i])
        out.append("".join(parts))
    return "\n".join(out)


# --- Variant 1: renamed vulnerable variant ---
b = rename_outside_strings(BLOCK, (("script", "inputScript"), ("txContainingThis", "spendingTx"),
                                   ("scriptSigIndex", "inputIndex"), ("witness", "segwitData"), ("value", "prevoutValue"),
                                   ("scriptPubKey", "lockingScript"), ("verifyFlags", "flags"), ("chunks", "pushes"),
                                   ("signature", "txSig"), ("pubkey", "publicKey"), ("scriptCode", "codeScript"),
                                   ("sigHash", "digest"), ("validSig", "sigOk"), ("data", "raw"), ("x", "decodeEx")))
b = b.replace("public static void correctlySpends(", "public static void verifySpend(", 1)
assert "verifySpend(Script inputScript, Transaction spendingTx, int inputIndex," in b
assert "correctlySpends(inputScript, spendingTx, inputIndex, lockingScript, flags);" in b   # 5-arg overload call kept
assert "publicKey.verify(digest, txSig)" in b and "ECKey.fromPublicOnly(segwitData.getPush(1))" in b
(CASE_DIR / "variant_vulnerable_01.java").write_text(build(b))

# --- Variant 2: structurally changed vulnerable variant ---
b = BLOCK.replace(VERIFY_TAIL, "            requireValidSignature(pubkey, sigHash, signature);\n")
helper = '''
    private static void requireValidSignature(ECKey pubkey, Sha256Hash sigHash, TransactionSignature signature)
            throws ScriptException {
        boolean validSig = pubkey.verify(sigHash, signature);
        if (!validSig)
            throw new ScriptException(ScriptError.SCRIPT_ERR_CHECKSIGVERIFY, "Invalid signature");
    }
'''
assert b.count("requireValidSignature(") == 3
(CASE_DIR / "variant_vulnerable_02.java").write_text(build(b, extra_after=helper))

# --- Variant 3: transformed safe variant ---
# The provided key's hash160 (ECKey.getPubKeyHash) must equal the hash in the
# scriptPubKey, compared with MessageDigest.isEqual (upstream recomputes
# sha256hash160 and uses Arrays.equals).
b = BLOCK.replace(P2WPKH_KEY, P2WPKH_KEY + '''            if (!MessageDigest.isEqual(ScriptPattern.extractHashFromP2WH(scriptPubKey), pubkey.getPubKeyHash()))
                throw new ScriptException(ScriptError.SCRIPT_ERR_EQUALVERIFY, "Invalid pubkey hash");
''').replace(P2PKH_KEY, P2PKH_KEY + '''            if (!MessageDigest.isEqual(ScriptPattern.extractHashFromP2PKH(scriptPubKey), pubkey.getPubKeyHash()))
                throw new ScriptException(ScriptError.SCRIPT_ERR_EQUALVERIFY, "Invalid pubkey hash");
''')
safe_source = build(b)
assert safe_source.count("Invalid pubkey hash") == 2 and "import java.security.MessageDigest;" in original
(CASE_DIR / "variant_safe_01.java").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
benign_source = '''import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.crypto.TransactionSignature;

public class OwnKeySignatureCheck {

    private final ECKey ownKey;

    public OwnKeySignatureCheck(ECKey ownKey) {
        this.ownKey = ownKey;
    }

    /**
     * Same "pubkey.verify(sigHash, signature)" call as a spend check, but the
     * public key is THIS wallet's own key held locally, never one supplied by
     * the party being checked, so there is no committed hash it could
     * substitute around: a valid signature here really is from the owner.
     */
    public boolean isSignedByOwner(Sha256Hash sigHash, TransactionSignature signature) {
        return ownKey.verify(sigHash, signature);
    }
}
'''
assert "ownKey.verify(sigHash, signature)" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0131.")
