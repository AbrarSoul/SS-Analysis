import org.bitcoinj.base.Sha256Hash;
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
