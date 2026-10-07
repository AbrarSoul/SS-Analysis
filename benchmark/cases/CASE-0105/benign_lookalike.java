import java.util.Arrays;

public class PublishedArtifactCheck {

    private PublishedArtifactCheck() {}

    /**
     * Same Arrays.equals(byte[], byte[]) comparison, but of two digests of a
     * PUBLIC artifact that anyone can download and hash. There is no secret
     * whose bytes the timing could reveal, so early-exit comparison is fine.
     */
    public static boolean matchesPublishedDigest(byte[] computedDigest, byte[] publishedDigest) {
        return Arrays.equals(computedDigest, publishedDigest);
    }
}
