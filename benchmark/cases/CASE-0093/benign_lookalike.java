import java.util.Random;

public class WidgetIds {

    private static final String SYMBOLS = "abcdefghijklmnopqrstuvwxyz0123456789";
    private final Random random = new Random();

    /**
     * Same "random alphanumeric string" shape, but only used to build a
     * cosmetic DOM element id for the UI. It is not a credential or token, an
     * attacker gains nothing by predicting it, so a non-cryptographic Random
     * is appropriate here.
     */
    public String nextElementId() {
        StringBuilder sb = new StringBuilder("widget-");
        for (int i = 0; i < 8; i++) {
            sb.append(SYMBOLS.charAt(random.nextInt(SYMBOLS.length())));
        }
        return sb.toString();
    }
}
