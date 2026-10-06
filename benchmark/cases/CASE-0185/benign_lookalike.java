import java.util.Locale;

public class LocalePreference {

    /**
     * Same String.equals comparison as the state check, but on non-secret
     * values (two language tags shown in the UI), so how long the comparison
     * takes reveals nothing an attacker could not already read.
     */
    public static boolean sameLanguage(String requested, String configured) {
        return requested.toLowerCase(Locale.ROOT).equals(configured.toLowerCase(Locale.ROOT));
    }
}
