public class TrailingNewline {

    /**
     * Same "drop one trailing newline" step as the multiline string reader, but
     * it returns early for an empty builder, so the charAt(length - 1) lookup
     * can never see index -1.
     */
    public static String withoutTrailingNewline(StringBuilder sb) {
        if (sb.length() == 0) {
            return "";
        }
        if (sb.charAt(sb.length() - 1) == '\n') {
            sb.deleteCharAt(sb.length() - 1);
        }
        return sb.toString();
    }
}
