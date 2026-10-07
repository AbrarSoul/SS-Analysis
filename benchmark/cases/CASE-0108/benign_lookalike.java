import java.util.Collection;

public class RecipientPreviewButton {

    public interface Toggle {
        void setEnabled(boolean on);
    }

    /**
     * Same "enable when exactly one is selected" shape, but the enabled action
     * is a read-only preview of display names the current user has already
     * selected from a list they can already see. It generates no link or
     * token and grants no access, so it needs no authorization check.
     */
    public void updatePreview(Collection<String> selectedDisplayNames, Toggle previewButton) {
        previewButton.setEnabled(selectedDisplayNames.size() == 1);
    }
}
