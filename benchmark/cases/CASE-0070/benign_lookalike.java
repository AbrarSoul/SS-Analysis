public class DiagnosticsCommand {

    // This endpoint's filter chain (AdminOnlyContentTypeFilter, registered
    // in web.xml) rejects any request whose "contentType" parameter is not
    // exactly "text/plain" BEFORE this method ever runs -- so by the time
    // this code executes, the parameter is already guaranteed safe.
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        String contentType = request.getParameter("contentType");
        if (contentType == null) {
            contentType = "text/plain";
        }
        response.setHeader("Content-Type", contentType);
        response.setHeader("X-Diagnostics", "ok");
    }
}
