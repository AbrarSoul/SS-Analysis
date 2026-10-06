import java.io.IOException;
import java.security.SecureRandom;
import java.util.Locale;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class InternalErrorServlet extends HttpServlet
{
    private static final SecureRandom RANDOM = new SecureRandom();

    protected void doGet(HttpServletRequest request,
            HttpServletResponse response) throws ServletException, IOException
    {
        Throwable t = (Throwable) request
                .getAttribute("javax.servlet.error.exception");

        String logInfo = UIUtil.getRequestLogInfo(request);

        String referenceId = String.format(Locale.ROOT, "%08x", RANDOM.nextInt());

        String logMessage = ":reference_id=" + referenceId + ":session_id=" + request.getSession().getId()
                + ":internal_error:" + logInfo;

        log.warn(logMessage, t);

        UIUtil.sendAlert(request, (Exception) t);

        request.setAttribute("support.reference.id", referenceId);
        JSPManager.showJSP(request, response, "/error/internal.jsp");
    }
}
