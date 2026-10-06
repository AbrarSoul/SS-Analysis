import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Registered only under /debug/* in web.xml, restricted to localhost and
 * admin accounts by a servlet filter -- never reachable by an ordinary
 * end user, so showing raw exception detail here is a deliberate,
 * access-controlled developer convenience, not an information leak.
 */
public class DebugDiagnosticsServlet extends HttpServlet
{
    protected void doGet(HttpServletRequest request,
            HttpServletResponse response) throws ServletException, IOException
    {
        Throwable t = (Throwable) request
                .getAttribute("javax.servlet.error.exception");

        String logMessage = ":session_id=" + request.getSession().getId() + ":debug_diagnostics";
        log.warn(logMessage, t);

        request.setAttribute("javax.servlet.error.exception", t);
        JSPManager.showJSP(request, response, "/debug/stacktrace.jsp");
    }
}
