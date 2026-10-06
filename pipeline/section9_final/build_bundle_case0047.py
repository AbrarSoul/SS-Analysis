"""
Section 9 ground-truth test bundle: CASE-0047
(DSpace/DSpace, CVE-2022-31189, CWE-209 information exposure through an
error message).

Core vulnerable mechanism: `doGet()` forwards straight to the generic
error JSP with no correlation identifier at all -- only the exception is
logged server-side, with nothing but the raw session id, and nothing
distinguishing this specific error instance is ever handed to the client
or the log in a way that lets support staff correlate a user's bug report
with the right log line without exposing internals. The fix generates a
random per-request `errorCode` (a UUID), includes it in the log line for
correlation, and passes it to the error page via a request attribute --
so the page can show the user an opaque reference code instead of (or
before ever needing) raw exception detail.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0047"
original = (CASE_DIR / "vulnerable_source.java").read_text()

VULNERABLE_BLOCK = '''    protected void doGet(HttpServletRequest request,
            HttpServletResponse response) throws ServletException, IOException
    {
        // Get the exception that occurred, if any
        Throwable t = (Throwable) request
                .getAttribute("javax.servlet.error.exception");

        String logInfo = UIUtil.getRequestLogInfo(request);

        // Log the error. Since we don't have a context, we need to
        // build the info "by hand"
        String logMessage = ":session_id=" + request.getSession().getId()
                + ":internal_error:" + logInfo;

        log.warn(logMessage, t);

        // Now we try and mail the designated user, if any
        UIUtil.sendAlert(request, (Exception) t);

        JSPManager.showJSP(request, response, "/error/internal.jsp");
    }'''
assert VULNERABLE_BLOCK in original

# --- Variant 1: renamed vulnerable variant ---
# Rename doGet -> handleInternalError, logMessage -> logLine, logInfo ->
# requestLogInfo. Same exact absence of any per-request correlation code.
renamed_source = original.replace(
    VULNERABLE_BLOCK,
    '''    protected void handleInternalError(HttpServletRequest request,
            HttpServletResponse response) throws ServletException, IOException
    {
        // Get the exception that occurred, if any
        Throwable t = (Throwable) request
                .getAttribute("javax.servlet.error.exception");

        String requestLogInfo = UIUtil.getRequestLogInfo(request);

        // Log the error. Since we don't have a context, we need to
        // build the info "by hand"
        String logLine = ":session_id=" + request.getSession().getId()
                + ":internal_error:" + requestLogInfo;

        log.warn(logLine, t);

        // Now we try and mail the designated user, if any
        UIUtil.sendAlert(request, (Exception) t);

        JSPManager.showJSP(request, response, "/error/internal.jsp");
    }''',
)
assert "protected void handleInternalError(" in renamed_source
assert renamed_source != original
(CASE_DIR / "variant_vulnerable_01.java").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: intermediate variable + equivalent conditional rewriting
# (StringBuilder instead of string concatenation). Same exact vulnerability
# (no correlation code at all), no renaming.
structural_source = original.replace(
    VULNERABLE_BLOCK,
    '''    protected void doGet(HttpServletRequest request,
            HttpServletResponse response) throws ServletException, IOException
    {
        Throwable t = (Throwable) request
                .getAttribute("javax.servlet.error.exception");

        String logInfo = UIUtil.getRequestLogInfo(request);

        StringBuilder logMessageBuilder = new StringBuilder();
        logMessageBuilder.append(":session_id=").append(request.getSession().getId());
        logMessageBuilder.append(":internal_error:").append(logInfo);
        String logMessage = logMessageBuilder.toString();

        log.warn(logMessage, t);

        UIUtil.sendAlert(request, (Exception) t);

        JSPManager.showJSP(request, response, "/error/internal.jsp");
    }''',
)
assert structural_source != original
assert "StringBuilder logMessageBuilder" in structural_source
(CASE_DIR / "variant_vulnerable_02.java").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same core idea as upstream (generate a per-request opaque correlation
# code, log it, hand it to the error page) but a materially different
# generation technique: a short hex digest of the current time + a random
# salt instead of a UUID, and a differently-named request attribute --
# genuinely gives support staff a way to correlate a report with the right
# log line without exposing raw exception detail, different implementation
# from the real patch.
SAFE_SOURCE = '''import java.io.IOException;
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
'''
(CASE_DIR / "variant_safe_01.java").write_text(SAFE_SOURCE)
assert "referenceId" in SAFE_SOURCE

# --- Variant 4: benign structural look-alike ---
# Same visible shape (catch a Throwable, build a log message from session
# info, log it, forward to a JSP) but this sibling servlet is registered
# ONLY under a `/debug/*` path that DSpace's own web.xml restricts to
# localhost/admin-only access (a local development diagnostics page) --
# exposing raw exception detail there is an intentional, access-controlled
# tradeoff, not a real information-exposure risk, unlike the
# publicly-reachable internal-error page this superficially resembles.
BENIGN_SOURCE = '''import java.io.IOException;

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
'''
(CASE_DIR / "benign_lookalike.java").write_text(BENIGN_SOURCE)
assert "internal.jsp" not in BENIGN_SOURCE

print("Wrote 4 new samples for CASE-0047.")
