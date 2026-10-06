public class SystemStatusController {

    private static final String HEALTH_CHECK_URL = "http://localhost:8080/actuator/health";

    // No @PreAuthorize here either, but the fetch target is a fixed,
    // compile-time constant pointing at this same server's own health
    // endpoint -- never derived from request input -- so there is no
    // SSRF surface for a missing authorization check to matter for.
    public CommonResult<String> checkOwnHealth() {
        String status = httpClient.get(HEALTH_CHECK_URL);
        return success(status);
    }
}
