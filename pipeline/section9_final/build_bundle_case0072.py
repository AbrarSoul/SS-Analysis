"""
Section 9 ground-truth test bundle: CASE-0072
(PerfreeBlog/PerfreeBlog, CVE-2025-60319, CWE-918 server-side request
forgery via missing authorization).

Core vulnerable mechanism: `uploadAttachByUrl()` has the server fetch and
store whatever URL the caller supplies (`attachUploadByUrlVO.getUrl()`),
a classic SSRF-capable operation (a caller can point it at internal-only
services, cloud metadata endpoints, etc., and get the response back
indirectly via the stored attachment). Unlike other admin-only mutating
endpoints in this controller, this method has NO `@PreAuthorize` check at
all -- any authenticated user, not just admins, can trigger the
server-side fetch. The fix adds `@PreAuthorize("@ss.hasPermission('admin:attach:update')")`,
restricting the endpoint to callers holding that specific admin
permission.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0072"
original = (CASE_DIR / "vulnerable_source.java").read_text()

VULNERABLE_BLOCK = '''    public CommonResult<AttachByUrlRespVO> uploadAttachByUrl(@Valid @RequestBody AttachUploadByUrlVO attachUploadByUrlVO) {
        Attach attach = attachService.uploadAttachByUrl(attachUploadByUrlVO.getUrl());
        AttachByUrlRespVO attachByUrlRespVO = AttachConvert.INSTANCE.convertByUrlRespVO(attach);
        attachByUrlRespVO.setOriginalURL(attachUploadByUrlVO.getUrl());
        return success(attachByUrlRespVO);
    }'''
assert VULNERABLE_BLOCK in original

# --- Variant 1: renamed vulnerable variant ---
# Rename uploadAttachByUrl -> importAttachFromUrl, attachUploadByUrlVO ->
# uploadRequest, attach -> importedAttach. Same exact missing
# authorization annotation on an SSRF-capable endpoint.
renamed_source = original.replace(
    VULNERABLE_BLOCK,
    '''    public CommonResult<AttachByUrlRespVO> importAttachFromUrl(@Valid @RequestBody AttachUploadByUrlVO uploadRequest) {
        Attach importedAttach = attachService.uploadAttachByUrl(uploadRequest.getUrl());
        AttachByUrlRespVO attachByUrlRespVO = AttachConvert.INSTANCE.convertByUrlRespVO(importedAttach);
        attachByUrlRespVO.setOriginalURL(uploadRequest.getUrl());
        return success(attachByUrlRespVO);
    }''',
)
assert "public CommonResult<AttachByUrlRespVO> importAttachFromUrl(" in renamed_source
assert renamed_source != original
(CASE_DIR / "variant_vulnerable_01.java").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: intermediate variable holding the target URL before use.
# Same exact missing authorization, no renaming.
structural_source = original.replace(
    VULNERABLE_BLOCK,
    '''    public CommonResult<AttachByUrlRespVO> uploadAttachByUrl(@Valid @RequestBody AttachUploadByUrlVO attachUploadByUrlVO) {
        String targetUrl = attachUploadByUrlVO.getUrl();
        Attach attach = attachService.uploadAttachByUrl(targetUrl);
        AttachByUrlRespVO attachByUrlRespVO = AttachConvert.INSTANCE.convertByUrlRespVO(attach);
        attachByUrlRespVO.setOriginalURL(targetUrl);
        return success(attachByUrlRespVO);
    }''',
)
assert structural_source != original
assert "String targetUrl = attachUploadByUrlVO.getUrl();" in structural_source
(CASE_DIR / "variant_vulnerable_02.java").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same core idea as upstream (restrict this endpoint to admin-permission
# holders) but a materially different technique: an explicit imperative
# permission check at the top of the method body, throwing if the check
# fails, instead of the real patch's declarative @PreAuthorize AOP
# annotation -- genuinely enforces the same restriction, different
# mechanism (runtime check vs. framework-intercepted annotation).
SAFE_SOURCE = '''public class AttachController {

    public CommonResult<AttachByUrlRespVO> uploadAttachByUrl(@Valid @RequestBody AttachUploadByUrlVO attachUploadByUrlVO) {
        if (!currentUserPermissionService.hasPermission("admin:attach:update")) {
            throw new AccessDeniedException("Missing required permission: admin:attach:update");
        }
        Attach attach = attachService.uploadAttachByUrl(attachUploadByUrlVO.getUrl());
        AttachByUrlRespVO attachByUrlRespVO = AttachConvert.INSTANCE.convertByUrlRespVO(attach);
        attachByUrlRespVO.setOriginalURL(attachUploadByUrlVO.getUrl());
        return success(attachByUrlRespVO);
    }
}
'''
(CASE_DIR / "variant_safe_01.java").write_text(SAFE_SOURCE)
assert "hasPermission" in SAFE_SOURCE
assert "AccessDeniedException" in SAFE_SOURCE

# --- Variant 4: benign structural look-alike ---
# Same visible shape (a controller method with no @PreAuthorize
# annotation, calling out to a service method) but this sibling always
# fetches a FIXED, hard-coded internal health-check URL -- never anything
# derived from the request body -- so there is no server-side-fetch
# target a caller could ever influence, unlike uploadAttachByUrl()'s
# caller-supplied getUrl().
BENIGN_SOURCE = '''public class SystemStatusController {

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
'''
(CASE_DIR / "benign_lookalike.java").write_text(BENIGN_SOURCE)
assert "getUrl()" not in BENIGN_SOURCE

print("Wrote 4 new samples for CASE-0072.")
