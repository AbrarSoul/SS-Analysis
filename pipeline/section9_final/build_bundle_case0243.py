"""
Section 9 ground-truth test bundle: CASE-0243
(opencast/opencast, modules/ingest-service-impl/.../IngestServiceImpl.java
addContentToRepo, CVE-2022-29237, CWE-287 improper authentication).

Core vulnerable mechanism: when an ingest request names a remote media file by
URL, `addContentToRepo` decides how to fetch it. It builds the list of "our
own servers" from
`organizationDirectoryService.getOrganization(uri.toURL()).getServers().keySet()`,
i.e. it asks which organization the REQUESTED URL belongs to, and if the URL's
`scheme://host` is in that organization's server list it fetches with the
system-level `httpClient`, which sends the system digest credentials. In a
multi-tenant installation the caller can therefore name a URL that belongs to
ANOTHER tenant's servers (or any URL that maps to some organization) and make
the server send its system credentials there and read the response as the
system user. The upstream fix takes the server list from the caller's own
organization, `securityService.getOrganization().getServers().keySet()`.

Sibling sites: `getOrganization(URL)` is called once in the file; the decision
tree below it (download-source client, system client, no-auth client) is unchanged.

Verification: `addContentToRepo(MediaPackage, String, URI)` is extracted verbatim from
each full file into a class compiled with javac against stand-ins for the Opencast
and Apache HTTP types (Organization, OrganizationDirectoryService, SecurityService,
HttpGet, HttpResponse, CloseableHttpClient, NotFoundException). The directory service
maps a URL's host to the organization that owns it (tenant A owns http://a.example,
tenant B owns http://b.internal); the calling security context is tenant A. The stand-in
clients record which client (system / download-source / no-auth) executed the GET.

Every variant is the FULL real file. `addContentToRepo` is protected and called by
`addZippedMediaPackage`/`addTrack` etc., so its name and signature are kept; the renamed
variant renames locals.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0243"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


CLUSTER = '''        HttpGet get = new HttpGet(uri);
        List<String> clusterUrls = new LinkedList<>();
        try {
          // Note that we are not checking ports here.
          clusterUrls = organizationDirectoryService.getOrganization(uri.toURL()).getServers()
                          .keySet()
                          .stream()
                          .collect(Collectors.toUnmodifiableList());
        } catch (NotFoundException e) {
          logger.warn("Unable to determine cluster members, will not be able to authenticate any downloads from them", e);
        }
'''
assert original.count(CLUSTER) == 1

# --- Variant 1: renamed vulnerable variant ---
s = original.index("  protected URI addContentToRepo(MediaPackage mp, String elementId, URI uri) throws IOException {")
e = original.index("  private String getContentDispositionFileName(")
seg = original[s:e]
import re
for a, b in (("clusterUrls", "ownServers"), ("externalHttpClient", "fetchClient"), ("get", "fetch")):
    if a == "get":
        seg = seg.replace("HttpGet get = new HttpGet(uri);", "HttpGet fetch = new HttpGet(uri);").replace("execute(get)", "execute(fetch)")
    else:
        seg = re.sub(r"\b%s\b" % a, b, seg)
assert "HttpGet fetch" in seg and "execute(fetch)" in seg and "ownServers" in seg
(CASE_DIR / "variant_vulnerable_01.java").write_text(original[:s] + seg + original[e:])

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, CLUSTER, '''        HttpGet get = new HttpGet(uri);
        List<String> clusterUrls = clusterUrlsFor(uri);
''')
v2 = swap(v2, "  protected URI addContentToRepo(MediaPackage mp, String elementId, URI uri) throws IOException {", '''  private List<String> clusterUrlsFor(URI uri) throws IOException {
    try {
      // Note that we are not checking ports here.
      return organizationDirectoryService.getOrganization(uri.toURL()).getServers()
              .keySet()
              .stream()
              .collect(Collectors.toUnmodifiableList());
    } catch (NotFoundException e) {
      logger.warn("Unable to determine cluster members, will not be able to authenticate any downloads from them", e);
      return new LinkedList<>();
    }
  }

  protected URI addContentToRepo(MediaPackage mp, String elementId, URI uri) throws IOException {''')
(CASE_DIR / "variant_vulnerable_02.java").write_text(v2)

# --- Variant 3: transformed safe variant ---
v3 = swap(original, CLUSTER, '''        HttpGet get = new HttpGet(uri);
        // The caller's own organization decides which servers are "ours" (ports are not checked).
        java.util.Set<String> clusterUrls = securityService.getOrganization().getServers().keySet();
''')
(CASE_DIR / "variant_safe_01.java").write_text(v3)

BENIGN = '''package org.opencastproject.ingest.impl;

import java.net.URI;
import java.util.Set;

/**
 * Standalone example of the same shape: decide whether a URL belongs to a
 * server list, for a log message only (no credentials are attached because of
 * the answer).
 */
public class UrlLabel {

    public static String label(Set<String> ownServers, URI uri) {
        String origin = uri.getScheme() + "://" + uri.getHost();
        return ownServers.contains(origin) ? "own" : "external";
    }
}
'''
(CASE_DIR / "benign_lookalike.java").write_text(BENIGN)
