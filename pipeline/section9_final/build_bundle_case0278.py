"""
Section 9 ground-truth test bundle: CASE-0278
(quarkusio/quarkus, extensions/kubernetes/vanilla/deployment/src/main/java/
io/quarkus/kubernetes/deployment/KubernetesCommonHelper.java
createAnnotationDecorators, CVE-2024-1979, CWE-200 exposure of sensitive
information).

Core vulnerable mechanism: when generating Kubernetes manifests, Quarkus
stamps a `app.quarkus.io/vcs-url` annotation with the project's git
`origin` remote URL, read verbatim from the project's SCM info. Git remotes
are routinely configured with embedded credentials
(`https://user:ghp_token@github.com/org/repo.git`), so the raw URL -- token
included -- is written into the generated Deployment/Service YAML, which is
typically committed, shipped in container images/CI artifacts, and readable
by anyone with cluster read access. The upstream fix wraps the value in
`Git.sanitizeRemoteUrl(vcsUrl)` (dekorate's helper that strips the
userinfo component).

Sibling sites: the only other SCM-derived annotation is the commit id
(`QUARKUS_ANNOTATIONS_COMMIT_ID`), which is a hash, not sensitive; the
vcs-url annotation is the single site.

Verification: the `project.ifPresent(p -> {...})` block of each full file's
`createAnnotationDecorators` (plus any helper method a variant adds) is
extracted verbatim and compiled with javac inside a harness class with
minimal stand-ins for the dekorate/quarkus types it touches (`Project`,
`ScmInfo`, `Annotation`, `AddAnnotationDecorator`, `RemoveAnnotationDecorator`,
`DecoratorBuildItem`, `Annotations`, `Version`, `PlatformConfiguration`) and
a stand-in `Git.sanitizeRemoteUrl` that strips `user:secret@` userinfo (the
real dekorate function's documented behaviour). The harness runs it with an
`origin` remote of `https://user:s3cr3t@github.com/org/repo.git` and reads
the resulting vcs-url annotation value.

Every variant is the FULL real file. `createAnnotationDecorators` is called
by name elsewhere in the class, so its signature is kept.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0278"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


BLK = '''            if (vcsUrl != null) {
                result.add(new DecoratorBuildItem(target,
                        new AddAnnotationDecorator(name,
                                new Annotation(QUARKUS_ANNOTATIONS_VCS_URL, vcsUrl, new String[0]))));
            }
'''
assert original.count(BLK) == 1

v1 = swap(original, BLK, '''            if (vcsUrl != null) {
                result.add(new DecoratorBuildItem(target,
                        new AddAnnotationDecorator(name,
                                new Annotation(QUARKUS_ANNOTATIONS_VCS_URL, vcsUrl, new String[0]))));
            }
'''.replace("vcsUrl", "remoteUrl"))
v1 = swap(v1, "String vcsUrl = scm != null", "String remoteUrl = scm != null")
(CASE_DIR / "variant_vulnerable_01.java").write_text(v1)

v2 = swap(original, BLK, '''            if (vcsUrl != null) {
                result.add(vcsUrlDecorator(target, name, vcsUrl));
            }
''')
v2 = swap(v2, "    private static List<DecoratorBuildItem> createAnnotationDecorators(", '''    private static DecoratorBuildItem vcsUrlDecorator(String target, String name, String vcsUrl) {
        return new DecoratorBuildItem(target,
                new AddAnnotationDecorator(name,
                        new Annotation(QUARKUS_ANNOTATIONS_VCS_URL, vcsUrl, new String[0])));
    }

    private static List<DecoratorBuildItem> createAnnotationDecorators(''')
(CASE_DIR / "variant_vulnerable_02.java").write_text(v2)

v3 = swap(original, BLK, '''            if (vcsUrl != null) {
                String publicUrl = Git.sanitizeRemoteUrl(vcsUrl);
                result.add(new DecoratorBuildItem(target,
                        new AddAnnotationDecorator(name,
                                new Annotation(QUARKUS_ANNOTATIONS_VCS_URL, publicUrl, new String[0]))));
            }
''')
v3 = swap(v3, "import io.dekorate.utils.Annotations;\n", "import io.dekorate.utils.Annotations;\nimport io.dekorate.utils.Git;\n")
(CASE_DIR / "variant_safe_01.java").write_text(v3)

(CASE_DIR / "benign_lookalike.java").write_text('''package io.quarkus.kubernetes.deployment;

/**
 * Standalone example of the same shape: stamp a manifest annotation with the
 * build tool version string, a public, non-sensitive value that needs no
 * sanitization.
 */
public class BuildToolAnnotation {

    public static String annotationValue(String buildToolVersion) {
        return buildToolVersion == null ? null : buildToolVersion.trim();
    }
}
''')
