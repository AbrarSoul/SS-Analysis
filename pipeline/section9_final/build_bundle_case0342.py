"""
Section 9 ground-truth test bundle: CASE-0342
(fabric8io/kubernetes-client, CVE-2021-4178, CWE-502 unsafe YAML
deserialization). Replacement for the retired duplicate CASE-0338
(top-up 40).

Core vulnerable mechanism: `Serialization.unmarshalYaml()` parses YAML
with `new Yaml()`. In SnakeYAML 1.x the default constructor honours GLOBAL
tags such as `!!javax.script.ScriptEngineManager [...]` or
`!!java.io.FileOutputStream ["/path"]`, instantiating arbitrary classes
from attacker-supplied YAML (remote code execution gadget chains). The
upstream fix constructs the parser with `new Yaml(new SafeConstructor())`,
which only builds standard types.

Every variant is the FULL real file with unmarshalYaml replaced (the
renamed variant also renames its two call sites).
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0342"
original = "\n".join(l.rstrip() for l in (CASE_DIR / "vulnerable_source.java").read_text().splitlines()) + "\n"

BLOCK = '''  private static <T> T unmarshalYaml(InputStream is, TypeReference<T> type) throws JsonProcessingException {
    final Yaml yaml = new Yaml();
    Map<String, Object> obj = yaml.load(is);
    String objAsJsonStr = JSON_MAPPER.writeValueAsString(obj);
    return unmarshalJsonStr(objAsJsonStr, type);
  }
'''
assert original.count(BLOCK) == 1 and original.count("unmarshalYaml(") == 3


def build(new_block):
    assert new_block != BLOCK
    return original.replace(BLOCK, new_block)


# --- Variant 1: renamed vulnerable variant ---
renamed = build('''  private static <T> T parseYamlStream(InputStream input, TypeReference<T> typeRef) throws JsonProcessingException {
    final Yaml loader = new Yaml();
    Map<String, Object> document = loader.load(input);
    String jsonText = JSON_MAPPER.writeValueAsString(document);
    return unmarshalJsonStr(jsonText, typeRef);
  }
''')
renamed = re.sub(r"\bunmarshalYaml\(", "parseYamlStream(", renamed)
assert "unmarshalYaml" not in renamed and renamed.count("parseYamlStream(") == 3
(CASE_DIR / "variant_vulnerable_01.java").write_text(renamed)

# --- Variant 2: structurally changed vulnerable variant ---
(CASE_DIR / "variant_vulnerable_02.java").write_text(build('''  private static <T> T unmarshalYaml(InputStream is, TypeReference<T> type) throws JsonProcessingException {
    final Yaml yaml = new Yaml();
    final Object loaded = yaml.load(is);
    @SuppressWarnings("unchecked")
    final Map<String, Object> obj = (Map<String, Object>) loaded;
    final String objAsJsonStr = JSON_MAPPER.writeValueAsString(obj);
    return unmarshalJsonStr(objAsJsonStr, type);
  }
'''))

# --- Variant 3: transformed safe variant ---
# A Constructor subclass that refuses EVERY global (class-naming) tag while
# still allowing the standard YAML types -- a different mechanism from the
# upstream SafeConstructor.
SAFE = '''  /** Rejects every global tag (e.g. !!java.io.File) so YAML input can never name a class to instantiate. */
  private static final class NoGlobalTagsConstructor extends Constructor {
    @Override
    protected Class<?> getClassForName(String name) throws ClassNotFoundException {
      throw new YAMLException("Global tag not allowed: " + name);
    }
  }

  private static <T> T unmarshalYaml(InputStream is, TypeReference<T> type) throws JsonProcessingException {
    final Yaml yaml = new Yaml(new NoGlobalTagsConstructor());
    Map<String, Object> obj = yaml.load(is);
    String objAsJsonStr = JSON_MAPPER.writeValueAsString(obj);
    return unmarshalJsonStr(objAsJsonStr, type);
  }
'''
safe = build(SAFE).replace("import org.yaml.snakeyaml.Yaml;\n",
                           "import org.yaml.snakeyaml.Yaml;\nimport org.yaml.snakeyaml.constructor.Constructor;\nimport org.yaml.snakeyaml.error.YAMLException;\n", 1)
assert "import org.yaml.snakeyaml.constructor.Constructor;" in safe
(CASE_DIR / "variant_safe_01.java").write_text(safe)

# --- Variant 4: benign structural look-alike ---
(CASE_DIR / "benign_lookalike.java").write_text('''import org.yaml.snakeyaml.Yaml;

import java.io.InputStream;
import java.util.Map;

public class BundledDefaults {

    private BundledDefaults() {}

    /**
     * Same `new Yaml()` + load(...) shape, but the stream is a resource
     * bundled inside the application's own jar (developer-authored, never
     * user-supplied), so no attacker-controlled YAML can name a class.
     */
    public static Map<String, Object> load() {
        try (InputStream in = BundledDefaults.class.getResourceAsStream("/defaults.yaml")) {
            final Yaml yaml = new Yaml();
            return yaml.load(in);
        } catch (java.io.IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
''')
print("Wrote 4 new samples for CASE-0342.")
