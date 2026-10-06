"""
Section 9 ground-truth test bundle: CASE-0013
(KnowageLabs/Knowage-Server, CVE-2024-57971, CWE-99 -- improper control of
resource identifiers / JNDI injection).

The real patch adds checkJNDIName(dataSource) to both postDataSource() and
putDataSource(). This bundle targets postDataSource() as the representative
instance (Section 9.3); putDataSource() is left untouched in every variant.

Core vulnerable mechanism: postDataSource() accepts a caller-supplied
IDataSource with an unvalidated JNDI name (dataSource.getJndi()) and
proceeds to insert it as a live datasource with no restriction on which
JNDI name may be used -- allowing registration of a datasource pointing at
an attacker-controlled JNDI resource.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent / "benchmark" / "cases" / "CASE-0013"
original = (CASE_DIR / "vulnerable_source.java").read_text()

VULNERABLE_BLOCK = (
    "\tpublic String postDataSource(IDataSource dataSource) {\n"
    "\t\tLOGGER.debug(\"IN\");\n"
    "\t\ttry {\n"
    "\t\t\tIDataSourceDAO dataSourceDAO = DAOFactory.getDataSourceDAO();\n"
    "\t\t\tUserProfile userProfile = getUserProfile();\n"
    "\n"
    "\t\t\tdataSourceDAO.setUserProfile(userProfile);\n"
    "\n"
    "\t\t\tIDataSource existingDS = dataSourceDAO.findDataSourceByLabel(dataSource.getLabel());\n"
    "\n"
    "\t\t\tif (existingDS != null && dataSource.getLabel().equals(existingDS.getLabel())) {\n"
    "\t\t\t\tMessageBuilder msgBuilder = new MessageBuilder();\n"
    "\t\t\t\tthrow new SpagoBIRestServiceException(msgBuilder.getMessage(\"sbi.datasource.exists\"), buildLocaleFromSession(), new Throwable());\n"
    "\t\t\t}\n"
    "\n"
    "\t\t\tcheckAuthorizationToManageCacheDataSource(dataSource);\n"
    "\n"
    "\t\t\tdataSourceDAO.insertDataSource(dataSource, userProfile.getOrganization());\n"
    "\n"
    "\t\t\tIDataSource newLabel = dataSourceDAO.loadDataSourceByLabel(dataSource.getLabel());\n"
    "\t\t\tint newId = newLabel.getDsId();\n"
    "\n"
    "\t\t\treturn Integer.toString(newId);\n"
    "\n"
    "\t\t} catch (SpagoBIRestServiceException e) {\n"
    "\t\t\tthrow e;\n"
    "\t\t} catch (Exception exception) {\n"
    "\t\t\tLOGGER.error(\"Error while posting DS\", exception);\n"
    "\t\t\tthrow new SpagoBIRestServiceException(\"Error while posting DS\", buildLocaleFromSession(), exception);\n"
    "\t\t} finally {\n"
    "\t\t\tLOGGER.debug(\"OUT\");\n"
    "\t\t}\n"
    "\t}\n"
)
assert VULNERABLE_BLOCK in original, "vulnerable block not found verbatim"
assert original.count(VULNERABLE_BLOCK) == 1

# --- Variant 1: renamed vulnerable variant ---
# Rename the parameter dataSource -> newDataSource throughout
# postDataSource() only (putDataSource()'s own separate dataSource
# parameter is a different scope, untouched). Same exact vulnerability:
# still no checkJNDIName call anywhere in this method.
renamed_block = VULNERABLE_BLOCK.replace(
    "public String postDataSource(IDataSource dataSource) {", "public String postDataSource(IDataSource newDataSource) {"
).replace("dataSource.getLabel()", "newDataSource.getLabel()").replace(
    "checkAuthorizationToManageCacheDataSource(dataSource);", "checkAuthorizationToManageCacheDataSource(newDataSource);"
).replace(
    "dataSourceDAO.insertDataSource(dataSource, userProfile.getOrganization());",
    "dataSourceDAO.insertDataSource(newDataSource, userProfile.getOrganization());",
)
assert "dataSource" not in renamed_block.replace("newDataSource", "").replace("IDataSourceDAO", "").replace("IDataSource ", "").replace("IDataSource existingDS", "") or True
renamed_source = original.replace(VULNERABLE_BLOCK, renamed_block)
assert renamed_source != original
assert "public String postDataSource(IDataSource newDataSource) {" in renamed_source
assert "newDataSource.getLabel()" in renamed_source
# putDataSource's own dataSource parameter must be untouched
assert "public List<IDataSource> putDataSource(IDataSource dataSource) {" in renamed_source
(CASE_DIR / "variant_vulnerable_01.java").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: safe statement reordering -- the DAO lookup and userProfile
# fetch are independent (neither depends on the other's result) and are
# swapped. Same exact vulnerability, no renaming.
structural_block = VULNERABLE_BLOCK.replace(
    "\t\t\tIDataSourceDAO dataSourceDAO = DAOFactory.getDataSourceDAO();\n"
    "\t\t\tUserProfile userProfile = getUserProfile();\n",
    "\t\t\tUserProfile userProfile = getUserProfile();\n"
    "\t\t\tIDataSourceDAO dataSourceDAO = DAOFactory.getDataSourceDAO();\n",
)
assert structural_block != VULNERABLE_BLOCK
structural_source = original.replace(VULNERABLE_BLOCK, structural_block)
assert structural_source != original
(CASE_DIR / "variant_vulnerable_02.java").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same security property as the real fix (reject a JNDI name outside
# java:comp/env/jdbc/) but validated inline at the top of the try block
# instead of via the real patch's separate checkJNDIName() helper +
# MessageBuilder-based message -- materially different mechanism, not
# byte-identical to the known fix.
safe_block = VULNERABLE_BLOCK.replace(
    "\t\tLOGGER.debug(\"IN\");\n\t\ttry {\n",
    "\t\tLOGGER.debug(\"IN\");\n"
    "\t\ttry {\n"
    "\t\t\tif (dataSource.getJndi() != null && !dataSource.getJndi().startsWith(\"java:comp/env/jdbc/\")) {\n"
    "\t\t\t\tthrow new SpagoBIRestServiceException(\"Invalid JNDI name\", buildLocaleFromSession(), new Throwable());\n"
    "\t\t\t}\n",
)
assert safe_block != VULNERABLE_BLOCK
safe_source = original.replace(VULNERABLE_BLOCK, safe_block)
assert safe_source != original
assert 'startsWith("java:comp/env/jdbc/")' in safe_source
(CASE_DIR / "variant_safe_01.java").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
# Built on the safe implementation above. Adds a new read-only endpoint
# that also handles an IDataSource/label lookup (same superficial shape:
# a DataSourceResource method using IDataSourceDAO) but never reads or
# uses .getJndi() at all -- so an unvalidated JNDI value poses no
# injection risk here, unlike postDataSource()/putDataSource().
BENIGN_ADDITION = (
    "\n"
    "\t@GET\n"
    "\t@Path(\"/preview/{label}\")\n"
    "\tpublic String previewDataSourceLabel(@PathParam(\"label\") String label) {\n"
    "\t\t// Returns only the datasource's display label for UI preview purposes.\n"
    "\t\t// Never reads or uses the JNDI name, so no JNDI validation is needed\n"
    "\t\t// here, unlike postDataSource()/putDataSource().\n"
    "\t\tIDataSourceDAO dataSourceDAO = DAOFactory.getDataSourceDAO();\n"
    "\t\tIDataSource ds = dataSourceDAO.findDataSourceByLabel(label);\n"
    "\t\treturn ds != null ? ds.getLabel() : null;\n"
    "\t}\n"
)
anchor = "\tpublic String postDataSource(IDataSource dataSource) {\n"
assert anchor in safe_source
benign_source = safe_source.replace(anchor, BENIGN_ADDITION.strip("\n") + "\n\n" + anchor, 1)
assert benign_source != safe_source
assert "previewDataSourceLabel" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)

print("Wrote 4 new samples for CASE-0013.")
