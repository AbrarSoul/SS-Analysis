"""
Section 9 ground-truth test bundle: CASE-0286
(shsuishang/modulithshop, src/main/java/com/suisung/shopsuite/pt/service/
impl/ProductIndexServiceImpl.java listItem, CVE-2026-5328, CWE-74/CWE-89
SQL injection through the ORDER BY column).

Core vulnerable mechanism: `listItem` takes a client-supplied
`ProductItemInput` whose `sidx` (sort column) and `sort` (direction) fields
are passed straight to `productItemRepository.listItemKey(...)`, where the
MyBatis mapper interpolates them into an `ORDER BY ${sidx} ${sort}` clause.
MyBatis `${}` substitution does not parameterize: a request with
`sidx=(SELECT SLEEP(5))` or `sidx=item_id; DROP TABLE ...` puts attacker
SQL into the query (ORDER BY cannot use bind parameters, so validation is
the only defence). The upstream fix validates that `sidx` (after stripping
backticks) names a real field of `ProductItem` via `CheckUtil.hasField`,
resets the column to empty and direction to DESC otherwise, and forces the
direction to exactly `DESC` or `ASC`.

Sibling sites: other list endpoints in the project may take the same
`sidx`/`sort` pair, but this bundle covers the one function the patch
changes.

Verification: the statements of `listItem` between the itemId-clearing
`if` and the `IPage<Long> lists = productItemRepository.listItemKey(...)`
call (where the fix sits; for variants that define a local validation
lambda it is inside this span too) are extracted verbatim from each full
file and compiled with javac inside a harness with stand-ins for
`ProductItemInput` (a POJO), `StrUtil.isNotBlank`, and `CheckUtil.hasField`
(real reflection over a `ProductItem` stand-in class with fields
`itemId`, `itemName`, `itemPrice`). The harness runs the span on
`sidx="(SELECT SLEEP(5))", sort="ASC; DROP TABLE x"` and prints the
`sidx`/`sort` that would reach the repository; a control with
`sidx="itemPrice", sort="DESC"` must be preserved.

Every variant is the FULL real file. `listItem` is an interface
implementation called by name; its signature is kept (the renamed variant
renames only its parameter/locals).
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0286"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


ANCHOR = '''        if (productItemListReq.getItemId() != null && productItemListReq.getItemId().isEmpty()) {
            productItemListReq.setItemId(null);
        }

'''
assert original.count(ANCHOR) == 1

# --- Variant 1: renamed vulnerable variant (parameter/locals of listItem) ---
ms = original.index("    public ItemListRes listItem(ProductItemInput productItemListReq) {")
me = original.index("\n    @Override", ms)
body = original[ms:me]
b1 = re.sub(r"\bproductItemListReq\b", "itemQuery", body)
b1 = re.sub(r"\bitemNumVoMap\b", "activityItemNums", b1)
assert b1 != body
(CASE_DIR / "variant_vulnerable_01.java").write_text(original[:ms] + b1 + original[me:])

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, ANCHOR, '''        java.util.function.Consumer<ProductItemInput> normalizeQuery = req -> {
            if (req.getItemId() != null && req.getItemId().isEmpty()) {
                req.setItemId(null);
            }
        };
        normalizeQuery.accept(productItemListReq);

''')
(CASE_DIR / "variant_vulnerable_02.java").write_text(v2)

# --- Variant 3: transformed safe variant ---
v3 = swap(original, ANCHOR, ANCHOR + '''        java.util.function.Consumer<ProductItemInput> sanitizeOrderBy = req -> {
            String column = StrUtil.blankToDefault(req.getSidx(), "").replace("`", "");
            if (column.isEmpty()) {
                return;
            }
            if (CheckUtil.hasField(ProductItem.class, column)) {
                req.setSidx(column);
                req.setSort("DESC".equals(req.getSort()) ? "DESC" : "ASC");
            } else {
                req.setSidx("");
                req.setSort("DESC");
            }
        };
        sanitizeOrderBy.accept(productItemListReq);

''')
(CASE_DIR / "variant_safe_01.java").write_text(v3)

(CASE_DIR / "benign_lookalike.java").write_text('''package com.suisung.shopsuite.pt.service.impl;

/**
 * Standalone example of the same shape: pick a display sort label for a UI
 * dropdown from a fixed enum, never building any SQL from it.
 */
public class SortLabelPicker {

    public enum Order { NEWEST, PRICE_ASC, PRICE_DESC }

    public static String label(Order order) {
        return switch (order) {
            case NEWEST -> "Newest first";
            case PRICE_ASC -> "Price: low to high";
            case PRICE_DESC -> "Price: high to low";
        };
    }
}
''')
