"""
Section 9 ground-truth test bundle: CASE-0270
(py-pdf/pypdf, pypdf/generic/_data_structures.py DictionaryObject._clone,
CVE-2023-46250, CWE-835 loop with unreachable exit condition).

Core vulnerable mechanism: when cloning a PDF object graph (e.g.
`PdfWriter(clone_from=reader)`), `_clone` special-cases dictionaries linked
by a `/Next`, `/Prev`, `/N`, or `/V` chain (used for things like annotation
appearance-state chains and outline/bookmark siblings): it walks the chain
with `while cur_obj is not None: ... cur_obj = cur_obj[k]`, and the ONLY
loop-exit condition is `if cur_obj == src: cur_obj = None` -- comparing the
current node's CONTENT (`DictionaryObject` is a `dict` subclass; `==` is
by-value, not by-identity) to the object the CURRENT `_clone` call started
from. A PDF is untrusted, attacker-controlled input; a malicious PDF can
link three or more chain objects into a cycle that returns to an
INTERMEDIATE node rather than back to `src` -- e.g. `A -> B -> C -> B` (B
and C cycle between themselves; the cycle never revisits A). Since `cur_obj`
then only ever takes the values B and C, and neither equals `src` (A), the
while loop's exit condition is never satisfied: it walks B, C, B, C, ...
forever, appending to an ever-growing list and hanging the process
(confirmed live: the real vulnerable file hangs indefinitely on such a PDF,
while the same call returns immediately once patched -- see Verification).
The upstream fix threads a `visited: Set[Tuple[int, int]]` (idnum,
generation pairs) through the whole clone call tree and checks/populates it
on every chain-walk step, breaking the loop the first time ANY previously
seen object -- not just the original `src` -- is encountered again.

Sibling sites: the same 4-argument `_clone`/`clone` signature (and the
identical unbounded chain-walk) is duplicated in `StreamObject._clone`
(delegates to `DictionaryObject._clone` via `super()`) and
`ContentStream.clone`/`_clone` (has its own top-level `clone()` entry
point mirroring `DictionaryObject.clone()`); the safe variant threads
`visited` through all three, matching the real patch's scope, even though
this bundle's PoC only needs to exercise the `DictionaryObject` path
directly.

Verification: each full file is copied over
`site-packages/pypdf/generic/_data_structures.py` inside a real virtualenv
with `pypdf==3.16.4` (the version contemporaneous with this CVE) pip-
installed, so `DictionaryObject`/`PdfWriter` run as real, unmodified code.
Three real `DictionaryObject`s are built and added to a real `PdfWriter`:
`A['/Next'] = B`, `B['/Next'] = C`, `C['/Next'] = B` (each also carries a
distinct `/Marker` value so no two of them are spuriously `==`-equal by
content, which would otherwise let the buggy check accidentally halt the
walk for the wrong reason). `A.clone(dest_writer)` is run in a subprocess
with a wall-clock timeout: the vulnerable file never returns within the
timeout (confirmed hanging, not merely slow); the patched file returns
immediately.

Every variant is the FULL real file. `DictionaryObject.clone`/`_clone` are
called throughout pypdf (`PdfWriter.append`, `clone_from=`, merging pages)
and by any application embedding pypdf, so their names and signatures are
kept wherever unchanged from upstream; the renamed variant renames only its
own locals.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0270"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


CHAIN_WALK = """                        cur_obj: Optional[DictionaryObject] = cast(
                            "DictionaryObject", src[k]
                        )
                        prev_obj: Optional[DictionaryObject] = self
                        while cur_obj is not None:
                            clon = cast(
                                "DictionaryObject",
                                cur_obj._reference_clone(
                                    cur_obj.__class__(), pdf_dest, force_duplicate
                                ),
                            )
                            objs.append((cur_obj, clon))
                            assert prev_obj is not None
                            prev_obj[NameObject(k)] = clon.indirect_reference
                            prev_obj = clon
                            try:
                                if cur_obj == src:
                                    cur_obj = None
                                else:
                                    cur_obj = cast("DictionaryObject", cur_obj[k])
                            except Exception:
                                cur_obj = None
                        for s, c in objs:
                            c._clone(s, pdf_dest, force_duplicate, ignore_fields)"""
assert original.count(CHAIN_WALK) == 1

# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, CHAIN_WALK, """                        node: Optional[DictionaryObject] = cast(
                            "DictionaryObject", src[k]
                        )
                        prior: Optional[DictionaryObject] = self
                        while node is not None:
                            cloned = cast(
                                "DictionaryObject",
                                node._reference_clone(
                                    node.__class__(), pdf_dest, force_duplicate
                                ),
                            )
                            objs.append((node, cloned))
                            assert prior is not None
                            prior[NameObject(k)] = cloned.indirect_reference
                            prior = cloned
                            try:
                                if node == src:
                                    node = None
                                else:
                                    node = cast("DictionaryObject", node[k])
                            except Exception:
                                node = None
                        for s, c in objs:
                            c._clone(s, pdf_dest, force_duplicate, ignore_fields)""")
(CASE_DIR / "variant_vulnerable_01.py").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, CHAIN_WALK, """                        objs.extend(
                            self._walk_chain(src, k, pdf_dest, force_duplicate)
                        )
                        for s, c in objs:
                            c._clone(s, pdf_dest, force_duplicate, ignore_fields)""")
v2 = swap(v2, "    def _clone(\n        self,\n        src: \"DictionaryObject\",",
          """    def _walk_chain(self, src, k, pdf_dest, force_duplicate):
        chain = []
        cur_obj: Optional[DictionaryObject] = cast("DictionaryObject", src[k])
        prev_obj: Optional[DictionaryObject] = self
        while cur_obj is not None:
            clon = cast(
                "DictionaryObject",
                cur_obj._reference_clone(cur_obj.__class__(), pdf_dest, force_duplicate),
            )
            chain.append((cur_obj, clon))
            assert prev_obj is not None
            prev_obj[NameObject(k)] = clon.indirect_reference
            prev_obj = clon
            try:
                if cur_obj == src:
                    cur_obj = None
                else:
                    cur_obj = cast("DictionaryObject", cur_obj[k])
            except Exception:
                cur_obj = None
        return chain

    def _clone(\n        self,\n        src: \"DictionaryObject\",""")
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant ---
# Same fix outcome as upstream (thread a shared "already cloned" set
# through the whole call tree so the chain walk stops on ANY repeat, not
# only a repeat of `src`) but the check-and-mark step is a single extracted
# _mark_visited(visited, clon) helper call, instead of upstream's five
# inline statements.
CLONE_TOP = """        d__ = cast(
            "DictionaryObject",
            self._reference_clone(self.__class__(), pdf_dest, force_duplicate),
        )
        if ignore_fields is None:
            ignore_fields = []
        if len(d__.keys()) == 0:
            d__._clone(self, pdf_dest, force_duplicate, ignore_fields)
        return d__

    def _clone(
        self,
        src: "DictionaryObject",
        pdf_dest: PdfWriterProtocol,
        force_duplicate: bool,
        ignore_fields: Optional[Sequence[Union[str, int]]],
    ) -> None:"""
assert original.count(CLONE_TOP) == 1
v3 = swap(original, CLONE_TOP, """        visited: Set[Tuple[int, int]] = set()
        d__ = cast(
            "DictionaryObject",
            self._reference_clone(self.__class__(), pdf_dest, force_duplicate),
        )
        if ignore_fields is None:
            ignore_fields = []
        if len(d__.keys()) == 0:
            d__._clone(self, pdf_dest, force_duplicate, ignore_fields, visited)
        return d__

    def _clone(
        self,
        src: "DictionaryObject",
        pdf_dest: PdfWriterProtocol,
        force_duplicate: bool,
        ignore_fields: Optional[Sequence[Union[str, int]]],
        visited: Set[Tuple[int, int]],
    ) -> None:""")
v3 = swap(v3, CHAIN_WALK, """                        cur_obj: Optional[DictionaryObject] = cast(
                            "DictionaryObject", src[k]
                        )
                        prev_obj: Optional[DictionaryObject] = self
                        while cur_obj is not None:
                            clon = cast(
                                "DictionaryObject",
                                cur_obj._reference_clone(
                                    cur_obj.__class__(), pdf_dest, force_duplicate
                                ),
                            )
                            if _mark_visited(visited, clon):
                                cur_obj = None
                                break
                            objs.append((cur_obj, clon))
                            assert prev_obj is not None
                            prev_obj[NameObject(k)] = clon.indirect_reference
                            prev_obj = clon
                            try:
                                if cur_obj == src:
                                    cur_obj = None
                                else:
                                    cur_obj = cast("DictionaryObject", cur_obj[k])
                            except Exception:
                                cur_obj = None
                        for s, c in objs:
                            c._clone(s, pdf_dest, force_duplicate, ignore_fields, visited)""")
v3 = swap(v3, "from typing import (", "from typing import (\n    Set,")
v3 = swap(v3, "class DictionaryObject(dict, PdfObject):", """def _mark_visited(visited: Set[Tuple[int, int]], clon: "DictionaryObject") -> bool:
    \"\"\"Return True (without marking) if clon was already visited; else mark and return False.\"\"\"
    if clon.indirect_reference is None:
        return False
    key = (clon.indirect_reference.idnum, clon.indirect_reference.generation)
    if key in visited:
        return True
    visited.add(key)
    return False


class DictionaryObject(dict, PdfObject):""")
# Thread visited through StreamObject._clone (delegates via super()) and
# ContentStream.clone/_clone, matching the real patch's scope.
v3 = swap(v3, """    def _clone(
        self,
        src: DictionaryObject,
        pdf_dest: PdfWriterProtocol,
        force_duplicate: bool,
        ignore_fields: Optional[Sequence[Union[str, int]]],
    ) -> None:
        \"\"\"
        Update the object from src.

        Args:
            src:
            pdf_dest:
            force_duplicate:
            ignore_fields:
        \"\"\"
        self._data = cast("StreamObject", src)._data
        try:
            decoded_self = cast("StreamObject", src).decoded_self
            if decoded_self is None:
                self.decoded_self = None
            else:
                self.decoded_self = cast(
                    "DecodedStreamObject",
                    decoded_self.clone(pdf_dest, force_duplicate, ignore_fields),
                )
        except Exception:
            pass
        super()._clone(src, pdf_dest, force_duplicate, ignore_fields)""",
          """    def _clone(
        self,
        src: DictionaryObject,
        pdf_dest: PdfWriterProtocol,
        force_duplicate: bool,
        ignore_fields: Optional[Sequence[Union[str, int]]],
        visited: Set[Tuple[int, int]],
    ) -> None:
        \"\"\"
        Update the object from src.

        Args:
            src:
            pdf_dest:
            force_duplicate:
            ignore_fields:
        \"\"\"
        self._data = cast("StreamObject", src)._data
        try:
            decoded_self = cast("StreamObject", src).decoded_self
            if decoded_self is None:
                self.decoded_self = None
            else:
                self.decoded_self = cast(
                    "DecodedStreamObject",
                    decoded_self.clone(pdf_dest, force_duplicate, ignore_fields),
                )
        except Exception:
            pass
        super()._clone(src, pdf_dest, force_duplicate, ignore_fields, visited)""")
v3 = swap(v3, """        d__ = cast(
            "ContentStream",
            self._reference_clone(
                self.__class__(None, None), pdf_dest, force_duplicate
            ),
        )
        if ignore_fields is None:
            ignore_fields = []
        d__._clone(self, pdf_dest, force_duplicate, ignore_fields)
        return d__

    def _clone(
        self,
        src: DictionaryObject,
        pdf_dest: PdfWriterProtocol,
        force_duplicate: bool,
        ignore_fields: Optional[Sequence[Union[str, int]]],
    ) -> None:""", """        visited: Set[Tuple[int, int]] = set()
        d__ = cast(
            "ContentStream",
            self._reference_clone(
                self.__class__(None, None), pdf_dest, force_duplicate
            ),
        )
        if ignore_fields is None:
            ignore_fields = []
        d__._clone(self, pdf_dest, force_duplicate, ignore_fields, visited)
        return d__

    def _clone(
        self,
        src: DictionaryObject,
        pdf_dest: PdfWriterProtocol,
        force_duplicate: bool,
        ignore_fields: Optional[Sequence[Union[str, int]]],
        visited: Set[Tuple[int, int]],
    ) -> None:""")
(CASE_DIR / "variant_safe_01.py").write_text(v3)

BENIGN = '''"""
Standalone example of the same shape: walk a singly-linked list of the
CALLER'S OWN in-memory nodes (never attacker-controlled data) looking for
a target value, stopping when the list's tail (None) is reached -- a
normal caller never constructs a cyclic linked list here, so there is no
untrusted-input path that could make this loop run forever.
"""


class ListNode:
    def __init__(self, value, next=None):
        self.value = value
        self.next = next


def contains(head, target):
    node = head
    while node is not None:
        if node.value == target:
            return True
        node = node.next
    return False
'''
(CASE_DIR / "benign_lookalike.py").write_text(BENIGN)
