"""
Section 9 ground-truth test bundle: CASE-0004
(FederatedAI/FATE, CVE-2020-25459, CWE-668).

Core vulnerable mechanism: sync_tree() sends the raw decision-tree nodes
(self.tree_), including per-node weight/sum_grad/sum_hess, directly to the
HOST role over the cross-party transfer channel. In this federated-learning
protocol HOST must not see GUEST's raw gradients/weights -- doing so leaks
sensitive training data across the trust boundary (CWE-668: exposure to
wrong sphere).
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent / "benchmark" / "cases" / "CASE-0004"
original = (CASE_DIR / "vulnerable_source.py").read_text()

VULNERABLE_BLOCK = """    def sync_tree(self):
        LOGGER.info("sync tree to host")

        self.transfer_inst.tree.remote(self.tree_,
                                       role=consts.HOST,
                                       idx=-1)"""
assert VULNERABLE_BLOCK in original

# --- Variant 1: renamed vulnerable variant ---
# Rename the method sync_tree -> synchronize_tree (definition + its one call
# site elsewhere in the file). Same exact vulnerability: raw self.tree_ with
# unredacted weight/sum_grad/sum_hess sent to HOST.
renamed_source = original.replace(
    VULNERABLE_BLOCK,
    """    def synchronize_tree(self):
        LOGGER.info("sync tree to host")

        self.transfer_inst.tree.remote(self.tree_,
                                       role=consts.HOST,
                                       idx=-1)""",
)
renamed_source = renamed_source.replace("        self.sync_tree()\n", "        self.synchronize_tree()\n")
assert "def sync_tree(self):" not in renamed_source
assert "self.sync_tree()" not in renamed_source
assert renamed_source.count("synchronize_tree") == 2
# the unrelated sync_tree_node_queue method (different name, different
# purpose) must be untouched
assert "def sync_tree_node_queue(self" in renamed_source
(CASE_DIR / "variant_vulnerable_01.py").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: introduction of intermediate variable. Same exact
# vulnerability (still the raw, unredacted tree), no renaming.
structural_source = original.replace(
    VULNERABLE_BLOCK,
    """    def sync_tree(self):
        LOGGER.info("sync tree to host")

        tree_payload = self.tree_
        self.transfer_inst.tree.remote(tree_payload,
                                       role=consts.HOST,
                                       idx=-1)""",
)
assert structural_source != original
assert "tree_payload = self.tree_" in structural_source
(CASE_DIR / "variant_vulnerable_02.py").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same security property as the real fix (HOST never receives per-node
# weight/sum_grad/sum_hess) but implemented inline, without a separate
# remove_sensitive_info() method or its docstring -- materially different
# wording/structure from the real patched_source.py.
SAFE_BLOCK = """    def sync_tree(self):
        LOGGER.info("sync tree to host")

        sanitized_tree = copy.deepcopy(self.tree_)
        for node in sanitized_tree:
            node.weight = None
            node.sum_grad = None
            node.sum_hess = None
        self.transfer_inst.tree.remote(sanitized_tree,
                                       role=consts.HOST,
                                       idx=-1)"""
safe_source = original.replace(VULNERABLE_BLOCK, SAFE_BLOCK)
assert safe_source != original
assert "sanitized_tree" in safe_source
assert "self.transfer_inst.tree.remote(self.tree_" not in safe_source
(CASE_DIR / "variant_safe_01.py").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
# Built on the safe implementation above. Adds a new method that also calls
# self.transfer_inst.tree.remote(..., role=consts.HOST, idx=-1) -- the same
# call shape as the vulnerable line -- but sends only an aggregate integer
# (tree depth/node count), which carries no per-node weight/gradient/hessian
# information. A rule that fires on "any transfer_inst.tree.remote(...,
# role=consts.HOST)" regardless of payload would wrongly flag this.
BENIGN_ADDITION = '''
    def sync_tree_depth(self):
        """Shares only the final tree's node count with the host.

        An aggregate integer, not the underlying weights, gradients, or
        hessians, so unlike sync_tree() this transfer carries no
        sensitive per-node information across the trust boundary.
        """
        tree_depth = len(self.tree_)
        self.transfer_inst.tree.remote(tree_depth,
                                       role=consts.HOST,
                                       idx=-1)
'''
anchor = "    def sync_tree(self):"
benign_source = safe_source.replace(anchor, BENIGN_ADDITION.strip("\n") + "\n\n" + anchor, 1)
assert benign_source != safe_source
assert "sync_tree_depth" in benign_source
(CASE_DIR / "benign_lookalike.py").write_text(benign_source)

print("Wrote 4 new samples for CASE-0004.")
