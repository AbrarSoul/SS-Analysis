"""
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
