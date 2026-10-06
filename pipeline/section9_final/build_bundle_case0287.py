"""
Section 9 ground-truth test bundle: CASE-0287
(siemvk/OpenLearn, app/server/routers/forum.ts forumRouter,
CVE-2026-41243, CWE-284 improper access control / excessive data exposure).

Core vulnerable mechanism: the forum tRPC router loads posts, replies and
review queues with Prisma `include: { author: true }`. `include: true` on a
relation returns EVERY column of the related `User` row -- email address,
password hash, role, tokens -- and the router returns the query result
directly to the client. The `getPosts` and `getSpecificPost` procedures are
PUBLIC (`publicProcedure`), so an unauthenticated visitor listing forum
posts receives every author's private profile fields. The upstream fix
replaces each `author: true` with
`author: { select: { id: true, name: true } }` so only the public
identity fields leave the server.

Sibling sites: there are six `author: true` includes (getPosts x2 for the
safeMode/non-safeMode branches, getSpecificPost x2 (post author and reply
authors), forumReviewQueue, forumReplyReviewQueue); the upstream fix
changes all of them and so does this bundle's safe variant.

Verification: each full file is transpiled with Node's
`stripTypeScriptTypes`, its imports removed, and run for real in a Node vm
with stand-ins for the tRPC builders (`publicProcedure` etc. return the
handler function) and `zod`, plus a fake `ctx.prisma` that implements
Prisma's include/select semantics faithfully for the relation in question
(`author: true` yields the full user row including `email` and
`passwordHash`; `author: {select: {...}}` yields only the selected keys).
The four read procedures (`getPosts` in both safeMode states,
`getSpecificPost`, `forumReviewQueue`, `forumReplyReviewQueue`) are called
and every returned object is scanned recursively for `email`/`passwordHash`.

Every variant is the FULL real file. Router procedure names/shape are kept
(clients call them by name); the renamed variant renames only handler
locals.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0287"
original = (CASE_DIR / "vulnerable_source.ts").read_text()
assert "\r" not in original
assert original.count("author: true") == 6


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant ---
v1 = re.sub(r"\bsafeMode\b", "safeModeConfig", original)
v1 = re.sub(r"\bpendingPosts\b", "postsAwaitingReview", v1)
v1 = re.sub(r"\bpendingReplies\b", "repliesAwaitingReview", v1)
assert v1 != original
(CASE_DIR / "variant_vulnerable_01.ts").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = original.replace("author: true", "author: AUTHOR_RELATION")
v2 = swap(v2, "export const forumRouter = {", "// relation spec used by every include below\nconst AUTHOR_RELATION = true\n\nexport const forumRouter = {")
(CASE_DIR / "variant_vulnerable_02.ts").write_text(v2)

# --- Variant 3: transformed safe variant ---
v3 = original.replace("author: true", "author: PUBLIC_AUTHOR")
v3 = swap(v3, "export const forumRouter = {", "// only the public identity fields of an author ever leave the server\nconst PUBLIC_AUTHOR = { select: { id: true, name: true } } as const\n\nexport const forumRouter = {")
(CASE_DIR / "variant_safe_01.ts").write_text(v3)

(CASE_DIR / "benign_lookalike.ts").write_text('''// Standalone example of the same shape: include a full related row in a
// query whose result is only ever used server-side to compute a count, never
// returned to a client.
import type { PrismaClient } from '@prisma/client'

export async function countAuthorsWithPosts(prisma: PrismaClient): Promise<number> {
    const posts = await prisma.forumPost.findMany({ include: { author: true } })
    return new Set(posts.map(p => p.author.id)).size
}
''')
