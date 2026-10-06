// Standalone example of the same shape: include a full related row in a
// query whose result is only ever used server-side to compute a count, never
// returned to a client.
import type { PrismaClient } from '@prisma/client'

export async function countAuthorsWithPosts(prisma: PrismaClient): Promise<number> {
    const posts = await prisma.forumPost.findMany({ include: { author: true } })
    return new Set(posts.map(p => p.author.id)).size
}
