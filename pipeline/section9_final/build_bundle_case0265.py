"""
Section 9 ground-truth test bundle: CASE-0265
(polonel/trudesk, src/controllers/messages.js messagesController.getConversation,
CVE-2022-1947, CWE-480/NVD-CWE-Other broken access control / IDOR).

Core vulnerable mechanism: `getConversation` renders a full message thread
for `req.params.convoid`, fetched with `conversationSchema.getConversation(cid,
...)` -- a lookup by conversation id ALONE, with no check that `req.user` is
one of that conversation's participants. Any authenticated user (an agent,
or any account with access to the messages page) can therefore view any
OTHER conversation's private messages between two different users just by
changing the `convoid` in the URL to a guessed or enumerated id -- a classic
IDOR. The upstream fix converts the conversation's `participants` array into
a bare `isPart` boolean (`_.each(c.participants, ... if
(p._id.toString() === req.user._id.toString()) isPart = true)`) and
redirects to `/messages` instead of rendering when the requesting user is
not a participant.

Sibling sites: the OTHER `async.parallel` task in the same function (listing
the user's own conversations, via `getConversationsWithLimit(req.user._id,
...)`) is already scoped to the requesting user's own id, so it has no
equivalent gap; this is the only unauthorized-lookup site in the file.

Verification: each full file is placed as the real, unmodified
`src/controllers/messages.js` inside a small directory tree
(`src/logger.js`, `src/models/chat/conversation.js`,
`src/models/chat/message.js` as stand-ins for the app's own DB-backed
modules; REAL `lodash` and `async` packages installed via npm, so the
function's actual `async.parallel`/`async.eachSeries`/`_.each`/
`_.findIndex` control flow runs unmodified) and `getConversation` is called
with a fake `req.user` and a canned conversation whose `participants` do
NOT include that user. The fake `res.render`/`res.redirect` are recorded;
the requesting user's OWN conversation (participants include them) is
checked as a control case to confirm normal viewing still works.

Every variant is the FULL real file. `messagesController.getConversation` is
looked up by the app's router as `messagesController.getConversation`, so
its name and `(req, res)` signature are kept; the renamed variant renames
its own locals.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0265"
original = (CASE_DIR / "vulnerable_source.js").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


TASK2_HEAD = """      function (next) {
        content.data.page = 2

        conversationSchema.getConversation(cid, function (err, convo) {
          if (err) return next(err)

          if (convo === null || convo === undefined) {
            return res.redirect('/messages')
          }

          const c = convo.toObject()
          messageSchema.getConversationWithObject(
"""
assert original.count(TASK2_HEAD) == 1

# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, TASK2_HEAD, """      function (nextTask) {
        content.data.page = 2

        conversationSchema.getConversation(cid, function (err, foundConvo) {
          if (err) return nextTask(err)

          if (foundConvo === null || foundConvo === undefined) {
            return res.redirect('/messages')
          }

          const c = foundConvo.toObject()
          messageSchema.getConversationWithObject(
""")
v1 = swap(v1, "{ cid: c._id, userMeta: convo.userMeta, requestingUser: req.user },",
          "{ cid: c._id, userMeta: foundConvo.userMeta, requestingUser: req.user },")
v1 = swap(v1, """              c.requestingUserMeta =
                convo.userMeta[
                  _.findIndex(convo.userMeta, function (item) {
                    return item.userId.toString() === req.user._id.toString()
                  })
                ]

              content.data.conversation = c
              content.data.conversation.messages = messages.reverse()

              return next()
            }
          )
        })
      }
    ],
    function (err) {
      if (err) return handleError(res, err)
      return res.render('messages', content)
    }
  )
}""", """              c.requestingUserMeta =
                foundConvo.userMeta[
                  _.findIndex(foundConvo.userMeta, function (item) {
                    return item.userId.toString() === req.user._id.toString()
                  })
                ]

              content.data.conversation = c
              content.data.conversation.messages = messages.reverse()

              return nextTask()
            }
          )
        })
      }
    ],
    function (err) {
      if (err) return handleError(res, err)
      return res.render('messages', content)
    }
  )
}""")
(CASE_DIR / "variant_vulnerable_01.js").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
OLD_TASK2_FULL = """      function (next) {
        content.data.page = 2

        conversationSchema.getConversation(cid, function (err, convo) {
          if (err) return next(err)

          if (convo === null || convo === undefined) {
            return res.redirect('/messages')
          }

          const c = convo.toObject()
          messageSchema.getConversationWithObject(
            { cid: c._id, userMeta: convo.userMeta, requestingUser: req.user },
            function (err, messages) {
              if (err) return next(err)

              _.each(c.participants, function (p) {
                if (p._id.toString() !== req.user._id.toString()) {
                  c.partner = p
                }
              })

              c.requestingUserMeta =
                convo.userMeta[
                  _.findIndex(convo.userMeta, function (item) {
                    return item.userId.toString() === req.user._id.toString()
                  })
                ]

              content.data.conversation = c
              content.data.conversation.messages = messages.reverse()

              return next()
            }
          )
        })
      }
"""
assert original.count(OLD_TASK2_FULL) == 1
NEW_TASK2_FULL = """      function (next) {
        content.data.page = 2
        loadConversationDetail(cid, req, content, next, res)
      }
"""
v2 = swap(original, OLD_TASK2_FULL, NEW_TASK2_FULL)
HELPER = """function loadConversationDetail (cid, req, content, next, res) {
  conversationSchema.getConversation(cid, function (err, convo) {
    if (err) return next(err)

    if (convo === null || convo === undefined) {
      return res.redirect('/messages')
    }

    const c = convo.toObject()
    messageSchema.getConversationWithObject(
      { cid: c._id, userMeta: convo.userMeta, requestingUser: req.user },
      function (err, messages) {
        if (err) return next(err)

        _.each(c.participants, function (p) {
          if (p._id.toString() !== req.user._id.toString()) {
            c.partner = p
          }
        })

        c.requestingUserMeta =
          convo.userMeta[
            _.findIndex(convo.userMeta, function (item) {
              return item.userId.toString() === req.user._id.toString()
            })
          ]

        content.data.conversation = c
        content.data.conversation.messages = messages.reverse()

        return next()
      }
    )
  })
}

messagesController.getConversation = function (req, res) {"""
v2 = swap(v2, "messagesController.getConversation = function (req, res) {", HELPER)
(CASE_DIR / "variant_vulnerable_02.js").write_text(v2)

# --- Variant 3: transformed safe variant ---
# Same fix outcome as upstream (redirect when the requester is not a
# participant) but expressed with Array.prototype.some() over c.participants
# instead of upstream's _.each with a mutated boolean flag.
NEW_TASK2_SAFE = """      function (next) {
        content.data.page = 2

        conversationSchema.getConversation(cid, function (err, convo) {
          if (err) return next(err)

          if (convo === null || convo === undefined) {
            return res.redirect('/messages')
          }

          const c = convo.toObject()

          const isParticipant = (c.participants || []).some(
            (p) => p._id.toString() === req.user._id.toString()
          )
          if (!isParticipant) {
            return res.redirect('/messages')
          }

          messageSchema.getConversationWithObject(
            { cid: c._id, userMeta: convo.userMeta, requestingUser: req.user },
            function (err, messages) {
              if (err) return next(err)

              _.each(c.participants, function (p) {
                if (p._id.toString() !== req.user._id.toString()) {
                  c.partner = p
                }
              })

              c.requestingUserMeta =
                convo.userMeta[
                  _.findIndex(convo.userMeta, function (item) {
                    return item.userId.toString() === req.user._id.toString()
                  })
                ]

              content.data.conversation = c
              content.data.conversation.messages = messages.reverse()

              return next()
            }
          )
        })
      }
"""
v3 = swap(original, OLD_TASK2_FULL, NEW_TASK2_SAFE)
(CASE_DIR / "variant_safe_01.js").write_text(v3)

BENIGN = """// Standalone example of the same shape: skip rendering a "welcome back"
// banner unless the viewer's OWN locally-stored preference flag says to
// show it (never data another user's record controls), so a missing flag
// is a UX default, not an authorization gap.
function renderDashboardBanner (viewer, content) {
  const showBanner = Boolean(viewer.preferences && viewer.preferences.showWelcomeBanner)
  if (!showBanner) return content
  content.banner = 'Welcome back, ' + viewer.fullname
  return content
}

module.exports = { renderDashboardBanner }
"""
(CASE_DIR / "benign_lookalike.js").write_text(BENIGN)
