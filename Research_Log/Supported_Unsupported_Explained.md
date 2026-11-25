# Supported / Partially Supported / Unsupported — a study guide

This is a deep, example-driven explanation of the single classification that decides which cases
the paper actually evaluates on (the 150) versus which ones are built but not scored (the other
149). Written to be read on its own, slowly, with the real code in front of you — every example
below points at a real case folder (`benchmark/cases/CASE-XXXX/`) you can open and read yourself.

---

## Part 1 — The one idea everything else depends on

A Semgrep rule is a **pattern matched against the text/structure of one file, in isolation**. It
can see: the shape of an expression, which function is being called, which variable flows into
which argument, within the file (or occasionally a few files) it's actually scanning.

It **cannot** see: what happens at runtime, how fast something executes, whether some *other*,
unrelated part of the application already protects this code path, or whether a value that looks
safe here will become dangerous somewhere else entirely.

That's the whole classification, really. Every case in the dataset got asked one question: **"is
the thing that makes this code vulnerable something a pattern-matcher looking at this one spot
could actually recognize?"** The answer sorts into exactly three buckets.

---

## Part 2 — Supported, with a real worked example

**Definition:** the vulnerable code has a shape that's self-contained and recognizable — a
dangerous function call, a missing check, an incomplete deny-list, or a value flowing from input
straight to a risky sink, all within reach of one pattern.

### Worked example: `CASE-0042` (MaxKB, CVE-2025-32383, CWE-94 — Code Injection)

Open `benchmark/cases/CASE-0042/vulnerable_source.py`, lines 84-95:

```python
def _exec_sandbox(self, _code, _id):
    exec_python_file = f'{self.sandbox_path}/{_id}.py'
    with open(exec_python_file, 'w') as file:
        file.write(_code)
        os.system(f"chown {self.user}:{self.user} {exec_python_file}")
    kwargs = {'cwd': BASE_DIR}
    subprocess_result = subprocess.run(
        ['su', '-c', python_directory + ' ' + exec_python_file, self.user],
        text=True,
        capture_output=True, **kwargs)
```

Read this with no other context at all: `_code` gets written straight to a `.py` file, and that
file is then **executed**. That's the entire vulnerability, visible in 6 lines, no knowledge of the
rest of the application required. A Semgrep rule looking for "a value gets written to a file, and
that same file path is later passed to `subprocess.run`/`os.system`" would catch exactly this,
every time it appears this way, without needing to understand anything about MaxKB as a whole.
That self-containedness is what "supported" means.

Other real `supported` cases to read if you want more examples: `CASE-0045` (CWE-74/77, command
injection), `CASE-0046` (CWE-915, taint mode — a value flows from an unsafe source to a dangerous
sink across a couple of steps, but still entirely traceable within the file).

---

## Part 3 — Partially supported, with a real worked example

**Definition:** part of what makes the code dangerous depends on context *outside* the function
being matched — something elsewhere in the application that the pattern can't see from where it's
looking.

### Worked example: `CASE-0044` (CVE-2025-67731, CWE-400 — Uncontrolled Resource Consumption / DoS)

Open `benchmark/cases/CASE-0044/vulnerable_source.js` — the **entire file**:

```javascript
const express = require("express");

class StartServer {
    static listen(port) {
        const app = express();
        app.use(express.json());
        app.get("/", (req, res) => {
            res.send("Server is running!");
        });
        app.listen(port, () => {
            console.log(`Server is running on port ${port}`);
        });
    }
}

module.exports = StartServer;
```

Read this on its own: there is **nothing here that looks dangerous**. It's an ordinary Express
server starting up. The actual vulnerability (resource exhaustion — the server can be overwhelmed
because nothing here bounds request size, connection count, or timeouts) isn't a bad *line* of
code at all — it's the **absence** of protection that might, or might not, exist somewhere else in
the real application (a reverse proxy in front of it, middleware applied elsewhere, a process
manager with its own limits). A pattern rule looking only at this file has no way to know whether
the surrounding deployment already handles this. That's exactly what "depends on context outside
the function" means in practice — not a vague caveat, a concrete blind spot.

Other real `partially_supported` cases: `CASE-0041` (CWE-1236, CSV/formula injection — whether a
value is dangerous depends on whether it's later exported to a spreadsheet elsewhere in the app),
`CASE-0060` (CWE-59, symlink-following path issue — depends on filesystem state a single function
can't see).

---

## Part 4 — Unsupported, with a real worked example

**Definition:** the vulnerability can't be localized to a code pattern at all — timing behavior,
concurrent execution, or authorization logic spread across multiple components.

### Worked example: `CASE-0056` (Radicale, CVE-2017-8342, CWE-362 — Race Condition)

Open `benchmark/cases/CASE-0056/vulnerable_source.py`, lines 186-198:

```python
def is_authenticated(self, user, password):
    # The content of the file is not cached because reading is generally a
    # very cheap operation, and it's useful to get live updates of the
    # htpasswd file.
    with open(self.filename) as fd:
        for line in fd:
            line = line.strip()
            if line:
                login, hash_value = line.split(":")
                if login == user:
                    return self.verify(hash_value, password)
    return False
```

Read this as *text* and it looks completely reasonable — open a file, loop through lines, check a
password hash, return a boolean. There is no dangerous function call, no missing check visible
anywhere in this code. The real problem is about **when** things happen relative to each other
(a race/timing issue) — something you can only find by reasoning about *execution*, not by reading
the shape of the code. A pattern-matcher has no concept of "how long does this take" or "what else
might run concurrently with this" — that information simply isn't present in the source text at
all, no matter how good the pattern is.

Other real `unsupported` cases: `CASE-0043` (CWE-862, missing authorization — would require
knowing whether some other part of the app already checks permissions, which is a whole-program
question, not a local one), `CASE-0058` (CWE-310, a cryptographic weakness that's about the
*algorithm's* mathematical properties, not any specific line of code).

---

## Part 5 — A rubric you can apply yourself to a new case

Ask these in order:

1. **Can I point at the specific line(s) that are dangerous, using only what's in this one file?**
   If yes, and nothing outside this file changes whether it's dangerous → likely **supported**.
2. **If no** — is the danger real but conditional on something else in the app (a missing
   protection elsewhere, a value that becomes dangerous only once it reaches some other part of the
   system)? → **partially supported**.
3. **If the "vulnerability" isn't really about code shape at all** — it's about timing, ordering,
   concurrency, cryptographic strength, or whether some entirely separate piece of the application
   enforces a check → **unsupported**.

Try it yourself: open any case folder you haven't looked at yet (`benchmark/all_cases_reference.csv`
has the real classification for every one, so you can check your own answer against it), read
`vulnerable_source.*`, and work through the three questions before looking at the `status` column.

---

## Part 6 — Why the other 149 cases are still built, even though they're not scored

Now that you've seen real examples, the reason is more concrete than it was in the abstract version
of this explanation:

- **The ratio is itself the finding.** Having actually classified all 299 real CVE fixes this way,
  the paper can honestly say "about half of real-world vulnerability fixes aren't even the kind of
  thing a pattern-matching tool could express" — and that claim is only credible because every real
  case was checked, not a convenient subset chosen in advance.
- **`CASE-0044` and `CASE-0056` are useful precisely because they're examples of the limit**, not
  despite it. Keeping them (with full documentation of *why* they don't qualify) is what lets you —
  or anyone else — verify the boundary wasn't drawn arbitrarily to make the "supported" bucket look
  good.
- **All 299 got the full six-sample treatment**, not just the 150 — meaning the "partially
  supported" and "unsupported" cases are a real, usable resource for anyone building a tool that
  *can* reason across files or about timing/concurrency (unlike plain Semgrep patterns), not wasted
  effort.

---

## Quick index of every example used above

| Case | Bucket | CWE | What makes it that way |
|---|---|---|---|
| `CASE-0042` | supported | CWE-94 | Danger is 6 self-contained lines: write code to disk, execute it |
| `CASE-0045` | supported | CWE-74/77 | Command injection, self-contained |
| `CASE-0046` | supported | CWE-915 | Taint flow traceable within the file |
| `CASE-0044` | partially supported | CWE-400 | File alone looks harmless; danger depends on deployment context |
| `CASE-0041` | partially supported | CWE-1236 | Danger depends on where the value is later exported to |
| `CASE-0060` | partially supported | CWE-59 | Depends on filesystem state outside the function |
| `CASE-0056` | unsupported | CWE-362 | Timing/race issue — not visible in code shape at all |
| `CASE-0043` | unsupported | CWE-862 | Requires whole-app knowledge of where auth checks live |
| `CASE-0058` | unsupported | CWE-310 | About cryptographic algorithm strength, not code shape |
