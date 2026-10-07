"""
Section 9 ground-truth test bundle: CASE-0292
(spiral-project/ihatemoney, ihatemoney/models.py Person.PersonQuery
get_by_name/get, CVE-2020-15120, CWE-863 incorrect authorization / IDOR).

Core vulnerable mechanism: ihatemoney scopes a person lookup to the
current project with `.filter(Project.id == project.id)` -- but that
predicate is on the `Project` table, not on `Person`. SQLAlchemy therefore
adds `Project` to the FROM clause as an unrelated table (a cross join) and
the filter only tests that the project the caller is authenticated for
exists, which is always true. The lookup effectively becomes "the person
with this id/name in ANY project". A user of project A who requests
`/A/members/<id>/delete` (or edit) with the id of a member of a DIFFERENT
project B passes the check, and the view then reads/edits/deletes B's
member: cross-project IDOR. The upstream fix filters on the person's own
foreign key: `.filter(Person.project_id == project.id)`.

Sibling sites: both `get_by_name` and `get` have the identical defect; the
upstream fix (and this bundle's safe variant) changes both.

Verification: each full file's `PersonQuery` class body is extracted
verbatim and installed as the `query_class` of a REAL Flask-SQLAlchemy
`Person` model (minimal `Project`/`Person` tables with the same relevant
columns, `id`, `name`, `project_id`), on a REAL in-memory SQLite database
with two projects, A and B, and a person `Bob` (id known) belonging to B.
`Person.query.get(bob.id, project=A)` and `Person.query.get_by_name('Bob',
A)` are executed for real: a cross-project result (instead of
`NoResultFound`) shows the IDOR. Controls: a lookup of Bob under project B
must succeed in every variant.

Every variant is the FULL real file. `Person.query.get/get_by_name` are
used by name throughout the views, so their names/signatures are kept.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0292"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


Q = '''    class PersonQuery(BaseQuery):
        def get_by_name(self, name, project):
            return (
                Person.query.filter(Person.name == name)
                .filter(Project.id == project.id)
                .one()
            )

        def get(self, id, project=None):
            if not project:
                project = g.project
            return (
                Person.query.filter(Person.id == id)
                .filter(Project.id == project.id)
                .one()
            )
'''
assert original.count(Q) == 1

v1 = swap(original, Q, '''    class PersonQuery(BaseQuery):
        def get_by_name(self, person_name, project):
            return (
                Person.query.filter(Person.name == person_name)
                .filter(Project.id == project.id)
                .one()
            )

        def get(self, person_id, project=None):
            if not project:
                project = g.project
            return (
                Person.query.filter(Person.id == person_id)
                .filter(Project.id == project.id)
                .one()
            )
''')
(CASE_DIR / "variant_vulnerable_01.py").write_text(v1)

v2 = swap(original, Q, '''    class PersonQuery(BaseQuery):
        def _in_project(self, project):
            return Project.id == project.id

        def get_by_name(self, name, project):
            return (
                Person.query.filter(Person.name == name)
                .filter(self._in_project(project))
                .one()
            )

        def get(self, id, project=None):
            if not project:
                project = g.project
            return (
                Person.query.filter(Person.id == id)
                .filter(self._in_project(project))
                .one()
            )
''')
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

v3 = swap(original, Q, '''    class PersonQuery(BaseQuery):
        def _one_in_project(self, criterion, project):
            return Person.query.filter(criterion, Person.project_id == project.id).one()

        def get_by_name(self, name, project):
            return self._one_in_project(Person.name == name, project)

        def get(self, id, project=None):
            if not project:
                project = g.project
            return self._one_in_project(Person.id == id, project)
''')
(CASE_DIR / "variant_safe_01.py").write_text(v3)

(CASE_DIR / "benign_lookalike.py").write_text('''"""
Standalone example of the same shape: look a tag up by name among the
system-wide default tags that every project shares (deliberately not
per-project), so there is no tenant boundary to cross.
"""


class Tag:
    registry = {}

    @classmethod
    def get_shared(cls, name):
        return cls.registry[name]
''')
