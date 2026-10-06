"""Standalone example of the same shape: choose which servers must vouch for a
record, for an internal audit report where nothing is trusted because of the
answer."""


def reviewers_needed(record):
    reviewers = [record["owner_team"]]
    if record["requested_by_team"] != record["owner_team"]:
        reviewers.append(record["requested_by_team"])
    return reviewers
