"""Standalone example of the same shape: one worker thread per queued job, for
a fixed list of nightly jobs read from configuration (a handful, chosen by the
operator, never by remote clients)."""
import threading


def run_nightly(jobs, run_job):
    threads = []
    for job in jobs:
        t = threading.Thread(target=run_job, args=(job,), daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
