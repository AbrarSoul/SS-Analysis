import os

_LOG_LEVEL_EXTENSIONS = ('info', 'warn', 'error')


def build_log_cache_path(session_id, level_index, cache_dir):
    # level_index always selects from the fixed tuple above -- never a
    # raw string taken from a request, so there is no unvalidated value
    # that could ever reach the path.
    extension = _LOG_LEVEL_EXTENSIONS[level_index % len(_LOG_LEVEL_EXTENSIONS)]
    fp = '{}.{}'.format(session_id, extension)
    c_dir = os.path.join(cache_dir, 'logs')
    return os.path.join(c_dir, fp)
