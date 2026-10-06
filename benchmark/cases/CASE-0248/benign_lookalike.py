"""Standalone example of the same shape: a debug line naming the operation, the
host, the bucket and the key, with no credentials (the access key stays in the
client object)."""
import logging

LOG = logging.getLogger(__name__)


def log_get(s3_host, bucket, key):
    LOG.debug("Retrieved image object from S3 using s3_host=%(s3_host)s, "
              "bucket=%(bucket)s, key=%(key)s)",
              {'s3_host': s3_host, 'bucket': bucket, 'key': key})
