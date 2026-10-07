"""Log-level adapter: translates the standard-library logging levels to a vendor SDK's own numbering."""
import logging

_stdlib_to_vendor = {
    logging.DEBUG: 5,
    logging.INFO: 4,
    logging.WARNING: 3,
    logging.ERROR: 2,
}
_vendor_to_stdlib = dict((v, k) for k, v in _stdlib_to_vendor.items())


class VendorLogger(object):
    def __init__(self):
        self._level = 3

    @property
    def level(self):
        return _vendor_to_stdlib[self._level]

    @level.setter
    def level(self, value):
        self._level = _stdlib_to_vendor[value]
