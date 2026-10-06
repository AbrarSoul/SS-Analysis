def parse_dimensions(text):
    """Returns (length, width, height) from a string like '2x3x4'."""
    length, width, height = (int(part) for part in text.split("x"))
    return length, width, height


def box_volume(text):
    """Unpacks the tuple in a different order than it is returned, but the
    result is a product, which does not depend on the order, so the
    'wrong' order is harmless here."""
    height, width, length = parse_dimensions(text)
    return length * width * height
