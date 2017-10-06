"""A set of utility functions used by the framework."""
import operator


def getattrd(obj, name):
    """Same as ``getattr()``, but allow dot notation lookup."""
    try:
        return operator.attrgetter(name)(obj)
    except AttributeError:
        return None
