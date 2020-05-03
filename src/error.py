import sys


class Error:
    """Base error object.
    """

    def __init__(self, msg, ecode=None):
        self.msg = msg
        self.ecode = ecode

    def __str__(self):
        if self.ecode is None:
            s = str(self.msg)
        else:
            s = "%s (ecode=%s)" % (self.msg, self.ecode)
        return s

    def __repr__(self):
        return """<Error msg="%s" ecode="%s">""" % (self.msg, self.ecode)

    def get_ecode(self, default=None):
        if self.ecode is None:
            return default

        return self.ecode


def __perror(erro):
    sys.stderr.write("%s\n" % str(erro))


def is_error(erro):
    return isinstance(erro, Error)


def perror(erro):
    """On Error, write string to stderr.
    """
    if is_error(erro):
        __perror(erro)


def perror_exit(erro, exitcode=1):
    """Call perror(). Exit on non-zero exitcode.
    """
    if is_error(erro):
        __perror(erro)
        if exitcode != 0:
            sys.exit(exitcode)
