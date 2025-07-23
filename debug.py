import sys


class ThisModule(sys.__class__):

    @property
    def quiet(self) -> int:
        return self._quiet

    @quiet.setter
    def quiet(self, value: int) -> None:
        self._quiet = value


sys.modules[__name__].__class__ = ThisModule


KOFTA_VERSION = "0.10"

CBLK = "\x1b[0;30m"
CRED = "\x1b[0;31m"
CGRN = "\x1b[0;32m"
CBRN = "\x1b[0;33m"
CBLU = "\x1b[0;34m"
CMGN = "\x1b[0;35m"
CCYA = "\x1b[0;36m"
CLGR = "\x1b[0;37m"
CGRA = "\x1b[1;90m"
CLRD = "\x1b[1;91m"
CLGN = "\x1b[1;92m"
CYEL = "\x1b[1;93m"
CLBL = "\x1b[1;94m"
CPIN = "\x1b[1;95m"
CLCY = "\x1b[1;96m"
CBRI = "\x1b[1;97m"
CRST = "\x1b[0m"


_quiet: int = 0


def psay(msg: str, /, *args, **kwargs) -> None:
    print(msg, file=sys.stderr, flush=True, *args, **kwargs)


def pwarn(msg: str, /, *args, **kwargs) -> None:
    if _quiet < 2:
        psay(f"{CYEL}[!] {CBRI}WARNING: {CRST}{msg}", *args, **kwargs)


def pact(msg: str, /, *args, **kwargs) -> None:
    if _quiet < 3:
        psay(f"{CGRN}[*] {CRST}{msg}", *args, **kwargs)


def pok(msg: str, /, *args, **kwargs) -> None:
    if _quiet < 3:
        psay(f"{CGRN}[+] {CRST}{msg}", *args, **kwargs)


def pfatal(msg: str, /, *args, **kwargs) -> None:
    if _quiet < 4:
        psay(f"{CRED}[-] {CBRI}PROGRAM ABORT: {CRST}{msg}", *args, **kwargs)
    sys.exit(1)


def phello(prog: str) -> None:
    psay(f"{CCYA}{prog} {CBRI}{KOFTA_VERSION}{CRST} by <me@alardutp.dev>\n")