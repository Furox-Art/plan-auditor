"""The CLI exit-code contract, in one place.

The exit codes used to be literals spread across cli.py: every new failure path
re-picked a number, and nothing proved the numbers still meant what docs/cli.md
said they meant. They are now exactly four, with the meaning the documented
legend states:

0  verification passed        every active plan is complete and authenticated
                              (other commands: "this operation succeeded")
1  verification failed        a check did not pass, or a gate requirement was
                              unmet — the user's work is not proven complete
2  request refused            the request could not be evaluated: attempt
                              budget exhausted, seal violated, tampered
                              evidence, bad plan/config, prerequisite missing
3  undetermined               the verdict is UNKNOWN, so completion is withheld
                              (an undetermined outcome is never success)

Rule behind the numbers: 0/1 answer "what did verification conclude"; 2/3
answer "could verification be performed at all". 2 and 3 are fixable
configuration/integrity problems; 1 means the operator must keep working.
"""
from __future__ import annotations

from enum import IntEnum


class ExitCode(IntEnum):
    """Process exit codes. IntEnum so `sys.exit(ExitCode.X)` stays an int."""

    VERIFICATION_PASSED = 0
    VERIFICATION_FAILED = 1
    REQUEST_REFUSED = 2
    UNDETERMINED = 3

    @property
    def reason(self) -> str:
        return _REASONS[self]


_REASONS = {
    ExitCode.VERIFICATION_PASSED: "every active plan is complete and its evidence is authenticated",
    ExitCode.VERIFICATION_FAILED: "a check did not pass or a gate requirement was not met",
    ExitCode.REQUEST_REFUSED: "the request could not be evaluated (budget exhausted, seal violated, tampered evidence, bad plan/config)",
    ExitCode.UNDETERMINED: "the assessment could not be determined, so completion is withheld (never success)",
}

__all__ = ["ExitCode"]
