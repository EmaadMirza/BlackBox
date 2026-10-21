"""Shared core validation errors."""
# Spec §9.3 and §16.3: errors are distinct from offline evidence verdicts.


class BlackBoxError(Exception):
    """Base error for shared BlackBox operations."""


class SchemaError(BlackBoxError):
    """A signed structure violates its schema."""


class VerificationError(BlackBoxError):
    """Evidence fails verification."""


class SignerRuleError(BlackBoxError):
    """A candidate violates a signer rule."""

    def __init__(self, message: str, *, code: str = "rule_conflict") -> None:
        super().__init__(message)
        self.code = code
