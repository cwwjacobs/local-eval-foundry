"""Domain-specific errors surfaced as safe, actionable API failures."""


class EvalFoundryError(Exception):
    """Base error for expected engine failures."""


class ArchiveValidationError(EvalFoundryError):
    """The immutable input archive does not meet the package contract."""


class SplitAccessError(EvalFoundryError):
    """A caller tried to cross a dataset split or expose protected material."""


class BudgetExceeded(EvalFoundryError):
    """A run attempted to exceed its explicit model-call budget."""


class ModelBusy(EvalFoundryError):
    """Only one local model call may be active at a time."""


class ModelProtocolError(EvalFoundryError):
    """A model endpoint response did not satisfy the local contract."""


class UnsupportedEndpoint(EvalFoundryError):
    """An endpoint is remote or malformed without explicit authorization."""
