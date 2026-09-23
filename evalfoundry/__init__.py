"""EvalFoundry: a local, split-safe evidence evaluation engine."""

from .rubric import RUBRIC_VERSION, evaluate_rubric
from .vault import DatasetVault

__all__ = ["DatasetVault", "RUBRIC_VERSION", "evaluate_rubric"]
