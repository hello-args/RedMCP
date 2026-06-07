"""MCTS Sigma rule loading and metadata matching."""

from mcts.taxonomy.sigma.loader import load_metadata_rules
from mcts.taxonomy.sigma.matcher import (
    convert_sigma_pattern_to_regex,
    is_substantive_pattern,
    match_sigma_pattern,
)

__all__ = [
    "convert_sigma_pattern_to_regex",
    "is_substantive_pattern",
    "load_metadata_rules",
    "match_sigma_pattern",
]
