"""MCTS Sigma rule loading and metadata matching."""

from mcts.taxonomy.sigma.loader import (
    MetadataSigmaRule,
    compile_metadata_rules,
    dedupe_rules,
    load_bundled_rules,
    load_metadata_rules,
    load_rules_from_directory,
)
from mcts.taxonomy.sigma.matcher import (
    convert_sigma_pattern_to_regex,
    is_substantive_pattern,
    match_sigma_pattern,
)

__all__ = [
    "MetadataSigmaRule",
    "compile_metadata_rules",
    "convert_sigma_pattern_to_regex",
    "dedupe_rules",
    "is_substantive_pattern",
    "load_bundled_rules",
    "load_metadata_rules",
    "load_rules_from_directory",
    "match_sigma_pattern",
]
