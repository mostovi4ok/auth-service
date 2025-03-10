"""
This type stub file was generated by pyright.
"""

from enum import Enum

class IndexType(Enum):
    """Enum of the currently supported index types."""

    HASH = ...
    JSON = ...

class IndexDefinition:
    """IndexDefinition is used to define a index definition for automatic
    indexing on Hash or Json update.
    """

    def __init__(
        self,
        prefix=...,
        filter=...,
        language_field=...,
        language=...,
        score_field=...,
        score=...,
        payload_field=...,
        index_type=...,
    ) -> None: ...
