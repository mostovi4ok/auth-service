"""
This type stub file was generated by pyright.
"""

class Path:
    def __init__(self, nodes, edges) -> None: ...
    @classmethod
    def new_empty_path(cls):  # -> Self:
        ...
    def nodes(self):  # -> list[Any]:
        ...
    def edges(self):  # -> list[Any]:
        ...
    def get_node(self, index): ...
    def get_relationship(self, index): ...
    def first_node(self): ...
    def last_node(self): ...
    def edge_count(self):  # -> int:
        ...
    def nodes_count(self):  # -> int:
        ...
    def add_node(self, node):  # -> Self:
        ...
    def add_edge(self, edge):  # -> Self:
        ...
    def __eq__(self, other) -> bool: ...
