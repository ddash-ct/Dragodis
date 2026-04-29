"""
Interface for data types.
"""

from __future__ import annotations
from abc import ABCMeta, abstractmethod


class DataType(metaclass=ABCMeta):

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return f"<DataType: {self.name}, size={self.size}, count={self.count}>"

    def __eq__(self, other):
        return isinstance(other, DataType) and self.name == other.name and self.size == other.size

    @property
    @abstractmethod
    def name(self) -> str:
        """
        The name of the data type.
        e.g: "dword", "char", etc.
        """

    @property
    @abstractmethod
    def size(self) -> int:
        """
        The size of the data type.
        """

    @property
    def base(self) -> DataType:
        """
        The data type for the elements in an array.
        This defaults to itself unless it is an explicitly defined array.
        """
        return self

    @property
    def count(self) -> int:
        """
        The number of elements in the data type.
        This defaults to 1 unless it is an explicitly defined array.
        """
        return 1
