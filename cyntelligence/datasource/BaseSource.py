from abc import ABC, abstractmethod

class BaseSource(ABC):
    def __init__(self, query: str):
        self.query = query

    @abstractmethod
    def get_info(self) -> list[dict]:
        return [{}]
