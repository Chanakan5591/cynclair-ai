from abc import ABC, abstractmethod

class BaseSource(ABC):
    def __init__(self, targets: list[str]):
        self.targets = targets

    @abstractmethod
    def get_info(self):
        pass