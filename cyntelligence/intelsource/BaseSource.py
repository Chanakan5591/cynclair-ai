from abc import ABC, abstractmethod

class BaseSource(ABC):
    @abstractmethod
    def get_info(self):
        pass