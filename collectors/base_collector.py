"""
Base collector class for triage analysis.
"""

from abc import ABC, abstractmethod


class BaseCollector(ABC):
    """Base class for all collectors."""
    
    @abstractmethod
    def collect(self):
        """
        Collect data from the system.
        
        Returns:
            dict: Collected data
        """
        pass
    
    def get_name(self):
        """Get the name of the collector."""
        return self.__class__.__name__













