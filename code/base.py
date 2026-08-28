"""
Base class for defense baselines.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Dict, Any


class DefenseDecision(Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    MONITOR = "MONITOR"
    ESCALATE = "ESCALATE"


@dataclass
class NetworkRequest:
    method: str
    url: str
    headers: Dict[str, str]
    body: Optional[str] = None


@dataclass
class DecisionResult:
    decision: DefenseDecision
    tier_used: int  # 1 or 2
    latency_ms: float
    reason: Optional[str] = None
    confidence: Optional[float] = None


class BaselineDefense(ABC):
    """Abstract base class for all defense baselines."""

    def __init__(self, name: str, task_context: str = ""):
        self.name = name
        self.task_context = task_context
        self.request_history: List[NetworkRequest] = []

    def reset(self, task_context: str = ""):
        """Reset state for a new scenario."""
        self.task_context = task_context
        self.request_history = []

    @abstractmethod
    def evaluate(self, request: NetworkRequest) -> DecisionResult:
        """Evaluate a single request and return a decision."""
        pass

    def should_escalate_scenario(self) -> bool:
        """Check if the overall scenario should be flagged as attack."""
        return False

    def __repr__(self):
        return f"{self.__class__.__name__}(name={self.name})"
