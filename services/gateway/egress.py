"""Agent network egress boundary and firewall controls (spec §29.4 E5, deploy/networks.md)."""

from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar

T = TypeVar("T")


class EgressBlockedError(ConnectionError):
    """Raised when an agent container or process attempts direct egress violating network policy."""

    def __init__(self, target: str, message: str | None = None) -> None:
        self.target = target
        msg = message or f"Egress blocked: agent network policy prohibits direct access to {target}"
        super().__init__(msg)


class AgentNetworkSandbox:
    """Simulates Docker/firewall egress policy on Zone A (agent_net).

    Under default egress enforcement (spec §6.2, §29.4, deploy/networks.md),
    the agent container can ONLY route traffic to the Gateway. Direct egress
    to the downstream provider or external hosts fails closed at Layer 1.
    """

    def __init__(
        self,
        *,
        gateway_target: str = "gateway",
        egress_enforced: bool = True,
    ) -> None:
        self.gateway_target = gateway_target
        self.egress_enforced = egress_enforced
        self.blocked_attempts: list[str] = []

    def dispatch(
        self,
        destination: str,
        request_fn: Callable[[], T],
    ) -> T:
        """Route an outbound request from the agent network, enforcing egress policy."""
        if self.egress_enforced and destination != self.gateway_target:
            self.blocked_attempts.append(destination)
            raise EgressBlockedError(
                destination,
                f"Connection refused: agent network firewall blocked direct egress to '{destination}'. "
                f"All traffic must transit the Gateway ('{self.gateway_target}').",
            )
        return request_fn()

    def loosen_egress_rule(self) -> None:
        """Deliberately disable egress firewall to test Layer 2 safety net (Scenario E5)."""
        self.egress_enforced = False

    def restore_egress_rule(self) -> None:
        """Re-enable strict egress control."""
        self.egress_enforced = True
