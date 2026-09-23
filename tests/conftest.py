"""Shared test configuration.

Unit tests (the default run) must not touch the network (TESTING-STANDARD §3). This guard makes
any DNS lookup or outbound socket connect fail loudly in a non-integration test, so an
accidentally-live test is caught instead of silently depending on (or timing out on) the network.
Tests marked ``@pytest.mark.integration`` are exempt.
"""
import socket

import pytest


class NetworkBlocked(RuntimeError):
    """Raised when a unit test tries to reach the network."""


@pytest.fixture(autouse=True)
def _no_network(request, monkeypatch):
    if request.node.get_closest_marker("integration"):
        yield
        return

    def _blocked(*args, **kwargs):
        raise NetworkBlocked(f"network access in unit test {request.node.nodeid}: {args[:2]!r}")

    monkeypatch.setattr(socket, "getaddrinfo", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)
    monkeypatch.setattr(socket.socket, "connect", _blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", _blocked)
    yield
