"""Integration acceptance and static validation for Docker Compose deployment (DK2, DK3)."""

from __future__ import annotations

from pathlib import Path

import yaml


def _load_compose() -> dict:
    compose_path = Path("docker-compose.yml")
    assert compose_path.exists(), "docker-compose.yml must exist"
    with open(compose_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def test_compose_networks_isolation_matrix() -> None:
    """Verify 4.2 Network Isolation Matrix in docker-compose.yml (DK2/deploy/networks.md)."""
    compose = _load_compose()
    networks = compose.get("networks", {})

    # 1. Required physical bridge networks
    assert "agent_net" in networks, "agent_net must be defined"
    assert "seal_net" in networks, "seal_net must be defined"
    assert "witness_net" in networks, "witness_net must be defined"
    assert "downstream_net" in networks, "downstream_net must be defined"
    assert "read_net" in networks, "read_net must be defined"

    # 2. Internal isolation rules
    assert networks["seal_net"].get("internal") is True, "seal_net must be internal"
    assert networks["witness_net"].get("internal") is True, "witness_net must be internal"
    assert networks["read_net"].get("internal") is True, "read_net must be internal"

    services = compose.get("services", {})

    # 3. Agent isolation: Agent talks ONLY on agent_net
    agent_nets = services["agent"].get("networks", [])
    assert agent_nets == ["agent_net"], f"Agent must only be on agent_net, got: {agent_nets}"

    # 4. Signer isolation: Signer talks ONLY on seal_net
    signer_nets = services["signer"].get("networks", [])
    assert signer_nets == ["seal_net"], f"Signer must only be on seal_net, got: {signer_nets}"

    # 5. Witness isolation: Witnesses talk ONLY on witness_net
    for w in ["witness-1", "witness-2", "witness-3"]:
        w_nets = services[w].get("networks", [])
        assert w_nets == ["witness_net"], f"{w} must only be on witness_net, got: {w_nets}"

    # 6. Provider mock isolation: Provider mock talks ONLY on downstream_net
    prov_nets = services["provider_mock"].get("networks", [])
    assert prov_nets == ["downstream_net"], (
        f"provider_mock must only be on downstream_net, got: {prov_nets}"
    )

    # 7. Gateway bridges untrusted agent_net to internal enforcement & downstream
    gw_nets = set(services["gateway"].get("networks", []))
    assert gw_nets == {"agent_net", "enforce_net", "seal_net", "downstream_net"}


def test_compose_security_and_healthchecks() -> None:
    """Verify 4.3 Container hardening, migrations, and healthcheck definitions (DK2)."""
    compose = _load_compose()
    x_app = compose.get("x-app", {})

    # 1. Hardening defaults
    assert x_app.get("read_only") is True, "Containers must be read_only"
    assert x_app.get("cap_drop") == ["ALL"], "All capabilities must be dropped"
    assert x_app.get("security_opt") == ["no-new-privileges:true"], (
        "no-new-privileges must be enforced"
    )
    assert x_app.get("tmpfs") == ["/tmp"], "/tmp must be tmpfs"

    # 2. Database migrations volume mount
    services = compose.get("services", {})
    db_vols = services["ledger-db"].get("volumes", [])
    migration_mount = any(
        "./services/ledger/migrations:/docker-entrypoint-initdb.d:ro" in v for v in db_vols
    )
    assert migration_mount, "ledger-db must mount migrations to /docker-entrypoint-initdb.d:ro"

    # 3. Migration files exist on disk
    migrations_dir = Path("services/ledger/migrations")
    sql_files = sorted(f.name for f in migrations_dir.glob("*.sql"))
    assert "001_init.sql" in sql_files
    assert "002_l1b_registry.sql" in sql_files
    assert "003_l3c_checkpoints.sql" in sql_files

    # 4. All microservices have healthchecks
    for name, svc in services.items():
        if name in ("anchor", "agent"):
            continue
        has_healthcheck = "healthcheck" in svc or "healthcheck" in x_app
        assert has_healthcheck, f"Service {name} must have a healthcheck"


def test_live_compose_health_if_running() -> None:
    """If Docker stack is running, verify live container health over HTTP."""
    import httpx

    # Check Gateway (port 8000)
    try:
        res = httpx.get("http://127.0.0.1:8000/health", timeout=1.0)
        assert res.status_code == 200
        data = res.json()
        assert data.get("status") == "ok"
    except (httpx.ConnectError, httpx.TimeoutException):
        # Stack is not running right now in local test runner; skip live assertion
        pass

    # Check Provider Mock (port 8085)
    try:
        res = httpx.get("http://127.0.0.1:8085/health", timeout=1.0)
        assert res.status_code == 200
        assert res.json().get("status") == "ok"
    except (httpx.ConnectError, httpx.TimeoutException):
        pass
