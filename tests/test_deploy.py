"""The deployment assets are part of the security posture: check them."""

from pathlib import Path

import yaml

from promptwarden.config import parse_policy

ROOT = Path(__file__).parent.parent
K8S = ROOT / "deploy" / "kubernetes"


def load(name: str) -> dict:
    return yaml.safe_load((K8S / name).read_text(encoding="utf-8"))


def test_all_manifests_parse_and_are_listed():
    listed = set(load("kustomization.yaml")["resources"])
    for path in K8S.glob("*.yaml"):
        assert yaml.safe_load(path.read_text(encoding="utf-8")), path.name
        if path.name not in {"kustomization.yaml", "secret.example.yaml"}:
            assert path.name in listed, f"{path.name} missing from kustomization.yaml"


def test_pod_is_hardened():
    spec = load("deployment.yaml")["spec"]["template"]["spec"]
    assert spec["automountServiceAccountToken"] is False
    assert spec["securityContext"]["runAsNonRoot"] is True
    assert spec["securityContext"]["seccompProfile"]["type"] == "RuntimeDefault"
    container = spec["containers"][0]
    security = container["securityContext"]
    assert security["allowPrivilegeEscalation"] is False
    assert security["readOnlyRootFilesystem"] is True
    assert security["capabilities"]["drop"] == ["ALL"]
    assert container["readinessProbe"]["httpGet"]["path"] == "/readyz"
    assert container["livenessProbe"]["httpGet"]["path"] == "/healthz"
    assert "memory" in container["resources"]["limits"]


def test_no_secret_values_in_the_deployment():
    container = load("deployment.yaml")["spec"]["template"]["spec"]["containers"][0]
    names = {item["name"] for item in container["env"]}
    assert not {"PW_HEC_TOKEN", "PW_UPSTREAM_API_KEY", "PW_WEBHOOK_TOKEN"} & names
    assert container["envFrom"][0]["secretRef"]["name"] == "promptwarden-secrets"


def test_network_policy_is_default_deny_both_ways():
    spec = load("networkpolicy.yaml")["spec"]
    assert set(spec["policyTypes"]) == {"Ingress", "Egress"}
    assert all("from" in rule for rule in spec["ingress"])


def test_configmap_policy_is_valid_and_starts_in_monitor_mode():
    policy = parse_policy(yaml.safe_load(load("configmap.yaml")["data"]["policy.yaml"]))
    assert policy.gateway.mode == "monitor" and policy.auth.required
    assert policy.gateway.expose_detections is False


def test_container_image_runs_as_non_root():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "USER 10001" in dockerfile and "promptwarden\", \"serve" in dockerfile


def test_prometheus_alert_rules_reference_real_metrics():
    from promptwarden.metrics import Metrics

    exported = Metrics().render().decode()
    rules = yaml.safe_load((ROOT / "dashboards" / "prometheus" / "alerts.yaml").read_text())
    import re

    for rule in rules["groups"][0]["rules"]:
        for metric in re.findall(r"promptwarden_[a-z_]+", rule["expr"]):
            base = re.sub(r"_(bucket|count|sum)$", "", metric)
            assert base in exported, f"{rule['alert']} uses unknown metric {metric}"
