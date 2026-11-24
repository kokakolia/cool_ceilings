from pki_primitives import FORMATTER, pipe, sds, tcp


HOSTS = {role: f"{role}.ceilings.test" for role in ("web", "auth", "order")}
TEST_HOSTS = {"web": "app.ceilings.test", "mailpit": "mailpit.ceilings.test"}


def tls_socket(settings, direction="Downstream"):
    return {
        "name": "envoy.transport_sockets.tls",
        "typed_config": {"@type": FORMATTER + f"transport_sockets.tls.v3.{direction}TlsContext", **settings},
    }


def service_tls(peer, outgoing):
    """All listeners get CA and CRL from SDS, while each peer name is fixed in config."""
    common = {
        "tls_certificate_sds_secret_configs": [sds("identity", "tls-sds.yaml")],
        "combined_validation_context": {
            "default_validation_context": {"match_typed_subject_alt_names": [
                {"san_type": "DNS", "matcher": {"exact": peer}},
            ]},
            "validation_context_sds_secret_config": sds("trust", "trust-sds.yaml"),
        },
    }
    if outgoing:
        return tls_socket({"common_tls_context": common, "sni": peer, "max_session_keys": 0}, "Upstream")
    return tls_socket({
        "common_tls_context": common, "require_client_certificate": True,
        "disable_stateless_session_resumption": True, "disable_stateful_session_resumption": True,
    })


def browser_tls():
    return tls_socket({"common_tls_context": {"tls_certificates": [{
        "certificate_chain": {"filename": "/run/secrets/browser_cert"},
        "private_key": {"filename": "/run/secrets/browser_key"},
    }]}})


def virtual_host(name, domains, cluster=None):
    action = {"route": {"cluster": cluster}} if cluster else {
        "direct_response": {"status": 421, "body": {"inline_string": "Unsupported host\n"}},
    }
    return {"name": name, "domains": domains, "routes": [{"match": {"prefix": "/"}, **action}]}


def listener(name, address, hosts, transport=None):
    hcm = {
        "@type": FORMATTER + "filters.network.http_connection_manager.v3.HttpConnectionManager",
        "stat_prefix": name,
        "route_config": {"name": name, "virtual_hosts": hosts},
        "http_filters": [{"name": "envoy.filters.http.router", "typed_config": {
            "@type": FORMATTER + "filters.http.router.v3.Router",
        }}],
    }
    chain = {"filters": [{"name": "envoy.filters.network.http_connection_manager", "typed_config": hcm}]}
    if transport:
        chain["transport_socket"] = transport
    return {"name": name, "address": address, "filter_chains": [chain]}


def cluster(name, address, transport=None):
    settings = {
        "name": name, "connect_timeout": "2s", "type": "STRICT_DNS" if "socket_address" in address else "STATIC",
        "load_assignment": {"cluster_name": name, "endpoints": [
            {"lb_endpoints": [{"endpoint": {"address": address}}]},
        ]},
    }
    if transport:
        settings["transport_socket"] = transport
    return settings


def config_for(role):
    if role == "web":
        ingress = [virtual_host(name, [host, f"{host}:8443"], name) for name, host in TEST_HOSTS.items()]
        listeners = [
            listener("browser", tcp("0.0.0.0", 8443), [*ingress, virtual_host("unknown", ["*"])], browser_tls()),
            listener("outbound", pipe("/sockets/web-out.sock", 0o660), [
                *(virtual_host(name, [HOSTS[name]], name) for name in ("auth", "order")),
                virtual_host("unknown", ["*"]),
            ]),
        ]
        clusters = [cluster("web", pipe("/sockets/web-in.sock")), cluster("mailpit", tcp("mailpit-ui", 8025))]
        clusters.extend(cluster(name, tcp(HOSTS[name], 8443), service_tls(HOSTS[name], outgoing=True))
                        for name in ("auth", "order"))
    else:
        listeners = [listener(role, tcp("0.0.0.0", 8443), [virtual_host(role, ["*"], role)],
                              service_tls(HOSTS["web"], outgoing=False))]
        clusters = [cluster(role, pipe(f"/sockets/{role}-in.sock"))]
    return {"node": {"id": role, "cluster": "ceilings"}, "static_resources": {"listeners": listeners, "clusters": clusters}}
