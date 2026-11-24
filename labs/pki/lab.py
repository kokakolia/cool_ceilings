"""In-container PKI and HTTP tools for the isolated Compose experiment."""

import argparse
import hashlib
import http.client
import json
import os
import secrets
import shutil
import socket
import ssl
import subprocess
import tempfile
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import unquote
from urllib.request import urlopen

CA_URL = "https://ca.ceilings.test:9000"
CRL_URL = "http://ca.ceilings.test:9001/1.0/crl"
OFFLINE = Path("/offline/step")
PASSWORD = Path("/offline/operator-password")
ROLES = Path("/roles")
FORMATTER = "type.googleapis.com/envoy.extensions."


def run(*args, data=None):
    result = subprocess.run(
        [str(arg) for arg in args], input=data, capture_output=True, timeout=25, check=False
    )
    if result.returncode:
        name = " ".join(map(str, args[:3]))
        raise RuntimeError(f"{name}: {result.stderr.decode(errors='replace').strip()}")
    return result.stdout


def atomic(path, data):
    """Publish by replacing a file within its own filesystem."""
    if isinstance(data, str):
        data = data.encode()
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as f:
        staged = Path(f.name)
        try:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
            f.close()
            staged.chmod(0o644)
            os.replace(staged, path)
        finally:
            staged.unlink(missing_ok=True)


def provisioner_token(name, csr, root):
    return run(
        "step", "ca", "token", name, "--san", name, "--cnf-file", csr,
        "--ca-url", CA_URL, "--root", root, "--provisioner", "lab-operator",
        "--provisioner-password-file", PASSWORD,
    ).decode().strip()


def pipe(path, mode=None):
    address = {"path": path}
    if mode is not None:
        address["mode"] = mode
    return {"pipe": address}


def tcp(host, port):
    return {"socket_address": {"address": host, "port_value": port}}


def sds(name, filename):
    return {"name": name, "sds_config": {
        "path_config_source": {"path": f"/run/pki/{filename}", "poll_interval": "1s"}
    }}


def tls(role):
    web = role == "web"
    config = {
        "@type": FORMATTER + "transport_sockets.tls.v3."
                 + ("UpstreamTlsContext" if web else "DownstreamTlsContext"),
        "common_tls_context": {
            "tls_certificate_sds_secret_configs": [sds("identity", "tls-sds.yaml")],
            "validation_context_sds_secret_config": sds("trust", "trust-sds.yaml"),
        },
    }
    if web:
        config.update(sni="order.ceilings.test", max_session_keys=0)
    else:
        config.update(require_client_certificate=True, disable_stateless_session_resumption=True,
                      disable_stateful_session_resumption=True)
    return {"name": "envoy.transport_sockets.tls", "typed_config": config}


def envoy_config(role):
    web = role == "web"
    route = {"match": {"prefix": "/"}, "route": {"cluster": "target", "timeout": "0s"}}
    if not web:
        route["response_headers_to_add"] = [{
            "header": {"key": "x-lab-web-cert", "value": "%DOWNSTREAM_PEER_CERT%"},
            "append_action": "OVERWRITE_IF_EXISTS_OR_ADD",
        }]
    hcm = {
        "@type": FORMATTER + "filters.network.http_connection_manager.v3.HttpConnectionManager",
        "stat_prefix": role,
        "route_config": {"name": "lab", "virtual_hosts": [
            {"name": "lab", "domains": ["*"], "routes": [route]}
        ]},
        "http_filters": [{
            "name": "envoy.filters.http.router",
            "typed_config": {"@type": FORMATTER + "filters.http.router.v3.Router"},
        }],
    }
    endpoint = tcp("order.ceilings.test", 8443) if web else pipe("/sockets/order.sock")
    cluster = {
        "name": "target", "connect_timeout": "2s", "type": "STRICT_DNS" if web else "STATIC",
        "load_assignment": {"cluster_name": "target", "endpoints": [
            {"lb_endpoints": [{"endpoint": {"address": endpoint}}]}
        ]},
    }
    if web:
        cluster["transport_socket"] = tls(role)
        # Test runs force fresh handshakes; the production design permits connection reuse.
        cluster["typed_extension_protocol_options"] = {
            "envoy.extensions.upstreams.http.v3.HttpProtocolOptions": {
                "@type": FORMATTER + "upstreams.http.v3.HttpProtocolOptions",
                "common_http_protocol_options": {"max_requests_per_connection": 1},
                "explicit_http_config": {"http_protocol_options": {}},
            },
        }
    chain = {"filters": [{"name": "envoy.filters.network.http_connection_manager",
                          "typed_config": hcm}]}
    if not web:
        chain["transport_socket"] = tls(role)
    return {"node": {"id": role, "cluster": "ceilings-pki"}, "static_resources": {"listeners": [{
        "name": "ingress",
        "address": pipe("/sockets/web.sock", 0o660) if web else tcp("0.0.0.0", 8443),
        "filter_chains": [chain],
    }], "clusters": [cluster]}}


def identity(role_dir, version):
    folder = role_dir / "versions" / version
    return folder / "cert.pem", folder / "key.pem"


def public_key(cert_pem):
    return run("openssl", "x509", "-pubkey", "-noout", data=cert_pem)


def cert_facts(cert_pem):
    opts = run("openssl", "x509", "-noout", "-serial", "-enddate", data=cert_pem)
    values = dict(line.split("=", 1) for line in opts.decode().splitlines())
    return {
        "serial": values["serial"].upper(),
        "spki_sha256": hashlib.sha256(run(
            "openssl", "pkey", "-pubin", "-outform", "DER", data=public_key(cert_pem)
        )).hexdigest(),
        "not_after": values["notAfter"],
    }


def publish(role_dir, version):
    cert, key = identity(role_dir, version)
    if public_key(cert.read_bytes()) != run("openssl", "pkey", "-in", key, "-pubout"):
        raise RuntimeError("Certificate and private key do not match")
    atomic(role_dir / "tls-sds.yaml", json.dumps({"resources": [{
        "@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret",
        "name": "identity",
        "tls_certificate": {
            "certificate_chain": {"filename": f"/run/pki/versions/{version}/cert.pem"},
            "private_key": {"filename": f"/run/pki/versions/{version}/key.pem"},
        },
    }]}))
    return cert_facts(cert.read_bytes())


def active_version(role_dir):
    config = json.loads((role_dir / "tls-sds.yaml").read_text())
    cert = config["resources"][0]["tls_certificate"]["certificate_chain"]["filename"]
    return Path(cert).parent.name


def seal_key(key):
    os.chown(key, 0, 101)
    key.chmod(0o640)


def root_crl(seconds, password_file=PASSWORD):
    """Simulate an offline signer in the operator container; CA never mounts /offline."""
    ca_dir = Path("/offline/crl")
    ca_dir.mkdir(exist_ok=True)
    (ca_dir / "index.txt").touch()
    if not (ca_dir / "crlnumber").exists():
        (ca_dir / "crlnumber").write_text("01\n")
    config = ca_dir / "openssl.cnf"
    config.write_text(
        f"[ ca ]\ndefault_ca = root\n[ root ]\ndatabase = {ca_dir}/index.txt\n"
        f"certificate = {OFFLINE}/certs/root_ca.crt\n"
        f"private_key = {OFFLINE}/secrets/root_ca_key\n"
        f"crlnumber = {ca_dir}/crlnumber\ndefault_md = sha256\n"
    )
    return run("openssl", "ca", "-gencrl", "-config", config,
               "-crlsec", seconds, "-passin", f"file:{password_file}")


def verify_crl(data, issuer):
    result = subprocess.run(
        ["openssl", "crl", "-noout", "-verify", "-CAfile", str(issuer)],
        input=data, capture_output=True, timeout=5, check=False,
    )
    if result.returncode or b"verify OK" not in result.stdout + result.stderr:
        raise RuntimeError("CRL signature check failed")
    stamp = run("openssl", "crl", "-noout", "-nextupdate", data=data).decode().strip()
    deadline = datetime.strptime(stamp.split("=", 1)[1], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
    if deadline <= datetime.now(UTC):
        raise RuntimeError("CRL has expired")
    return deadline.timestamp()


def publish_trust(role_dir, root_list, leaf_list):
    root_deadline = verify_crl(root_list, role_dir / "root.crt")
    leaf_deadline = verify_crl(leaf_list, role_dir / "intermediate.crt")
    atomic(role_dir / "crls.pem", leaf_list.rstrip() + b"\n" + root_list.rstrip() + b"\n")
    return {"root_next_update": root_deadline, "leaf_next_update": leaf_deadline}


def refresh_crl(role_dir):
    with urlopen(CRL_URL, timeout=4) as response:
        # step-ca serves the signed list as DER; Envoy expects PEM.
        leaf = run("openssl", "crl", "-inform", "DER", "-outform", "PEM", data=response.read())
    result = publish_trust(role_dir, (role_dir / "root.crl").read_bytes(), leaf)
    atomic(role_dir / "leaf.crl", leaf)
    return result


def bootstrap():
    if (Path("/ca/config") / "ca.json").exists():
        raise RuntimeError("Use a fresh Compose project for the acceptance run")
    os.umask(0o077)
    PASSWORD.write_text(secrets.token_urlsafe(32) + "\n")
    run("step", "ca", "init", "--deployment-type", "standalone", "--name", "Ceilings test CA",
        "--dns", "ca.ceilings.test", "--address", ":9000", "--provisioner", "lab-operator",
        "--password-file", PASSWORD, "--provisioner-password-file", PASSWORD)
    config = json.loads((OFFLINE / "config/ca.json").read_text().replace(str(OFFLINE), "/ca"))
    config["insecureAddress"] = ":9001"
    config["crl"] = {
        "enabled": True, "generateOnRevoke": True, "cacheDuration": "150s", "renewPeriod": "40s",
        "idpURL": CRL_URL,
    }
    config["authority"].setdefault("claims", {}).update(
        minTLSCertDuration="5s", defaultTLSCertDuration="30m",
        maxTLSCertDuration="30m", disableRenewal=False, allowRenewalAfterExpiry=False,
    )
    provisioner = config["authority"]["provisioners"][0]
    provisioner["options"] = {"x509": {"templateFile": "/ca/config/leaf.tpl"}}
    for folder in ("config", "certs", "secrets"):
        Path("/ca", folder).mkdir(exist_ok=True)
    for filename in ("certs/root_ca.crt", "certs/intermediate_ca.crt", "secrets/intermediate_ca_key"):
        shutil.copyfile(OFFLINE / filename, Path("/ca") / filename)
    shutil.copyfile(PASSWORD, "/ca/secrets/password")
    Path("/ca/config/leaf.tpl").write_text(
        '{"subject": {{ toJson .Subject }}, "sans": {{ toJson .SANs }},'
        ' "keyUsage": ["digitalSignature"], "extKeyUsage": '
        '{{ if eq .Subject.CommonName "web.ceilings.test" }}["clientAuth"]'
        '{{ else }}["serverAuth", "clientAuth"]{{ end }},'
        f' "crlDistributionPoints": ["{CRL_URL}"]' + '}'
    )
    Path("/ca/config/ca.json").write_text(json.dumps(config))
    os.umask(0o022)
    os.chown("/web-socket", 101, 101)
    signed_root = root_crl(1800)
    for role in ("web", "order"):
        folder = ROLES / role
        (folder / "versions").mkdir()
        for local, remote in (("root.crt", "root_ca.crt"), ("intermediate.crt", "intermediate_ca.crt")):
            atomic(folder / local, (OFFLINE / "certs" / remote).read_bytes())
        atomic(folder / "root.crl", signed_root)
        atomic(folder / "envoy.json", json.dumps(envoy_config(role)))
        atomic(folder / "trust-sds.yaml", json.dumps({"resources": [{
            "@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret",
            "name": "trust",
            "validation_context": {
                "trusted_ca": {"filename": "/run/pki/root.crt"},
                "crl": {"filename": "/run/pki/crls.pem"},
                "match_typed_subject_alt_names": [{
                    "san_type": "DNS",
                    "matcher": {"exact": f"{'order' if role == 'web' else 'web'}.ceilings.test"},
                }],
            },
        }]}))


def issue(role, version, name):
    role_dir = ROLES / role
    cert, key = identity(role_dir, version)
    cert.parent.mkdir()
    with tempfile.TemporaryDirectory() as temporary:
        csr = Path(temporary) / "request.csr"
        run("step", "certificate", "create", name, csr, key, "--csr", "--san", name,
            "--no-password", "--insecure")
        seal_key(key)
        token = provisioner_token(name, csr, role_dir / "root.crt")
        run("step", "ca", "sign", csr, cert, "--ca-url", CA_URL,
            "--root", role_dir / "root.crt", "--token", token, "--not-after", "30m")
    cert.chmod(0o644)
    return cert_facts(cert.read_bytes())


def rekey(role_dir, version, interrupted):
    old_cert, old_key = identity(role_dir, active_version(role_dir))
    cert, key = identity(role_dir, version)
    cert.parent.mkdir()
    # Stage results privately; neither output is referenced by SDS at this point.
    with tempfile.TemporaryDirectory(dir=cert.parent) as temporary:
        new_cert = Path(temporary) / "cert.pem"
        new_key = Path(temporary) / "key.pem"
        run("step", "ca", "rekey", old_cert, old_key, "--out-cert", new_cert,
            "--out-key", new_key, "--ca-url", CA_URL, "--root", role_dir / "root.crt", "--force")
        shutil.move(new_cert, cert)
        cert.chmod(0o644)
        if interrupted:
            print("stopped before publishing tls-sds.yaml", flush=True)
            os._exit(77)  # Simulate termination and leave the partial staged version on disk.
        shutil.move(new_key, key)
        seal_key(key)
        return publish(role_dir, version)


def unix_http(path, timeout):
    conn = http.client.HTTPConnection("order", timeout=timeout)
    conn.sock = socket.socket(socket.AF_UNIX)
    conn.sock.settimeout(timeout)
    conn.sock.connect(path)
    return conn


def observe_web(hold=False):
    with closing(unix_http("/web-socket/web.sock", 30 if hold else 5)) as conn:
        conn.request("GET", "/hold" if hold else "/")
        response = conn.getresponse()
        if hold:
            if response.status != 200 or response.read(len(b"order ok\n")) != b"order ok\n":
                raise RuntimeError("Could not establish the held HTTP response")
            print("READY", flush=True)
            try:
                if response.read(1):
                    raise RuntimeError("Held request finished instead of being terminated")
            except (ConnectionResetError, http.client.IncompleteRead):
                pass
            return {"closed": True}
        header = response.getheader("x-lab-web-cert")
        return {"status": response.status, "body": response.read().decode(),
                "web": cert_facts(unquote(header).encode()) if header else None}


def probe_order(version=None, hostname="order.ceilings.test"):
    """A fresh diagnostic connection to the same listener used by Envoy Web."""
    context = ssl.create_default_context(cafile=str(ROLES / "web/root.crt"))
    if version:
        cert, key = identity(ROLES / "web", version)
        context.load_cert_chain(cert, key)
    with socket.create_connection(("order.ceilings.test", 8443), timeout=4) as sock:
        try:
            with context.wrap_socket(sock, server_hostname=hostname) as client:
                peer = ssl.DER_cert_to_PEM_cert(client.getpeercert(binary_form=True))
                client.sendall(b"GET / HTTP/1.1\r\nHost: order.ceilings.test\r\nConnection: close\r\n\r\n")
                result = http.client.HTTPResponse(client)
                result.begin()
                return {"accepted": result.status == 200, "order": cert_facts(peer.encode())}
        except (ssl.SSLError, http.client.RemoteDisconnected, ConnectionResetError, BrokenPipeError) as exc:
            return {"accepted": False, "reason": str(exc)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=(
        "bootstrap", "health", "issue", "publish", "active", "rekey", "crl", "root-crl",
        "web", "hold", "probe-order", "revoke", "facts", "version",
    ))
    parser.add_argument("args", nargs="*")
    options = parser.parse_args()
    args = options.args
    folder = Path("/run/pki")
    action = options.action
    result = None
    if action == "bootstrap":
        bootstrap()
    elif action == "version":
        print(run("step", "version").decode().strip())
        return
    elif action == "health":
        result = run("step", "ca", "health", "--ca-url", CA_URL,
                     "--root", ROLES / "web/root.crt").decode().strip()
    elif action == "issue":
        result = issue(*args)
    elif action == "publish":
        role, version = args
        result = publish(ROLES / role, version)
    elif action == "active":
        result = active_version(folder)
    elif action == "rekey":
        result = rekey(folder, args[0], len(args) == 2 and args[1] == "interrupt")
    elif action == "crl":
        result = refresh_crl(folder)
    elif action == "root-crl":
        signed = root_crl(int(args[0]))
        for role in ("web", "order"):
            role_dir = ROLES / role
            result = publish_trust(role_dir, signed, (role_dir / "leaf.crl").read_bytes())
            atomic(role_dir / "root.crl", signed)
    elif action in ("web", "hold"):
        result = observe_web(hold=action == "hold")
    elif action == "probe-order":
        result = probe_order(*args)
    elif action in ("revoke", "facts"):
        cert, _ = identity(ROLES / args[0], args[1])
        result = cert_facts(cert.read_bytes())
        result["unexpired"] = subprocess.run(
            ["openssl", "x509", "-checkend", "0", "-noout", "-in", str(cert)],
            capture_output=True,
        ).returncode == 0
        if action == "revoke":
            serial = str(int(result["serial"], 16))
            root = ROLES / "web/root.crt"
            token = run(
                "step", "ca", "token", "--revoke=true", f"--ca-url={CA_URL}", f"--root={root}",
                "--provisioner=lab-operator", f"--provisioner-password-file={PASSWORD}", serial,
            ).decode().strip()
            run("step", "ca", "revoke", f"--token={token}", "--reason=lab test",
                "--reasonCode=1", f"--ca-url={CA_URL}", f"--root={root}", serial)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
