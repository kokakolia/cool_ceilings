"""Issue and maintain certificates for local Compose."""

import argparse
import json
import os
import shutil
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from envoy_config import HOSTS, config_for
from pki_primitives import (
    CA_URL, CRL_URL, OFFLINE, ROLES, active_version, atomic, cert_facts,
    identity, public_key, publish, refresh_crl, rekey, root_crl, run, seal_key, verify_crl,
)


PROVISIONER = "ceilings-operator"
NATIVE = {role: f"{role}.ceilings.test" for role in ("pg-auth", "pg-order", "pg-noti", "rabbitmq")}
TRUST = Path("/trust")
CONF = Path("/ca/config/ca.json")
OFFLINE_CONFIG = OFFLINE / "config/ca.json"
CA_PASSWORD = Path("/run/secrets/ca_password")
OPERATOR_PASSWORD = Path("/run/secrets/operator_password")
ROLE_VOLUME = Path("/run/pki")
CA_ASSETS = ("certs/root_ca.crt", "certs/intermediate_ca.crt", "secrets/intermediate_ca_key")
ROOT_CRL_SECONDS = 365 * 24 * 60 * 60


def initialize():
    os.umask(0o077)
    ca_password, operator_password = (path.read_text().strip() for path in (CA_PASSWORD, OPERATOR_PASSWORD))
    if not ca_password or not operator_password or ca_password == operator_password:
        raise RuntimeError("Set distinct non-empty passwords for the CA and operator")
    if not OFFLINE_CONFIG.is_file():
        run("step", "ca", "init", "--deployment-type", "standalone", "--name", "Ceilings local CA",
            "--dns", "ca.ceilings.test", "--address", ":9000", "--provisioner", PROVISIONER,
            "--password-file", CA_PASSWORD, "--provisioner-password-file", OPERATOR_PASSWORD)

    root = (OFFLINE / CA_ASSETS[0]).read_bytes()
    intermediate = (OFFLINE / CA_ASSETS[1]).read_bytes()
    os.umask(0o022)
    atomic(TRUST / "root.crt", root)
    if not CONF.exists():
        configure_ca()
    separate_legacy_operator_key()
    Path("/offline/operator-password").unlink(missing_ok=True)

    root_list = TRUST / "root.crl"
    if not root_list.exists():
        atomic(root_list, sign_root_crl())
    for role in HOSTS:
        folder = ROLES / role
        (folder / "versions").mkdir(exist_ok=True)
        atomic(folder / "envoy.json", json.dumps(config_for(role)))
        atomic(folder / "root.crt", root)
        atomic(folder / "intermediate.crt", intermediate)
        if not (folder / "root.crl").exists():
            atomic(folder / "root.crl", root_list.read_bytes())
        atomic(folder / "trust-sds.yaml", json.dumps({"resources": [{
            "@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret",
            "name": "trust",
            "validation_context": {
                "trusted_ca": {"filename": "/run/pki/root.crt"},
                "crl": {"filename": "/run/pki/crls.pem"},
            },
        }]}))
        sockets = Path("/socket-volumes") / role
        os.chown(sockets, 101, 101)
        sockets.chmod(0o770)


def configure_ca():
    config = json.loads(OFFLINE_CONFIG.read_text().replace(str(OFFLINE), "/ca"))
    config["insecureAddress"] = ":9001"
    config["crl"] = {
        "enabled": True, "generateOnRevoke": True, "cacheDuration": "24h", "renewPeriod": "8h", "idpURL": CRL_URL,
    }
    config["authority"].setdefault("claims", {}).update(
        minTLSCertDuration="5m", defaultTLSCertDuration="24h", maxTLSCertDuration="24h",
        disableRenewal=False, allowRenewalAfterExpiry=False,
    )
    provisioner = config["authority"]["provisioners"][0]
    provisioner["options"] = {"x509": {"templateFile": "/ca/config/leaf.tpl"}}
    for folder in ("config", "certs", "secrets"):
        (Path("/ca") / folder).mkdir(exist_ok=True)
    for filename in CA_ASSETS:
        shutil.copyfile(OFFLINE / filename, Path("/ca") / filename)
    Path("/ca/secrets/intermediate_ca_key").chmod(0o600)
    Path("/ca/config/leaf.tpl").write_text(
        '{"subject": {{ toJson .Subject }}, "sans": {{ toJson .SANs }},'
        ' "keyUsage": ["digitalSignature"], "extKeyUsage": '
        '{{ if eq .Subject.CommonName "web.ceilings.test" }}["clientAuth"]'
        '{{ else if or (eq .Subject.CommonName "order.ceilings.test") (eq .Subject.CommonName "auth.ceilings.test") }}'
        '["serverAuth", "clientAuth"]{{ else }}["serverAuth"]{{ end }},'
        f' "crlDistributionPoints": ["{CRL_URL}"]' + '}'
    )
    atomic(CONF, json.dumps(config))


def operator_provisioner(config):
    return next(provisioner for provisioner in config["authority"]["provisioners"]
                if provisioner["name"] == PROVISIONER and provisioner["type"] == "JWK")


def separate_legacy_operator_key():
    active_config = json.loads(CONF.read_text())
    provisioner = operator_provisioner(active_config)
    encrypted_key = provisioner["encryptedKey"].encode()
    try:
        run("step", "crypto", "jwe", "decrypt", "--password-file", OPERATOR_PASSWORD, data=encrypted_key)
        return
    except RuntimeError:
        # Rotate only a legacy key that used the CA password. Preserve a config
        # with an unknown password so an incorrect file cannot replace the key.
        try:
            run("step", "crypto", "jwe", "decrypt", "--password-file", CA_PASSWORD, data=encrypted_key)
        except RuntimeError:
            raise RuntimeError("The operator password does not match the configured provisioner") from None

    with tempfile.TemporaryDirectory() as temporary:
        public = Path(temporary) / "public.jwk"
        private = Path(temporary) / "private.jwe"
        run("step", "crypto", "jwk", "create", "--use", "sig", "--password-file", OPERATOR_PASSWORD, public, private)
        jwe = json.loads(private.read_text())
        compact = ".".join(jwe[field] for field in ("protected", "encrypted_key", "iv", "ciphertext", "tag"))
        material = {"key": json.loads(public.read_text()), "encryptedKey": compact}

    offline_config = json.loads(OFFLINE_CONFIG.read_text())
    operator_provisioner(offline_config).update(material)
    atomic(OFFLINE_CONFIG, json.dumps(offline_config))
    provisioner.update(material)
    atomic(CONF, json.dumps(active_config))
    print("Replaced the provisioner key that used the CA password")


def sign_root_crl():
    with tempfile.TemporaryDirectory() as temporary:
        # OpenSSL treats CRLF differently from step. Always use a local LF copy.
        password_file = Path(temporary) / "password"
        password_file.write_text(CA_PASSWORD.read_text().strip() + "\n")
        password_file.chmod(0o600)
        return root_crl(ROOT_CRL_SECONDS, password_file)


def issue(role):
    name = HOSTS.get(role) or NATIVE[role]
    folder = ROLES / role if role in HOSTS else Path("/native") / role
    version = uuid4().hex
    cert, key = identity(folder, version)
    cert.parent.mkdir(parents=True)
    with tempfile.TemporaryDirectory() as temporary:
        csr = Path(temporary) / "request.csr"
        run("step", "certificate", "create", name, csr, key, "--csr", "--san", name,
            "--no-password", "--insecure")
        token = run("step", "ca", "token", name, "--san", name, "--cnf-file", csr,
                    "--ca-url", CA_URL, "--root", TRUST / "root.crt", "--provisioner", PROVISIONER,
                    "--provisioner-password-file", OPERATOR_PASSWORD).decode().strip()
        run("step", "ca", "sign", csr, cert, "--ca-url", CA_URL, "--root", TRUST / "root.crt",
            "--token", token, "--not-after", "24h")
    cert.chmod(0o644)
    if role in HOSTS:
        seal_key(key)
        return publish(folder, version)

    if public_key(cert.read_bytes()) != run("openssl", "pkey", "-in", key, "-pubout"):
        raise RuntimeError("Certificate and key do not match")
    run("openssl", "verify", "-verify_hostname", name, "-purpose", "sslserver", "-CAfile", TRUST / "root.crt",
        "-untrusted", OFFLINE / CA_ASSETS[1], cert)
    key.chmod(0o600)
    pending = folder / f"next-{version}"
    pending.symlink_to(Path("versions") / version, target_is_directory=True)
    os.replace(pending, folder / "active")
    return cert_facts(cert.read_bytes())


def wait_for_ca():
    for _ in range(20):
        try:
            run("step", "ca", "health", "--ca-url", CA_URL, "--root", TRUST / "root.crt")
            return
        except RuntimeError:
            time.sleep(1)
    raise RuntimeError("step-ca did not become ready")


def certificate_expired(cert):
    stamp = run("openssl", "x509", "-noout", "-enddate", "-in", cert).decode().strip().split("=", 1)[1]
    expiry = datetime.strptime(stamp, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
    return expiry <= datetime.now(UTC)


def ensure_certificate(role, cert, recover_expired):
    if cert.exists():
        if not certificate_expired(cert):
            return
        if not recover_expired:
            raise RuntimeError(f"{role}: certificate expired. Run scripts/local.py recover.")
    print(role, issue(role))


def issue_missing(recover_expired=False):
    wait_for_ca()
    for role in HOSTS:
        folder = ROLES / role
        marker = folder / "tls-sds.yaml"
        if marker.exists():
            ensure_certificate(role, identity(folder, active_version(folder))[0], recover_expired)
        else:
            print(role, issue(role))
        refresh_crl(folder)
    for role in NATIVE:
        cert = Path("/native") / role / "active/cert.pem"
        ensure_certificate(role, cert, recover_expired)


def publish_root_crl():
    signed = sign_root_crl()
    atomic(TRUST / "root.crl", signed)
    for role in HOSTS:
        folder = ROLES / role
        verify_crl(signed, folder / "root.crt")
        atomic(folder / "root.crl", signed)
        print(role, refresh_crl(folder))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("init", "issue-missing", "recover-expired", "rekey", "crl", "root-crl", "status"):
        commands.add_parser(name)
    commands.add_parser("issue").add_argument("role", choices=(*HOSTS, *NATIVE))
    args = parser.parse_args()
    if args.command == "init":
        initialize()
    elif args.command in ("issue-missing", "recover-expired"):
        issue_missing(recover_expired=args.command == "recover-expired")
    elif args.command == "issue":
        print(issue(args.role))
    elif args.command == "rekey":
        print(rekey(ROLE_VOLUME, uuid4().hex, False))
    elif args.command == "crl":
        print(refresh_crl(ROLE_VOLUME))
    elif args.command == "root-crl":
        publish_root_crl()
    else:
        version = active_version(ROLE_VOLUME)
        print(cert_facts(identity(ROLE_VOLUME, version)[0].read_bytes()))


if __name__ == "__main__":
    main()
