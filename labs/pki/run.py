"""Run the four acceptance checks in a disposable Compose project."""

import argparse
import json
import os
import queue
import shutil
import subprocess
import sys
import threading
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

LAB = Path(__file__).resolve().parent
ORDER_OK = "order ok\n"
OUTSIDER = """
import socket
from pathlib import Path

# A control connection proves the outsider is really on the Envoy network.
with socket.create_connection(('order.ceilings.test', 8443), 3):
    pass
for host, port in (('envoy-web', 8080), ('envoy-web', 8443),
                   ('envoy-order', 8000), ('order', 8000)):
    try:
        with socket.create_connection((host, port), 2):
            raise RuntimeError(f'Unexpected network access to {host}:{port}')
    except OSError:
        pass
for path in ('/sockets/web.sock', '/sockets/order.sock'):
    if Path(path).exists():
        raise RuntimeError(f'Unexpected mount with {path}')
print('Outsider reaches the Order mTLS listener only; direct routes unavailable')
"""


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def execute(argv, timeout=60):
    return subprocess.run(argv, cwd=LAB, capture_output=True, text=True, timeout=timeout,
                          encoding="utf-8", errors="replace", check=False)


def until(label, check, timeout=25):
    deadline = time.monotonic() + timeout
    detail = "condition not reached"
    while time.monotonic() < deadline:
        try:
            result = check()
            if result:
                return result
        except RuntimeError as exc:
            detail = str(exc)
        time.sleep(0.5)
    raise RuntimeError(f"{label}: {detail}")


class Experiment:
    def __init__(self, docker, project):
        self.docker = docker
        self.project = project
        self.compose = [docker, "compose", "-f", "compose.yaml", "-p", project]

    def command(self, *args, timeout=60, expected=0):
        result = execute([*self.compose, *args], timeout)
        if result.returncode != expected:
            detail = (result.stderr or result.stdout).strip()
            raise RuntimeError(f"Compose {args[0]} exited {result.returncode}: {detail[-2400:]}")
        return result.stdout.strip()

    def tool(self, container, *args):
        return json.loads(self.command("run", "--rm", "--no-deps", "-T", container, *args))

    def op(self, *args):
        return self.tool("operator", *args)

    def refresh(self):
        limits = [self.tool(f"{role}-updater", "crl") for role in ("web", "order")]
        return {field: min(entry[field] for entry in limits) for field in limits[0]}

    def boot(self):
        daemon = execute([self.docker, "info", "--format", "{{.OSType}}"], 20)
        require(daemon.returncode == 0 and daemon.stdout.strip() == "linux",
                f"Linux Docker daemon unavailable: {daemon.stderr.strip() or daemon.stdout.strip()}")
        self.command("config", "-q")
        self.command("build", "operator", timeout=360)
        self.op("bootstrap")
        self.command("up", "-d", "ca", "order", timeout=180)
        until("CA health", lambda: self.op("health") == "ok", 45)
        for role in ("web", "order"):
            self.op("issue", role, "initial", f"{role}.ceilings.test")
            self.op("publish", role, "initial")
            until(f"initial {role} CRL", lambda: self.tool(f"{role}-updater", "crl"))
        self.command("up", "-d", "envoy-web", "envoy-order", timeout=180)
        self.expect_web(200)
        step = self.command("run", "--rm", "--no-deps", "-T", "operator", "version")
        ca = self.command("exec", "-T", "ca", "step-ca", "version")
        envoy = self.command("exec", "-T", "envoy-web", "envoy", "--version")
        return {"step": step, "step-ca": ca, "envoy": envoy}

    def expect_web(self, status, cert=None):
        def probe():
            result = self.op("web")
            require(result["status"] == status,
                    f"wanted HTTP {status}, received {result['status']}: {result['body'][:240]}")
            if status == 200:
                require(result["body"] == ORDER_OK and result["web"], "missing Order answer or Web peer certificate")
                if cert:
                    require(result["web"] == cert, "Envoy still presents the previous Web certificate")
            return result

        return until(f"Web → Order HTTP {status}", probe)

    def inspect_order(self, web_version, hostname="order.ceilings.test"):
        result = self.op("probe-order", web_version, hostname)
        require(result["accepted"], f"direct TLS control rejected: {result}")
        return result["order"]

    def starts(self):
        ids = self.command("ps", "-q", "envoy-web", "envoy-order").splitlines()
        require(len(ids) == 2, f"expected two running Envoy containers, got {len(ids)}")
        result = execute([self.docker, "inspect", "--format", "{{.Id}} {{.State.StartedAt}}", *ids])
        require(result.returncode == 0, result.stderr)
        return sorted(result.stdout.splitlines())

    def identities(self):
        good = self.expect_web(200)
        missing = self.op("probe-order")
        require(not missing["accepted"], "Order accepted a request without a client certificate")

        wrong_name = "other.ceilings.test"
        wrong_web = self.op("issue", "web", "wrong-web", wrong_name)
        require(wrong_web["serial"] != good["web"]["serial"], "wrong Web identity was not independently issued")
        self.op("publish", "web", "wrong-web")
        self.expect_web(503)
        wrong_web_result = self.op("probe-order", "wrong-web")
        require(not wrong_web_result["accepted"], "Order accepted a client SAN different from Web")
        self.op("publish", "web", "initial")
        self.expect_web(200, good["web"])

        wrong_order = self.op("issue", "order", "wrong-order", wrong_name)
        self.op("publish", "order", "wrong-order")
        until("trusted server under its actual wrong name", lambda:
              self.inspect_order("initial", wrong_name) == wrong_order)
        self.expect_web(503)
        self.op("publish", "order", "initial")
        self.expect_web(200, good["web"])

        outsider = self.command("run", "--rm", "--no-deps", "-T", "outsider", "python", "-c", OUTSIDER)
        return {"good_web_serial": good["web"]["serial"], "without_client": missing,
                "wrong_client_san": wrong_web_result, "wrong_server_san": "valid at its own name; Web returned 503",
                "outsider": outsider}

    def rotate(self):
        starts = self.starts()
        old_web = self.expect_web(200)["web"]
        old_order = self.inspect_order("initial")
        interruption = self.command("run", "--rm", "--no-deps", "-T", "web-updater", "rekey",
                                    "interrupted", "interrupt", expected=77)
        require("stopped before publishing" in interruption, "expected fault injection did not run")
        self.expect_web(200, old_web)

        new_web = self.tool("web-updater", "rekey", "rotated")
        new_order = self.tool("order-updater", "rekey", "rotated")
        self.expect_web(200, new_web)
        until("new Order server certificate", lambda: self.inspect_order("rotated") == new_order)
        for old, new in ((old_web, new_web), (old_order, new_order)):
            require(old["serial"] != new["serial"], "serial did not change")
            require(old["spki_sha256"] != new["spki_sha256"], "public key did not change")
        require(self.starts() == starts, "an Envoy restarted during rekey")
        return {"interrupted": interruption, "web": [old_web, new_web], "order": [old_order, new_order]}

    def stop_with_open_connection(self, verifier):
        argv = [*self.compose, "run", "--rm", "--no-deps", "-T", "operator", "hold"]
        with subprocess.Popen(argv, cwd=LAB, text=True, encoding="utf-8", errors="replace",
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as probe:
            output = queue.Queue()

            def read():
                for line in probe.stdout:
                    output.put(line.strip())
                output.put(None)

            reader = threading.Thread(target=read, daemon=True)
            reader.start()
            try:
                while True:
                    line = output.get(timeout=20)
                    require(line is not None, "long request exited before READY")
                    if line == "READY":
                        break
                self.command("stop", "-t", "1", verifier)
                require(probe.wait(timeout=25) == 0, "open-connection probe failed")
                reader.join(timeout=5)
                lines = list(output.queue)
                require('{"closed": true}' in lines, f"no proof that the established connection closed: {lines}")
            finally:
                if probe.poll() is None:
                    probe.kill()

    def revoke(self):
        results = {}
        for role, verifier in (("web", "envoy-order"), ("order", "envoy-web")):
            self.expect_web(200)
            self.stop_with_open_connection(verifier)
            revoked = self.op("revoke", role, "rotated")
            require(revoked["unexpired"], f"{role}: expired before revocation")
            self.refresh()
            replacement = self.op("issue", role, "reissued", f"{role}.ceilings.test")
            self.op("publish", role, "reissued")
            self.command("start", verifier)
            self.expect_web(200)
            current_web = "reissued"
            if role == "web":
                self.expect_web(200, replacement)
                reason = self.op("probe-order", "rotated")
                require(not reason["accepted"], "Order accepted the revoked Web certificate")
            else:
                until("replacement Order server certificate", lambda:
                      self.inspect_order(current_web) == replacement)
                # Present the original, still-valid certificate on the very same listener.
                self.op("publish", "order", "rotated")
                until("old Order certificate present", lambda:
                      self.inspect_order(current_web)["serial"] == revoked["serial"])
                rejected = self.expect_web(503)
                reason = {"accepted": False, "web_http_status": rejected["status"],
                          "web_error": rejected["body"], "old_certificate_observed": True}
                self.op("publish", "order", "reissued")
                self.expect_web(200)
            require(self.op("facts", role, "rotated")["unexpired"],
                    f"{role}: old certificate expired before proof of rejection")
            results[role] = {"old_serial": revoked["serial"], "new_serial": replacement["serial"],
                             "old_still_unexpired": True, "established_connection_closed": True,
                             "revoked_result": reason}
        return results

    def expiration(self):
        result = {}
        for kind in ("service", "root"):
            # Make the list under test definitely expire before the other one.
            limits = until("fresh service CRL", lambda: (
                value if (value := self.refresh())["leaf_next_update"] > time.time() + 75 else None
            ), 55)
            if kind == "root":
                deadline = self.op("root-crl", "30")["root_next_update"]
                other_deadline = limits["leaf_next_update"]
                require(other_deadline > deadline + 30, "service CRL would expire too early for the root test")
            else:
                deadline = limits["leaf_next_update"]
                other_deadline = limits["root_next_update"]
            self.command("stop", "ca")
            self.expect_web(200)
            delay = max(0, deadline - time.time()) + 1
            require(delay <= 155, "unexpected CRL expiry outside the lab window")
            print(f"  waiting for {kind} CRL nextUpdate ({delay:.0f}s)", flush=True)
            time.sleep(delay)
            rejected = self.expect_web(503)
            require(time.time() < other_deadline, f"{kind}: both CRLs expired before proof of rejection")
            require(all(self.op("facts", role, "reissued")["unexpired"] for role in ("web", "order")),
                    f"{kind}: leaf certificate expired before the CRL observation")
            self.command("start", "ca")
            until("CA health after expiry", lambda: self.op("health") == "ok")
            if kind == "root":
                self.op("root-crl", "1800")
            until("fresh local CRLs", self.refresh, 55)
            self.expect_web(200)
            result[kind] = {"status_while_ca_down_and_crl_valid": 200,
                            "status_after_next_update": rejected["status"], "error": rejected["body"],
                            "other_crl_unexpired": True, "leaf_certs_unexpired": True,
                            "status_after_refresh": 200}
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    default_docker = shutil.which("docker")
    if default_docker is None and sys.platform == "win32":
        local = Path(os.environ.get("LOCALAPPDATA", "")) / "Programs/DockerDesktop/resources/bin/docker.exe"
        if local.is_file():
            default_docker = str(local)
    parser.add_argument("--docker", default=os.environ.get("DOCKER", default_docker or "docker"))
    parser.add_argument("--report", type=Path, help="write measured outcomes as JSON")
    parser.add_argument("--keep", action="store_true", help="keep the isolated project for inspection")
    args = parser.parse_args()
    project = f"ceilings-pki-{uuid.uuid4().hex[:8]}"
    names = ("1. issuance and mTLS", "2. rekey and SDS", "3. emergency revocation", "4. CA outage and CRL expiry")
    evidence = {"project": project, "at": datetime.now(UTC).isoformat(),
                "checks": {name: {"status": "not run"} for name in names}}
    started = False
    active = None
    error = None
    lab = Experiment(args.docker, project)
    try:
        cli = shutil.which(args.docker)
        require(cli, f"Docker CLI not found: {args.docker}")
        # Desktop installs its credential helper beside docker.exe in per-user installations.
        os.environ["PATH"] = str(Path(cli).resolve().parent) + os.pathsep + os.environ.get("PATH", "")
        run_version = execute([args.docker, "compose", "version"], 20)
        require(run_version.returncode == 0, run_version.stderr.strip())
        print(f"{project} | {run_version.stdout.strip()}", flush=True)
        started = True
        evidence["versions"] = lab.boot()
        for name, check in zip(names, (lab.identities, lab.rotate, lab.revoke, lab.expiration)):
            active = name
            print(f"Running {name}", flush=True)
            evidence["checks"][name] = {"status": "passed", "evidence": check()}
            print(f"Passed {name}", flush=True)
    except (RuntimeError, OSError, ValueError, subprocess.TimeoutExpired, queue.Empty) as exc:
        error = f"{type(exc).__name__}: {exc}"
        if active:
            evidence["checks"][active] = {"status": "failed", "error": error}
        else:
            evidence["setup_error"] = error
        print(error, file=sys.stderr)
    finally:
        if started and not args.keep:
            try:
                lab.command("--profile", "tools", "down", "--volumes", "--remove-orphans")
            except (RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
                evidence["cleanup_error"] = str(exc)
                print(exc, file=sys.stderr)
        if args.keep and started:
            print(f"Cleanup: docker compose -p {project} --profile tools down --volumes --remove-orphans")
        if args.report:
            args.report.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    return 1 if error or "cleanup_error" in evidence else 0


if __name__ == "__main__":
    sys.exit(main())
