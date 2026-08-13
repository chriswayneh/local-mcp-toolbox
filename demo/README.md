# Safe demo fixtures

Everything in this directory is synthetic and local-only.  It exists to
exercise read-only diagnostics; it is not an application template.

- `compose.yaml` starts one healthy and one intentionally unhealthy BusyBox
  service.  Neither service mounts the host, exposes a port, uses a secret, or
  receives a Docker socket.
- `logs/api.log` contains fabricated incident evidence, including strings that
  should be redacted by log tools.
- `project/` contains harmless top-level markers for infrastructure detection.
- `insecure-fixtures/` contains intentionally risky snippets for *inventory*
  demonstrations only.  Do not build, deploy, copy, or merge them.

Run the lifecycle only from this directory:

```powershell
docker compose up -d
docker compose ps
docker compose logs --tail 20
docker compose down --volumes --remove-orphans
```

The final command removes only the named demo resources created by this Compose
project.  See [the walkthrough](../docs/demo-walkthrough.md) for the complete,
least-privilege inspection sequence.
