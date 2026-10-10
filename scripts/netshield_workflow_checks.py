"""Conservative workflow checks: missing evidence is not a proven failure."""
import re

import yaml


def git_push_auth_warnings(content):
    """Report explicitly disabled checkout credentials without visible alternatives.

    This is advisory: secrets and runner-side credentials cannot be validated
    by reading a workflow. Examine jobs separately, not unrelated checkouts.
    """
    try:
        config = yaml.safe_load(content)
    except yaml.YAMLError:
        return []  # The syntax check reports invalid YAML separately.
    if not isinstance(config, dict):
        return []
    warnings = []
    for name, job in (config.get("jobs") or {}).items():
        if not isinstance(job, dict):
            continue
        steps = [s for s in job.get("steps", []) if isinstance(s, dict)]
        checkouts = [s for s in steps
                     if str(s.get("uses", "")).startswith("actions/checkout@")]
        # Omitted persist-credentials defaults to true. Expressions are unknown.
        if not checkouts or not all(
                (s.get("with") or {}).get("persist-credentials", True)
                in (False, "false") for s in checkouts):
            continue
        shell = "\n".join(str(s.get("run", "")) for s in steps)
        shell = "\n".join(line for line in shell.splitlines()
                          if not line.lstrip().startswith("#"))
        if not re.search(r"\bgit\s+push\b", shell):
            continue
        explicit_auth = (
            re.search(r"https?://[^\s\"'<>]+@[^\s\"'<>]+", shell)
            or re.search(r"\bgh\s+auth\s+setup-git\b", shell)
            or re.search(r"\bgit\s+config\b[^\n]*(?:extraheader|credential\.)",
                         shell, re.I)
            or "GIT_SSH_COMMAND" in shell
            or any("ssh-agent" in str(s.get("uses", "")) for s in steps)
        )
        if not explicit_auth:
            warnings.append(
                f"Job {name}: checkout speichert keine Zugangsdaten und keine "
                "alternative Git-Anmeldung erkannt; Push-Anmeldung pruefen.")
    return warnings
