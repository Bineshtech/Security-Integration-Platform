"""Run trusted local commands with timeout, minimal environment and no shell."""
import os, subprocess

def run_restricted(argv: list[str], *, timeout: int = 30, cwd: str | None = None, env_allowlist: tuple[str, ...] = ("PATH", "SYSTEMROOT", "WINDIR")) -> subprocess.CompletedProcess:
    if not isinstance(argv, list) or not argv or not all(isinstance(x, str) for x in argv): raise ValueError("argv must be a non-empty list of strings.")
    if timeout < 1 or timeout > 300: raise ValueError("timeout must be between 1 and 300 seconds.")
    env = {k: os.environ[k] for k in env_allowlist if k in os.environ}
    return subprocess.run(argv, shell=False, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout, check=False)
