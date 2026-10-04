"""Local Ollama judge (native /api/chat with format=json). No auth by default.

``local_weights`` defaults to True only when ``base_url`` is a loopback or
private-range address (two_key.netloc). An Ollama cloud model on ollama.com
or any other remote host defaults to False. Declaring ``local_weights: true``
on a remote host does not make the judge local: ``is_local()`` also requires
the host to be loopback or private, and ``is_cloud()`` ignores the flag. The
flag is a declaration, not an attestation, and ``weights_sha256`` is
recorded, not verified. See DESIGN_OPTIONS.md section 7 in
Insomniac-VibeLabs/two-key, not in this repository.

``keep_alive`` asks Ollama not to unload the weights between ballots. It does
not change the ballot.
"""

from __future__ import annotations

from ..netloc import host_is_local, url_host
from .llm import LLMJudge


class OllamaJudge(LLMJudge):
    default_auth_header = "none"

    def __init__(self, *a, **kw):
        kw.setdefault("base_url", "http://localhost:11434")
        if kw.get("local_weights") is None:
            kw["local_weights"] = host_is_local(url_host(kw["base_url"]))
        super().__init__(*a, **kw)

    def _request(self, system: str, user: str):
        body = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "stream": False,
            "format": "json",
            "keep_alive": "10m",
            "options": {"temperature": 0},
        }
        return f"{self.base_url}/api/chat", body

    def _extract_text(self, resp: dict) -> str:
        return resp["message"]["content"]
