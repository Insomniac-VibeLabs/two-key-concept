"""
Two-Key: a Path B judge must not be the monitored agent
=======================================================
The rule (the owner's, revised 2026-10-03): at least one judge, and no judge
may be the *same agent* as the monitored agent. The same provider is allowed.
``TwoKey`` checks it when it starts and refuses with ``TwoKeyConfigError``.

The agent's identity comes only from operator configuration
(``TwoKey(monitored_agent=...)``, the ``monitored_agent:`` block of
judges.yaml, and any configured ``agents``), never from anything the agent
says about itself. The declaration names the model, the provider (recorded as
a label, never compared), the endpoint ``base_url``, the credential (the
name of the environment variable that holds the agent's key,
``credential_env``, or ``credential: none`` for a keyless loopback agent),
and optionally a ``tenant`` mapping (see below). If any required field is
missing or cannot be read, Two-Key refuses to start.

Each judge and agent is resolved to:

- ``model``: the model id, normalized (case, router prefixes such as
  ``openai/`` or Bedrock's ``anthropic.``, dated snapshot suffixes such as
  ``-2024-08-06`` or ``-20241022``, ``-latest``, Vertex ``@`` versions,
  Bedrock ``-v2:0``, Ollama ``:latest``, and a few known aliases). The id is
  NFKC-normalized first, Unicode dashes are folded to ``-``, and zero-width
  characters are removed, so ``gpt\u20104o`` and fullwidth ``gpt-4o`` equal
  ``gpt-4o``.
- ``endpoint``: the normalized ``host:port`` of ``base_url`` (lower case,
  default port filled in, every loopback name or address written
  ``localhost``).
- ``upstreams``: who really serves or made the model, as upstream hosts.
  A direct provider host is itself (``api.openai.com``). A recognized router
  (OpenRouter, Azure OpenAI and Azure AI, Bedrock, Vertex, Cloudflare AI
  Gateway, Portkey) or a ``provider/model`` id (LiteLLM style) resolves to the
  model maker's API host, or ``maker:<name>`` for a maker without one. A
  loopback or private host is itself. An unrecognized host or router that
  cannot be resolved from the model id stays **unresolved**. Upstreams are
  used only to detect an unresolved identity; a shared upstream is allowed.
- ``tenant``: account ids, each scoped by provider family, from what the
  base_url shows plus what the operator declares under ``tenant:``
  (keys ``organization``, ``project``, ``account``, ``deployment``):
  Azure resource (host) and deployment (``/openai/deployments/<name>``),
  Vertex project (``/projects/<id>/`` in the path, or declared ``project``),
  Bedrock ``account`` (declared) with the region from the host, OpenAI
  ``organization`` / ``project`` (declared). Elsewhere a declared id is scoped
  by the endpoint host.
- ``credential``: a fingerprint, HMAC-SHA256 of the key with leading and
  trailing whitespace stripped (``hmac-sha256:...``). The HMAC key is a
  random per-install secret in ``fingerprint.key`` (created once with O_EXCL,
  mode 0600; ``$TWO_KEY_FINGERPRINT_KEY`` names another path), so a ledger
  reader cannot test guessed keys against a fingerprint. Raw keys are never
  stored or logged. ``none`` means the endpoint takes no key; two keyless
  endpoints do not match on it.

Refusals, judge against agent (all hard, no opt-out), message prefix
``judge_matches_agent:``:

- same credential fingerprint
- either side unresolved (unknown identity fails closed)
- same normalized model on the same normalized endpoint ``host:port``
- a shared tenant id (same Azure resource or deployment, OpenAI organization
  or project, Bedrock account in the same region, Vertex project, or a
  declared id on the same host)

Allowed: the same provider or upstream with a different model, the same
endpoint with a different model, and the same model on a different endpoint
in a different (or undeclared) tenant with a different key.
``allow_same_provider_judge`` is a deprecated no-op.

The runtime check stays as a second layer: a judge whose credential equals
the frozen agent session abstains with ``cloud_judge_reused_agent_session``.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import stat
import re
import sys
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urlparse

from .netloc import host_is_local, host_is_loopback, model_is_cloud

FINGERPRINT_DOMAIN = b"two-key/credential-fingerprint/1\x00"
NO_CREDENTIAL = "none"
IN_PROCESS = "in-process"
_FOLD = dict.fromkeys(map(ord, "\u2010\u2011\u2012\u2013\u2014\u2015\u2212\u2043\ufe58\ufe63\uff0d"), "-")
_FOLD.update(dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff\u00ad"), None))


def fold_model_text(model: str | None) -> str:
    """NFKC, Unicode dashes to '-', zero-width characters removed, trimmed, lower case."""
    return unicodedata.normalize("NFKC", model or "").translate(_FOLD).strip().lower()


AGENT_KEYS = {"id", "model", "provider", "base_url", "credential_env", "credential", "tenant", "upstream"}
TENANT_KEYS = ("organization", "project", "account", "deployment")
SEPARATION_CHECKS = ("same_credential", "unresolved_identity", "same_model_same_endpoint", "same_tenant")


class IdentityError(ValueError):
    """The agent or a judge cannot be identified, or a judge could be the agent."""


FINGERPRINT_KEY_ENV = "TWO_KEY_FINGERPRINT_KEY"
FINGERPRINT_KEY_BYTES = 32
_FINGERPRINT_KEYS: dict[str, bytes] = {}


def fingerprint_key_path() -> str:
    """``$TWO_KEY_FINGERPRINT_KEY``, else ``$XDG_CONFIG_HOME/two-key/fingerprint.key`` (``~/.config``)."""
    explicit = os.environ.get(FINGERPRINT_KEY_ENV)
    if explicit:
        return os.path.abspath(explicit)
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(os.path.abspath(base), "two-key", "fingerprint.key")


def _read_fingerprint_key(path: str) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as e:
        raise IdentityError(f"fingerprint_key_unreadable: {path}: {e.strerror}") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise IdentityError(f"fingerprint_key_unreadable: {path} is not a regular file")
        if st.st_mode & 0o077:
            raise IdentityError(f"fingerprint_key_insecure: {path} is readable by group or others; chmod 600 it")
        data = os.read(fd, FINGERPRINT_KEY_BYTES + 1)
    finally:
        os.close(fd)
    if len(data) != FINGERPRINT_KEY_BYTES:
        raise IdentityError(f"fingerprint_key_unreadable: {path} is not a {FINGERPRINT_KEY_BYTES}-byte key")
    return data


def fingerprint_key(path: str | None = None) -> bytes:
    """Load the per-install HMAC key, creating it (O_EXCL, 0600, directory 0700) the first time."""
    path = path or fingerprint_key_path()
    if path in _FINGERPRINT_KEYS:
        return _FINGERPRINT_KEYS[path]
    if not os.path.lexists(path):
        try:
            os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            fd = None                      # another process created it first: read theirs
        except OSError as e:
            raise IdentityError(f"fingerprint_key_unavailable: cannot create {path}: {e.strerror}; set "
                                f"{FINGERPRINT_KEY_ENV} to a writable path") from None
        if fd is not None:
            with os.fdopen(fd, "wb") as fh:
                fh.write(secrets.token_bytes(FINGERPRINT_KEY_BYTES))
    key = _read_fingerprint_key(path)
    _FINGERPRINT_KEYS[path] = key
    return key


def fingerprint_key_id(key: bytes | None = None) -> str:
    """A public id for the HMAC key, so a ledger reader knows which install's fingerprints these are."""
    key = fingerprint_key() if key is None else key
    return hashlib.sha256(b"two-key/fingerprint-key-id/1\x00" + key).hexdigest()[:16]


def credential_fingerprint(secret: str | None, *, key: bytes | None = None) -> str:
    """HMAC-SHA256 of the stripped secret under the per-install key; ``none`` for no secret."""
    secret = (secret or "").strip()
    if not secret:
        return NO_CREDENTIAL
    key = fingerprint_key() if key is None else key
    mac = hmac.new(key, FINGERPRINT_DOMAIN + secret.encode("utf-8", "surrogatepass"), hashlib.sha256)
    return "hmac-sha256:" + mac.hexdigest()


# ---------------------------------------------------------------- model ids
_MAKER_HOSTS = {
    "openai": "api.openai.com", "anthropic": "api.anthropic.com", "google": "generativelanguage.googleapis.com",
    "xai": "api.x.ai", "mistral": "api.mistral.ai", "deepseek": "api.deepseek.com", "cohere": "api.cohere.com",
}
_PREFIX_MAKERS = {
    "openai": "openai", "anthropic": "anthropic", "google": "google", "gemini": "google", "xai": "xai",
    "x-ai": "xai", "meta-llama": "meta", "meta": "meta", "mistralai": "mistral", "mistral": "mistral",
    "qwen": "alibaba", "alibaba": "alibaba", "deepseek": "deepseek", "deepseek-ai": "deepseek",
    "cohere": "cohere", "microsoft": "microsoft", "amazon": "amazon", "ai21": "ai21", "nvidia": "nvidia",
    "moonshotai": "moonshot", "zhipuai": "zhipu", "writer": "writer",
}
# LiteLLM-style prefixes that name a router, not a maker; the rest of the id is resolved again.
_ROUTER_PREFIXES = {"bedrock", "vertex_ai", "vertex", "azure", "azure_ai", "openrouter", "litellm_proxy"}
_FAMILIES = [
    (re.compile(r"^(gpt|chatgpt|o[1-9]\b|o[1-9]-|text-davinci|davinci|babbage|gpt-oss)"), "openai"),
    (re.compile(r"^claude"), "anthropic"),
    (re.compile(r"^(gemini|gemma|palm|text-bison|chat-bison)"), "google"),
    (re.compile(r"^grok"), "xai"),
    (re.compile(r"^(llama|codellama|meta-llama)"), "meta"),
    (re.compile(r"^(qwen|qwq)"), "alibaba"),
    (re.compile(r"^(mistral|mixtral|codestral|ministral|pixtral|magistral|devstral)"), "mistral"),
    (re.compile(r"^deepseek"), "deepseek"),
    (re.compile(r"^phi"), "microsoft"),
    (re.compile(r"^command"), "cohere"),
    (re.compile(r"^(nemotron|nvidia)"), "nvidia"),
    (re.compile(r"^(kimi|moonshot)"), "moonshot"),
    (re.compile(r"^glm"), "zhipu"),
]
_ALIASES = {"chatgpt-4o": "gpt-4o", "gemini-pro": "gemini-1.0-pro", "gpt-4-turbo-preview": "gpt-4-turbo"}
_SUFFIXES = [
    re.compile(r"-20\d{2}-\d{2}-\d{2}$"),     # -2024-08-06
    re.compile(r"-20\d{6}$"),                 # -20241022
    re.compile(r"-v\d+(:\d+)?$"),             # Bedrock -v2:0
    re.compile(r"-(latest|cloud)$"),
    re.compile(r"-\d{2}-\d{2}$"),             # -preview-05-06
    re.compile(r"-\d{4}$"),                   # -0613, -2407
    re.compile(r"-0\d{2}$"),                  # Gemini -001
    re.compile(r"-(instruct|chat|it)$"),
]


def _bare(model: str) -> tuple[str, str | None]:
    """(model id without router/maker prefixes, maker named by a prefix if any)."""
    m = fold_model_text(model)
    maker = None
    m = re.sub(r"^projects/[^/]+/locations/[^/]+/", "", m)
    pub = re.match(r"^publishers/([^/]+)/models/(.+)$", m)
    if pub:
        maker = _PREFIX_MAKERS.get(pub.group(1), maker)
        m = pub.group(2)
    if m.startswith("models/"):
        m = m[len("models/"):]
    while "/" in m:
        head, m = m.split("/", 1)
        if head not in _ROUTER_PREFIXES:
            maker = _PREFIX_MAKERS.get(head, maker)
    m = re.sub(r"^(us|eu|apac|us-gov|global|jp|au)\.", "", m)          # Bedrock cross-region ids
    bedrock = re.match(r"^([a-z0-9-]+)\.(.+)$", m)
    if bedrock and bedrock.group(1) in _PREFIX_MAKERS:
        maker = _PREFIX_MAKERS[bedrock.group(1)]
        m = bedrock.group(2)
    return m, maker


def normalize_model(model: str) -> str:
    """Comparable model id. Two ids that may name the same model should normalize the same."""
    m, _ = _bare(model)
    m = m.split("@", 1)[0]                                    # Vertex @20241022 / @001
    m = re.sub(r":(latest|cloud)$", "", m)                    # Ollama tags that name no variant
    m = re.sub(r":\d+$", "", m)                               # Bedrock :0
    m = m.replace(":", "-").replace("_", "-")
    if m.startswith("claude"):
        m = re.sub(r"(?<=\d)\.(?=\d)", "-", m)                # claude-3.5-sonnet == claude-3-5-sonnet
    changed = True
    while changed:
        changed = False
        for pat in _SUFFIXES:
            new = pat.sub("", m)
            if new != m and new:
                m, changed = new, True
        if m.startswith("claude") and re.search(r"-\d+-0$", m):
            m, changed = m[:-2], True                          # claude-opus-4-0 == claude-opus-4
    m = _ALIASES.get(m, m)
    m = re.sub(r"(?<=[a-z])-(?=\d)", "", m)                   # llama-3.1 == llama3.1, gpt-4o == gpt4o
    return m


def model_maker(model: str) -> str | None:
    bare, maker = _bare(model)
    if maker:
        return maker
    for pat, name in _FAMILIES:
        if pat.match(bare):
            return name
    return None


def _maker_upstream(maker: str) -> str:
    return _MAKER_HOSTS.get(maker, f"maker:{maker}")


# ---------------------------------------------------------------- endpoints
_DIRECT_HOSTS = {
    "api.openai.com": "openai", "api.anthropic.com": "anthropic", "generativelanguage.googleapis.com": "google",
    "api.x.ai": "xai", "api.mistral.ai": "mistral", "api.deepseek.com": "deepseek", "api.cohere.com": "cohere",
    "api.cohere.ai": "cohere",
}
# Inference hosts that serve other makers' models themselves: the host is an upstream, and so is the maker.
_INFERENCE_HOSTS = {"api.groq.com", "api.together.xyz", "api.fireworks.ai", "api.deepinfra.com",
                    "api.perplexity.ai", "ollama.com"}


def _router(host: str) -> str | None:
    if host in ("openrouter.ai", "api.openrouter.ai"):
        return "openrouter"
    if host.endswith(".openai.azure.com"):
        return "azure-openai"
    if host.endswith((".services.ai.azure.com", ".models.ai.azure.com", ".inference.ai.azure.com")):
        return "azure-ai"
    if re.fullmatch(r"bedrock-runtime(-fips)?\.[a-z0-9-]+\.amazonaws\.com", host):
        return "bedrock"
    if host == "aiplatform.googleapis.com" or host.endswith("-aiplatform.googleapis.com"):
        return "vertex"
    if host == "gateway.ai.cloudflare.com":
        return "cloudflare-ai-gateway"
    if host == "api.portkey.ai":
        return "portkey"
    return None


def endpoint_key(base_url: str) -> str:
    u = urlparse(base_url or "")
    host = (u.hostname or "").lower().rstrip(".")
    if u.scheme == IN_PROCESS:
        return f"{IN_PROCESS}:{host}"
    try:
        port = u.port or {"https": 443, "http": 80}.get(u.scheme, 0)
    except ValueError:
        port = 0
    if host_is_loopback(host):
        host = "localhost"
    return f"{host}:{port}"


def resolve_upstream_info(base_url: str, model: str) -> tuple[frozenset[str], str | None, str | None]:
    """(upstream hosts, router name, resolved_by). An empty set means unresolved (resolved_by None).

    ``resolved_by``: ``endpoint`` (the host itself says who serves the model), ``model_prefix`` (the
    model id names its maker; operator-attested through the model name, not verified). A loopback or
    private endpoint whose model names no recognizable maker is unresolved: a local proxy can route
    an alias anywhere. ``declared_upstream`` is set by ``_identity`` when the operator declares one.
    """
    u = urlparse(base_url or "")
    host = (u.hostname or "").lower().rstrip(".")
    maker = model_maker(model)
    up: set[str] = set()
    if u.scheme == IN_PROCESS:
        return frozenset({f"{IN_PROCESS}:{host}"}), None, "endpoint"
    router = _router(host)
    bare, prefixed = _bare(model)
    by: str | None = None
    if host in _DIRECT_HOSTS:
        up.add(_maker_upstream(_DIRECT_HOSTS[host]))
        if maker:
            up.add(_maker_upstream(maker))
        by = "endpoint"
    elif router == "azure-openai":
        up.add(_maker_upstream("openai"))        # deployment names are free text; the maker is OpenAI
        by = "endpoint"
    elif router is not None:
        if maker:
            up.add(_maker_upstream(maker))
            by = "model_prefix"
    elif host in _INFERENCE_HOSTS:
        up.add(endpoint_key(base_url))
        if maker:
            up.add(_maker_upstream(maker))
        by = "endpoint"
    elif host_is_local(host):
        if maker or model_is_cloud(model):
            up.add(endpoint_key(base_url))
            if maker:
                up.add(_maker_upstream(maker))
            if model_is_cloud(model):
                up.add("ollama.com")             # an Ollama cloud model, proxied by the local daemon
            by = "model_prefix"
        # otherwise unresolved: a local proxy (LiteLLM and the like) can route an alias to anything
    else:
        if prefixed:                             # LiteLLM-style provider/model id on an unrecognized host
            up.add(_maker_upstream(prefixed))
            by = "model_prefix"
        # otherwise unresolved: an unrecognized host may be a router to anything
    return frozenset(up), router, (by if up else None)


def resolve_upstreams(base_url: str, model: str) -> tuple[frozenset[str], str | None]:
    """(upstream hosts, router name). An empty set means unresolved."""
    up, router, _ = resolve_upstream_info(base_url, model)
    return up, router


def validate_upstream(upstream: Any, who: str) -> frozenset[str]:
    """An operator-declared ``upstream:`` (a host or label, or a list of them). Ledgered; not verified."""
    if upstream is None:
        return frozenset()
    items = [upstream] if isinstance(upstream, str) else upstream
    if not isinstance(items, (list, tuple)) or not items:
        raise IdentityError(f"{who}: upstream must be a non-empty string or list of strings")
    out = set()
    for v in items:
        if not isinstance(v, str) or not v.strip() or v.startswith("REPLACE_"):
            raise IdentityError(f"{who}: upstream entries must be non-empty strings")
        out.add(v.strip().lower())
    return frozenset(out)


# ---------------------------------------------------------------- tenants
def validate_tenant(tenant: Any, who: str) -> dict[str, str]:
    """An operator-declared ``tenant:`` mapping: organization, project, account, deployment."""
    if tenant is None:
        return {}
    if not isinstance(tenant, Mapping):
        raise IdentityError(f"{who}: tenant must be a mapping of {', '.join(TENANT_KEYS)}")
    extra = set(tenant) - set(TENANT_KEYS)
    if extra:
        raise IdentityError(f"{who}: unknown tenant key(s) {sorted(extra)}")
    out = {}
    for k, v in tenant.items():
        if not isinstance(v, str) or not v.strip() or v.startswith("REPLACE_"):
            raise IdentityError(f"{who}: tenant {k} must be a non-empty string")
        out[k] = v.strip()
    return out


def resolve_tenants(base_url: str, declared: Mapping[str, str] | None = None) -> frozenset[str]:
    """Account ids, scoped by provider family, from the base_url plus the operator's declaration."""
    u = urlparse(base_url or "")
    host = (u.hostname or "").lower().rstrip(".")
    path = u.path or ""
    router = _router(host)
    declared = dict(declared or {})
    ids: set[str] = set()
    if router in ("azure-openai", "azure-ai"):
        resource = host.split(".", 1)[0]
        ids.add(f"azure:resource:{resource}")
        m = re.search(r"/openai/deployments/([^/?#]+)", path)
        for dep in {m.group(1) if m else None, declared.pop("deployment", None)} - {None}:
            ids.add(f"azure:deployment:{resource}/{dep.lower()}")
        scope = "azure"
    elif router == "bedrock":
        region = host.split(".")[1]
        account = declared.pop("account", None)
        if account:
            ids.add(f"aws:account:{account.lower()}@{region}")
        scope = "aws"
    elif router == "vertex":
        m = re.search(r"/projects/([^/?#]+)", path)
        for project in {m.group(1) if m else None, declared.pop("project", None)} - {None}:
            ids.add(f"gcp:project:{project.lower()}")
        scope = "gcp"
    elif host == "api.openai.com" or (host.endswith(".openai.com") and not host.endswith(".azure.com")):
        scope = "openai"
    else:
        scope = endpoint_key(base_url)
    for k, v in declared.items():
        ids.add(f"{scope}:{k}:{v.lower()}")
    return frozenset(ids)


# ---------------------------------------------------------------- identities
@dataclass(frozen=True)
class ResolvedIdentity:
    role: str                 # "agent" or "judge"
    id: str
    model_declared: str
    model: str
    endpoint: str
    upstreams: frozenset[str]
    router: str | None
    credentials: frozenset[str] = field(default_factory=frozenset)   # fingerprints; may include "none"
    provider_label: str | None = None
    tenants: frozenset[str] = field(default_factory=frozenset)       # scoped account ids, see resolve_tenants
    resolved_by: str | None = None    # endpoint | model_prefix | declared_upstream; None = unresolved

    @property
    def unresolved(self) -> bool:
        return not self.upstreams or not self.model

    def to_record(self) -> dict:
        return {"role": self.role, "id": self.id, "model": self.model, "model_declared": self.model_declared,
                "upstream": sorted(self.upstreams) or None, "router": self.router, "endpoint": self.endpoint,
                "credential_fingerprint": sorted(self.credentials) or None,
                "tenant": sorted(self.tenants) or None, "resolved_by": self.resolved_by,
                "provider_label": self.provider_label, "resolved": not self.unresolved}


def _identity(role: str, ident: str, model: str, base_url: str, credentials: Iterable[str],
              provider_label: str | None, tenant: Mapping[str, str] | None = None,
              upstream: frozenset[str] = frozenset()) -> ResolvedIdentity:
    upstreams, router, by = resolve_upstream_info(base_url, model)
    if upstream:                       # operator-attested; ledgered, not verified
        upstreams, by = frozenset(upstreams | upstream), "declared_upstream"
    return ResolvedIdentity(role, ident, model, normalize_model(model), endpoint_key(base_url), upstreams,
                            router, frozenset(credentials), provider_label, resolve_tenants(base_url, tenant), by)


def _secret_from(credential: Any) -> str:
    """Read a judge or agent credential once, at start-up, to fingerprint it."""
    if credential is None or getattr(credential, "kind", None) == "none":
        return ""
    try:
        token = credential.get_token()
    except Exception as e:
        raise IdentityError(f"credential could not be read at start-up ({type(e).__name__}); "
                            "Two-Key cannot show it differs from the monitored agent's") from None
    if not token:
        raise IdentityError("credential is empty at start-up")
    return token


def judge_identity(judge: Any) -> ResolvedIdentity:
    jid = str(getattr(judge, "judge_id", "?"))
    if getattr(judge, "is_test_double", False) and not getattr(judge, "base_url", None):
        vendor = str(getattr(judge, "vendor", None) or getattr(judge, "provider", "test-double"))
        return ResolvedIdentity("judge", jid, f"test-double/{jid}", f"test-double/{jid}",
                                f"{IN_PROCESS}:{jid}", frozenset({f"{IN_PROCESS}:{vendor}"}), None,
                                frozenset({NO_CREDENTIAL}), getattr(judge, "provider", None))
    model, base_url = getattr(judge, "model", None), getattr(judge, "base_url", None)
    if not isinstance(model, str) or not model or not isinstance(base_url, str) or not base_url:
        raise IdentityError(f"judge {jid!r} declares no model and base_url; Two-Key cannot show it is not "
                            "the monitored agent")
    try:
        fp = credential_fingerprint(_secret_from(getattr(judge, "credential", None)))
    except IdentityError as e:
        raise IdentityError(f"judge {jid!r}: {e}") from None
    tenant = validate_tenant(getattr(judge, "tenant", None), f"judge {jid!r}")
    upstream = validate_upstream(getattr(judge, "upstream", None), f"judge {jid!r}")
    return _identity("judge", jid, model, base_url, {fp}, getattr(judge, "provider", None), tenant, upstream)


@dataclass(frozen=True)
class AgentDeclaration:
    """The operator's statement of who the monitored agent is."""

    model: str
    provider: str
    base_url: str
    credential_env: str | None = None
    credential: str | None = None        # only "none", for a keyless loopback agent
    id: str = "monitored-agent"
    tenant: Mapping[str, str] | None = None   # organization / project / account / deployment, if declared
    upstream: Any = None                      # operator-declared upstream host(s), for a proxy; not verified

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "AgentDeclaration":
        if not isinstance(data, Mapping):
            raise IdentityError("monitored_agent must be a mapping")
        extra = set(data) - AGENT_KEYS
        if extra:
            raise IdentityError(f"monitored_agent: unknown key(s) {sorted(extra)}")
        return cls(model=data.get("model"), provider=data.get("provider"), base_url=data.get("base_url"),
                   credential_env=data.get("credential_env"), credential=data.get("credential"),
                   id=data.get("id") or "monitored-agent",
                   tenant=validate_tenant(data.get("tenant"), "monitored_agent") or None,
                   upstream=data.get("upstream"))

    def validate(self, *, allow_in_process: bool = False) -> None:
        for name in ("model", "provider", "base_url"):
            v = getattr(self, name)
            if not isinstance(v, str) or not v.strip() or v.startswith("REPLACE_"):
                raise IdentityError(f"monitored_agent {self.id!r}: declare {name}")
        u = urlparse(self.base_url)
        if u.scheme == IN_PROCESS:
            if not allow_in_process:
                raise IdentityError("in_process_agent_refused: an in-process monitored agent is for offline tests "
                                    "only: pass allow_test_doubles=True and use test-double judges only")
        elif u.scheme not in ("https", "http") or not u.hostname:
            raise IdentityError(f"monitored_agent {self.id!r}: base_url must be an http(s) URL")
        if self.credential not in (None, NO_CREDENTIAL):
            raise IdentityError("monitored_agent credential may only be 'none'; name the key with credential_env")
        if (self.credential_env is None) == (self.credential is None):
            raise IdentityError(f"monitored_agent {self.id!r}: declare exactly one of credential_env "
                                "or credential: none")
        if self.credential == NO_CREDENTIAL and u.scheme != IN_PROCESS and not host_is_local(u.hostname or ""):
            raise IdentityError(f"monitored_agent {self.id!r}: credential: none is only for a loopback or "
                                "private-address agent; declare credential_env")
        validate_tenant(self.tenant, f"monitored_agent {self.id!r}")
        validate_upstream(self.upstream, f"monitored_agent {self.id!r}")

    def resolve(self, *, allow_in_process: bool = False, extra_secrets: Iterable[str] = ()) -> ResolvedIdentity:
        self.validate(allow_in_process=allow_in_process)
        fps = {credential_fingerprint(s) for s in extra_secrets if s}
        if self.credential_env is not None:
            value = os.environ.get(self.credential_env) if isinstance(self.credential_env, str) else None
            if not value:
                raise IdentityError(f"monitored_agent {self.id!r}: credential_env {self.credential_env} is not set")
            fps.add(credential_fingerprint(value))
        else:
            fps.add(NO_CREDENTIAL)
        return _identity("agent", self.id, self.model, self.base_url, fps, self.provider,
                         validate_tenant(self.tenant, f"monitored_agent {self.id!r}"),
                         validate_upstream(self.upstream, f"monitored_agent {self.id!r}"))

    def to_record(self) -> dict:
        return {"id": self.id, "model": self.model, "provider": self.provider, "base_url": self.base_url,
                "credential_env": self.credential_env, "credential": self.credential,
                "tenant": dict(self.tenant) if self.tenant else None,
                "upstream": sorted(validate_upstream(self.upstream, "monitored_agent")) or None}


def configured_agent_identity(agent: Any) -> ResolvedIdentity:
    """A MonitoredAgent from agents.yaml is operator configuration too."""
    secret = ""
    try:
        secret = _secret_from(getattr(agent, "credential", None))
    except IdentityError:
        if agent.is_cloud():
            raise IdentityError(f"agent {agent.agent_id!r}: credential could not be read at start-up") from None
    return _identity("agent", str(agent.agent_id), agent.model, agent.base_url, {credential_fingerprint(secret)},
                     getattr(agent, "provider", None),
                     validate_tenant(getattr(agent, "tenant", None), f"agent {agent.agent_id!r}"),
                     validate_upstream(getattr(agent, "upstream", None), f"agent {agent.agent_id!r}"))


@dataclass(frozen=True)
class SeparationReport:
    ok: bool
    agents: tuple[ResolvedIdentity, ...]
    judges: tuple[ResolvedIdentity, ...]
    refusals: tuple[str, ...]

    def to_record(self) -> dict:
        return {"ok": self.ok, "rule": "judge_is_not_monitored_agent", "checks": list(SEPARATION_CHECKS),
                "same_provider": "allowed",
                "credential_fingerprint": {"alg": "hmac-sha256", "key_id": fingerprint_key_id(),
                                           "input": "secret with surrounding whitespace stripped"},
                "refusals": list(self.refusals),
                "agents": [a.to_record() for a in self.agents],
                "judges": [j.to_record() for j in self.judges]}


def compare(agent: ResolvedIdentity, judge: ResolvedIdentity) -> str | None:
    """The refusal for one judge against one agent, or None. The same provider alone is not a match."""
    who = f"judge {judge.id!r} vs agent {agent.id!r}"
    if (agent.credentials & judge.credentials) - {NO_CREDENTIAL}:
        return f"{who}: same credential fingerprint"
    if agent.unresolved or judge.unresolved:
        side = "agent" if agent.unresolved else "judge"
        return (f"{who}: {side} upstream unresolved (unrecognized router or host, or a local proxy with no "
                f"recognizable model maker; declare upstream: to attest it); treated as a match")
    if agent.model == judge.model and agent.endpoint == judge.endpoint:
        return f"{who}: same model {judge.model!r} on the same endpoint {judge.endpoint}"
    shared = agent.tenants & judge.tenants
    if shared:
        return f"{who}: same tenant {sorted(shared)[0]}"
    return None


def check_separation(agents: Sequence[ResolvedIdentity], judges: Sequence[ResolvedIdentity],
                     allow_same_provider_judge: bool | None = None) -> SeparationReport:
    """Refuse any judge that is the same agent. ``allow_same_provider_judge`` is a deprecated no-op."""
    if not agents:
        raise IdentityError("monitored_agent_required: declare the monitored agent (monitored_agent: model, provider, base_url, "
                            "credential_env) whenever judges are configured")
    if allow_same_provider_judge:
        warn_allow_same_provider_judge()
    refusals = [r for a in agents for j in judges if (r := compare(a, j))]
    if refusals:
        raise IdentityError("judge_matches_agent: a judge could be the monitored agent: " + "; ".join(refusals))
    return SeparationReport(True, tuple(agents), tuple(judges), ())


def warn_allow_same_provider_judge() -> None:
    print("two-key: allow_same_provider_judge is deprecated and has no effect: the same provider is allowed "
          "by default; a judge is refused only when it is the same agent", file=sys.stderr)


def load_monitored_agent(data: Mapping[str, Any] | None) -> AgentDeclaration | None:
    """The ``monitored_agent:`` block of a judges config, if present."""
    if not isinstance(data, Mapping) or data.get("monitored_agent") is None:
        return None
    return AgentDeclaration.from_mapping(data["monitored_agent"])


def load_monitored_agent_file(path) -> AgentDeclaration | None:
    from .strict import StrictParseError, load_file_strict
    try:
        data = load_file_strict(path)
    except StrictParseError as e:
        raise IdentityError(f"{path}: {e}") from None
    return load_monitored_agent(data)
