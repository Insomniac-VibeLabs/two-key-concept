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
  default port filled in, every alias of this machine written ``localhost``:
  loopback names and addresses in any spelling such as ``127.1``,
  ``localhost.localdomain``, ``0.0.0.0``/``::``, and the machine's own names
  and addresses). Other hosts are compared literally.
- ``upstreams``: who really serves or made the model, as upstream hosts.
  A direct provider host is itself (``api.openai.com``). A recognized router
  (OpenRouter, Azure OpenAI and Azure AI, Bedrock, Vertex, Cloudflare AI
  Gateway, Portkey) or a ``provider/model`` id (LiteLLM style) resolves to the
  model maker's API host, or ``maker:<name>`` for a maker without one. A
  loopback or private host is itself. An unrecognized host or router that
  cannot be resolved from the model id stays **unresolved**. Upstream labels
  are normalized (``host`` or ``host:port``, default port removed). A shared
  maker upstream is allowed; the same *model* reaching the same route is not
  (see ``routes``).
- ``routes``: where the model is actually served, for the same-model check:
  the endpoint, every declared ``upstream:``, and ``ollama.com`` for an Ollama
  cloud model.
- ``tenant``: account ids, each scoped by provider family, from what the
  base_url shows plus what the operator declares under ``tenant:``
  (keys ``organization``, ``project``, ``account``, ``deployment``):
  Azure resource (host) and deployment (``/openai/deployments/<name>``),
  Vertex project (``/projects/<id>/`` in the path, or declared ``project``),
  Bedrock ``account`` (declared) with the region from the host, OpenAI
  ``organization`` / ``project`` (declared). Elsewhere a declared id is scoped
  by provider family: the endpoint's, or for a proxy (local or unrecognized
  host) the family of its declared upstream, its Ollama cloud model, or its
  model maker, never the proxy's address.
- ``credential``: a fingerprint, HMAC-SHA256 of the key with leading and
  trailing whitespace stripped (``hmac-sha256:...``). The HMAC key is a
  random per-install secret, ``fingerprint.key`` beside the ledger key
  (``<ledger>.ledger-key/``, created once with O_EXCL, mode 0600), so a
  ledger reader cannot test guessed keys against a fingerprint. Raw keys are never
  stored or logged. ``none`` means the endpoint takes no key; two keyless
  endpoints do not match on it.

Refusals, judge against agent (all hard, no opt-out), message prefix
``judge_matches_agent:``:

- same credential fingerprint
- either side unresolved (unknown identity fails closed)
- same normalized model on the same normalized endpoint ``host:port``
- same normalized model where either side is a loopback or private endpoint
  (a proxy or daemon, keyed or not) with no declared ``upstream:``: it could
  forward to the other side's provider and account, so upstream and tenant
  are unknown
- same normalized model with a shared route: a declared upstream, the
  endpoint itself, or ollama.com for a ``-cloud`` model
  (``same_model_same_upstream``). Declared tenants do not lift this: two
  accounts on one upstream serving one model are still the same model
  from the same provider, as in two-key
- a shared tenant id (same Azure resource or deployment, OpenAI organization
  or project, Bedrock account in the same region, Vertex project, or a
  declared id on the same host)

Allowed: the same provider or upstream with a different model, the same
endpoint with a different model, the same model on a different endpoint
in a different (or undeclared) tenant with a different key, a local proxy
declaring a non-overlapping upstream (a different provider), and a different
daemon (each declaring its own address). The same provider on another model
or endpoint is allowed.
``allow_same_provider_judge`` is a deprecated no-op.

Logged opt-in, default off: ``allow_same_model_distinct_tenant: true`` in the
quorum config lifts the same-endpoint and same-upstream refusals only when
both sides declare a tenant, the scoped tenant ids are non-empty and share
nothing, and both sides have keys with different fingerprints. A keyless
side, an undeclared tenant, a local proxy with no declared upstream, or an
unresolved side is still refused. When the flag is set, a warning goes to
stderr, and ``constitution_loaded`` records ``same_model_tenant_optin: true``
with both tenant labels of every pair it let through. The flag is part of
the quorum policy, so it is in ``policy_digest``.

The runtime check stays as a second layer: a judge whose credential equals
the frozen agent session abstains with ``cloud_judge_reused_agent_session``.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import ipaddress
import secrets
import socket
import stat
import re
import sys
from functools import lru_cache
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urlparse

from .netloc import fold_model_id, host_is_local, host_is_loopback, model_is_cloud

FINGERPRINT_DOMAIN = b"two-key/credential-fingerprint/1\x00"
NO_CREDENTIAL = "none"
IN_PROCESS = "in-process"
AGENT_KEYS = {"id", "model", "provider", "base_url", "credential_env", "credential", "tenant", "upstream"}
TENANT_KEYS = ("organization", "project", "account", "deployment")
SEPARATION_CHECKS = ("same_credential", "unresolved_identity", "same_model_same_endpoint",
                     "same_model_unknown_upstream", "same_model_same_upstream", "same_tenant")


class IdentityError(ValueError):
    """The agent or a judge cannot be identified, or a judge could be the agent."""


FINGERPRINT_KEY_BYTES = 32


def load_fingerprint_key(path: str | os.PathLike) -> bytes:
    """Load the per-install HMAC key at ``path``, creating it the first time.

    32 random bytes, created with O_EXCL (two processes never write different
    keys) at mode 0600 in a 0700 directory. An existing key is read with
    O_NOFOLLOW and refused if it is not a regular file, is group- or
    world-accessible, or is not 32 bytes. Never regenerated.
    """
    path = os.fspath(path)
    if not os.path.lexists(path):
        try:
            os.makedirs(os.path.dirname(path) or ".", mode=0o700, exist_ok=True)
            os.chmod(os.path.dirname(path) or ".", 0o700)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            fd = None                      # another process created it first: read theirs
        except OSError as e:
            raise IdentityError(f"fingerprint_key_unavailable: cannot create {path}: {e.strerror}") from None
        if fd is not None:
            with os.fdopen(fd, "wb") as fh:
                fh.write(secrets.token_bytes(FINGERPRINT_KEY_BYTES))
                fh.flush()
                os.fsync(fh.fileno())
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


def fingerprint_key_id(key: bytes) -> str:
    """A public id for the HMAC key, so a ledger reader knows which install's fingerprints these are."""
    return hashlib.sha256(b"two-key/fingerprint-key-id/1\x00" + key).hexdigest()[:16]


def credential_fingerprint(secret: str | None, key: bytes | None = None) -> str:
    """Fingerprint of the secret with surrounding whitespace stripped; ``none`` for no secret.

    ``hmac-sha256:`` under the per-install key (TwoKey always passes one: ``Ledger.fingerprint_key``).
    Without a key, a plain ``sha256:`` (offline use only).
    """
    secret = (secret or "").strip()
    if not secret:
        return NO_CREDENTIAL
    data = FINGERPRINT_DOMAIN + secret.encode("utf-8", "surrogatepass")
    if key is not None:
        return "hmac-sha256:" + hmac.new(key, data, hashlib.sha256).hexdigest()
    return "sha256:" + hashlib.sha256(data).hexdigest()


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
    m = fold_model_id(model)                                  # NFKC, Unicode dashes, zero-width, case
    m = re.sub(r"^gpt-35(?=-|$)", "gpt-3.5", m)               # Azure OpenAI names gpt-3.5 "gpt-35"
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


_LOCAL_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}


@lru_cache(maxsize=1)
def _own_addresses() -> frozenset[str]:
    """This machine's own names and addresses (best effort, no network traffic)."""
    out: set[str] = set()
    try:
        names = {socket.gethostname().lower(), socket.getfqdn().lower()} - {""}
    except OSError:
        names = set()
    out |= names
    for name in names:
        try:
            for info in socket.getaddrinfo(name, None):
                out.add(str(info[4][0]).split("%", 1)[0].lower())
        except (OSError, UnicodeError):
            pass
    # The source address of the default route. Connecting a UDP socket sends no packet; the target is
    # a documentation address that is never contacted.
    for family, target in ((socket.AF_INET, "192.0.2.1"), (socket.AF_INET6, "2001:db8::1")):
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as probe:
                probe.connect((target, 9))
                out.add(str(probe.getsockname()[0]).split("%", 1)[0].lower())
        except OSError:
            pass
    return frozenset(out)


def _legacy_ipv4(host: str):
    """``127.1``, ``0x7f.1``, ``2130706433``: forms inet_aton accepts but ipaddress does not."""
    if not re.fullmatch(r"[0-9a-fx.]+", host) or not re.search(r"[0-9]", host):
        return None
    try:
        return ipaddress.IPv4Address(socket.inet_aton(host))
    except (OSError, ValueError):
        return None


def local_alias(host: str) -> bool:
    """True for a name or address that reaches this machine: a loopback name or address (any
    127.0.0.0/8 spelling, ``::1``), ``localhost.localdomain``, an unspecified address (which a client
    connects to as this machine), or one of this machine's own names or addresses."""
    host = (host or "").lower().rstrip(".").strip("[]").split("%", 1)[0]
    if not host:
        return False
    if host in _LOCAL_NAMES or host_is_loopback(host):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = _legacy_ipv4(host)
    if ip is not None:
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        if ip.is_unspecified or ip.is_loopback:
            return True
        return str(ip) in _own_addresses()
    return host in _own_addresses()


def endpoint_key(base_url: str) -> str:
    """``host:port`` with the default port filled in; every local alias of this machine is ``localhost``."""
    u = urlparse(base_url or "")
    host = (u.hostname or "").lower().rstrip(".")
    if u.scheme == IN_PROCESS:
        return f"{IN_PROCESS}:{host}"
    try:
        port = u.port or {"https": 443, "http": 80}.get(u.scheme, 0)
    except ValueError:
        port = 0
    if local_alias(host):
        host = "localhost"
    return f"{host}:{port}"


def normalize_upstream(label: str) -> str:
    """A comparable upstream: a URL or ``host[:port]`` becomes lower-case ``host`` or ``host:port`` with a
    default port (80, 443) removed and local aliases written ``localhost``; ``maker:<name>`` and
    ``in-process:`` labels are kept as they are.

    Declared labels are folded first (NFKC, zero-width / soft-hyphen stripped, Unicode dashes to
    ASCII, strip, lower case). A bare maker name such as ``openai`` maps to that maker's API host
    (``api.openai.com``).
    """
    s = fold_model_id(label).rstrip("/")
    if not s or s.startswith(("maker:", f"{IN_PROCESS}:")):
        return s
    if s in _PREFIX_MAKERS:
        return _maker_upstream(_PREFIX_MAKERS[s])
    try:
        u = urlparse(s if "://" in s else f"//{s}")
        host = (u.hostname or "").rstrip(".")
        port = u.port
    except ValueError:
        return s
    if not host:
        return s
    if local_alias(host):
        host = "localhost"
    elif ":" in host:
        host = f"[{host}]"
    return host if port in (None, 80, 443) else f"{host}:{port}"


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
    up = {normalize_upstream(x) for x in up}
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
        out.add(normalize_upstream(v))
    return frozenset(out)


# ---------------------------------------------------------------- tenants
def validate_tenant(tenant: Any, who: str) -> dict[str, str]:
    """An operator-declared ``tenant:`` mapping: organization, project, account, deployment.

    ``None`` (omit the field) means no tenant. An empty mapping ``{}`` is invalid — omit
    ``tenant`` instead of passing an empty dict.
    """
    if tenant is None:
        return {}
    if not isinstance(tenant, Mapping):
        raise IdentityError(f"{who}: tenant must be a mapping of {', '.join(TENANT_KEYS)}")
    if len(tenant) == 0:
        raise IdentityError(f"{who}: tenant mapping must not be empty (omit tenant instead)")
    extra = set(tenant) - set(TENANT_KEYS)
    if extra:
        raise IdentityError(f"{who}: unknown tenant key(s) {sorted(extra)}")
    out = {}
    for k, v in tenant.items():
        if not isinstance(v, str) or not v.strip() or v.startswith("REPLACE_"):
            raise IdentityError(f"{who}: tenant {k} must be a non-empty string")
        out[k] = v.strip()
    return out


def _family(label: str) -> str:
    """The provider family of a normalized upstream label, for scoping tenant ids."""
    if label.startswith("maker:"):
        return label[len("maker:"):]
    host = label.rsplit(":", 1)[0] if label.count(":") == 1 else label
    if host in _DIRECT_HOSTS:
        return _DIRECT_HOSTS[host]
    if host == "ollama.com":
        return "ollama"
    if host.endswith(".openai.com") and not host.endswith(".azure.com"):
        return "openai"
    router = _router(host)
    return {"azure-openai": "azure", "azure-ai": "azure", "bedrock": "aws", "vertex": "gcp"}.get(router or "", router or label)


def _tenant_scopes(host: str, base_url: str, model: str | None, upstreams: frozenset[str]) -> list[str]:
    """Where a declared tenant id lives: the provider family of the endpoint, or for a proxy (a local
    or unrecognized host) the family of its declared upstream, its Ollama cloud model, or its model
    maker. Never the proxy's own address while any of those is known."""
    if host in _DIRECT_HOSTS or host == "ollama.com" or host.endswith(".openai.com"):
        return [_family(host)]
    if host in _INFERENCE_HOSTS:
        return [host]
    if upstreams:
        return sorted({_family(u) for u in upstreams})
    if model and model_is_cloud(model):
        return ["ollama"]
    maker = model_maker(model) if model else None
    if maker:
        return [maker]
    return [endpoint_key(base_url)]


def resolve_tenants(base_url: str, declared: Mapping[str, str] | None = None, *, model: str | None = None,
                    upstreams: Iterable[str] = ()) -> frozenset[str]:
    """Account ids, scoped by provider family, from the base_url plus the operator's declaration.

    A declared id on a proxy is scoped by the family it reaches (declared ``upstreams``, an Ollama
    cloud model, or the model maker), so ``project: p1`` behind a local proxy to OpenAI is the same
    tenant as ``project: p1`` at api.openai.com."""
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
    else:
        scope = None
    scopes = [scope] if scope else _tenant_scopes(host, base_url, model, frozenset(upstreams))
    for sc in scopes:
        for k, v in declared.items():
            ids.add(f"{sc}:{k}:{v.lower()}")
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
    declared_upstreams: frozenset[str] = field(default_factory=frozenset)   # normalized operator `upstream:`
    local: bool = False               # the endpoint is this machine or a private address (a proxy or daemon)
    routes: frozenset[str] = field(default_factory=frozenset)   # endpoint + declared upstreams (+ ollama.com)
    tenant_declared: bool = False     # the operator declared a non-empty tenant: mapping
    proxy: bool = False               # local, or a host that is no recognized vendor, router, or inference host

    @property
    def unresolved(self) -> bool:
        return not self.upstreams or not self.model

    def to_record(self) -> dict:
        return {"role": self.role, "id": self.id, "model": self.model, "model_declared": self.model_declared,
                "upstream": sorted(self.upstreams) or None, "router": self.router, "endpoint": self.endpoint,
                "credential_fingerprint": sorted(self.credentials) or None,
                "tenant": sorted(self.tenants) or None, "resolved_by": self.resolved_by,
                "upstream_declared": sorted(self.declared_upstreams) or None, "local_endpoint": self.local,
                "routes": sorted(self.routes) or None, "tenant_declared": self.tenant_declared,
                "proxy_endpoint": self.proxy,
                "provider_label": self.provider_label, "resolved": not self.unresolved}


def _identity(role: str, ident: str, model: str, base_url: str, credentials: Iterable[str],
              provider_label: str | None, tenant: Mapping[str, str] | None = None,
              upstream: frozenset[str] = frozenset()) -> ResolvedIdentity:
    upstreams, router, by = resolve_upstream_info(base_url, model)
    upstream = frozenset(normalize_upstream(u) for u in upstream)
    if upstream:                       # operator-attested; ledgered, not verified
        upstreams, by = frozenset(upstreams | upstream), "declared_upstream"
    host = (urlparse(base_url or "").hostname or "").lower().rstrip(".")
    local = urlparse(base_url or "").scheme != IN_PROCESS and (local_alias(host) or host_is_local(host))
    # A host that is no recognized vendor, router, or inference host (litellm, host.docker.internal,
    # proxy.corp.example, 100.64.x, 169.254.x) says nothing about who serves the model, whatever the
    # model id's maker prefix claims: for the same-model check it is a proxy, like a local one.
    proxy = local or (urlparse(base_url or "").scheme != IN_PROCESS and host not in _DIRECT_HOSTS
                      and host not in _INFERENCE_HOSTS and _router(host) is None)
    # Where the model is really served, for the same-model comparison: the endpoint itself, every
    # declared upstream, and ollama.com for an Ollama cloud model (the local daemon forwards it there).
    routes = {normalize_upstream(base_url)} | set(upstream)
    if model_is_cloud(model):
        routes.add("ollama.com")
    return ResolvedIdentity(role, ident, model, normalize_model(model), endpoint_key(base_url), upstreams,
                            router, frozenset(credentials), provider_label,
                            resolve_tenants(base_url, tenant, model=model, upstreams=upstream), by,
                            upstream, local, frozenset(routes - {""}), bool(tenant), proxy)


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


def judge_identity(judge: Any, fp_key: bytes | None = None) -> ResolvedIdentity:
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
        fp = credential_fingerprint(_secret_from(getattr(judge, "credential", None)), fp_key)
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

    def resolve(self, *, allow_in_process: bool = False, extra_secrets: Iterable[str] = (),
                fp_key: bytes | None = None) -> ResolvedIdentity:
        self.validate(allow_in_process=allow_in_process)
        fps = {credential_fingerprint(s, fp_key) for s in extra_secrets if s}
        if self.credential_env is not None:
            value = os.environ.get(self.credential_env) if isinstance(self.credential_env, str) else None
            if not value:
                raise IdentityError(f"monitored_agent {self.id!r}: credential_env {self.credential_env} is not set")
            fps.add(credential_fingerprint(value, fp_key))
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


def configured_agent_identity(agent: Any, fp_key: bytes | None = None) -> ResolvedIdentity:
    """A MonitoredAgent from agents.yaml is operator configuration too."""
    secret = ""
    try:
        secret = _secret_from(getattr(agent, "credential", None))
    except IdentityError:
        if agent.is_cloud():
            raise IdentityError(f"agent {agent.agent_id!r}: credential could not be read at start-up") from None
    return _identity("agent", str(agent.agent_id), agent.model, agent.base_url, {credential_fingerprint(secret, fp_key)},
                     getattr(agent, "provider", None),
                     validate_tenant(getattr(agent, "tenant", None), f"agent {agent.agent_id!r}"),
                     validate_upstream(getattr(agent, "upstream", None), f"agent {agent.agent_id!r}"))


@dataclass(frozen=True)
class SeparationReport:
    ok: bool
    agents: tuple[ResolvedIdentity, ...]
    judges: tuple[ResolvedIdentity, ...]
    refusals: tuple[str, ...]

    tenant_optin: bool = False
    tenant_optin_pairs: tuple[dict, ...] = ()

    def to_record(self) -> dict:
        return {"ok": self.ok, "rule": "judge_is_not_monitored_agent", "checks": list(SEPARATION_CHECKS),
                "same_provider": "allowed",
                "same_model_tenant_optin": self.tenant_optin,
                "same_model_tenant_optin_pairs": list(self.tenant_optin_pairs),
                "refusals": list(self.refusals),
                "agents": [a.to_record() for a in self.agents],
                "judges": [j.to_record() for j in self.judges]}


TENANT_OPTIN_FLAG = "allow_same_model_distinct_tenant"
TENANT_OPTIN_WARNING = ("two-key: WARNING: allow_same_model_distinct_tenant is set: a judge running the monitored "
                        "agent's model on the same endpoint or upstream is allowed when both sides declare "
                        "different tenants and use different keys. Tenants are declared by the operator, not "
                        "verified; this is logged as same_model_tenant_optin in constitution_loaded.")


def distinct_tenants(agent: ResolvedIdentity, judge: ResolvedIdentity) -> bool:
    """Both sides declared a tenant, the scoped tenant ids are non-empty and share nothing, and both sides
    have a key with different fingerprints. A keyless side (a local daemon) or an undeclared tenant is not."""
    def keyed(side: ResolvedIdentity) -> bool:
        return bool(side.credentials) and NO_CREDENTIAL not in side.credentials
    return (agent.tenant_declared and judge.tenant_declared and bool(agent.tenants) and bool(judge.tenants)
            and not (agent.tenants & judge.tenants) and keyed(agent) and keyed(judge)
            and not (agent.credentials & judge.credentials))


def same_model_overlap(agent: ResolvedIdentity, judge: ResolvedIdentity) -> bool:
    """The same normalized model on the same endpoint or a shared upstream route."""
    return agent.model == judge.model and (agent.endpoint == judge.endpoint or bool(agent.routes & judge.routes))


def compare(agent: ResolvedIdentity, judge: ResolvedIdentity, *,
            allow_same_model_distinct_tenant: bool = False) -> str | None:
    """The refusal for one judge against one agent, or None. The same provider alone is not a match.

    With ``allow_same_model_distinct_tenant`` (a logged opt-in, default off), the same model on the same
    endpoint or upstream is allowed when ``distinct_tenants`` holds. Every other refusal still applies:
    the same key, an unresolved side, a local proxy with no declared upstream, and a shared tenant id."""
    who = f"judge {judge.id!r} vs agent {agent.id!r}"
    optin = allow_same_model_distinct_tenant and distinct_tenants(agent, judge)
    if (agent.credentials & judge.credentials) - {NO_CREDENTIAL}:
        return f"{who}: same credential fingerprint"
    if agent.unresolved or judge.unresolved:
        side = "agent" if agent.unresolved else "judge"
        return (f"{who}: {side} upstream unresolved (unrecognized router or host, or a local proxy with no "
                f"recognizable model maker; declare upstream: to attest it); treated as a match")
    if agent.model == judge.model:
        if agent.endpoint == judge.endpoint and not optin:
            return f"{who}: same model {judge.model!r} on the same endpoint {judge.endpoint}"
        # A loopback or private endpoint (a LiteLLM-style proxy, a local Ollama daemon), or any host
        # that is no recognized vendor (a maker/ prefix does not identify it), can forward the same model
        # to the other side's provider and account without a key of its own. Its upstream and tenant are
        # unknown unless the operator declares an upstream (compared as a route below).
        for side, label in ((judge, "judge"), (agent, "agent")):
            if side.proxy and not side.declared_upstreams:
                return (f"{who}: same model {judge.model!r} through a local or unrecognized proxy or daemon ({label} at "
                        f"{side.endpoint}) with no declared upstream; upstream and tenant unknown "
                        "(declare upstream: on it)")
        # Declared upstreams count as endpoints: the same model reaching the same upstream is the same
        # agent. Declared tenants do not lift it; a different account on one upstream is still that model.
        via = agent.routes & judge.routes
        if via and not optin:
            return f"{who}: same model {judge.model!r} through the same upstream {sorted(via)[0]}"
    shared = agent.tenants & judge.tenants
    if shared:
        return f"{who}: same tenant {sorted(shared)[0]}"
    return None


def check_separation(agents: Sequence[ResolvedIdentity], judges: Sequence[ResolvedIdentity],
                     allow_same_provider_judge: bool | None = None, *,
                     allow_same_model_distinct_tenant: bool = False) -> SeparationReport:
    """Refuse any judge that is the same agent. ``allow_same_provider_judge`` is a deprecated no-op.

    ``allow_same_model_distinct_tenant`` is the logged opt-in (see ``compare``). When it is set, a warning
    goes to stderr and the report lists every pair it let through with both tenant labels."""
    if not agents:
        raise IdentityError("monitored_agent_required: declare the monitored agent (monitored_agent: model, provider, base_url, "
                            "credential_env) whenever judges are configured")
    if allow_same_provider_judge:
        warn_allow_same_provider_judge()
    optin = allow_same_model_distinct_tenant is True
    if optin:
        print(TENANT_OPTIN_WARNING, file=sys.stderr)
    refusals = [r for a in agents for j in judges
                if (r := compare(a, j, allow_same_model_distinct_tenant=optin))]
    if refusals:
        raise IdentityError("judge_matches_agent: a judge could be the monitored agent: " + "; ".join(refusals))
    pairs = tuple({"agent": a.id, "judge": j.id, "model": j.model,
                   "agent_tenant": sorted(a.tenants), "judge_tenant": sorted(j.tenants)}
                  for a in agents for j in judges if optin and same_model_overlap(a, j))
    return SeparationReport(True, tuple(agents), tuple(judges), (), optin, pairs)


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
