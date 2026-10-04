"""
Two-Key: a Path B judge must not be the monitored agent
=======================================================
The rule (the owner's, approved by the Cybersecurity Practitioner): at least
one judge, and no judge may be the monitored agent. ``TwoKey`` checks it when
it starts and refuses with ``TwoKeyConfigError``.

The agent's identity comes only from operator configuration
(``TwoKey(monitored_agent=...)``: a mapping, an ``AgentDeclaration``, a
``MonitoredAgent`` built from agents.yaml, or a list of them; the CLI reads
the ``monitored_agent:`` block of judges.yaml), never from anything the agent
says about itself. The declaration names the model, the provider (recorded as
a label, never compared), the endpoint ``base_url``, and the credential: the
name of the environment variable that holds the agent's key
(``credential_env``), or ``credential: none`` for a keyless loopback agent.
If any of these is missing or cannot be read, Two-Key refuses to start.

Each judge and agent is resolved to:

- ``model``: the model id, normalized (case, router prefixes such as
  ``openai/`` or Bedrock's ``anthropic.``, dated snapshot suffixes such as
  ``-2024-08-06`` or ``-20241022``, ``-latest``, Vertex ``@`` versions,
  Bedrock ``-v2:0``, Ollama ``:latest``, and a few known aliases). The id is
  NFKC-normalized first, Unicode dashes are folded to ``-``, and zero-width
  characters are removed, so ``gpt‐4o`` and ``ｇｐｔ-4o`` equal ``gpt-4o``.
- ``upstream``: the normalized endpoint that really serves the model, as
  ``host:port``. A direct provider host or an inference host is its own
  ``host:port``. A recognized router (OpenRouter, Azure OpenAI and Azure AI,
  Bedrock, Vertex, Cloudflare AI Gateway, Portkey) or a ``provider/model`` id
  on any other host (LiteLLM style) resolves to the model maker's API host
  (``api.openai.com:443``), or ``maker:<name>`` for a maker without one. A
  loopback or private host is itself when the model id names a known maker;
  if that maker only serves its models from its own API (GPT, Claude,
  Gemini, Grok), the host is a proxy and the maker's API host is added. A
  ``-cloud`` Ollama model adds ``ollama.com:443``. A loopback or private
  host whose model names no known maker, and an unrecognized host or router
  that cannot be resolved from the model id, stay **unresolved**, and
  unresolved is treated as a match, unless the operator declares
  ``upstream:`` (a host, URL, or maker name) for that judge or agent.
- ``resolved_by``: ``endpoint`` (the host, or a router plus the model's
  family), ``declared_upstream`` (the operator's ``upstream:``, recorded in
  the ledger), or ``model_prefix`` (a ``maker/model`` id on a host Two-Key
  does not know). Both of the last two are operator-attested and not
  verified: Two-Key cannot see where a proxy really forwards.
- ``tenant``: account, org, project, or deployment ids. Declared with the
  optional ``tenant`` key (a string or a list) on the agent or a judge, or
  derived from the URL: ``azure:<resource>`` for Azure OpenAI and Azure AI,
  ``gcp-project:<project>`` for a Vertex path or model id,
  ``cloudflare-account:<id>`` for Cloudflare AI Gateway. Compared as
  lower-case strings.
- ``endpoint``: the ``host:port`` of ``base_url``.
- ``credential``: a fingerprint, SHA-256 over a domain-separated encoding of
  the key (``sha256:...``). Raw keys are never stored or logged. ``none``
  means the endpoint takes no key; two keyless endpoints do not match on it.

A judge is refused only when it is the same agent (owner decision,
2026-10-03):

- the same credential fingerprint;
- the same tenant, account, org, project, or deployment id;
- the same normalized model on the same normalized endpoint (a shared
  ``upstream``);
- either side unresolved, or undeclared (fail closed).

The same provider with a different model, or the same model at a different
endpoint, is allowed. Such pairs are recorded in ``same_provider_allowed``.
``allow_same_provider_judge`` is accepted for old configurations and has no
effect.

Free-text provider labels are recorded and never compared.

The runtime check stays as a second layer, for every judge: a judge whose
credential equals the ``agent_session`` passed to ``authorize`` abstains with
``cloud_judge_reused_agent_session``.
"""

from __future__ import annotations

import hashlib
import os
import re
import sys
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urlparse

from .netloc import host_is_local

FINGERPRINT_DOMAIN = b"two-key/credential-fingerprint/1\x00"
NO_CREDENTIAL = "none"
IN_PROCESS = "in-process"
AGENT_KEYS = {"id", "model", "provider", "base_url", "credential_env", "credential", "tenant", "upstream"}
RESOLVED_BY = ("endpoint", "declared_upstream", "model_prefix")
_DASHES = dict.fromkeys(map(ord, "\u2010\u2011\u2012\u2013\u2014\u2015\u2212\u2043\ufe58\ufe63\uff0d"), "-")
_DASHES.update(dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff\u00ad"), None))


def fold_model_text(model: str) -> str:
    """NFKC, Unicode dashes to '-', zero-width characters removed, lower case."""
    return unicodedata.normalize("NFKC", model or "").translate(_DASHES).strip().lower()


class IdentityError(ValueError):
    """The agent or a judge cannot be identified, or a judge could be the agent."""


def credential_fingerprint(secret: str | None) -> str:
    if not secret:
        return NO_CREDENTIAL
    return "sha256:" + hashlib.sha256(FINGERPRINT_DOMAIN + secret.encode("utf-8", "surrogatepass")).hexdigest()


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
    port = u.port or {"https": 443, "http": 80}.get(u.scheme, 0)
    return f"{host}:{port}"


def _hostport(host: str) -> str:
    return host if host.startswith("maker:") else f"{host}:443"


# Makers whose models are served only from the maker's own API (or a cloud reseller): a loopback or
# private host serving one of these is a proxy, so the maker's API host is added.
_CLOSED = re.compile(r"^(gpt-(?!oss)|gpt\d|chatgpt|o[1-9]|text-davinci|claude|gemini|palm|text-bison|chat-bison|grok)")


def declared_upstream(value: Any, who: str) -> str | None:
    """Normalize an operator's ``upstream:`` to host:port, or maker:<name>."""
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip() or value.startswith("REPLACE_"):
        raise IdentityError(f"{who}: upstream must be a host, a URL, or a maker name")
    v = value.strip().lower()
    if "://" in v:
        return endpoint_key(v)
    if v.startswith("maker:"):
        return v
    if v in _PREFIX_MAKERS:
        return _hostport(_maker_upstream(_PREFIX_MAKERS[v]))
    host, _, port = v.partition(":")
    if not host or (port and not port.isdigit()):
        raise IdentityError(f"{who}: upstream {value!r} is not a host, a URL, or a maker name")
    return f"{host}:{port or 443}"


def resolve_upstreams(base_url: str, model: str, declared: str | None = None) -> tuple[frozenset[str], str | None, str | None]:
    """(normalized serving endpoints as host:port, router name, resolved_by). An empty set means unresolved."""
    u = urlparse(base_url or "")
    host = (u.hostname or "").lower().rstrip(".")
    maker = model_maker(model)
    up: set[str] = set()
    by = "endpoint"
    if u.scheme == IN_PROCESS:
        return frozenset({f"{IN_PROCESS}:{host}"}), None, by
    router = _router(host)
    bare, prefixed = _bare(model)
    if host in _DIRECT_HOSTS:
        up.add(endpoint_key(base_url))
    elif router == "azure-openai":
        up.add(_hostport(_maker_upstream("openai")))  # deployment names are free text; the maker is OpenAI
    elif router is not None:
        if maker:                                # the router itself routes by this id
            up.add(_hostport(_maker_upstream(maker)))
    elif host in _INFERENCE_HOSTS:
        up.add(endpoint_key(base_url))
    elif host_is_local(host):
        if maker:                                # a local host with no known maker stays unresolved
            up.add(endpoint_key(base_url))
            by = "model_prefix" if prefixed else "endpoint"
            if _CLOSED.match(bare):
                up.add(_hostport(_maker_upstream(maker)))   # these weights are not local: a proxy
        if re.search(r"[:-]cloud$", fold_model_text(model)):
            up.add(endpoint_key(base_url))
            up.add("ollama.com:443")             # an Ollama cloud model, proxied by the local daemon
    else:
        if prefixed:                             # LiteLLM-style provider/model id on an unrecognized host
            up.add(_hostport(_maker_upstream(prefixed)))
            by = "model_prefix"
        # otherwise unresolved: an unrecognized host may be a router to anything
    if declared:
        if not up:
            by = "declared_upstream"             # resolved only because the operator said so
        up.add(declared)                         # the operator's statement; added, never a replacement
    if not up:
        by = None
    return frozenset(up), router, by


def derive_tenants(base_url: str, model: str = "") -> frozenset[str]:
    """Account, project, or deployment ids that the URL or model id names."""
    u = urlparse(base_url or "")
    host = (u.hostname or "").lower().rstrip(".")
    path = (u.path or "").lower()
    out: set[str] = set()
    azure = re.fullmatch(r"([a-z0-9-]+)\.(openai\.azure\.com|services\.ai\.azure\.com|"
                         r"models\.ai\.azure\.com|inference\.ai\.azure\.com)", host)
    if azure:
        out.add(f"azure:{azure.group(1)}")
    for text in (path, (model or "").strip().lower()):
        project = re.search(r"(?:^|/)projects/([^/]+)/", text)
        if project:
            out.add(f"gcp-project:{project.group(1)}")
    if host == "gateway.ai.cloudflare.com":
        cf = re.match(r"^/v1/([^/]+)/", path)
        if cf:
            out.add(f"cloudflare-account:{cf.group(1)}")
    return frozenset(out)


def declared_tenants(value: Any, who: str) -> frozenset[str]:
    if value is None:
        return frozenset()
    items = [value] if isinstance(value, str) else value
    if not isinstance(items, (list, tuple)) or not all(isinstance(v, str) and v.strip() for v in items):
        raise IdentityError(f"{who}: tenant must be a non-empty string or a list of them")
    return frozenset(v.strip().lower() for v in items)


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
    tenants: frozenset[str] = field(default_factory=frozenset)
    resolved_by: str | None = "endpoint"
    upstream_declared: str | None = None

    @property
    def unresolved(self) -> bool:
        return not self.upstreams or not self.model

    def to_record(self) -> dict:
        return {"role": self.role, "id": self.id, "model": self.model, "model_declared": self.model_declared,
                "upstream": sorted(self.upstreams) or None, "router": self.router, "endpoint": self.endpoint,
                "credential_fingerprint": sorted(self.credentials) or None,
                "tenant": sorted(self.tenants) or None,
                "resolved_by": self.resolved_by if not self.unresolved else None,
                "upstream_declared": self.upstream_declared,
                "provider_label": self.provider_label, "resolved": not self.unresolved}


def _identity(role: str, ident: str, model: str, base_url: str, credentials: Iterable[str],
              provider_label: str | None, tenant: Any = None, upstream: Any = None) -> ResolvedIdentity:
    who = f"{role} {ident!r}"
    declared = declared_upstream(upstream, who)
    upstreams, router, by = resolve_upstreams(base_url, model, declared)
    tenants = derive_tenants(base_url, model) | declared_tenants(tenant, who)
    return ResolvedIdentity(role, ident, model, normalize_model(model), endpoint_key(base_url), upstreams,
                            router, frozenset(credentials), provider_label, tenants, by, declared)


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
    return _identity("judge", jid, model, base_url, {fp}, getattr(judge, "provider", None),
                     getattr(judge, "tenant", None), getattr(judge, "upstream", None))


@dataclass(frozen=True)
class AgentDeclaration:
    """The operator's statement of who the monitored agent is."""

    model: str
    provider: str
    base_url: str
    credential_env: str | None = None
    credential: str | None = None        # only "none", for a keyless loopback agent
    id: str = "monitored-agent"
    tenant: Any = None                   # optional account/org/project/deployment id, or a list
    upstream: str | None = None          # optional: where a proxy really forwards (operator-attested)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "AgentDeclaration":
        if not isinstance(data, Mapping):
            raise IdentityError("monitored_agent must be a mapping")
        extra = set(data) - AGENT_KEYS
        if extra:
            raise IdentityError(f"monitored_agent: unknown key(s) {sorted(extra)}")
        return cls(model=data.get("model"), provider=data.get("provider"), base_url=data.get("base_url"),
                   credential_env=data.get("credential_env"), credential=data.get("credential"),
                   id=data.get("id") or "monitored-agent", tenant=data.get("tenant"),
                   upstream=data.get("upstream"))

    def validate(self, *, allow_in_process: bool = False) -> None:
        for name in ("model", "provider", "base_url"):
            v = getattr(self, name)
            if not isinstance(v, str) or not v.strip() or v.startswith("REPLACE_"):
                raise IdentityError(f"monitored_agent {self.id!r}: declare {name}")
        u = urlparse(self.base_url)
        if u.scheme == IN_PROCESS:
            if not allow_in_process:
                raise IdentityError("an in-process monitored agent is for tests only (allow_test_doubles=True)")
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
        return _identity("agent", self.id, self.model, self.base_url, fps, self.provider, self.tenant,
                         self.upstream)

    def to_record(self) -> dict:
        return {"id": self.id, "model": self.model, "provider": self.provider, "base_url": self.base_url,
                "credential_env": self.credential_env, "credential": self.credential, "tenant": self.tenant,
                "upstream": self.upstream}


def configured_agent_identity(agent: Any) -> ResolvedIdentity:
    """A MonitoredAgent from agents.yaml is operator configuration too."""
    secret = ""
    try:
        secret = _secret_from(getattr(agent, "credential", None))
    except IdentityError:
        if agent.is_cloud():
            raise IdentityError(f"agent {agent.agent_id!r}: credential could not be read at start-up") from None
    return _identity("agent", str(agent.agent_id), agent.model, agent.base_url, {credential_fingerprint(secret)},
                     getattr(agent, "provider", None), getattr(agent, "tenant", None),
                     getattr(agent, "upstream", None))


@dataclass(frozen=True)
class SeparationReport:
    ok: bool
    agents: tuple[ResolvedIdentity, ...]
    judges: tuple[ResolvedIdentity, ...]
    refusals: tuple[str, ...]
    same_provider_allowed: tuple[str, ...]
    allow_same_provider_judge: bool

    def to_record(self) -> dict:
        return {"ok": self.ok, "rule": "judge_is_not_monitored_agent",
                "allow_same_provider_judge": self.allow_same_provider_judge,
                "same_provider_allowed": list(self.same_provider_allowed),
                "refusals": list(self.refusals),
                "agents": [a.to_record() for a in self.agents],
                "judges": [j.to_record() for j in self.judges]}


def compare(agent: ResolvedIdentity, judge: ResolvedIdentity) -> tuple[str | None, str | None]:
    """(refusal, same-provider note) for one judge against one agent.

    Refused only when the judge is the same agent: a shared credential, a shared
    tenant id, or the same normalized model on a shared normalized endpoint.
    Unresolved is a refusal (fail closed). The same provider is allowed and noted.
    """
    who = f"judge {judge.id!r} vs agent {agent.id!r}"
    shared = (agent.credentials & judge.credentials) - {NO_CREDENTIAL}
    if shared:
        return f"{who}: same credential fingerprint", None
    tenants = agent.tenants & judge.tenants
    if tenants:
        return f"{who}: same tenant {sorted(tenants)[0]!r}", None
    if agent.unresolved or judge.unresolved:
        side = "agent" if agent.unresolved else "judge"
        return (f"{who}: {side} upstream unresolved (unrecognized router or host, or a local endpoint whose "
                f"model names no known maker); treated as a match (declare upstream: to name it)"), None
    common = agent.upstreams & judge.upstreams
    if agent.model == judge.model and common:
        return f"{who}: same model {judge.model!r} on the same endpoint {sorted(common)[0]}", None
    if agent.model == judge.model:
        return None, f"{who}: same model {judge.model!r} on a different endpoint"
    if common or agent.endpoint == judge.endpoint:
        where = sorted(common)[0] if common else agent.endpoint
        return None, f"{who}: same provider {where} with a different model"
    return None, None


def check_separation(agents: Sequence[ResolvedIdentity], judges: Sequence[ResolvedIdentity],
                     allow_same_provider_judge: bool = False) -> SeparationReport:
    """Refuse a judge that is the monitored agent. ``allow_same_provider_judge`` is a deprecated no-op."""
    if not agents:
        raise IdentityError("monitored_agent_required: declare the monitored agent (monitored_agent: model, provider, base_url, "
                            "credential_env) whenever judges are configured")
    refusals, same = [], []
    for a in agents:
        for j in judges:
            refusal, note = compare(a, j)
            if refusal:
                refusals.append(refusal)
            elif note:
                same.append(note)
    report = SeparationReport(not refusals, tuple(agents), tuple(judges), tuple(refusals), tuple(same),
                              allow_same_provider_judge)
    if refusals:
        raise IdentityError("judge_matches_agent: a judge could be the monitored agent: " + "; ".join(refusals))
    if allow_same_provider_judge:
        print("two-key: allow_same_provider_judge is deprecated and has no effect; "
              "the same provider is allowed by default", file=sys.stderr)
    return report


def load_monitored_agent(data: Mapping[str, Any] | None) -> AgentDeclaration | None:
    """The ``monitored_agent:`` block of a judges config, if present."""
    if not isinstance(data, Mapping) or data.get("monitored_agent") is None:
        return None
    return AgentDeclaration.from_mapping(data["monitored_agent"])


def load_monitored_agent_file(path) -> AgentDeclaration | None:
    from pathlib import Path
    import json
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    data = json.loads(text) if path.suffix.lower() == ".json" else __import__("yaml").safe_load(text)
    return load_monitored_agent(data)
