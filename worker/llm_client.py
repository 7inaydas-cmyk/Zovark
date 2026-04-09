"""
Singleton LLM client with dual-role concurrency control.

Provides a shared httpx.AsyncClient and split semaphores for FAST and CODE roles:
  - _fast_semaphore(1): tool selection (FAST model, short requests)
  - _code_semaphore(1): assessment (CODE model, longer reasoning)

On dev tier (single container, --parallel 2): prevents GPU contention.
On customer tier (dual containers): each semaphore maps to a different GPU.

Path A investigations (no LLM) bypass this entirely.
"""
import asyncio
import os
import re
import time
import logging

import httpx

logger = logging.getLogger(__name__)

try:
    from settings import settings as _settings
    _BASE_URL = _settings.llm_base_url
except ImportError:
    _BASE_URL = os.environ.get("ZOVARK_LLM_BASE_URL", "http://zovark-inference:8080")

# Dual-endpoint support: separate FAST and CODE base URLs
_FAST_BASE_URL = os.environ.get("ZOVARK_LLM_ENDPOINT_FAST", "").replace("/v1/chat/completions", "").rstrip("/") or _BASE_URL
_CODE_BASE_URL = os.environ.get("ZOVARK_LLM_ENDPOINT_CODE", "").replace("/v1/chat/completions", "").rstrip("/") or _BASE_URL
_IS_SPLIT_ENDPOINT = _FAST_BASE_URL != _CODE_BASE_URL

# Client pool keyed by base URL
_clients: dict[str, httpx.AsyncClient] = {}
_fast_semaphore = asyncio.Semaphore(1)  # FAST role: tool selection, param fill
_code_semaphore = asyncio.Semaphore(1)  # CODE role: assessment, summary

# Health state for graceful degradation
_code_endpoint_healthy = True
_code_health_failures = 0
_CODE_FAILURE_THRESHOLD = 3  # Fall back to FAST after N consecutive failures

# Per-role sampling configs (Agent 4)
SAMPLING_CONFIGS = {
    "param_fill":  {"temperature": 0.0, "top_p": 1.0, "top_k": 1},
    "tool_select": {"temperature": 0.1, "top_p": 0.9, "top_k": 40},
    "verdict":     {"temperature": 0.1, "top_p": 0.9, "top_k": 40},
    "summary":     {"temperature": 0.3, "top_p": 0.95, "top_k": 50},
}

# Grammar cache (Agent 3)
_GRAMMAR_DIR = os.path.join(os.path.dirname(__file__), "grammars")
_grammar_cache: dict[str, str | None] = {}


def _load_grammar(name: str) -> str | None:
    """Load a GBNF grammar file. Returns None if not found."""
    if name not in _grammar_cache:
        path = os.path.join(_GRAMMAR_DIR, f"{name}.gbnf")
        try:
            with open(path) as f:
                _grammar_cache[name] = f.read()
        except FileNotFoundError:
            _grammar_cache[name] = None
    return _grammar_cache[name]


# --- LLM output sanitizer (model-agnostic, defense in depth) ---
# Strips control tokens that may leak into grammar-constrained output.
# Gemma 4 26B thinking tokens can leak INSIDE JSON string values when using
# GBNF grammar (because `<`, `c`, `h` etc. are valid string characters and
# the grammar doesn't constrain content inside string values).
# Observed corruption: `<channel|>thought\n<channel|>...` inside JSON strings.
_CONTROL_TOKEN_RE = re.compile(
    r'<channel\|>[^"]*?<channel\|>'      # Gemma 4 paired channel thinking (inside strings)
    r'|<channel\|>[^"]*'                 # Unpaired channel markers (cleanup tail)
    r'|<\|channel>.*?<channel\|>'        # Legacy format (kept for compat)
    r'|<think>.*?</think>'               # <think> tags (some Gemma variants)
    r'|<\|think\|>'                      # Thinking trigger token
    r'|\[<\|"\|>\]'                      # Tool call corruption (llama.cpp issue #21316)
    r'|<\|turn\|>'                       # Turn markers
    r'|<\|"\|>',                         # Quote token corruption
    re.DOTALL
)


def _sanitize_llm_output(text: str) -> str:
    """Strip control tokens that may leak into grammar-constrained output."""
    cleaned = _CONTROL_TOKEN_RE.sub('', text).strip()
    if cleaned != text:
        logger.warning(
            "LLM output contained control tokens — sanitized",
            extra={"original_len": len(text), "cleaned_len": len(cleaned)},
        )
    return cleaned


def _make_client(base_url: str) -> httpx.AsyncClient:
    # CODE endpoint (Ollama with 31B) needs longer read timeout:
    # thinking tokens + generation can take 60-120s on first request
    is_code = _IS_SPLIT_ENDPOINT and base_url == _CODE_BASE_URL
    read_timeout = 300.0 if is_code else 120.0
    return httpx.AsyncClient(
        base_url=base_url,
        timeout=httpx.Timeout(connect=10.0, read=read_timeout, write=5.0, pool=10.0),
    )


def get_client(base_url: str | None = None) -> httpx.AsyncClient:
    """Get or create an httpx.AsyncClient for the given base URL."""
    url = base_url or _BASE_URL
    existing = _clients.get(url)
    if existing is None or existing.is_closed:
        _clients[url] = _make_client(url)
    return _clients[url]


async def llm_request(
    model: str,
    messages: list[dict],
    temperature: float = 0.1,
    max_tokens: int = 4096,
    stage: str = "unknown",
    response_format: dict | None = None,
    role: str = "tool_select",
    grammar_name: str | None = None,
) -> dict:
    """Make an LLM request through semaphore-controlled singleton client.

    Args:
        role: LLM role — "param_fill", "tool_select", "verdict", "summary".
              Controls which semaphore (fast vs code) and sampling config.
        grammar_name: GBNF grammar file name (without .gbnf). None = no grammar.

    Returns the raw response JSON from the /v1/chat/completions endpoint.
    """
    global _code_endpoint_healthy, _code_health_failures

    # Determine if this request needs the CODE endpoint.
    # Route by role (verdict/summary) OR by model name (Path C tool selection
    # uses MODEL_CODE because the bigger model handles novel attack types better).
    _MODEL_CODE = os.environ.get("ZOVARK_MODEL_CODE", "")
    is_code_role = role in ("verdict", "summary")
    is_code_model = _MODEL_CODE and model == _MODEL_CODE
    needs_code = is_code_role or is_code_model
    sem = _code_semaphore if needs_code else _fast_semaphore

    # Endpoint routing: CODE needs → CODE endpoint (with degradation fallback)
    if needs_code and _IS_SPLIT_ENDPOINT and _code_endpoint_healthy:
        target_base = _CODE_BASE_URL
    else:
        target_base = _FAST_BASE_URL
        if needs_code and _IS_SPLIT_ENDPOINT and not _code_endpoint_healthy:
            logger.warning(f"CODE endpoint degraded — falling back to FAST for {role}/{model}")

    # Merge role-based sampling config
    sampling = SAMPLING_CONFIGS.get(role, SAMPLING_CONFIGS["tool_select"])

    async with sem:
        client = get_client(target_base)
        start = time.perf_counter()

        # When routing to CODE endpoint (Ollama), ensure the model name
        # matches what Ollama has loaded. The pipeline may pass generic
        # names like "zovark-standard" from model_router.
        effective_model = model
        if target_base == _CODE_BASE_URL and _IS_SPLIT_ENDPOINT and _MODEL_CODE:
            effective_model = _MODEL_CODE

        body = {
            "model": effective_model,
            "messages": messages,
            "temperature": temperature if temperature != 0.1 else sampling["temperature"],
            "max_tokens": max_tokens,
            "keep_alive": "30m",
        }
        if sampling.get("top_k"):
            body["top_k"] = sampling["top_k"]
        if response_format:
            body["response_format"] = response_format

        # Grammar-constrained decoding (Agent 3)
        # Both FAST and CODE endpoints are llama-server — GBNF works on both.
        if grammar_name:
            grammar_text = _load_grammar(grammar_name)
            if grammar_text:
                body["grammar"] = grammar_text
                # Remove response_format when using grammar — they conflict
                body.pop("response_format", None)
        else:
            # Prose output (no grammar): disable Gemma 4 thinking so content
            # goes to content field instead of reasoning_content.
            # With grammar, the model needs thinking to select the right tools.
            body["reasoning_effort"] = "none"

        # OTEL span
        _span = None
        try:
            from tracing import get_tracer
            _span = get_tracer().start_span("llm.call")
            _span.set_attribute("llm.model", model)
            _span.set_attribute("llm.stage", stage)
            _span.set_attribute("llm.role", role)
            _span.set_attribute("llm.grammar_used", grammar_name is not None)
        except Exception:
            pass

        try:
            response = await client.post("/v1/chat/completions", json=body)
            response.raise_for_status()
            duration = round(time.perf_counter() - start, 2)

            result = response.json()
            usage = result.get("usage", {})
            tokens_in = usage.get("prompt_tokens", 0)
            tokens_out = usage.get("completion_tokens", 0)

            # Sanitize control tokens before they reach JSON parsing / Pydantic
            raw_content = result["choices"][0]["message"]["content"]
            sanitized = _sanitize_llm_output(raw_content)
            result["choices"][0]["message"]["content"] = sanitized

            logger.info(f"LLM {model} [{stage}/{role}] {duration}s tokens={tokens_in}/{tokens_out} endpoint={target_base}")

            # Reset CODE health on success
            if needs_code and _IS_SPLIT_ENDPOINT and target_base == _CODE_BASE_URL:
                _code_endpoint_healthy = True
                _code_health_failures = 0

            if _span:
                try:
                    _span.set_attribute("llm.tokens_in", tokens_in)
                    _span.set_attribute("llm.tokens_out", tokens_out)
                    _span.set_attribute("llm.e2e_ms", int(duration * 1000))
                    _span.set_attribute("llm.success", True)
                    _span.end()
                except Exception:
                    pass

            return result

        except httpx.TimeoutException as e:
            duration = round(time.perf_counter() - start, 2)
            logger.error(f"LLM {model} [{stage}/{role}] timed out after {duration}s endpoint={target_base}")
            # Track CODE endpoint failures for graceful degradation
            if needs_code and _IS_SPLIT_ENDPOINT and target_base == _CODE_BASE_URL:
                _code_health_failures += 1
                if _code_health_failures >= _CODE_FAILURE_THRESHOLD:
                    _code_endpoint_healthy = False
                    logger.warning(f"CODE endpoint marked unhealthy after {_code_health_failures} failures — degrading to FAST")
            if _span:
                try:
                    _span.set_attribute("llm.success", False)
                    _span.set_attribute("llm.e2e_ms", int(duration * 1000))
                    _span.record_exception(e)
                    _span.end()
                except Exception:
                    pass
            raise

        except httpx.HTTPStatusError as e:
            logger.error(f"LLM {model} [{stage}/{role}] returned {e.response.status_code}")
            if _span:
                try:
                    _span.set_attribute("llm.success", False)
                    _span.record_exception(e)
                    _span.end()
                except Exception:
                    pass
            raise


async def close_client():
    """Close all clients (call on shutdown)."""
    for url, client in list(_clients.items()):
        if client and not client.is_closed:
            await client.aclose()
    _clients.clear()


async def check_endpoint_health():
    """Check LLM endpoint health on startup. Log status for each endpoint."""
    global _code_endpoint_healthy, _code_health_failures

    endpoints = [("FAST", _FAST_BASE_URL)]
    if _IS_SPLIT_ENDPOINT:
        endpoints.append(("CODE", _CODE_BASE_URL))
    else:
        logger.info(f"LLM endpoints: FAST=CODE={_FAST_BASE_URL} (single endpoint mode)")

    for label, base_url in endpoints:
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(connect=5.0, read=10.0)) as c:
                # Try /health (llama.cpp) then /v1/models (OpenAI compat)
                for path in ["/health", "/v1/models"]:
                    try:
                        resp = await c.get(f"{base_url}{path}")
                        if resp.status_code == 200:
                            logger.info(f"LLM {label} endpoint healthy: {base_url} ({path})")
                            break
                    except Exception:
                        continue
                else:
                    logger.warning(f"LLM {label} endpoint unreachable: {base_url}")
                    if label == "CODE":
                        _code_endpoint_healthy = False
                        logger.warning("CODE endpoint down on startup — will use FAST for all roles")
        except Exception as e:
            logger.warning(f"LLM {label} health check failed: {e}")
            if label == "CODE":
                _code_endpoint_healthy = False
