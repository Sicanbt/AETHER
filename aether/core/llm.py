from aether.core.config import AetherConfig


async def call_llm(config: AetherConfig, prompt: str, system: str = "You are a security expert.") -> str:
    """Unified LLM caller for AETHER agents."""
    if config.model.startswith("openai/") or config.model.startswith("gpt"):
        return await _call_openai(config, prompt, system)
    elif config.model.startswith("anthropic/") or config.model.startswith("claude"):
        return await _call_anthropic(config, prompt, system)
    raise ValueError(f"Unsupported model: {config.model}")


async def _call_openai(config: AetherConfig, prompt: str, system: str) -> str:
    from openai import AsyncOpenAI
    client = AsyncOpenAI(api_key=config.openai_api_key)
    model = config.model.replace("openai/", "")
    resp = await client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ],
    )
    return resp.choices[0].message.content


async def _call_anthropic(config: AetherConfig, prompt: str, system: str) -> str:
    import anthropic
    client = anthropic.AsyncAnthropic(api_key=config.anthropic_api_key)
    model = config.model.replace("anthropic/", "")
    msg = await client.messages.create(
        model=model,
        max_tokens=4096,
        system=system,
        messages=[{"role": "user", "content": prompt}],
    )
    return msg.content[0].text
