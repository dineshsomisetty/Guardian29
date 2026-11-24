"""LLM access for Guardian agents.

Package map:
    provider.py   LLMProvider (live / record / replay + response cache) over two backends: the Anthropic SDK and
                  any OpenAI-compatible endpoint (DeepSeek, local models). Agents depend only on
                  `LLMProvider.complete_json(agent, system, user, schema)` and on the error classes there.

Prompt text lives in guardian/prompts/*.md; grounding of what comes back is in guardian/guardrails/grounding.py.
"""