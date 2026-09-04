"""Externalised prompt loading."""

from vulnintel.prompts.registry import Prompt, PromptError, PromptRegistry, get_prompt, get_registry

__all__ = ["Prompt", "PromptError", "PromptRegistry", "get_prompt", "get_registry"]
