import anthropic

from app.config import settings

client = anthropic.Anthropic(api_key=settings.anthropic_api_key)


async def ask_assistant(messages: list[dict]) -> str:
    reply = client.messages.create(model="example-chat-model", max_tokens=1024, messages=messages)
    return reply.content[0].text
