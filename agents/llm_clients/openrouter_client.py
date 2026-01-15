from openai import OpenAI


class OpenRouterClient:
    """
    OpenRouter client for planner LLMs.
    """

    def __init__(
        self,
        api_key: str,
        model: str = "google/gemma-3n-e2b-it:free",
    ):
        self.client = OpenAI(
            api_key=api_key,
            base_url="https://openrouter.ai/api/v1",
        )
        self.model = model

    def complete(self, prompt: str) -> str:
        response = self.client.chat.completions.create(
    model=self.model,
    messages=[
        {
            "role": "user",
            "content": (
                "You are a security scan planner.\n"
                "You MUST return ONLY valid JSON matching the schema.\n\n"
                + prompt
            ),
        }
    ],
    temperature=0.1,
)


        return response.choices[0].message.content.strip()
