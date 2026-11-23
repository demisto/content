To use the common OpenAI integration logic, import the `OpenAiChatGPTApiModule` and call its entry point.

```python
def main():
    run_openai_integration()


from OpenAiChatGPTApiModule import *  # noqa: E402

if __name__ in ["builtins", "__main__"]:
    main()
```

The `run_openai_integration` entry point and the `OpenAiClient` class are then available. For the canonical consumer, see the `OpenAI GPT` integration.
