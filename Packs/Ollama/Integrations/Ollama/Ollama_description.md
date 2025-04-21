
## Ollama
This section explains how to configure the instance of Ollama in Cortex XSOAR:
- **Name:** Name of the integration instance
- **Protocol:** HTTP or HTTPS
- **Server hostname or IP:** The domain or IP of the Ollama instance
- **Port:** Ollama's default port is `11434`
- **Path:** Ollama's default api path is `/api`
- **Cloudflare Access Client ID:** If Ollama is running behind Cloudflare's ZeroTrust, enter the service account client ID 
- **Cloudflare Access Client Secret:** If Ollama is running behind Cloudflare's ZeroTrust, enter the service account client secret key
- **Default Model:** Many commands allow you to specify what model to use. The value entered here will be used if no model is specified in the command

## Install Ollama
Get the latest version for MacOS, Windows, Linux or Docker from Ollama's [official website](https://ollama.com/).

## Model names
Model names follow a `model:tag` format, where `model` can have an optional namespace such as `example/model`. Some examples are `orca-mini:3b-q4_1` and `llama2:70b`. The tag is optional and, if not provided, will default to `latest`. The tag is used to identify a specific version.

See the list of available models [here](https://ollama.com/library).

---
[View Ollama's API Documentation](https://github.com/ollama/ollama/blob/main/docs/api.md)