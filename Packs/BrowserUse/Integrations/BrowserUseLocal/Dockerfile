# Suggested Dockerfile for the `demisto/browser-use` image used by the
# Browser Use Local integration. Submit upstream to demisto/dockerfiles to
# generate `demisto/browser-use:1.0.0.<build>`.
#
# The image must contain Chromium + Playwright + the open-source `browser-use`
# library and the LLM client SDKs we want to support out of the box.

FROM mcr.microsoft.com/playwright/python:v1.49.0-jammy

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Pin everything that gets imported by the integration. Bump in lockstep with
# upstream releases. browser-use itself bundles its own Playwright bindings;
# we still install Chromium so it is guaranteed available offline.
RUN pip install --upgrade pip \
 && pip install \
        "browser-use==0.3.*" \
        "anthropic==0.39.*" \
        "google-generativeai==0.8.*" \
        "openai==1.55.*" \
        "pydantic==2.*"

# Install the Chromium browser binary Playwright will drive.
RUN playwright install chromium --with-deps

# Drop privileges (matches the rest of the demisto/* images).
RUN useradd -m demisto
USER demisto
WORKDIR /home/demisto
