FROM mcr.microsoft.com/playwright:v1.52.0-noble

WORKDIR /app

# Install international fonts for proper non-Latin script rendering
RUN apt-get update && apt-get install -y --no-install-recommends \
    fonts-noto-cjk \
    fonts-noto-color-emoji \
    fonts-noto \
    fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

# Copy package files and install dependencies
COPY package*.json ./
RUN npm ci --production

# Copy compiled TypeScript output
COPY dist/ ./dist/

# Create screenshots directory
RUN mkdir -p /app/screenshots

# Memory and Chrome optimizations
ENV NODE_OPTIONS="--max-old-space-size=512"
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
ENV SCREENSHOT_DIR=/app/screenshots

ENTRYPOINT ["node", "dist/index.js"]
