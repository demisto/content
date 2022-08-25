FROM python:3.10.6-bullseye

ADD create_certs.sh .
RUN apt-get update && apt-get install dos2unix -y \
    && dos2unix /create_certs.sh \
    && chmod +x /create_certs.sh \ 
    && /create_certs.sh /usr/local/share/ca-certificates/certs.crt \
    && update-ca-certificates

ENV NODE_EXTRA_CA_CERTS /usr/local/share/ca-certificates/certs.crt
ENV PATH /root/.local/bin:$PATH

# install zsh first
RUN apt-get update && apt-get install -y zsh wget \
    && sh -c "$(wget -O- https://github.com/deluan/zsh-in-docker/releases/download/v1.1.2/zsh-in-docker.sh)" -- \
    -p https://github.com/zsh-users/zsh-autosuggestions \
    -p https://github.com/zsh-users/zsh-completions \
    -p https://github.com/zsh-users/zsh-syntax-highlighting

ADD .p10k.zsh /root/.p10k.zsh
ADD .zshrc /root/.zshrc

SHELL [ "/bin/zsh", "-c" ]

RUN apt-get update && apt-get -y --no-install-recommends upgrade && apt-get install \
    git \ 
    gcc \
    nodejs \
    npm \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    make \
    build-essential \
    python3-dev \
    python2-dev \
    python-dev \
    libffi-dev \
    libssl-dev \
    software-properties-common \
    apt-transport-https \
    dpkg-dev \
    libbz2-dev \
    libc6-dev \
    libdb-dev \
    libgdbm-dev \
    libncursesw5-dev \
    libreadline-dev \
    libsqlite3-dev \
    tk-dev \
    xz-utils \
    zlib1g-dev \
    libpq-dev \
    libxml2-dev \
    libxslt1-dev \
    libldap2-dev \ 
    libsasl2-dev \
    -y \
    # poetry, pyenv tools installation
    && curl -fsSL https://install.python-poetry.org | python3 - \
    && curl -fSSL https://pyenv.run | bash \
    && pip install pipx \
    && pipx ensurepath \
    && source ~/.zshrc \
    && python --version \
    && poetry --version \
    && pyenv --version \
    && source ~/.zshrc \
    && npm install -g jsdoc-to-markdown@5.0.3 \
    # install poetry plugin for oh my zsh 
    && poetry completions zsh > $HOME/.oh-my-zsh/custom/plugins/poetry \
    && apt-get autoclean && apt-get clean
