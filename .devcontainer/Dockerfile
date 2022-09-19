FROM mcr.microsoft.com/devcontainers/python:3

ADD create_certs.sh .
RUN apt-get update && apt-get install dos2unix -y \
    && dos2unix /create_certs.sh \
    && chmod +x /create_certs.sh \ 
    && /create_certs.sh /usr/local/share/ca-certificates/certs.crt \
    && update-ca-certificates \
    && apt-get install python2 -y

ENV NODE_EXTRA_CA_CERTS /usr/local/share/ca-certificates/certs.crt
ENV PATH $PATH:/root/.local/bin

# This is a workaround for VSCode devcontainer features in self signed certificate

ADD https://raw.githubusercontent.com/devcontainers/features/main/src/common-utils/install.sh /install-common.sh
ADD https://raw.githubusercontent.com/devcontainers/features/main/src/git/install.sh /install-git.sh
ADD https://raw.githubusercontent.com/devcontainers/features/main/src/docker-in-docker/install.sh /install-dind.sh
ADD https://raw.githubusercontent.com/devcontainers/features/main/src/node/install.sh /install-node.sh
ADD https://raw.githubusercontent.com/devcontainers/features/main/src/powershell/install.sh /install-powershell.sh

RUN USERNAME="root" bash install-common.sh 
RUN VERSION="os-provided" bash install-git.sh
RUN VERSION="latest" bash install-dind.sh
RUN VERSION="latest" bash install-node.sh
RUN VERSION="latest" bash install-powershell.sh

# install poetry, configure certificate for git and tools for oh my zsh
RUN curl -sSL https://install.python-poetry.org | python3 - \
    && git config --global http.sslCAInfo /usr/local/share/ca-certificates/certs.crt \
    && git clone https://github.com/zsh-users/zsh-syntax-highlighting.git ~/.zsh/zsh-syntax-highlighting \
    && echo "source ~/.zsh/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh" >> ~/.zshrc \
    && git clone https://github.com/zsh-users/zsh-autosuggestions ~/.zsh/zsh-autosuggestions \
    && echo "source ~/.zsh/zsh-autosuggestions/zsh-autosuggestions.zsh" >> ~/.zshrc
