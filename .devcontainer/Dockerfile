FROM python:3.10-slim-bullseye

ADD create_certs.sh .
RUN apt-get update && apt-get install dos2unix -y \
    && dos2unix /create_certs.sh \
    && chmod +x /create_certs.sh \ 
    && /create_certs.sh /usr/local/share/ca-certificates/certs.crt \
    && update-ca-certificates \
    && apt-get install python2 -y

ENV USERNAME demisto
ENV HOME /home/$USERNAME
ENV NODE_EXTRA_CA_CERTS /usr/local/share/ca-certificates/certs.crt
ENV PATH $PATH:$HOME/.local/bin:/root/.local/bin

# This is a workaround for VSCode devcontainer features in self signed certificate

ADD https://raw.githubusercontent.com/devcontainers/features/main/src/common-utils/install.sh /install-common.sh
ADD https://raw.githubusercontent.com/devcontainers/features/main/src/git/install.sh /install-git.sh
ADD https://raw.githubusercontent.com/devcontainers/features/main/src/docker-in-docker/install.sh /install-dind.sh
ADD https://raw.githubusercontent.com/devcontainers/features/main/src/node/install.sh /install-node.sh
ADD https://raw.githubusercontent.com/devcontainers/features/main/src/powershell/install.sh /install-powershell.sh

RUN UID="4000" GID="4000" bash install-common.sh 
RUN VERSION="os-provided" bash install-git.sh
RUN VERSION="latest" bash install-dind.sh
RUN VERSION="latest" bash install-node.sh
RUN VERSION="latest" bash install-powershell.sh

# install poetry, configure certificate for git and tools for oh my zsh
RUN curl -sSL https://install.python-poetry.org | python3 - \
    && python -m pip install --user pipx \
    && python -m pipx ensurepath \
    && git config --global http.sslCAInfo /usr/local/share/ca-certificates/certs.crt \
    && git clone https://github.com/zsh-users/zsh-syntax-highlighting.git $HOME/.zsh/zsh-syntax-highlighting \
    && echo "source ~/.zsh/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh" >> $HOME/.zshrc \
    && git clone https://github.com/zsh-users/zsh-autosuggestions $HOME/.zsh/zsh-autosuggestions \
    && echo "source ~/.zsh/zsh-autosuggestions/zsh-autosuggestions.zsh" >> $HOME/.zshrc

VOLUME [ "/var/lib/docker" ]

# Setting the ENTRYPOINT to docker-init.sh will start up the Docker Engine 
# inside the container "overrideCommand": false is set in devcontainer.json. 
# The script will also execute CMD if you need to alter startup behaviors.
ENTRYPOINT [ "/usr/local/share/docker-init.sh" ]
CMD [ "sleep", "infinity" ]
