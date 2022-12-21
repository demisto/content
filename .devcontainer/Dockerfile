FROM python:3.10-slim-bullseye

ENV USERNAME demisto
ENV HOME /home/$USERNAME
ENV POETRY_HOME $HOME/.poetry
ENV NODE_EXTRA_CA_CERTS /usr/local/share/ca-certificates/certs.crt
ENV PATH $PATH:$HOME/.local/bin:/root/.local/bin:/usr/local/share/nvm/current/bin

ADD createCerts.sh .
RUN apt-get update && apt-get install dos2unix git python2 -y \
    && dos2unix /createCerts.sh \
    && chmod +x /createCerts.sh \ 
    && /createCerts.sh /usr/local/share/ca-certificates/certs.crt \
    && update-ca-certificates \
    && rm -rf /features \
    && git clone https://github.com/devcontainers/features.git /features \
    && cd /features \
    && git checkout 42e5a013cc914f87d0ff7bf613a1f80d9ff57579

# This is a workaround for VSCode devcontainer features in self signed certificate
RUN UID="1000" GID="1000" bash /features/src/common-utils/install.sh
RUN VERSION="os-provided" bash /features/src/git/install.sh
RUN VERSION="latest" bash /features/src/docker-in-docker/install.sh
RUN VERSION="lts" bash /features/src/node/install.sh

# install poetry, configure certificate for git and tools for oh my zsh
RUN chown -R $USERNAME $HOME \
    && curl -sSL https://install.python-poetry.org | python3 - \
    && python -m pip install --user pipx \
    && python -m pipx ensurepath \
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
