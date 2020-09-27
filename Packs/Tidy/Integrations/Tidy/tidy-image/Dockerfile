
FROM demisto/python3:3.8.5.10845

COPY requirements.txt /requirements.txt


RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git linux-headers libffi-dev openssl-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies


RUN echo "===> Installing sudo to emulate normal OS behavior..."  && \
    apk --update add sudo                                         && \
    \
    \
    echo "===> Adding Python runtime..."  && \
    apk --update add python3 openssl ca-certificates    && \
    apk --update add --virtual build-dependencies python3-dev libffi-dev openssl-dev build-base  && \
    \
    \
    echo "===> Installing handy tools (not absolutely required)..."  && \
    apk --update add sshpass openssh-client rsync  && \
    \
    \
    echo "===> Removing package list..."  && \
    apk del build-dependencies            && \
    rm -rf /var/cache/apk/*               && \
    \
    \
    echo "===> Adding hosts for convenience..."  && \
    mkdir -p /etc/ansible                        && \
    echo 'localhost' > /etc/ansible/hosts && \
    \
    \
    echo "===> Adding Roles using ansible-galaxy..."  && \
    # Pyenv
    ansible-galaxy install -c geerlingguy.homebrew && \
    ansible-galaxy install -c ctorgalson.oh-my-zsh,v2.2.2 && \
    ansible-galaxy install -c pddg.anyenv && \
    ansible-galaxy install -c sawatani.github_ssh

