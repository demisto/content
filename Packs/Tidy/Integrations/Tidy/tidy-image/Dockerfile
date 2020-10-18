
FROM demisto/python3:3.8.5.10845


# Install Python requirements
COPY requirements.txt /requirements.txt
RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git linux-headers libffi-dev openssl-dev
RUN pip install --no-cache-dir -r requirements.txt
RUN apk del .build-dependencies

# Installing sudo to emulate normal OS behavior...
RUN apk --update add sudo
RUN apk --update add python3 openssl ca-certificates
RUN apk --update add --virtual build-dependencies python3-dev libffi-dev openssl-dev build-base

# Installing handy tools (not absolutely required)...
RUN apk --update add sshpass openssh-client rsync

# Removing package list...
RUN apk del build-dependencies
RUN rm -rf /var/cache/apk/*

# Adding hosts for convenience...
RUN mkdir -p /etc/ansible
RUN echo 'localhost' > /etc/ansible/hosts

# Ansible roles
RUN ansible-galaxy install -c geerlingguy.homebrew
RUN ansible-galaxy install -c ctorgalson.oh-my-zsh,v2.2.2
RUN ansible-galaxy install -c pddg.anyenv
RUN ansible-galaxy install -c elliotweiser.osx-command-line-tools
COPY ansible /home/demisto/ansible
