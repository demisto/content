FROM docker.io/raftt/dev:ubuntu-latest

COPY dev/cmds.sh /code/dev/cmds.sh
RUN printf 'source /code/dev/cmds.sh\nsource /code/dev/env\n' >> /root/.raftt_profile && \
    printf 'source /root/.raftt_profile\n' >> /root/.bash_profile && \
    printf 'source /root/.raftt_profile\n' >> /root/.bashrc
