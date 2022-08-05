FROM devdemisto/content-dev

ADD create_certs.sh .
RUN apt-get update && apt-get install dos2unix -y \
    && dos2unix /create_certs.sh \
    && chmod +x /create_certs.sh \ 
    && /create_certs.sh /usr/local/share/ca-certificates/certs.crt \
    && update-ca-certificates

ENV NODE_EXTRA_CA_CERTS /usr/local/share/ca-certificates/certs.crt

