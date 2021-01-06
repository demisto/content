FROM devtestdemisto/oauthlib:1.0.0.13983-20ea043466c45f9962197f46402e489c
RUN mkdir -p /devwork/
WORKDIR /devwork
RUN update-ca-certificates
COPY . .
RUN chown -R :4000 /devwork
RUN chmod -R 775 /devwork
