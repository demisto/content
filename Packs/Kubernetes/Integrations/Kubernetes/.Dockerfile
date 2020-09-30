FROM devtestkubernetes:latest-306e9fff32510c15fe5e4455d4f2e981
RUN mkdir -p /devwork/
WORKDIR /devwork
RUN update-ca-certificates
COPY . .
RUN chown -R :4000 /devwork
RUN chmod -R 775 /devwork
