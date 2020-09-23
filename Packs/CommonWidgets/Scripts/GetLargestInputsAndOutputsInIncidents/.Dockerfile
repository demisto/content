FROM devtestdemisto/python3:3.8.5.10845-0c3f8b95d9a8e26a53ac51c66de1adde
RUN mkdir -p /devwork/
WORKDIR /devwork
RUN update-ca-certificates
COPY . .
RUN chown -R :4000 /devwork
RUN chmod -R 775 /devwork
