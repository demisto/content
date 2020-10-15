FROM devtestdemisto/python3:3.8.3.8715-00c8a40f12d07b8164a5cc3b85d9e121
RUN mkdir -p /devwork/
WORKDIR /devwork
RUN update-ca-certificates
COPY . .
RUN chown -R :4000 /devwork
RUN chmod -R 775 /devwork
