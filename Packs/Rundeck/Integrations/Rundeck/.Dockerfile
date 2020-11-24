FROM devtestdemisto/python3:3.7.6.13358-e72769bca56966d7b32d5c43c0d5bc61
RUN mkdir -p /devwork/
WORKDIR /devwork
RUN update-ca-certificates
COPY . .
RUN chown -R :4000 /devwork
RUN chmod -R 775 /devwork
