FROM devtestdemisto/python3:3.8.6.13358-0b85e6c26fa6882633cd4ddbf1cc04d3
RUN mkdir -p /devwork/
WORKDIR /devwork
RUN update-ca-certificates
COPY . .
RUN chown -R :4000 /devwork
RUN chmod -R 775 /devwork
