FROM devtestdemisto/python3:3.8.6.13358-f106b04b4c2c1556ff556d9f2a6b2ecf
RUN mkdir -p /devwork/
WORKDIR /devwork
RUN update-ca-certificates
COPY . .
RUN chown -R :4000 /devwork
RUN chmod -R 775 /devwork
