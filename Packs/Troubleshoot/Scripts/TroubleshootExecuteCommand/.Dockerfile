FROM devtestdemisto/python3:3.9.1.14969-5efee03f201dacbfb9f667026a6539f0
RUN mkdir -p /devwork/
WORKDIR /devwork
RUN update-ca-certificates
COPY . .
RUN chown -R :4000 /devwork
RUN chmod -R 775 /devwork
