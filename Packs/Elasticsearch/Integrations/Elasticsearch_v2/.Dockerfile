FROM devtestdemisto/elasticsearch:1.0.0.12410-8ac94271d7cec120e6aaa729a7f3c87c
RUN mkdir -p /devwork/
WORKDIR /devwork
RUN update-ca-certificates
COPY . .
RUN chown -R :4000 /devwork
RUN chmod -R 775 /devwork
