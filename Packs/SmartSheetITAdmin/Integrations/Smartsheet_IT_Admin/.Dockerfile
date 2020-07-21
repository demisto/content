FROM devtestdemisto/smartsheet1:latest-8fb10fab6efb0bd04500f57a34723a5c
RUN mkdir -p /devwork/
WORKDIR /devwork
COPY . .
RUN chown -R :4000 /devwork
RUN chmod -R 775 /devwork
