FROM devtestdemisto/python3:3.9.6.22912-c45ba6dc17360bd02df996098d3eefc7
RUN mkdir -p /devwork/
WORKDIR /devwork
RUN update-ca-certificates
COPY . .
RUN chown -R :4000 /devwork
RUN chmod -R 775 /devwork
