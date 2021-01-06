FROM devtestdemisto/luminate:1.0.0.14061-a4d67d42a33f21811f3a60abc5534f5a
RUN mkdir -p /devwork/
WORKDIR /devwork
RUN update-ca-certificates
COPY . .
RUN chown -R :4000 /devwork
RUN chmod -R 775 /devwork
