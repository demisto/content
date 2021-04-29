FROM devtestdemisto/python3:3.8.6.12176-56f7b46d3e822490a371ce2d8cd4a21d
RUN mkdir -p /devwork/
WORKDIR /devwork
RUN update-ca-certificates
COPY . .
RUN chown -R :4000 /devwork
RUN chmod -R 775 /devwork
