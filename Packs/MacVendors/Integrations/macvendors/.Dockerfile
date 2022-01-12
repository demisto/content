FROM devtestdemisto/python3:3.9.7.24076-c36e172608fc3d346af0d9532cc4a7db
RUN mkdir -p /devwork/
WORKDIR /devwork
RUN update-ca-certificates
COPY . .
RUN chown -R :4000 /devwork
RUN chmod -R 775 /devwork
