FROM devtestdemisto/python_pancloud_v2:1.0.0.13988-250f112e58b778de4877069407d210d4
RUN mkdir -p /devwork/
WORKDIR /devwork
RUN update-ca-certificates
COPY . .
RUN chown -R :4000 /devwork
RUN chmod -R 775 /devwork
