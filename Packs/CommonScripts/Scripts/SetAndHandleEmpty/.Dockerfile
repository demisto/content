FROM devtestdemisto/python3:3.8.5.10845-63a8407f8bcb5e912d4ce596a2e86956
RUN mkdir -p /devwork/
WORKDIR /devwork
COPY . .
RUN chown -R :4000 /devwork
RUN chmod -R 775 /devwork
