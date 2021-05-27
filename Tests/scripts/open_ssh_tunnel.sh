# Generating the ips and ports with the following form: <instance-ip> <tunnel-port>
IPS_AND_PORTS=$(cat $ENV_RESULTS_PATH | jq ".[] | select(.Role==\"$INSTANCE_ROLE\")" | jq -r '[.InstanceDNS, .TunnelPort] | @tsv' | sed "s/\"//g")
# Handling the ip & port pairs line by line
echo $IPS_AND_PORTS | grep -o -E "[0-9\.]+ [0-9]{4}" | while read IP_AND_PORT;
do
  # Capturing the IP
  IP=$(echo $IP_AND_PORT | grep -o -E "10\.0\.[0-9]{1,3}\.[0-9]{1,3}")
  # Capturing the port
  PORT=$(echo $IP_AND_PORT | grep -o -E "[0-9]{4}")
  echo "Opening a tunnel for ip $IP with port $PORT"
  ssh -4 -o "ServerAliveInterval=15" -f -N "content-build@content-build-lb.demisto.works" -L "$PORT:$IP:443" # disable-secrets-detection
  echo "Waiting for tunnel to be established"
  until nc -z 127.0.0.1 $PORT -v; do
    if [[ $COUNT -ge 20 ]]; then
      echo "ssh tunnel set up timeout on instance with ip $IP";
      exit 1;
    fi;
    ((COUNT++))
    sleep 1
  done
done
