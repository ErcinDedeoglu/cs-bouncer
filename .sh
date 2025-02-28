repomix --no-file-summary --no-security-check \
  --include "src/**,docker-compose.yml" \
  --output "repopack.yml"


docker build -t dublok/cs-bouncer:latest -f src/Dockerfile src

# MANUAL API KEY
docker run -d \
 --name cs-bouncer \
 --network internal \
 --cap-add NET_ADMIN --privileged \
 -e CROWDSEC_API_KEY="YOUR_EXISTING_API_KEY" \
 -e CROWDSEC_URL="http://crowdsec:8080/v1/decisions" \
 -e SYNC_INTERVAL_SEC="60" \
 cs-bouncer

# AUTO GENERATE API KEY
docker run -d \
 --name cs-bouncer \
 --network internal \
 --cap-add NET_ADMIN \
 --privileged \
 -v /var/run/docker.sock:/var/run/docker.sock \
 -e AUTO_GENERATE_API_KEY="true" \
 -e CROWDSEC_CONTAINER_NAME="crowdsec" \
 -e CROWDSEC_URL="http://crowdsec:8080/v1/decisions" \
 -e SYNC_INTERVAL_SEC="60" \
 cs-bouncer

# CROWDSEC_API_KEY: CrowdSec API key obtained earlier.
# CROWDSEC_URL: API URL pointing to crowdsec endpoint.
# SYNC_INTERVAL_SEC: How frequently (in seconds) the bouncer syncs firewall rules with CrowdSec.