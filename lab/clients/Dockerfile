# lab/clients/Dockerfile — obraz soho-lab/bg-client:1
# Bez CMD: obraz startuje jak bazowy (ENTRYPOINT /etc/alpinet-init.sh)
FROM nazdridoy/alpinet@sha256:804fef43f3ec90d31c039bc689c0cca1a658767bbc8244cbe96908a17b681c59
COPY bg.sh beacon.sh /usr/local/bin/
RUN sed -i 's/\r$//' /usr/local/bin/bg.sh /usr/local/bin/beacon.sh \
 && chmod +x /usr/local/bin/bg.sh /usr/local/bin/beacon.sh
