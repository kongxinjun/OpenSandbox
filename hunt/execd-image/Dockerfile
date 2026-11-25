FROM busybox:latest
COPY execd /execd
COPY opensandbox-supervisor /opensandbox-supervisor
COPY bootstrap.sh /bootstrap.sh
RUN chmod 0755 /execd /opensandbox-supervisor /bootstrap.sh
WORKDIR /
ENTRYPOINT ["/execd"]
