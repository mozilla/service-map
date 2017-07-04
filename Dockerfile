FROM ubuntu:xenial

RUN apt-get update && \
	apt-get -y install golang net-tools git sudo curl

RUN cd /root && \
	curl -OL https://github.com/Yelp/dumb-init/releases/download/v1.2.0/dumb-init_1.2.0_amd64.deb && \
	dpkg -i dumb-init_1.2.0_amd64.deb

RUN groupadd serviceapi && useradd -g serviceapi -m serviceapi && \
	mkdir -p /home/serviceapi/go/src/github.com/mozilla

ADD . /home/serviceapi/go/src/github.com/mozilla/service-map
RUN chown -R serviceapi:serviceapi /home/serviceapi/go
RUN cp /home/serviceapi/go/src/github.com/mozilla/service-map/etc/serviceapi.conf \
	/etc/serviceapi.conf
USER serviceapi
RUN export GOPATH=/home/serviceapi/go && \
	go install github.com/mozilla/service-map/servicelib && \
	go install github.com/mozilla/service-map/serviceapi

EXPOSE 8080
WORKDIR /home/serviceapi
CMD chmod 755 /home/serviceapi/go/src/github.com/mozilla/service-map/scripts/start.sh && \
	/home/serviceapi/go/src/github.com/mozilla/service-map/scripts/start.sh
