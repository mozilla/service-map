TARGETS = servicelib serviceapi migindicators
GO = GOPATH=$(shell pwd):$(shell go env GOROOT)/bin go

all: $(TARGETS)

depends:
	$(GO) get -u github.com/mattbaird/elastigo
	$(GO) get -u github.com/montanaflynn/stats
	$(GO) get -u github.com/lib/pq
	$(GO) get -u gopkg.in/gcfg.v1
	$(GO) get -u github.com/gorilla/context
	$(GO) get -u github.com/gorilla/mux
	$(GO) get -u github.com/pborman/uuid
	$(GO) get -u github.com/jvehent/gozdef
	$(GO) get -u github.com/ameihm0912/http-observatory-go
	$(GO) get -u mig.ninja/mig
	$(GO) get -u mig.ninja/mig/client

servicelib:
	$(GO) install servicelib

serviceapi:
	$(GO) install serviceapi

migindicators:
	$(GO) install migindicators

clean:
	rm -f bin/*
	rm -rf pkg/*
	rm -f python/pyservicelib/pyservicelib/*.pyc
