TARGETS = importrra servicelib serviceapi
GO = GOPATH=$(shell pwd):$(shell go env GOROOT)/bin go

all: $(TARGETS)

depends:
	$(GO) get github.com/mattbaird/elastigo
	$(GO) get github.com/lib/pq
	$(GO) get code.google.com/p/gcfg
	$(GO) get github.com/gorilla/context
	$(GO) get github.com/gorilla/mux
	$(GO) get code.google.com/p/go-uuid/uuid

servicelib:
	$(GO) install servicelib

serviceapi:
	$(GO) install serviceapi

importrra:
	$(GO) install importrra

clean:
	rm -f bin/*
	rm -rf pkg/*
