GO = GO15VENDOREXPERIMENT=1 go

runtests: gotests

gotests:
	misc/dbinit.sh
	$(GO) test -v -covermode=count -coverprofile=coverage.out github.com/mozilla/service-map/serviceapi
