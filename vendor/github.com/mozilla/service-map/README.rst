service-map
===========

service-map is a tool set which collects risk analysis data in addition to
various control metrics, and combines this on an on-going basis to produce
risk scores associated with services.

serviceapi
----------

API service responsible for integrating with data sources and the backend
Postgres database. This is the primary component of the service.

serviceui
---------

Small Flask interface that can be used to view data managed in serviceapi.
