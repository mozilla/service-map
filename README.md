service-map
===========

Service map is a set of micro serverless services that marry
- Services
- Their risk levels
- Indicators about the security posture of the service
- Various control metrics

into an ongoing risk score for each service based on what we know about it.

## Architecture
The goal is to use as little servers, containers, etc as possible and rely on serverless tech such as lambda and dynamodb to focus on the business logic rather than the infra.



