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


## Deployment
First setup creds in credstash for the functions to use:
The cron function needs oauth creds as per the gspread docs:
https://gspread.readthedocs.io/en/latest/oauth2.html

Store these in credstash as a json blob:
```
credstash  --profile devadmin put serviceapi.gdrive @yourfilename.json app=serviceapi
```
where devadmin is the name of your aws profile in ~/.aws/config specifying where you will be deploying.

Then deploy:

    ```
    pipenv shell
    sls deploy

    ```

## Testing
Get credstash creds for oidc auth:
```
credstash --profile devadmin get serviceapi.oidc_client_secret app=serviceapi
credstash --profile devadmin get serviceapi.oidc_client_id app=serviceapi
```

Set env variables:
```
export API_URL="https://serviceapi.security.allizom.org"
export CLIENT_ID = value from above
export CLIENT_SECRET =  value from above
```
and run pytest