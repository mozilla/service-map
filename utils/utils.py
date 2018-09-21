import credstash
import os
import uuid
import yaml
from everett.manager import ConfigManager, ConfigDictEnv, ConfigOSEnv

def get_config():
    """
    Environment/yml config vars:
        API_AUDIENCE
        AUTHO_URL
    """
    # load our config file (if any)
    conf=yaml.load(open(os.environ.get('CONFIGFILE','/dev/null')))
    if conf is None:
        conf=dict()

    # get our secrets:
    creds= {
        'OIDC_CLIENT_ID': credstash.getSecret(
            name="serviceapi.oidc_client_id",
            context={'app': 'serviceapi'},
            region="us-east-1"
            ),
        'OIDC_CLIENT_SECRET': credstash.getSecret(
            name="serviceapi.oidc_client_secret",
            context={'app': 'serviceapi'},
            region="us-east-1"
            ),
    }
    os.environ.update(creds)
    return ConfigManager(
        [
            ConfigOSEnv(),
            ConfigDictEnv(conf),
        ]
)

def randuuid():
    return(str(uuid.uuid4()))