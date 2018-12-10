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

    return ConfigManager(
        [
            ConfigOSEnv(),
            ConfigDictEnv(conf),
        ]
)

def randuuid():
    return(str(uuid.uuid4()))