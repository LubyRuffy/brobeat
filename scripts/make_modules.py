from jinja2 import Environment, PackageLoader
import json
import os

with open('bro-logs.json') as json_file:
    bro_logs = json.load(json_file)

env = Environment(loader=PackageLoader(__name__, 'templates'))

# create logstash config
template = env.get_template('logstash/logstash.conf')
logstash_dir = '../logstash/bro.conf'
with open('../logstash/bro.conf', 'w') as lsfile:
    lsfile.write(template.render(logs=bro_logs['logs']))

# create module manifests
template = env.get_template('module/manifest.yml')
for log in bro_logs['logs']:
    module_dir = os.path.join('../modules', log['type'])
    if log.get('pattern', None):
        if not os.path.isdir(module_dir):
            os.makedirs(module_dir, 0755)
        with open(os.path.join(module_dir, 'manifest.yml'), 'w') as plfile:
            plfile.write(template.render(log_type=log['type']))

# create module config
template = env.get_template('module/config/config.yml')
for log in bro_logs['logs']:
    config_dir = os.path.join('../modules', log['type'], 'config')
    if log.get('pattern', None):
        if not os.path.isdir(config_dir):
            os.makedirs(config_dir, 0755)
        with open(os.path.join(config_dir, 'bro-'+log['type']+'.yml'), 'w') as cfile:
            cfile.write(template.render(log_type=log['type']))

# create ingest pipelines
template = env.get_template('module/ingest/pipeline.json')
for log in bro_logs['logs']:
    ingest_dir = os.path.join('../modules', log['type'], 'ingest')
    if log.get('pattern', None):
        if not os.path.isdir(ingest_dir):
            os.makedirs(ingest_dir, 0755)
        with open(os.path.join(ingest_dir, 'no_plugins.json'), 'w') as plfile:
            plfile.write(template.render(log_file=log['file'],
                                         log_type=log['type'],
                                         pattern=log['pattern'].get('pattern')))

# create _meta fields
template = env.get_template('module/_meta/fields.yml')
for log in bro_logs['logs']:
    meta_dir = os.path.join('../modules', log['type'], '_meta')
    if log.get('pattern', None):
        if not os.path.isdir(meta_dir):
            os.makedirs(meta_dir, 0755)
        with open(os.path.join(meta_dir, 'fields.yml'), 'w') as mfile:
            mfile.write(template.render(log_type=log['type'], log_descr=log['description'], fields=log['fields']))
