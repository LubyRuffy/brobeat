#!/bin/bash

set -e

echo "===> Add template"
http 'localhost:9200/_template/brobeat-*' < brobeat.template.json

echo "===> Add index-pattern"
http 'localhost:9200/.kibana/index-pattern/brobeat-*' < _meta/kibana/index-pattern/brobeat.json

echo "===> Get indices and _types"
http 'localhost:9200/_mapping' | jq 'to_entries | .[] | {(.key): .value.mappings | keys}'
