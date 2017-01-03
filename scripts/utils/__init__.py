import re
from requests.compat import urljoin

conn_id = [{'field': u'id.orig_h',
            'type': 'ip',
            'description': 'The originators IP address.'},
           {'field': u'id.orig_p',
            'type': 'integer',
            'description': 'The originators port number.'},
           {'field': u'id.resp_h',
            'type': 'ip',
            'description': 'The responders IP address.'},
           {'field': u'id.resp_p',
            'type': 'integer',
            'description': 'The responders port number.'}]


def is_url(url):
    regex = re.compile(r'^(?:http|ftp)s?://'  # http:// or https://
                       r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
                       r'localhost|'  # localhost...
                       r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
                       r'(?::\d+)?'  # optional port
                       r'(?:/?|[/?]\S+)$',
                       re.IGNORECASE)
    return regex.match(url)


def build_url(current_url, next_url):
    if is_url(next_url):
        return next_url
    else:
        return urljoin(current_url, next_url)


def field_type_2_grok_lookup(ftype, field):
    type2grok = {
        'time': 'NUMBER',
        'count': 'INT',
        'interval': 'DATA',
        'bool': 'DATA',
        'addr': 'IP',
        'port': 'INT',
        'string': 'DATA',
        'double': 'DATA',
        'geo_location': 'DATA',
        'int': 'INT',
        'transport_proto': 'WORD',
        'conn_id': 'NOTSPACE',
        'set': 'DATA',
        'vector': 'DATA',
    }
    if 'uid' in field:
        return 'NOTSPACE', field
    return type2grok.get(ftype, 'DATA'), field


def field_type_2_elastic_lookup(ftype, field):
    type2es = {
        'time': 'double',
        'count': 'integer',
        'interval': 'double',
        'bool': 'boolean',
        'addr': 'ip',
        'port': 'integer',
        'string': 'keyword',
        'double': 'double',
        'int': 'integer',
        'transport_proto': 'keyword',
        # 'geo_location': 'DATA',
        'conn_id': 'conn_id',
        # 'set': 'DATA',
        # 'vector': 'DATA',
    }
    if 'uid' in field:
        return 'text'
    return type2es.get(ftype, None)


def doc2grok(fields):
    converted = []
    for field in fields:
        if field['field'] == 'id':
            converted.append('%{IP:orig_h}\\t%{INT:orig_p}\\t%{IP:resp_h}\\t%{INT:resp_p}')
        else:
            converted.append('%%{%s:%s}' % field_type_2_grok_lookup(field['type'], field['field']))
    return '\\t'.join(converted)


def is_enum(soup, dt_text):
    p = soup.find("dt", id=dt_text).parent.find("p", {"class": "first"})
    if p is not None and 'enum' in p.text:
        return True
    else:
        return False
