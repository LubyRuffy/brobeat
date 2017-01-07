#!/usr/bin/env python

from bs4 import BeautifulSoup
import requests
from requests.compat import urljoin
import json
import os
import logging

from utils import is_enum, build_url, conn_id, get_filed_types, get_log_grok_pattern

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
consoleHandler = logging.StreamHandler()
logFormatter = logging.Formatter("%(asctime)s [%(levelname)-5.5s]  %(message)s")
consoleHandler.setFormatter(logFormatter)
logger.addHandler(consoleHandler)


def scrape_bro_docs():
    """ Crawl bro.org docs to extract log types """
    bro_logs = get_log_types()

    for log_type in bro_logs['logs']:
        if log_type.get('url', None):
            log_type['fields'] = parse_log_info(url=log_type.get('url'), log_file=log_type['file'])

            # build grok pattern from log field types
            log_type['pattern'] = get_log_grok_pattern(log_type)

    with open('bro-logs.json', 'w') as jsonfile:
        json.dump(bro_logs, jsonfile)

    return bro_logs


def get_log_types():
    """ Crawl log-files page and collect all available log sources.

    :return: list: Bro Log Sources
    """
    url = "https://www.bro.org/sphinx/script-reference/"
    resp = requests.get(url=url + "log-files.html")
    soup = BeautifulSoup(resp.content, "html.parser")
    bro_logs = dict(logs=[])

    for table in soup.find_all("table", {"class": "docutils"}):
        for row in table.find('tbody').find_all('tr'):
            log = {}
            cols = row.find_all('td')
            cols = [ele.text.strip() for ele in cols]
            tds = [ele for ele in cols if ele]
            log['file'] = tds[0]
            log['type'] = os.path.splitext(log['file'])[0]
            log['description'] = tds[1].replace('\n', ' ').replace('\r', '').encode('ascii', 'ignore').decode('ascii')
            log['fields'] = []
            link = row.find('a', href=True)
            # do not add a URL for notice_alarm.log
            if link is not None and 'notice_alarm' not in log['type']:
                log['url'] = urljoin(url, link['href'])
                logger.info('adding log type: {}'.format(log['type']))
            bro_logs['logs'].append(log)
    return bro_logs


def parse_log_info(url, log_file):
    log_fields = []

    resp = requests.get(url=url, allow_redirects=True)
    if not resp.ok:
        raise Exception("[BAD URL] {} - got status code: {}".format(url, resp.status_code))

    soup = BeautifulSoup(resp.content, "html.parser")
    dt_text = url.split('#', 1)[1]
    logger.info('[PARSING LOG] {}, field: {}'.format(log_file, dt_text))

    try:
        dl = soup.find("dt", id=dt_text).parent.find("dl", {"class": "docutils"})
        if dl is not None:
            for dfield in list(zip(dl.find_all("dt"), dl.find_all("dd"))):
                if len(dfield) == 2:
                    field_name = dfield[0].contents[0].split(':', 1)[0]
                    field_types = get_filed_types(field_name, dfield[0].contents[1].text)
                    # get field description
                    if dfield[1].p is not None:
                        field_description = dfield[1].p.text.replace('\n', ' ').replace('\r', '')
                        field_description = field_description.encode('ascii', 'ignore').decode('ascii')
                    else:
                        field_description = ""

                    if 'conn_id' in field_types.get('bro'):
                        log_fields += conn_id
                    elif '::' in field_types.get('bro'):
                        logger.info(' * parsing nested log in {}, field: {}'.format(log_file, field_types.get('bro')))
                        log_fields += get_nested_fields(field_name, field_types, build_url(url, dfield[0].a['href']))
                    else:
                        log_fields.append(dict(field=field_name, types=field_types, description=field_description))

        else:
            logger.warn(
                '   ===> unable to parse fields for log: ' + log_file + '. Not a dl-table, trying as p-table...')
            log_fields += parse_p_table(soup=soup, field_name=None, dt_text=dt_text, url=url)
    except Exception as e:
        logger.error('parsing log: {}, field: {}'.format(log_file, dt_text))
        logger.exception(e.message)

    return log_fields


def get_nested_fields(field_name, field_types, url):
    nested = []
    skip_list = ["FTP::PendingCmds", "Intel::TypeSet", "Notice::ActionSet", "Files::Info", "X509::Info"]

    if field_types.get('bro') in skip_list:
        logger.info('   ===> adding SKIPPED nested field: {}'.format(field_name))
        nested.append(dict(field=field_name, types=field_types, description=""))
    else:
        resp = requests.get(url=url)
        if not resp.ok:
            raise Exception("[BAD URL] {} - got status code: {}".format(url, resp.status_code))

        soup = BeautifulSoup(resp.content, "html.parser")
        dt_text = url.split('#')[-1]
        if is_enum(soup, dt_text):
            logger.info('   ===> adding ENUM field: {}'.format(field_types.get('bro')))
            nested.append(dict(field=field_name, types=field_types, description=""))
        else:
            try:
                dl = soup.find("dt", id=dt_text).parent.find("dl", {"class": "docutils"})
                if dl is not None:
                    for nfield in list(zip(dl.find_all("dt"), dl.find_all("dd"))):
                        if len(nfield) == 2:
                            nfield_name = nfield[0].contents[0].split(':', 1)[0]
                            if nfield[1].p is not None:
                                nfield_description = nfield[1].p.text.replace('\n', ' ').replace('\r', '')
                                nfield_description = nfield_description.encode('ascii', 'ignore').decode('ascii')
                            else:
                                nfield_description = ""
                            # convert field type to elasticsearch type
                            nfield_types = get_filed_types(nfield_name, nfield[0].contents[1].text)

                            if '::' in nfield_types.get('bro'):
                                # recursively call get_nested_fields to get next layer of nested fields
                                logger.info(' ** parsing nested field: {}'.format(nfield_types.get('bro')))
                                nested += get_nested_fields(field_name + '.' + nfield_name, nfield_types,
                                                            build_url(url, nfield[0].a['href']))
                            else:
                                logger.info('   ===> adding nested field: {}'.format(field_name + '.' + nfield_name))
                                nested.append(
                                    dict(
                                        field=field_name + '.' + nfield_name,
                                        types=nfield_types,
                                        description=nfield_description))
                else:
                    logger.warn('   ===> unable to parse nested field type: {}. Trying as p-table...'.format(
                        field_types.get('bro')))
                    nested += parse_p_table(soup=soup, field_name=field_name, dt_text=dt_text, url=url)
            except Exception as e:
                logger.error('parsing field: {}, type: {}'.format(field_name, field_types.get('bro')))
                logger.exception(e.message)

    return nested


def parse_p_table(soup=None, field_name=None, dt_text=None, url=None):
    pfields = []
    try:
        table = soup.find("dt", id=dt_text).parent.find("table")
        ps = table.find("th", text="Type:").parent.find_all("p")
        for p in ps[1:]:
            pfield_name = p.contents[0].split(':', 1)[0]

            # convert field type to elasticsearch type
            pfield_types = get_filed_types(pfield_name, p.contents[1].text)
            if '::' in pfield_types.get('bro'):
                logger.info(' *** parsing nested field: {}'.format(pfield_types.get('bro')))
                if field_name is None:
                    pfields += get_nested_fields(pfield_name, pfield_types, build_url(url, p.a['href']))
                else:
                    pfields += get_nested_fields(field_name + '.' + pfield_name, pfield_types,
                                                 build_url(url, p.a['href']))
            else:
                if field_name is None:
                    logger.info('   ===> adding nested field: {}'.format(pfield_name))
                    pfields.append(dict(field=pfield_name, types=pfield_types, description=""))
                else:
                    logger.info('   ===> adding nested field: {}'.format(field_name + '.' + pfield_name))
                    pfields.append(dict(field=field_name + '.' + pfield_name, types=pfield_types, description=""))
    except Exception as e:
        logger.error('Failed to parse field_name: {} and dt_text: {}'.format(field_name, dt_text))
        logger.exception(e.message)

    return pfields


def convert_docs_to_grok_patterns(bro_logs):
    """ Build pattern file """
    with open('../logstash/patterns/generated-bro', 'w') as patternfile:
        patternfile.write('# BRO-DOC-GENERATED patterns\n')
        patternfile.write('# author: blacktop\n')
        patternfile.write('# https://www.bro.org/sphinx/script-reference/log-files.html')
        patternfile.write('\n\n')
        for logtype in bro_logs['logs']:
            patternfile.write('# ' + logtype.get('file') + '\n')
            if logtype.get('fields'):
                patternfile.write(logtype['pattern'].get('name') + ' ' + logtype['pattern'].get('pattern'))
            patternfile.write('\n\n')


if __name__ == '__main__':
    docs = scrape_bro_docs()
    convert_docs_to_grok_patterns(docs)
