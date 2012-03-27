import argparse
import json
import logging
import sys
import time
import isodate
import requests


ENDPOINTS = {
        'us': 'https://identity.api.rackspacecloud.com/v1.1/',
        'uk': 'https://lon.identity.api.rackspacecloud.com/v1.1/',
        }


class APIError(Exception):
    def __init__(self, response, data=None):
        self.response = response
        self.data = json.loads(response.text) if data is None else data
        import pdb ; pdb.set_trace()

    def __str__(self):
        try:
            return self.data['message']
        except KeyError:
            return str(self.data)

    def __repr__(self):
        return '<APIError code=%s msg=%s>' % \
                (self.response.status_code, self.data['message'])


class Record(object):
    def __init__(self, domain, record):
        self.api = domain.api
        self.domain = domain
        self.name = record['name']
        self.id = record['id']
        self.type = record['type']
        self.data = record['data']
        self.ttl = record['ttl']
        self.priority = record.get('priority')
        self.created = isodate.parse_datetime(record['created'])
        self.updated = isodate.parse_datetime(record['updated'])
        self.comment = record.get('comment')

    def delete(self):
        self.api._delete('/domains/%s/records/%s' % (self.domain.id, self.id))
        self.domain._records.pop(self.id, None)

    def modify(self, ttl=None, name=None, data=None):
        pdata = {}
        if ttl:
            pdata['ttl'] = self.ttl = ttl
        if name:
            pdata['name'] = self.name = name
        if data:
            pdata['data'] = self.data = data
        self.api._put('/domains/%s/records/%s' % (self.domain.id, self.id),
                data=pdata)


class Domain(object):
    _records_loaded = False

    def __init__(self, api, record):
        self.api = api
        self.id = record['id']
        self.name = record['name']
        self.ttl = record.get('ttl')
        self.email_address = record.get('emailAddress')
        self.created = isodate.parse_datetime(record['created'])
        self.updated = isodate.parse_datetime(record['updated'])
        self.comment = record.get('comment')

    def delete(self):
        self.api._delete('/domains/%s' % self.id,
                params={'deleteSubdomains': 'true'})
        self.api._unregister_domain(self)

    def export(self):
        r = self.api._get('/domains/%s/export' % self.id)
        return r['contents']

    @property
    def records(self):
        if not self._records_loaded:
            self._records = {}
            params = {'limit': 100, 'offset': 0}
            path = '/domains/%s/records' % self.id
            r = self.api._get(path, params=params)
            total_entries = r['totalEntries']
            for record in r['records']:
                record = Record(self, record)
                self._records[record.id] = record
            while len(self._records) < total_entries:
                params['offset'] += params['limit']
                r = self.api._get(path, params=params)
                for record in r['records']:
                    record = Record(self, record)
                    self._records[record.id] = record
            self._records_loaded = True
        return self._records

    def add_records(self, records):
        data = {'records': records}
        self.api._post('/domains/%s/records' % self.id, data=data)

    def delete_records(self, records):
        ids = []
        for record_id in records:
            if not isinstance(record_id, basestring):
                record_id = record_id.id
            self._records.pop(record_id, None)
            ids.append(record_id)
        self.api._delete('/domains/%s/records' % self.id,
                params={'id': ids})

    def modify(self, ttl=None, email_address=None, comment=None):
        data = {}
        if ttl:
            data['ttl'] = self.ttl = ttl
        if email_address:
            data['emailAddress'] = self.email_address = email_address
        if comment:
            data['comment'] = self.comment = comment
        self.api._put('/domains/%s' % self.id, data=data)


class API(object):
    domains_loaded = False

    def __init__(self, endpoint, username, api_key):
        (self.api_url, self.auth_token) = self.get_auth_info(
                endpoint, username, api_key)

    def _send(self, method, path, **kw):
        if 'data' in kw and not isinstance(kw['data'], str):
            kw['data'] = json.dumps(kw['data'])
        headers = {'Content-Type': 'application/json',
                   'Accept': 'application/json',
                   'X-Auth-Token': self.auth_token}
        r = method('%s%s' % (self.api_url, path), headers=headers, **kw)
        assert 'application/json' in r.headers['Content-Type']
        if r.status_code == 202:
            callback = json.loads(r.text)['callbackUrl']
            logging.debug('Waiting for asynchronous task to complete')
            interval = 1
            while r.status_code == 202:
                time.sleep(interval)
                r = requests.get(callback, params={'showDetails': 'true'},
                        headers=headers)
                interval *= 2
            info = json.loads(r.text)
            if info['status'] == 'ERROR':
                raise APIError(r, info['error'])
            return json.loads(r.text).get('response')
        elif r.status_code != 200:
            raise APIError(r)
        return json.loads(r.text)

    def _get(self, path, **kw):
        return self._send(requests.get, path, **kw)

    def _post(self, path, **kw):
        return self._send(requests.post, path, **kw)

    def _put(self, path, **kw):
        return self._send(requests.put, path, **kw)

    def _delete(self, path, **kw):
        return self._send(requests.delete, path, **kw)

    def get_auth_info(self, endpoint, username, api_key):
        if endpoint.endswith('/'):
            endpoint = endpoint[:-1]

        data = {'credentials':
                {'username': username, 'key': api_key}}
        r = requests.post('%s/auth' % endpoint, data=json.dumps(data),
                headers={'Content-Type': 'application/json',
                         'Accept': 'application/json'})
        if r.status_code != 200:
            logging.error('Authentication failed')
            sys.exit(1)

        r = json.loads(r.text)
        if 'cloudDNS' not in r['auth']['serviceCatalog']:
            logging.error('cloudDNS service not available.')
            sys.exit(1)

        return(r['auth']['serviceCatalog']['cloudDNS'][0]['publicURL'],
               r['auth']['token']['id'])

    @property
    def domains(self):
        if not self.domains_loaded:
            self._domains_by_name = {}
            self._domains_by_id = {}
            r = self._get('/domains')
            for domain in r['domains']:
                domain = Domain(self, domain)
                self._domains_by_name[domain.name] = domain
                self._domains_by_id[domain.id] = domain
            self.domains_loaded = True
        return self._domains_by_name

    def _unregister_domain(self, domain):
        del self._domains_by_name[domain.name]
        del self._domains_by_id[domain.id]

    def import_domain(self, content, comment=None):
        data = {'domains': [
                {'contentType': 'BIND_9',
                 'contents': content}]}
        if comment:
            data['domains'][0] = comment
        return self._post('/domains/import', data=data)


def load_records(filename):
    records = []
    lineno = 0
    for line in open(filename).readlines():
        lineno += 1
        parts = line.split()
        if len(parts) == 3:
            records.append({'name': parts[0],
                            'ttl': None,
                            'type': parts[1],
                            'data': parts[2]})
        elif len(parts) == 4:
            records.append({'name': parts[0],
                            'ttl': int(parts[1]),
                            'type': parts[2],
                            'data': parts[3]})
        elif not parts:
            continue
        else:
            print >> sys.stderr, 'Syntax error at %s:%d' % (filename, lineno)
            sys.exit(1)
    return records


def list_domains(options, api):
    domains = api.domains.values()
    domains.sort(key=lambda s: s.name)
    for domain in domains:
        print '%s id=%d' % (domain.name, domain.id)


def delete_domain(options, api):
    try:
        domain = api.domains[options.domain]
        domain.delete()
    except KeyError:
        pass


def import_domain(options, api):
    try:
        input = open(options.zone, 'rt').read()
    except IOError as e:
        print >> sys.stderr, 'Error opening zone file: %s' % e.strerror
        sys.exit(1)

    api.import_domain(input, options.comment)


def export_domain(options, api):
    try:
        domain = api.domains[options.domain]
    except KeyError:
        print >> sys.stderr, 'Unknown domain: %s' % options.domain
        return 1
    print domain.export()


def dump_domain(options, api):
    try:
        domain = api.domains[options.domain]
    except KeyError:
        print >> sys.stderr, 'Unknown domain: %s' % options.domain
        return 1
    for record in domain.records.values():
        print '%(name)s\t%(ttl)d\t%(type)s\t%(data)s' % record.__dict__


def sync_domain(options, api):
    new_records = load_records(options.input)
    try:
        domain = api.domains[options.domain]
    except KeyError:
        print >> sys.stderr, 'Unkown domain: %s' % options.domain
        return 1

    key_to_record = dict(((r.name, r.ttl, r.type, r.data), r)
                         for r in domain.records.values())
    to_create = []
    for record in new_records:
        key = (record['name'], record['ttl'], record['type'], record['data'])
        old_record = key_to_record.get(key)
        if old_record is None:
            to_create.append(record)
        else:
            if record.get('ttl') and record['ttl'] and \
                    record['ttl'] != old_record.ttl:
                old_record.modify(ttl=record['ttl'])
            del key_to_record[key]
    if key_to_record:
        logging.debug('Removing %d obsolete records', len(key_to_record))
        ids = [r.id for r in key_to_record.values()]
        domain.delete_records(ids)
    if to_create:
        logging.debug('Adding %d new records', len(to_create))
        domain.add_records(to_create)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--region',
            choices=ENDPOINTS.keys(), default='us',
            help='Select the RackSpace geographic endpoint')
    parser.add_argument('--username', required=True,
            help='RackSpace username')
    parser.add_argument('--api', dest='api_key', required=True,
            help='API Access key')

    subparsers = parser.add_subparsers(title='Available actions')
    sub = subparsers.add_parser('list',
            help='List all known domains')
    sub.set_defaults(func=list_domains)

    sub = subparsers.add_parser('delete',
            help='Delete domain')
    sub.set_defaults(func=delete_domain)
    sub.add_argument('domain', help='Domain to delete')

    sub = subparsers.add_parser('export-zone',
            help='Export domain information in BIND zone format')
    sub.set_defaults(func=export_domain)
    sub.add_argument('domain', help='Domain to export')

    sub = subparsers.add_parser('import-zone',
            help='Import domain information from BIND zone file')
    sub.set_defaults(func=import_domain)
    sub.add_argument('--comment', help='Comment describing domain')
    sub.add_argument('zone', help='Zone file')

    sub = subparsers.add_parser('dump',
            help='Dump domain records')
    sub.set_defaults(func=dump_domain)
    sub.add_argument('domain', help='Domain to dump')

    sub = subparsers.add_parser('sync',
            help='Synchronize domain records')
    sub.set_defaults(func=sync_domain)
    sub.add_argument('domain', help='Domain to sync')
    sub.add_argument('input', help='File with record data')

    options = parser.parse_args()
    api = API(ENDPOINTS[options.region], options.username, options.api_key)
    try:
        sys.exit(options.func(options, api) or 0)
    except APIError as e:
        print >> sys.stderr, e
        sys.exit(2)


if __name__ == '__main__':
    main()
