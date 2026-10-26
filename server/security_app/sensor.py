"""Read authorized Zeek JSON connection logs or replay CIC CSV records."""
import argparse
import csv
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


def zeek_flow(record):
    # Only the four named features are bridged; byte counters are deliberately not equated.
    return {'event_id': 'zeek:' + hashlib.sha256(json.dumps(record, sort_keys=True).encode()).hexdigest(),
            'source_ip': record['id.orig_h'], 'collector': 'zeek-experimental',
            'duration_seconds': float(record.get('duration', 0)),
            'forward_packets': int(record['orig_pkts']), 'backward_packets': int(record['resp_pkts']),
            'destination_port': int(record['id.resp_p'])}


def send(url, token, flow):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != 'https' and not (parsed.scheme == 'http' and parsed.hostname in ['localhost', '127.0.0.1', '::1']):
        raise ValueError('Use HTTPS except for loopback demonstrations')
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None  # Never forward a sensor credential to a redirected host.
    request = urllib.request.Request(url.rstrip('/') + '/api/flows', data=json.dumps(flow).encode(),
                                     headers={'Content-Type': 'application/json', 'Authorization': f'Bearer {token}'})
    with urllib.request.build_opener(NoRedirect).open(request, timeout=15) as response:
        return json.load(response)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', default='http://127.0.0.1:5000')
    parser.add_argument('--format', choices=['zeek', 'cic'], required=True)
    parser.add_argument('--file', required=True)
    parser.add_argument('--watch', action='store_true', help='Tail Zeek log, retry transport failures, handle rotation')
    parser.add_argument('--limit', type=int, default=20, help='Maximum replay records; ignored in watch mode')
    args = parser.parse_args()
    token = os.environ.get('SENSOR_TOKEN')
    if not token:
        parser.error('Set SENSOR_TOKEN to the same secret as the server')
    if args.format == 'cic':
        if args.watch:
            parser.error('Watch mode supports Zeek JSON logs only')
        sent = 0
        with open(args.file, encoding='utf-8', errors='replace') as stream:
            for index, raw in enumerate(csv.DictReader(stream)):
                row = {k.strip(): v for k, v in raw.items()}
                try:
                    flow = {'event_id': 'cic:' + hashlib.sha256((str(Path(args.file).resolve()) + ':' + str(index)).encode()).hexdigest(),
                            'source_ip': '192.0.2.10', 'collector': 'cic-csv-replay',
                            'duration_seconds': float(row['Flow Duration']) / 1e6,
                            'forward_packets': float(row['Total Fwd Packets']),
                            'backward_packets': float(row['Total Backward Packets']),
                            'destination_port': float(row['Destination Port'])}
                    # ML CSVs omit source IP; the reserved documentation address is a visible placeholder.
                    print(json.dumps(send(args.url, token, flow)), flush=True)
                    sent += 1
                except (ValueError, KeyError) as error:
                    print(f'Skipped malformed CSV row {index}: {error}', file=sys.stderr)
                if sent >= args.limit:
                    break
        return
    offset, inode, sent = 0, None, 0
    while True:
        try:
            stat = os.stat(args.file)
            if inode != stat.st_ino or stat.st_size < offset:
                offset, inode = 0, stat.st_ino
            with open(args.file, 'rb') as stream:
                stream.seek(offset)
                while True:
                    start = stream.tell()
                    line = stream.readline()
                    if not line or not line.endswith(b'\n'):
                        break  # Wait for a complete record.
                    if line.startswith(b'#'):
                        offset = stream.tell()
                        continue
                    try:
                        flow = zeek_flow(json.loads(line))
                    except (ValueError, KeyError, TypeError) as error:
                        print(f'Skipped malformed Zeek record at byte {start}: {error}', file=sys.stderr)
                        offset = stream.tell()
                        continue
                    print(json.dumps(send(args.url, token, flow)), flush=True)
                    offset = stream.tell()  # Advance only after a successful response.
                    sent += 1
                    if not args.watch and sent >= args.limit:
                        return
        except (OSError, urllib.error.URLError) as error:
            if not args.watch:
                raise
            print(f'Collector waiting/retrying: {type(error).__name__}', file=sys.stderr)
        if not args.watch:
            return
        time.sleep(2)


if __name__ == '__main__':
    main()

