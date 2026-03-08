"""
MAC/IP Merge - Flask Frontend
Standalone tool for collecting ARP/MAC data from network devices.
"""

import os
import sys
import uuid
import csv
import json
import time
import logging
import tempfile
import threading
from datetime import datetime, timedelta
from pathlib import Path
from io import StringIO

from flask import (
    Flask, render_template, request, jsonify,
    Response, send_file, stream_with_context
)

# Add core directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'core'))

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'mac-ip-merge-standalone-key')

# ─── Configuration ────────────────────────────────────────────────────────────

OUTPUT_DIR = Path(__file__).parent / 'outputs'
OUTPUT_DIR.mkdir(exist_ok=True)

CLEANUP_AFTER_MINUTES = 15
MAX_CONCURRENT_SCANS = 5

# ─── In-memory scan state ─────────────────────────────────────────────────────

# scan_id → { status, progress_events, result_file, created_at, error }
scans = {}
scans_lock = threading.Lock()


# ─── Error translation ────────────────────────────────────────────────────────

def friendly_error(host: str, exc: Exception) -> str:
    """Translate Python exceptions into plain-English messages."""
    msg = str(exc).lower()
    if 'timed out' in msg or 'timeout' in msg:
        return f"{host} — Connection timed out. Verify the device is reachable and SSH is enabled."
    if 'authentication' in msg or 'auth' in msg:
        return f"{host} — Authentication failed. Check your username and password."
    if 'no route' in msg or 'unreachable' in msg or 'network' in msg:
        return f"{host} — Device unreachable. Verify the IP/hostname and network path."
    if 'refused' in msg:
        return f"{host} — Connection refused. SSH may not be enabled on this device."
    if 'name or service not known' in msg or 'name resolution' in msg or 'nodename' in msg:
        return f"{host} — Hostname could not be resolved. Check DNS or use an IP address."
    if 'permission' in msg:
        return f"{host} — Permission denied. The account may lack required privileges."
    return f"{host} — Could not connect: {str(exc)[:120]}"


# ─── Scan runner ──────────────────────────────────────────────────────────────

def run_scan(scan_id: str, devices: list, username: str, password: str, preflight_only: bool = False):
    """
    Run a scan in a background thread.
    Emits progress events to scans[scan_id]['events'].
    devices: list of {'hostname': str, 'type': str}
    """
    from mac_ip_merge import MACIPMerge, DRIVERS

    def emit(event_type: str, message: str, data: dict = None):
        """Append a progress event."""
        payload = {'type': event_type, 'message': message, 'ts': datetime.now().strftime('%H:%M:%S')}
        if data:
            payload.update(data)
        with scans_lock:
            if scan_id in scans:
                scans[scan_id]['events'].append(payload)

    with scans_lock:
        scans[scan_id]['status'] = 'running'

    try:
        # ── Write temp devices.csv ────────────────────────────────────────────
        tmp_csv = OUTPUT_DIR / f"{scan_id}_devices.csv"
        with open(tmp_csv, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['hostname', 'type'])
            writer.writeheader()
            writer.writerows(devices)

        merger = MACIPMerge()
        if not merger.load_devices(str(tmp_csv)):
            emit('error', 'Failed to load device list. Check device entries.')
            with scans_lock:
                scans[scan_id]['status'] = 'failed'
            return

        # ── Pre-flight check ──────────────────────────────────────────────────
        emit('section', '─── Pre-flight Connectivity Check ───')
        reachable = 0
        unreachable = 0
        reachable_devices = []

        for device_row in merger.devices:
            host = device_row['hostname']
            dtype = device_row['type'].lower()
            driver_class = DRIVERS[dtype]
            driver = driver_class(host, username, password, dtype)

            try:
                ok = driver.connect()
                if ok:
                    driver.disconnect()
                    reachable += 1
                    reachable_devices.append(device_row)
                    emit('preflight_ok', f"✓  {host}  ({dtype})", {'host': host})
                else:
                    unreachable += 1
                    emit('preflight_fail', f"✗  {host}  — Could not establish SSH session.", {'host': host})
            except Exception as exc:
                unreachable += 1
                emit('preflight_fail', friendly_error(host, exc), {'host': host})

        emit('preflight_summary', f"Pre-flight: {reachable} reachable, {unreachable} unreachable.")

        if preflight_only:
            with scans_lock:
                scans[scan_id]['status'] = 'complete'
                scans[scan_id]['preflight_only'] = True
            emit('done', 'Pre-flight check complete.')
            return

        if reachable == 0:
            emit('error', 'No devices reachable. Scan aborted.')
            with scans_lock:
                scans[scan_id]['status'] = 'failed'
            return

        # ── Data collection (parallel per device) ────────────────────────────
        emit('section', '─── Collecting Data ───')

        import concurrent.futures

        collect_results = {}   # host → (arp_data, mac_data, error)
        failed_devices = []
        failed_devices_lock = threading.Lock()

        def collect_one(device_row):
            host = device_row['hostname']
            dtype = device_row['type'].lower()
            driver_class = DRIVERS.get(dtype)
            if not driver_class:
                with failed_devices_lock:
                    failed_devices.append({'device_ip': host, 'device_type': dtype, 'reason': 'Unsupported device type'})
                emit('device_fail', f"{host} - Unsupported device type: {dtype}", {'host': host})
                return host, None, None, f"Unsupported device type: {dtype}"
            driver = driver_class(host, username, password, dtype)
            emit('collecting', f"Connecting to {host}...", {'host': host})

            try:
                if not driver.connect():
                    with failed_devices_lock:
                        failed_devices.append({'device_ip': host, 'device_type': dtype, 'reason': 'Connection failed'})
                    emit('device_fail', f"✗  {host}  — Connection failed.", {'host': host})
                    return host, None, None, 'Connection failed'

                # ARP collection
                arp_entries_all = []
                try:
                    vrfs_to_check = [None]
                    if dtype.startswith('cisco'):
                        discovered = driver.discover_vrfs()
                        if discovered:
                            vrfs_to_check.extend(discovered)
                    for vrf in vrfs_to_check:
                        entries = driver.get_arp_table(vrf)
                        arp_entries_all.extend(entries)
                    emit('device_arp', f"  {host}  — {len(arp_entries_all)} ARP entries collected.", {'host': host, 'count': len(arp_entries_all)})
                except Exception as e:
                    emit('warn', f"  {host}  — ARP collection error: {str(e)[:80]}", {'host': host})

                # MAC table collection
                mac_entries_all = []
                try:
                    mac_entries_all = driver.get_mac_table()
                    if mac_entries_all:
                        emit('device_mac', f"  {host}  — {len(mac_entries_all)} MAC table entries.", {'host': host, 'count': len(mac_entries_all)})
                except Exception as e:
                    emit('warn', f"  {host}  — MAC table not available (normal for routers/firewalls).", {'host': host})

                driver.disconnect()
                emit('device_ok', f"✓  {host}  — Complete.", {'host': host})
                return host, arp_entries_all, mac_entries_all, None

            except Exception as exc:
                with failed_devices_lock:
                    failed_devices.append({'device_ip': host, 'device_type': dtype, 'reason': str(exc)})
                emit('device_fail', friendly_error(host, exc), {'host': host})
                return host, None, None, str(exc)

        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_CONCURRENT_SCANS) as executor:
            futures = {executor.submit(collect_one, d): d for d in reachable_devices}
            for future in concurrent.futures.as_completed(futures):
                device_row = futures[future]
                host = device_row.get('hostname', 'unknown')
                dtype = device_row.get('type', 'unknown')
                try:
                    host, arp, mac, err = future.result()
                except Exception as exc:
                    with failed_devices_lock:
                        failed_devices.append({'device_ip': host, 'device_type': dtype, 'reason': str(exc)})
                    emit('device_fail', friendly_error(host, exc), {'host': host})
                    continue
                if arp is not None:
                    collect_results[host] = (arp, mac)

        # ── Feed results into merger ──────────────────────────────────────────
        from mac_path_tracer import MACPathTracer
        merger.path_tracer = MACPathTracer()
        merger.failed_devices = failed_devices
        merger.start_time = datetime.now()

        for device_row in reachable_devices:
            host = device_row['hostname']
            dtype = device_row['type'].lower()
            if host not in collect_results:
                continue
            arp_entries, mac_entries = collect_results[host]
            merger.devices_scanned += 1

            for entry in (arp_entries or []):
                ip = entry['ip']
                mac = entry['mac'].lower()
                is_local = entry.get('is_local', False)
                
                if ip not in merger.arp_data:
                    merger.arp_data[ip] = []
                merger.arp_data[ip].append({
                    'mac': mac,
                    'device_ip': host,
                    'hostname': host,
                    'interface': entry['interface'],
                    'vrf': entry.get('vrf', 'global'),
                    'device_type': dtype,
                    'is_local': is_local,
                    'interface_type': entry.get('interface_type', 'data'),
                })
                merger.path_tracer.add_arp_entry(mac=mac, ip=ip, device=host,
                                                  interface=entry['interface'], device_type=dtype)

            for entry in (mac_entries or []):
                mac = entry['mac'].lower()
                if mac not in merger.mac_data:
                    merger.mac_data[mac] = []
                merger.mac_data[mac].append({
                    'vlan': entry['vlan'],
                    'device_ip': host,
                    'hostname': host,
                    'interface': entry['interface'],
                    'port_type': entry['port_type'],
                    'device_type': dtype,
                })
                merger.path_tracer.add_mac_entry(mac=mac, device=host, interface=entry['interface'],
                                                  vlan=entry['vlan'], port_type=entry['port_type'])

        merger.end_time = datetime.now()

        # ── Export merged CSV ─────────────────────────────────────────────────
        emit('section', '─── Generating Output ───')
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = OUTPUT_DIR / f"{scan_id}_merged_{timestamp}.csv"
        merger.merge_and_export(str(output_file))

        # ── Summary report ────────────────────────────────────────────────────
        duration = (merger.end_time - merger.start_time).total_seconds()
        total_arp = sum(len(v) for v in merger.arp_data.values())
        unique_ips = len(merger.arp_data)
        unique_macs = len(set(
            entry['mac'] for entries in merger.arp_data.values() for entry in entries
        ))

        summary_lines = [
            "═" * 50,
            "  MAC/IP MERGE — SCAN SUMMARY",
            "═" * 50,
            f"  Devices Requested : {len(devices)}",
            f"  Devices Reachable : {reachable}",
            f"  Devices Scanned   : {merger.devices_scanned}",
            f"  Devices Failed    : {len(merger.failed_devices)}",
            f"  Total ARP Entries : {total_arp}",
            f"  Unique IPs        : {unique_ips}",
            f"  Unique MACs       : {unique_macs}",
            f"  Scan Duration     : {duration:.1f} seconds",
            "═" * 50,
        ]

        if merger.failed_devices:
            summary_lines.append("")
            summary_lines.append("  FAILED DEVICES:")
            for fd in merger.failed_devices:
                summary_lines.append(f"  ✗  {fd['device_ip']}  — {fd['reason']}")
            summary_lines.append("")

        summary_lines.append("  Scan complete.")
        summary = "\n".join(summary_lines)

        emit('summary', summary)

        with scans_lock:
            scans[scan_id]['status'] = 'complete'
            scans[scan_id]['result_file'] = str(output_file)
            scans[scan_id]['result_filename'] = f"merged_{timestamp}.csv"
            scans[scan_id]['summary'] = summary
        
        logging.info(f"Scan {scan_id} complete. Result file: {output_file}")
        logging.info(f"File exists: {Path(output_file).exists()}")

        emit('done', 'Scan complete. Results ready for download.')

    except Exception as exc:
        logging.exception("Unexpected scan error")
        with scans_lock:
            scans[scan_id]['status'] = 'failed'
        emit('error', f"Unexpected error: {str(exc)[:200]}")

    finally:
        # Clean up temp devices CSV
        try:
            tmp_csv.unlink(missing_ok=True)
        except Exception:
            pass


# ─── Cleanup thread ───────────────────────────────────────────────────────────

def cleanup_worker():
    """Background thread: delete old output files and scan state."""
    while True:
        time.sleep(60)
        cutoff = datetime.now() - timedelta(minutes=CLEANUP_AFTER_MINUTES)
        with scans_lock:
            to_delete = [
                sid for sid, s in scans.items()
                if s['created_at'] < cutoff and s.get('status') in ('complete', 'failed')
            ]
            for sid in to_delete:
                result_file = scans[sid].get('result_file')
                if result_file:
                    try:
                        Path(result_file).unlink(missing_ok=True)
                    except Exception:
                        pass
                del scans[sid]


threading.Thread(target=cleanup_worker, daemon=True).start()


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    """Start a new scan. Returns scan_id."""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    raw_devices = data.get('devices', [])
    preflight_only = data.get('preflight_only', False)

    if not username or not password:
        return jsonify({'error': 'Username and password are required.'}), 400

    from mac_ip_merge import DRIVERS

    devices = []
    invalid_types = []
    for d in raw_devices:
        host = d.get('hostname', '').strip()
        dtype = d.get('type', '').strip().lower()
        if host and dtype and dtype in DRIVERS:
            devices.append({'hostname': host, 'type': dtype})
        elif host and dtype:
            invalid_types.append({'hostname': host, 'type': dtype})

    if not devices:
        return jsonify({'error': 'No devices provided. Add at least one device.'}), 400

    if invalid_types:
        invalid_list = ", ".join(f"{i['hostname']} ({i['type']})" for i in invalid_types[:5])
        return jsonify({
            'error': f"Unsupported device type provided: {invalid_list}. "
                     f"Valid types: {', '.join(sorted(DRIVERS.keys()))}"
        }), 400

    scan_id = str(uuid.uuid4())
    with scans_lock:
        scans[scan_id] = {
            'status': 'starting',
            'events': [],
            'result_file': None,
            'result_filename': None,
            'summary': None,
            'created_at': datetime.now(),
            'preflight_only': preflight_only,
        }

    thread = threading.Thread(
        target=run_scan,
        args=(scan_id, devices, username, password, preflight_only),
        daemon=True
    )
    thread.start()

    return jsonify({'scan_id': scan_id})


@app.route('/api/scan/<scan_id>/events')
def scan_events(scan_id: str):
    """Server-Sent Events stream for scan progress."""

    def generate():
        last_index = 0
        while True:
            with scans_lock:
                if scan_id not in scans:
                    yield f"data: {json.dumps({'type': 'error', 'message': 'Scan not found.'})}\n\n"
                    return
                scan = scans[scan_id]
                events = scan['events'][last_index:]
                status = scan['status']

            for event in events:
                yield f"data: {json.dumps(event)}\n\n"
                last_index += 1

            if status in ('complete', 'failed'):
                yield f"data: {json.dumps({'type': 'stream_end', 'status': status})}\n\n"
                return

            time.sleep(0.3)

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
        }
    )


@app.route('/api/scan/<scan_id>/status')
def scan_status(scan_id: str):
    with scans_lock:
        if scan_id not in scans:
            return jsonify({'error': 'Scan not found'}), 404
        scan = scans[scan_id]
        return jsonify({
            'status': scan['status'],
            'has_result': scan['result_file'] is not None,
            'summary': scan.get('summary'),
        })


@app.route('/api/scan/<scan_id>/download')
def download_result(scan_id: str):
    with scans_lock:
        if scan_id not in scans:
            logging.error(f"Download failed: scan_id {scan_id} not found in scans dict")
            return jsonify({'error': 'Scan not found or expired'}), 404
        scan = scans[scan_id]
        result_file = scan.get('result_file')
        result_filename = scan.get('result_filename', 'merged.csv')
    
    logging.info(f"Download requested: scan_id={scan_id}, file={result_file}")
    
    if not result_file:
        logging.error(f"Download failed: result_file is None for scan_id {scan_id}")
        return jsonify({'error': 'Result file not found. It may have expired.'}), 404
    
    if not Path(result_file).exists():
        logging.error(f"Download failed: file does not exist at path: {result_file}")
        # List files in OUTPUT_DIR for debugging
        try:
            files = list(OUTPUT_DIR.glob(f"{scan_id}*"))
            logging.error(f"Files in OUTPUT_DIR matching {scan_id}: {files}")
        except Exception as e:
            logging.error(f"Error listing OUTPUT_DIR: {e}")
        return jsonify({'error': 'Result file not found. It may have expired.'}), 404

    logging.info(f"Sending file: {result_file}")
    return send_file(
        result_file,
        mimetype='text/csv',
        as_attachment=True,
        download_name=result_filename
    )


@app.route('/api/example-csv/all')
def example_csv():
    """Download a combined example CSV with both device types."""
    rows = [
        ['hostname', 'type'],
        ['192.168.10.254', 'paloalto_panos'],
        ['fw-01.corp.local', 'paloalto_panos'],
        ['192.168.10.1', 'cisco_ios'],
        ['192.168.10.2', 'cisco_ios'],
        ['core-sw-01.corp.local', 'cisco_ios'],
        ['dist-sw-02', 'cisco_iosxe'],
    ]
    output = StringIO()
    writer = csv.writer(output)
    writer.writerows(rows)
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=devices.csv'}
    )


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5523, debug=False)
