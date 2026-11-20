#!/usr/bin/env python3
"""TraceDroid test fixture generator (GPL-3.0-or-later).
Usage: gen_synthetic_evtx.py out.evtx && td_selftest out.evtx

Builds a small synthetic Sysmon .evtx file from the MS-EVEN6 / libevtx format description.
Exercises: inline + referenced names, inline + referenced template definitions, typed
substitutions (GUID, FILETIME, SID, ints, strings) and an embedded BinXML EventData fragment."""
import struct, sys, uuid, zlib

EPOCH_DIFF = 116444736000000000
def filetime(ms): return ms * 10000 + EPOCH_DIFF
def u16s(s): return s.encode('utf-16-le')

class Chunk:
    def __init__(self):
        self.buf = bytearray(65536)
        self.pos = 512
        self.names = {}
        self.templates = {}
    def put(self, b):
        self.buf[self.pos:self.pos+len(b)] = b; self.pos += len(b)
    def u8(self, v): self.put(struct.pack('<B', v))
    def u16(self, v): self.put(struct.pack('<H', v))
    def u32(self, v): self.put(struct.pack('<I', v))
    def name(self, n):
        if n in self.names:
            self.u32(self.names[n]); return
        off = self.pos + 4
        self.u32(off)
        self.names[n] = off
        self.u32(0); self.u16(0x1234); self.u16(len(n)); self.put(u16s(n)); self.u16(0)
    def open(self, n, attrs=False):
        self.u8(0x41 if attrs else 0x01); self.u16(0xFFFF); self.u32(0); self.name(n)
        if attrs: self.u32(0)
    def attr(self, n, more=False):
        self.u8(0x46 if more else 0x06); self.name(n)
    def text(self, s):
        self.u8(0x05); self.u8(0x01); self.u16(len(s)); self.put(u16s(s))
    def sub(self, idx, typ, optional=False):
        self.u8(0x0E if optional else 0x0D); self.u16(idx); self.u8(typ)
    def close_start(self): self.u8(0x02)
    def close_empty(self): self.u8(0x03)
    def end(self): self.u8(0x04)

    def template(self, key, body_fn, values_fn):
        """Emits a template instance; body_fn(chunk) writes the definition body on first use,
        values_fn(chunk, base) returns [(type, bytes or callable(base)->None)]."""
        self.u8(0x0C); self.u8(0x01)
        if key in self.templates:
            tid, off = self.templates[key]
            self.u32(tid); self.u32(off)
        else:
            guid = uuid.uuid5(uuid.NAMESPACE_DNS, key).bytes_le
            tid = struct.unpack('<I', guid[:4])[0]
            off = self.pos + 8
            self.templates[key] = (tid, off)
            self.u32(tid); self.u32(off)
            self.u32(0); self.put(guid)
            size_at = self.pos; self.u32(0)
            start = self.pos
            self.put(b'\x0f\x01\x01\x00'); body_fn(self); self.u8(0x00)
            struct.pack_into('<I', self.buf, size_at, self.pos - start)
        values = values_fn()
        self.u32(len(values))
        desc_at = self.pos
        self.pos += 4 * len(values)
        for i, (typ, val) in enumerate(values):
            start = self.pos
            if callable(val): val(self)
            else: self.put(val)
            struct.pack_into('<HBB', self.buf, desc_at + 4 * i, self.pos - start, typ, 0)

def sid(s):
    parts = s.split('-')[1:]
    rev, auth, subs = int(parts[0]), int(parts[1]), [int(x) for x in parts[2:]]
    return struct.pack('<BB', rev, len(subs)) + auth.to_bytes(6, 'big') + b''.join(struct.pack('<I', x) for x in subs)

def system_body(c):
    c.open('Event', True); c.attr('xmlns'); c.text('http://schemas.microsoft.com/win/2004/08/events/event'); c.close_start()
    c.open('System'); c.close_start()
    c.open('Provider', True); c.attr('Name', True); c.text('Microsoft-Windows-Sysmon'); c.attr('Guid'); c.sub(0, 0x0F); c.close_empty()
    c.open('EventID'); c.close_start(); c.sub(1, 0x06); c.end()
    c.open('Level'); c.close_start(); c.sub(2, 0x04); c.end()
    c.open('TimeCreated', True); c.attr('SystemTime'); c.sub(3, 0x11); c.close_empty()
    c.open('EventRecordID'); c.close_start(); c.sub(4, 0x0A); c.end()
    c.open('Correlation', True); c.attr('ActivityID'); c.sub(10, 0x0F, True); c.close_empty()
    c.open('Execution', True); c.attr('ProcessID', True); c.sub(5, 0x08); c.attr('ThreadID'); c.sub(6, 0x08); c.close_empty()
    c.open('Channel'); c.close_start(); c.text('Microsoft-Windows-Sysmon/Operational'); c.end()
    c.open('Computer'); c.close_start(); c.sub(7, 0x01); c.end()
    c.open('Security', True); c.attr('UserID'); c.sub(8, 0x13, True); c.close_empty()
    c.end()
    c.sub(9, 0x21)
    c.end()

def data_body(fields):
    def body(c):
        c.open('EventData'); c.close_start()
        for i, (name, typ, _) in enumerate(fields):
            c.open('Data', True); c.attr('Name'); c.text(name); c.close_start(); c.sub(i, typ); c.end()
        c.end()
    return body

def record(c, rec_id, time_ms, event_id, computer, key, fields):
    start = c.pos
    c.put(b'\x2a\x2a\x00\x00'); c.u32(0); c.put(struct.pack('<QQ', rec_id, filetime(time_ms)))
    c.put(b'\x0f\x01\x01\x00')
    def nested(ch):
        ch.put(b'\x0f\x01\x01\x00')
        ch.template(key, data_body(fields), lambda: [(t, v) for (_, t, v) in fields])
        ch.u8(0x00)
    def values():
        return [
            (0x0F, uuid.UUID('5770385f-c22a-43e0-bf4c-06f5698ffbd9').bytes_le),
            (0x06, struct.pack('<H', event_id)),
            (0x04, struct.pack('<B', 4)),
            (0x11, struct.pack('<Q', filetime(time_ms))),
            (0x0A, struct.pack('<Q', rec_id)),
            (0x08, struct.pack('<I', 2044)),
            (0x08, struct.pack('<I', 3120)),
            (0x01, u16s(computer)),
            (0x13, sid('S-1-5-18')),
            (0x21, nested),
            (0x00, b''),
        ]
    c.template('system', system_body, values)
    c.u8(0x00)
    while (c.pos - start) % 8 != 4: c.u8(0)
    size = c.pos - start + 4
    c.u32(size)
    struct.pack_into('<I', c.buf, start + 4, size)
    return start

def S(s): return (0x01, u16s(s))
def G(s): return (0x0F, uuid.UUID(s).bytes_le)
def I(n): return (0x08, struct.pack('<I', n))
def F(name, tv): return (name, tv[0], tv[1])

def main(path):
    c = Chunk()
    g_exp, g_ps, g_cmd = ('a23eae89-bd56-5903-0000-001000000001', 'a23eae89-bd56-5903-0000-001000000002', 'a23eae89-bd56-5903-0000-001000000003')
    t0 = 1717236000000  # 2024-06-01 10:00:00 UTC
    def proc(guid, pid, image, cmd, pguid, ppid, pimage, when):
        return [F('UtcTime', S(when)), F('ProcessGuid', G(guid)), F('ProcessId', I(pid)), F('Image', S(image)),
                F('CommandLine', S(cmd)), F('User', S('CORP\\alice')), F('ParentProcessGuid', G(pguid)), F('ParentProcessId', I(ppid)),
                F('ParentImage', S(pimage)), F('Hashes', S('MD5=0123456789ABCDEF0123456789ABCDEF,SHA256=' + 'AB' * 32 + ',IMPHASH=' + 'CD' * 16))]
    last = record(c, 1, t0, 1, 'WS01.corp.local', 'eid1', proc(g_ps, 4321, 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        'powershell.exe -NoP -ExecutionPolicy Bypass -enc SQBFAFgA \u2014 \u0442\u0435\u0441\u0442 \U0001F600', g_exp, 1200, 'C:\\Windows\\explorer.exe', '2024-06-01 10:00:00.000'))
    last = record(c, 2, t0 + 1500, 22, 'WS01.corp.local', 'eid22', [F('UtcTime', S('2024-06-01 10:00:01.500')), F('ProcessGuid', G(g_ps)), F('ProcessId', I(4321)),
        F('QueryName', S('abcdef0123456789.evil.com')), F('QueryStatus', S('0')), F('QueryResults', S('::ffff:10.1.2.3;')), F('Image', S('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'))])
    last = record(c, 3, t0 + 2000, 3, 'WS01.corp.local', 'eid3', [F('UtcTime', S('2024-06-01 10:00:02.000')), F('ProcessGuid', G(g_ps)), F('ProcessId', I(4321)),
        F('Image', S('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe')), F('Protocol', S('tcp')), F('SourceIp', S('10.0.0.5')), F('SourcePort', (0x06, struct.pack('<H', 50123))),
        F('DestinationIp', S('10.1.2.3')), F('DestinationPort', (0x06, struct.pack('<H', 4444))), F('DestinationHostname', S(''))])
    last = record(c, 4, t0 + 3000, 1, 'WS01.corp.local', 'eid1', proc(g_cmd, 5555, 'C:\\Windows\\System32\\cmd.exe', 'cmd.exe /c whoami', g_ps, 4321,
        'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', '2024-06-01 10:00:03.000'))
    free = c.pos
    b = c.buf
    b[0:8] = b'ElfChnk\x00'
    struct.pack_into('<QQQQIIII', b, 8, 1, 4, 1, 4, 128, last, free, zlib.crc32(bytes(b[512:free])))
    struct.pack_into('<I', b, 120, 0)
    struct.pack_into('<I', b, 124, zlib.crc32(bytes(b[0:120]) + bytes(b[128:512])))
    hdr = bytearray(4096)
    hdr[0:8] = b'ElfFile\x00'
    struct.pack_into('<QQQIHHHH', hdr, 8, 0, 0, 5, 128, 1, 3, 4096, 1)
    struct.pack_into('<I', hdr, 124, zlib.crc32(bytes(hdr[0:120])))
    open(path, 'wb').write(bytes(hdr) + bytes(b) + bytes(65536))  # plus one unused, zero-filled chunk slot

main(sys.argv[1])
