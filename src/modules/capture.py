import re
from collections import namedtuple
from modules.logger import logger
from modules.storage import storage
from scapy.all import IP, TCP, Raw

INTERFACE = None
BPF_FILTER = "tcp port 80"
TARGET_HOST = "http://pgweb.ignorelist.com"
TARGET_HOST_STRIPPED = TARGET_HOST.replace("http://", "").replace("https://", "").rstrip("/")

REQ_LINE_RE = re.compile(
    r"^(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH)\s+(\S+)\s+HTTP\/([\d\.]+)",
    re.IGNORECASE,
)

Flow = namedtuple("Flow", ["base_seq", "buffer"])
flows = {}

def parse_http_request_from_bytes(buf_bytes):
    try:
        text = buf_bytes.decode("utf-8", errors="replace")
    except Exception:
        return None

    idx = text.find("\r\n\r\n")
    if idx == -1:
        return None

    header_block = text[: idx + 2]
    lines = header_block.splitlines()
    if not lines:
        return None

    m = REQ_LINE_RE.match(lines[0].strip())
    if not m:
        return None

    host = None
    for header in lines[1:]:
        if header.lower().startswith("host:"):
            host = header.split(":", 1)[1].strip()
            break

    return host, idx + 4

def process_packet(pkt):
    if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
        return

    ip_src = pkt[IP].src
    ip_dst = pkt[IP].dst
    tcp = pkt[TCP]
    sport = tcp.sport
    dport = tcp.dport

    if dport != 80:
        return

    key = (ip_src, sport, ip_dst, dport)

    if not pkt.haslayer(Raw):
        return

    payload = bytes(pkt[Raw].load)
    if not payload:
        return

    seq = tcp.seq

    if key not in flows:
        flows[key] = Flow(base_seq=seq, buffer=bytearray())
    flow = flows[key]

    offset = seq - flow.base_seq
    if offset < 0:
        offset = 0

    needed_len = offset + len(payload)
    if len(flow.buffer) < needed_len:
        flow.buffer.extend(b"\x00" * (needed_len - len(flow.buffer)))

    flow.buffer[offset:offset + len(payload)] = payload

    flows[key] = Flow(base_seq=flow.base_seq, buffer=flow.buffer)

    parse_result = parse_http_request_from_bytes(bytes(flow.buffer))
    if not parse_result:
        return

    host, headers_end = parse_result

    full_text = flow.buffer[:headers_end].decode("utf-8", errors="replace")
    sanitized_text = []
    for line in full_text.splitlines():
        if line.lower().startswith(("authorization:", "cookie:", "set-cookie:")):
            sanitized_text.append(f"{line.split(':', 1)[0]}: <redacted>")
        else:
            sanitized_text.append(line)
    sanitized_text = "\n".join(sanitized_text)

    if host:
        host_norm = host.split(":")[0].lower()
    else:
        host_norm = None

    if TARGET_HOST_STRIPPED and host_norm and host_norm != TARGET_HOST_STRIPPED.lower():
        return

    storage.add(ip_src)
    logger(str(sanitized_text))
    storage.show()

    remaining = flow.buffer[headers_end:]
    if remaining:
        flows[key] = Flow(base_seq=flow.base_seq + headers_end, buffer=bytearray(remaining))
    else:
        del flows[key]
