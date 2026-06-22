"""
文件名: port_scanner.py
功能:   端口扫描模块。区别于「连上就报开放」的简单扫描，本模块按端口类型分别做
        协议级验证：HTTP 端口发探测包看状态码、Banner 端口收服务标识、数据库等高危
        端口（MSSQL/PostgreSQL/RDP/SMB/MongoDB/Oracle 等）发对应协议握手包校验响应特征，
        Redis/ZooKeeper/Memcached 校验协议应答。以此大幅降低防火墙转发造成的误报。
作者:   李豪
版本:   v1.0
创建时间: 2026-06
"""

import socket
import struct
import threading
from queue import Queue

from tqdm import tqdm

from core.base_module import BaseModule


# -----------------------------------------------------------------------
# 端口分类：按验证方式把目标端口划分为四类，分别采用不同的探测策略
# -----------------------------------------------------------------------

# HTTP类端口：发HTTP探测包，有响应才算开放
HTTP_PORTS = {80, 81, 443, 7001, 8000, 8001, 8080, 8081, 8443, 8888, 9000, 9200}

# Banner自推送端口：连接后服务主动发banner，直接收即可
BANNER_PUSH_PORTS = {21, 22, 23, 25, 110, 143, 3306, 5900}

# 需要协议握手验证的高危端口
HANDSHAKE_PORTS = {139, 445, 1433, 1521, 3389, 5432, 27017}

# 其他特殊端口
SPECIAL_PORTS = {
    2181: b'ruok',          # ZooKeeper
    6379: b'PING\r\n',     # Redis
    11211: b'version\r\n', # Memcached
}

DEFAULT_CONNECT_TIMEOUT = 1.5
DEFAULT_BANNER_TIMEOUT  = 2.0

PORT_TIMEOUTS = {
    3389:  3.0,
    1433:  3.0,
    1521:  3.0,
    27017: 3.0,
    5432:  3.0,
}


# -----------------------------------------------------------------------
# 协议握手验证函数
# -----------------------------------------------------------------------

def _verify_mssql(s):
    """
    发送 MSSQL PreLogin 包，验证服务端回包中包含 MSSQL 特征。
    PreLogin TDS 包 type=0x12, status=0x01
    """
    prelogin = bytes([
        0x12, 0x01, 0x00, 0x2F, 0x00, 0x00, 0x00, 0x00,  # TDS header
        0x00, 0x00, 0x1A, 0x00, 0x06, 0x01, 0x00, 0x20,
        0x00, 0x01, 0x02, 0x00, 0x21, 0x00, 0x01, 0x03,
        0x00, 0x22, 0x00, 0x04, 0x04, 0x00, 0x26, 0x00,
        0x01, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ])
    try:
        s.sendall(prelogin)
        s.settimeout(DEFAULT_BANNER_TIMEOUT)
        data = s.recv(256)
        # MSSQL响应第一字节为0x04（PreLogin Response）
        return len(data) > 0 and data[0] == 0x04
    except OSError:
        return False


def _verify_postgresql(s):
    """
    发送 PostgreSQL StartupMessage，验证服务端返回认证请求。
    """
    # StartupMessage: length(4) + protocol(4) + "user\x00postgres\x00\x00"
    user_param = b'user\x00postgres\x00\x00'
    protocol   = struct.pack('>I', 196608)  # 3.0
    length     = struct.pack('>I', 4 + 4 + len(user_param))
    startup    = length + protocol + user_param
    try:
        s.sendall(startup)
        s.settimeout(DEFAULT_BANNER_TIMEOUT)
        data = s.recv(256)
        # PG响应：'R'=认证请求, 'E'=错误（也说明是PG）
        return len(data) > 0 and data[0] in (ord('R'), ord('E'))
    except OSError:
        return False


def _verify_rdp(s):
    """
    发送 RDP Connection Request (X.224)，验证服务端回包含 RDP 特征。
    """
    rdp_req = bytes([
        0x03, 0x00, 0x00, 0x13,  # TPKT header
        0x0E,                    # X.224 length
        0xE0,                    # X.224 CR TPDU
        0x00, 0x00,              # dst-ref
        0x00, 0x00,              # src-ref
        0x00,                    # class
        0x01, 0x00, 0x08, 0x00,  # RDP Negotiation Request
        0x00, 0x00, 0x00, 0x00,
    ])
    try:
        s.sendall(rdp_req)
        s.settimeout(DEFAULT_BANNER_TIMEOUT)
        data = s.recv(256)
        # RDP响应：TPKT header首字节0x03
        return len(data) > 4 and data[0] == 0x03
    except OSError:
        return False


def _verify_smb(s):
    """
    发送 SMB Negotiate Protocol Request，验证服务端返回 SMB 响应。
    """
    smb_neg = bytes([
        # NetBIOS Session Service
        0x00, 0x00, 0x00, 0x54,
        # SMB header
        0xFF, 0x53, 0x4D, 0x42,  # \xffSMB
        0x72,                    # Negotiate Protocol
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        # SMB Parameters
        0x00,
        # SMB Data
        0x31, 0x00,
        0x02, 0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x31, 0x2E, 0x30, 0x00,
        0x02, 0x4C, 0x4D, 0x31, 0x32, 0x58, 0x30, 0x30, 0x32, 0x00,
        0x02, 0x4E, 0x54, 0x20, 0x4C, 0x4D, 0x20, 0x30, 0x2E, 0x31, 0x32, 0x00,
        0x02, 0x53, 0x4D, 0x42, 0x20, 0x32, 0x2E, 0x30, 0x30, 0x32, 0x00,
    ])
    try:
        s.sendall(smb_neg)
        s.settimeout(DEFAULT_BANNER_TIMEOUT)
        data = s.recv(256)
        # SMB响应包含 \xffSMB 或 SMB2 标识
        return (b'\xffSMB' in data or b'\xfeSMB' in data)
    except OSError:
        return False


def _verify_mongodb(s):
    """
    发送 MongoDB OP_QUERY isMaster，验证响应中含 MongoDB 特征。
    """
    # OP_QUERY for isMaster
    query = bytes([
        0x41, 0x00, 0x00, 0x00,  # messageLength
        0x01, 0x00, 0x00, 0x00,  # requestID
        0x00, 0x00, 0x00, 0x00,  # responseTo
        0xD4, 0x07, 0x00, 0x00,  # opCode OP_QUERY=2004
        0x00, 0x00, 0x00, 0x00,  # flags
        0x61, 0x64, 0x6D, 0x69, 0x6E, 0x2E, 0x24, 0x63,
        0x6D, 0x64, 0x00,        # fullCollectionName "admin.$cmd\x00"
        0x00, 0x00, 0x00, 0x00,  # numberToSkip
        0x01, 0x00, 0x00, 0x00,  # numberToReturn
        # BSON document: {isMaster: 1}
        0x13, 0x00, 0x00, 0x00,
        0x10, 0x69, 0x73, 0x4D, 0x61, 0x73, 0x74, 0x65,
        0x72, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    ])
    try:
        s.sendall(query)
        s.settimeout(DEFAULT_BANNER_TIMEOUT)
        data = s.recv(256)
        return len(data) > 16 and data[12:16] == b'\x01\x00\x00\x00'  # OP_REPLY
    except OSError:
        return False


def _verify_oracle(s):
    """
    发送 Oracle TNS Connect 包，验证响应包含 TNS 特征。
    """
    tns_connect = bytes([
        0x00, 0x5A, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x01, 0x36, 0x01, 0x2C, 0x00, 0x00, 0x08, 0x00,
        0x7F, 0xFF, 0x7F, 0x08, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x3A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x28, 0x41, 0x44, 0x44, 0x52, 0x3D,
        0x28, 0x50, 0x52, 0x4F, 0x54, 0x4F, 0x43, 0x4F,
        0x4C, 0x3D, 0x54, 0x43, 0x50, 0x29, 0x28, 0x48,
        0x4F, 0x53, 0x54, 0x3D, 0x6C, 0x6F, 0x63, 0x61,
        0x6C, 0x68, 0x6F, 0x73, 0x74, 0x29, 0x28, 0x50,
        0x4F, 0x52, 0x54, 0x3D, 0x31, 0x35, 0x32, 0x31,
        0x29, 0x29,
    ])
    try:
        s.sendall(tns_connect)
        s.settimeout(DEFAULT_BANNER_TIMEOUT)
        data = s.recv(256)
        # TNS响应第5字节为0x02（Accept）或0x04（Refuse）
        return len(data) > 5 and data[4] in (0x02, 0x04)
    except OSError:
        return False


def _verify_netbios(s):
    """
    发送 NetBIOS Session Request，验证响应。
    """
    netbios_req = bytes([
        0x81, 0x00, 0x00, 0x44,
        0x20, 0x43, 0x4B, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00,
        0x20, 0x43, 0x41, 0x43, 0x41, 0x43, 0x41, 0x43,
        0x41, 0x43, 0x41, 0x43, 0x41, 0x43, 0x41, 0x43,
        0x41, 0x43, 0x41, 0x43, 0x41, 0x43, 0x41, 0x43,
        0x41, 0x43, 0x41, 0x43, 0x41, 0x43, 0x41, 0x00,
    ])
    try:
        s.sendall(netbios_req)
        s.settimeout(DEFAULT_BANNER_TIMEOUT)
        data = s.recv(64)
        return len(data) > 0
    except OSError:
        return False


HANDSHAKE_VERIFIERS = {
    139:   _verify_netbios,
    445:   _verify_smb,
    1433:  _verify_mssql,
    1521:  _verify_oracle,
    3389:  _verify_rdp,
    5432:  _verify_postgresql,
    27017: _verify_mongodb,
}


# -----------------------------------------------------------------------
# PortScanner
# -----------------------------------------------------------------------

class PortScanner(BaseModule):
    """带协议验证的端口扫描模块。"""

    def __init__(self):
        super().__init__()
        self.category = "port_scan"
        self.thread_count = 50
        # 待扫描端口 = 四类端口的并集，去重排序
        self.common_ports = sorted(
            HTTP_PORTS | BANNER_PUSH_PORTS | HANDSHAKE_PORTS | set(SPECIAL_PORTS)
        )

    def check_port(self, ip, port):
        """
        连接端口后根据端口类型做对应验证。
        返回 "port|摘要" 字符串，或 None（未开放/验证失败）。
        """
        connect_timeout = PORT_TIMEOUTS.get(port, DEFAULT_CONNECT_TIMEOUT)
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(connect_timeout)
            if s.connect_ex((ip, port)) != 0:
                return None

            # HTTP类：发请求，验证响应
            if port in HTTP_PORTS:
                return self._check_http(s, ip, port)

            # Banner自推送类：直接收banner
            if port in BANNER_PUSH_PORTS:
                return self._check_banner_push(s, port)

            # 协议握手验证类
            if port in HANDSHAKE_PORTS:
                verifier = HANDSHAKE_VERIFIERS.get(port)
                if verifier and verifier(s):
                    service_names = {
                        139: "NetBIOS", 445: "SMB", 1433: "MSSQL",
                        1521: "Oracle", 3389: "RDP", 5432: "PostgreSQL",
                        27017: "MongoDB",
                    }
                    return f"{port}({service_names.get(port, str(port))})"
                return None  # 验证失败，视为误报

            # 特殊端口
            if port in SPECIAL_PORTS:
                return self._check_special(s, port)

            return None

        except OSError:
            return None
        finally:
            if s:
                try:
                    s.close()
                except Exception:
                    pass

    def _check_http(self, s, ip, port):
        """HTTP/HTTPS端口验证，过滤无意义的400/404响应"""
        try:
            probe = b'HEAD / HTTP/1.0\r\nHost: ' + ip.encode() + b'\r\n\r\n'
            s.sendall(probe)
            s.settimeout(DEFAULT_BANNER_TIMEOUT)
            data = s.recv(256).decode('utf-8', errors='ignore').strip()
            if not data:
                return None

            first_line = data.split('\n')[0].strip()

            # 提取状态码
            parts = first_line.split()
            if len(parts) >= 2:
                try:
                    status_code = int(parts[1])
                except ValueError:
                    return None

                # 过滤无意义响应：400/404说明端口开着但不是Web服务或路径不存在
                # 只保留有实际意义的状态码
                if status_code in (400, 404):
                    return None

                # 只返回端口号+状态码，不要冗长banner
                return f"{port}({status_code})"

            return None
        except OSError:
            return None

    def _check_banner_push(self, s, port):
        """接收服务主动推送的banner，只取第一行关键信息"""
        try:
            s.settimeout(DEFAULT_BANNER_TIMEOUT)
            data = s.recv(256).decode('utf-8', errors='ignore').strip()
            if not data:
                return None
            # 只取第一行，去掉版本号后面的冗余信息
            first_line = data.split('\n')[0].strip()[:30]
            return f"{port}({first_line})"
        except OSError:
            return None

    def _check_special(self, s, port):
        """
        特殊协议端口验证，必须验证响应内容符合协议特征才算开放。
        防止防火墙把所有端口流量转给HTTP服务导致的误报。
        """
        # 每个协议的探测包和必须包含的响应特征
        validators = {
            6379:  (b'PING\r\n',      b'+PONG'),    # Redis: 必须回 +PONG
            2181:  (b'ruok',           b'imok'),     # ZooKeeper: 必须回 imok
            11211: (b'version\r\n',   b'VERSION'),  # Memcached: 必须回 VERSION
        }
        port_names = {6379: "Redis", 2181: "ZooKeeper", 11211: "Memcached"}

        if port not in validators:
            return None

        probe, expected = validators[port]
        try:
            s.sendall(probe)
            s.settimeout(DEFAULT_BANNER_TIMEOUT)
            data = s.recv(256)
            # 响应必须包含协议特征字节，否则视为误报
            if expected not in data:
                return None
            return f"{port}({port_names[port]})"
        except OSError:
            return None

    def worker(self, q, results_map, lock, pbar):
        """扫描工作线程：从队列取 (IP, 端口) 检测，开放则按 IP 归类写入结果字典（加锁）。"""
        while True:
            task = q.get()
            if task is None:  # 哨兵值，退出线程
                q.task_done()
                break
            ip, port = task
            try:
                res = self.check_port(ip, port)
                if res:
                    with lock:
                        results_map.setdefault(ip, []).append(res)
            except Exception:
                pass
            finally:
                pbar.update(1)
                q.task_done()

    def run(self, ip_list):
        """
        端口扫描主流程：从存活站点中提取真实 IP（去重、排除 CDN 与无效 IP），
        用「任务队列 + 多线程」对每个 IP 的每个端口并发检测，返回 {IP: [开放端口...]}。
        """
        # 只扫描真实物理 IP：排除 0.0.0.0 占位与走 CDN 的站点
        targets = list({
            item.ip for item in ip_list
            if item.ip != "0.0.0.0" and not item.is_cdn
        })

        if not targets:
            self.log("没有符合扫描条件的真实 IP，跳过端口扫描。")
            return {}

        self.log(
            f"开始对 {len(targets)} 个独立 IP 进行端口扫描 "
            f"(端口数: {len(self.common_ports)}, 线程数: {self.thread_count})..."
        )

        q = Queue()
        for ip in targets:
            for port in self.common_ports:
                q.put((ip, port))

        results_map = {}
        lock = threading.Lock()
        pbar = tqdm(total=q.qsize(), desc="Port Scanning", unit="req", colour='cyan')

        threads = []
        for _ in range(self.thread_count):
            t = threading.Thread(
                target=self.worker,
                args=(q, results_map, lock, pbar)
            )
            t.daemon = True
            t.start()
            threads.append(t)

        q.join()
        for _ in range(self.thread_count):
            q.put(None)
        for t in threads:
            t.join()
        pbar.close()

        open_count = sum(len(v) for v in results_map.values())
        self.log(
            f"端口扫描完成，{len(results_map)} 个 IP 共发现 {open_count} 个开放端口。"
        )
        return results_map