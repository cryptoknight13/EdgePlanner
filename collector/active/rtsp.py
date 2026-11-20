"""RTSP banner: one OPTIONS request, response returned verbatim."""
import socket


def banner(ip: str, port: int, timeout: float = 5.0) -> str | None:
    request = f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: edge-monitor\r\n\r\n"
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.sendall(request.encode())
            data = s.recv(4096)
    except OSError:
        return None
    return data.decode("utf-8", "replace").strip() or None
