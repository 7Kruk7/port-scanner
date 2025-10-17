import socket
import errno
def scan_port(ip, port):
    #create the socket, ip v4, TCP protocol
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket.setdefaulttimeout(1)
    try:
        result = s.connect_ex((ip,port))
        if result == 0:
            return (port, "open")
        elif result in (errno.ECONNREFUSED, 10061):
            return (port, "close")
        else:
            return (port, "filtered")
    except Exception:
        return (port, "filtered")
    finally:
        s.close()