#!/usr/bin/env python3
"""Small stateful NAT-PMP gateway used only by the isolated acceptance test."""

import argparse
import select
import socket
import struct
import time


def reply_public(sock, peer, epoch):
    packet = struct.pack("!BBHI4B", 0, 128, 0, epoch, 198, 51, 100, 7)
    sock.sendto(packet, peer)


def reply_mapping(sock, peer, epoch, private_port, external_port):
    packet = struct.pack(
        "!BBHIHHI", 0, 129, 0, epoch, private_port, external_port, 2
    )
    sock.sendto(packet, peer)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", required=True)
    parser.add_argument("--events", required=True)
    args = parser.parse_args()

    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((args.bind, 5351))
    control = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    control.bind((args.bind, 5352))
    started = time.monotonic()
    responding = True
    external_port = 45000

    with open(args.events, "a", encoding="ascii", buffering=1) as events:
        events.write("ready\n")
        while True:
            readable, _, _ = select.select([server, control], [], [])
            for current in readable:
                packet, peer = current.recvfrom(64)
                if current is control:
                    command = packet.decode("ascii", errors="strict")
                    if command == "replace":
                        external_port = 45001
                    elif command == "drop":
                        responding = False
                    elif command == "restore":
                        responding = True
                        external_port = 45002
                    elif command == "stop":
                        current.sendto(b"ok", peer)
                        return
                    else:
                        raise RuntimeError(f"unknown control command {command!r}")
                    events.write(f"control {command}\n")
                    current.sendto(b"ok", peer)
                    continue

                if not responding or len(packet) < 2 or packet[0] != 0:
                    continue
                epoch = int(time.monotonic() - started)
                opcode = packet[1]
                if opcode == 0 and len(packet) == 2:
                    reply_public(server, peer, epoch)
                elif opcode == 1 and len(packet) == 12:
                    private_port = struct.unpack("!H", packet[4:6])[0]
                    lifetime = struct.unpack("!I", packet[8:12])[0]
                    if lifetime == 0:
                        events.write(f"delete {private_port}\n")
                    else:
                        events.write(f"map {private_port} {external_port}\n")
                        reply_mapping(
                            server, peer, epoch, private_port, external_port
                        )


if __name__ == "__main__":
    main()
