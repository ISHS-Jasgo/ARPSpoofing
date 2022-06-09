package com.github.jasgo;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapIf;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;

public class Test {
    public static void main(String[] args) {
        ArrayList<PcapIf> allDevs = new ArrayList<>();
        StringBuilder errbuf = new StringBuilder();

        int r = Pcap.findAllDevs(allDevs, errbuf);
        if (r == Pcap.NOT_OK || allDevs.isEmpty()) {
            System.out.println("네트워크 장치를 찾을 수 없습니다. " + errbuf.toString());
            return;
        }
        System.out.println("[ 네트워크 장치 탐색 성공 ]");

        try {
            for (final PcapIf device : allDevs) {
                final byte[] mac = device.getHardwareAddress();
                if (mac == null) {
                    continue;
                }
                System.out.printf("장치주소: %s\n맥주소: %s\n", device.getName(), asString(mac));
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        int i = 0;
        for (PcapIf device : allDevs) {
            String description = (device.getDescription() != null) ? device.getDescription() : "장비에 대한 설명이 없습니다.";
            System.out.printf("[%d번]: %s [%s]\n", i++, device.getName(), description);
        }

        PcapIf device = allDevs.get(4);
        System.out.printf("선택한 장치: %s\n", (device.getDescription() != null) ? device.getDescription() : device.getName());

        int snaplen = 64 * 1024;
        int flags = Pcap.MODE_PROMISCUOUS;
        int timeout = 10 * 1000;

        Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
        if (pcap == null) {
            System.out.printf("패킷캡쳐를 위해 네트워크 장치를 여는 데에 실패했습니다.");
            return;
        }

        byte[] bytes = new byte[14];
        Arrays.fill(bytes, (byte) 0xff);

        ByteBuffer buffer = ByteBuffer.wrap(bytes);

        if (pcap.sendPacket(buffer) != Pcap.OK) {
            System.out.println(pcap.getErr());
        }
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x ", b&0xff));
        }
        System.out.println("전송한 패킷: " + sb.toString());

        Ethernet eth = new Ethernet();
        Ip4 ip = new Ip4();
        Tcp tcp = new Tcp();
        Payload payload = new Payload();
        PcapHeader header = new PcapHeader(JMemory.POINTER);
        JBuffer buf = new JBuffer(JMemory.POINTER);
        int id = JRegistry.mapDLTToId(pcap.datalink());

        while (pcap.nextEx(header, buf) != Pcap.NEXT_EX_NOT_OK) {
            PcapPacket packet = new PcapPacket(header, buf);
            packet.scan(id);
            System.out.printf("[ #%d ]\n", packet.getFrameNumber());
            if (packet.hasHeader(eth)) {
                System.out.printf("출발지 MAC주소 = %s\n도착지 MAC주소 = %s\n", FormatUtils.mac(eth.source()), FormatUtils.mac(eth.destination()));
            }
            if (packet.hasHeader(ip)) {
                System.out.printf("출발지 IP주소 = %s\n도착지 IP주소 = %s\n", FormatUtils.ip(ip.source()), FormatUtils.ip(ip.destination()));
            }
            if (packet.hasHeader(tcp)) {
                System.out.printf("출발지 TCP주소 = %d\n도착지 TCP주소 = %d\n", tcp.source(), tcp.destination());
            }
            if (packet.hasHeader(payload)) {
                System.out.printf("페이로드의 길이 = %d\n", payload.getLength());
                System.out.print(payload.toHexdump());
            }
        }

        PcapPacketHandler<String> jPacketHandler = new PcapPacketHandler<String>() {
            @Override
            public void nextPacket(PcapPacket packet, String s) {
                System.out.printf("캡쳐시각: %s\n패킷의 길이: %-4d\n", new Date(packet.getCaptureHeader().timestampInMillis()), packet.getCaptureHeader().caplen());
            }
        };

        pcap.close();
    }
    public static String asString(final byte[] mac) {
        final StringBuilder buf = new StringBuilder();
        for (byte b : mac) {
            if (buf.length() != 0) {
                buf.append(":");
            }
            if (b >= 0 && b < 16) {
                buf.append("0");
            }
            buf.append(Integer.toHexString((b < 0) ? b+256 : b).toUpperCase());
        }
        return buf.toString();
    }
}
