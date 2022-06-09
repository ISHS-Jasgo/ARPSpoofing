package com.github.jasgo;

import java.util.Arrays;

public class ARP {
    private byte[] destinationMAC = new byte[6];
    private byte[] sourceMAC = new byte[6];
    private byte[] ethernetType = {0x08, 0x06};
    private byte[] hardwareType = {0x00, 0x01};
    private byte[] protocolType = {0x08, 0x00};
    private byte hardwareSize = 0x06;
    private byte protocolSize = 0x04;
    private byte[] opcode = new byte[2];
    private byte[] senderMAC = new byte[6];
    private byte[] senderIP = new byte[4];
    private byte[] targetMAC = new byte[6];
    private byte[] targetIP = new byte[4];

    public void makeARPRequest(byte[] sourceMAC, byte[] senderIP, byte[] targetIP) {
        Arrays.fill(destinationMAC, (byte) 0xff);
        System.arraycopy(sourceMAC, 0, this.sourceMAC, 0, 6);
        opcode[0] = 0x00; opcode[1] = 0x01;
        System.arraycopy(sourceMAC, 0, this.senderMAC, 0, 6);
        System.arraycopy(senderIP, 0, this.senderIP, 0, 4);
        Arrays.fill(targetMAC, (byte) 0xff);
        System.arraycopy(targetIP, 0, this.targetIP, 0, 4);
    }
    public void makeARPReply(byte[] destinationMAC, byte[] sourceMAC, byte[] senderMAC, byte[] senderIP, byte[] targetMAC, byte[] targetIP) {
        System.arraycopy(destinationMAC, 0, this.destinationMAC, 0, 6);
        System.arraycopy(sourceMAC, 0, this.sourceMAC, 0, 6);
        opcode[0] = 0x00; opcode[1] = 0x02;
        System.arraycopy(senderMAC, 0, this.senderMAC, 0, 6);
        System.arraycopy(senderIP, 0, this.senderIP, 0, 4);
        System.arraycopy(targetMAC, 0, this.targetMAC, 0, 6);
        System.arraycopy(targetIP, 0, this.targetIP, 0, 4);
    }
    public byte[] getPacket() {
        byte[] bytes = new byte[42];
        System.arraycopy(destinationMAC, 0, bytes, 0, destinationMAC.length);
        System.arraycopy(sourceMAC, 0, bytes, 6, sourceMAC.length);
        System.arraycopy(ethernetType, 0, bytes, 12, ethernetType.length);
        System.arraycopy(hardwareType, 0, bytes, 14, hardwareType.length);
        System.arraycopy(protocolType, 0, bytes, 16, protocolType.length);
        bytes[18] = hardwareSize;
        bytes[19] = protocolSize;
        System.arraycopy(opcode, 0, bytes, 20, opcode.length);
        System.arraycopy(senderMAC, 0, bytes, 22, senderMAC.length);
        System.arraycopy(senderIP, 0, bytes, 28, senderIP.length);
        System.arraycopy(targetMAC, 0, bytes, 32, targetMAC.length);
        System.arraycopy(targetIP, 0, bytes, 38, targetIP.length);
        return bytes;
    }

}
