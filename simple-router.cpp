/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

namespace simple_router
{
    const Buffer BROADCAST_ADDR{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    // 实现验证arp合法函数
    bool SimpleRouter::isValidArpHeader(const Buffer &packet, const arp_hdr *arpHeader) const
    {
        // 检查长度
        if (packet.size() != sizeof(arp_hdr) + sizeof(ethernet_hdr))
        {
            std::cerr << "Invalid ARP packet length: " << packet.size() << std::endl;
            return false;
        }

        // 硬件类型
        if (ntohs(arpHeader->arp_hrd) != arp_hrd_ethernet)
        {
            std::cerr << "Unsupported ARP hardware type: " << ntohs(arpHeader->arp_hrd) << std::endl;
            return false;
        }

        // 协议类型
        if (ntohs(arpHeader->arp_pro) != ethertype_ip)
        {
            std::cerr << "Unsupported ARP protocol type: " << ntohs(arpHeader->arp_pro) << std::endl;
            return false;
        }

        // 硬件地址长度
        if (arpHeader->arp_hln != ETHER_ADDR_LEN)
        {
            std::cerr << "Invalid ARP hardware address length: " << (int)arpHeader->arp_hln << std::endl;
            return false;
        }

        // 协议地址长度
        if (arpHeader->arp_pln != 4)
        {
            std::cerr << "Invalid ARP protocol address length: " << (int)arpHeader->arp_pln << std::endl;
            return false;
        }

        // 操作码
        if (ntohs(arpHeader->arp_op) != arp_op_request && ntohs(arpHeader->arp_op) != arp_op_reply)
        {
            std::cerr << "Invalid ARP opcode: " << ntohs(arpHeader->arp_op) << std::endl;
            return false;
        }

        return true;
    }

    // 填充以太网帧头部内容
    void SimpleRouter::fillEthernetHeader(Buffer &packet, const uint8_t *srcMac, const uint8_t *dstMac, uint16_t etherType)
    {
        ethernet_hdr *ethHeader = reinterpret_cast<ethernet_hdr *>(packet.data());
        memcpy(ethHeader->ether_shost, srcMac, ETHER_ADDR_LEN); // 源 MAC
        memcpy(ethHeader->ether_dhost, dstMac, ETHER_ADDR_LEN); // 目标 MAC
        ethHeader->ether_type = htons(etherType);               // 以太网类型
    }

    // 填充arp头部内容
    void SimpleRouter::fillArpHeader(Buffer &packet, uint32_t srcIp, const uint8_t *srcMac, uint32_t dstIp, const uint8_t *dstMac, uint16_t opCode)
    {
        arp_hdr *arpHeader = reinterpret_cast<arp_hdr *>(packet.data() + sizeof(ethernet_hdr));

        // 填充通用 ARP 头部字段
        arpHeader->arp_hrd = htons(arp_hrd_ethernet); // 硬件类型：以太网
        arpHeader->arp_pro = htons(ethertype_ip);     // 协议类型：IPv4
        arpHeader->arp_hln = ETHER_ADDR_LEN;          // 硬件地址长度
        arpHeader->arp_pln = sizeof(uint32_t);        // 协议地址长度
        arpHeader->arp_op = htons(opCode);            // 操作码：Request 或 Reply

        // 源 IP 和 MAC 地址
        arpHeader->arp_sip = srcIp;
        memcpy(arpHeader->arp_sha, srcMac, ETHER_ADDR_LEN);

        // 目标 IP 地址
        arpHeader->arp_tip = dstIp;

        // 目标 MAC 地址
        if (dstMac != nullptr)
        {
            memcpy(arpHeader->arp_tha, dstMac, ETHER_ADDR_LEN);
        }
        else
        {
            memset(arpHeader->arp_tha, 0, ETHER_ADDR_LEN);
        }
    }

    // 处理arp数据包
    void SimpleRouter::handleArpPacket(const Buffer &packet, const std::string &inface)
    {
        std::cerr << "Received ARP packet on interface " << inface << std::endl;

        // 解析ARP头部
        const arp_hdr *arpHeader = reinterpret_cast<const arp_hdr *>(packet.data() + sizeof(ethernet_hdr));

        // 校验ARP数据包合法性
        if (!isValidArpHeader(packet, arpHeader))
        {
            std::cerr << "Invalid ARP packet, ignoring." << std::endl;
            return;
        }

        // 根据操作码处理AR 数据包
        switch (ntohs(arpHeader->arp_op))
        {
        case arp_op_request:
            std::cerr << "Processing ARP Request" << std::endl;
            handleArpRequest(packet, inface);
            break;

        case arp_op_reply:
            std::cerr << "Processing ARP Reply" << std::endl;
            handleArpReply(packet);
            break;

        default:
            std::cerr << "Unexpected ARP opcode, ignoring." << std::endl;
            break;
        }
    }

    // 处理ARP请求
    void SimpleRouter::handleArpRequest(const Buffer &packet, const std::string &inface)
    {
        std::cerr << "[ARP Request] Received ARP request on interface " << inface << std::endl;

        // 解析以太网头部和ARP请求头部
        const ethernet_hdr *ethHeader = reinterpret_cast<const ethernet_hdr *>(packet.data());
        const arp_hdr *arpHeader = reinterpret_cast<const arp_hdr *>(packet.data() + sizeof(ethernet_hdr));

        // 获取接收数据包的接口信息
        const Interface *iface = findIfaceByName(inface);

        if (iface == nullptr)
        {
            std::cerr << "[ARP Request] Interface " << inface << " not found, ignoring." << std::endl;
            return;
        }
        // 检查目标IP地址是否属于路由器
        if (ntohl(arpHeader->arp_tip) != ntohl(iface->ip))
        {
            std::cerr << "[ARP Request] Target IP " << ipToString(arpHeader->arp_tip)
                      << " is not for this router, ignoring." << std::endl;
            return;
        }

        // 构造ARP回复
        Buffer reply(sizeof(ethernet_hdr) + sizeof(arp_hdr));

        // 填充以太网头部
        fillEthernetHeader(reply, iface->addr.data(), ethHeader->ether_shost, ethertype_arp);

        // 填充ARP回复头部
        fillArpHeader(reply, iface->ip, iface->addr.data(), arpHeader->arp_sip, arpHeader->arp_sha, arp_op_reply);

        // 发送ARP回复
        sendPacket(reply, inface);

        std::cerr << "[ARP Reply] Sent ARP reply: "
                  << " Target IP " << ipToString(arpHeader->arp_sip)
                  << ", Target MAC " << macToString(Buffer(arpHeader->arp_sha, arpHeader->arp_sha + ETHER_ADDR_LEN))
                  << ", Interface " << inface << std::endl;
    }

    // 处理ARP回复

    void SimpleRouter::handleArpReply(const Buffer &packet)
    {
        std::cerr << "Handling ARP Reply" << std::endl;

        // 解析 ARP 回复头部
        const ethernet_hdr *ethHeader = reinterpret_cast<const ethernet_hdr *>(packet.data());
        const arp_hdr *arp_ptr = reinterpret_cast<const arp_hdr *>(packet.data() + sizeof(ethernet_hdr));

        uint32_t sender_ip = arp_ptr->arp_sip;
        Buffer sender_mac(arp_ptr->arp_sha, arp_ptr->arp_sha + ETHER_ADDR_LEN);

        std::cout << "Received ARP Reply: IP " << ipToString(sender_ip) << " MAC " << macToString(sender_mac) << std::endl;

        // 检查 ARP 缓存中是否已存在该 IP
        auto existing_entry = m_arp.lookup(sender_ip);
        if (existing_entry)
        {
            std::cout << "IP " << ipToString(sender_ip) << " already exists in ARP cache, updating MAC address." << std::endl;
            existing_entry->mac = sender_mac;                // 更新 MAC 地址
            existing_entry->timeAdded = steady_clock::now(); // 可选：更新时间戳
        }
        else
        {
            std::cout << "IP " << ipToString(sender_ip) << " does not exist in ARP cache, inserting new entry." << std::endl;
            // 插入新的 ARP 缓存条目
            auto arp_req = m_arp.insertArpEntry(sender_mac, sender_ip);
            if (arp_req)
            {
                std::cout << "Handle queued requests for the IP/MAC" << std::endl;
                for (const auto &pkt : arp_req->packets)
                {
                    std::cerr << "Resending queued packet to interface " << pkt.iface << std::endl;
                    // 查找对应的接口
                    const Interface *outIface = findIfaceByName(pkt.iface);
                    if (outIface)
                    {
                        // 更新以太网头部
                        ethernet_hdr *ethHdr = reinterpret_cast<ethernet_hdr *>(const_cast<uint8_t *>(pkt.packet.data()));
                        memcpy(ethHdr->ether_shost, outIface->addr.data(), ETHER_ADDR_LEN); // 设置源 MAC 为出接口的 MAC
                        memcpy(ethHdr->ether_dhost, sender_mac.data(), ETHER_ADDR_LEN);     // 设置目标 MAC 为 ARP 回复中的 MAC
                        ethHdr->ether_type = htons(ethertype_ip);                           // 确保 EtherType 为 IP

                        std::cerr << "src MAC: " << macToString(outIface->addr) << " dst MAC: " << macToString(sender_mac) << std::endl;

                        // 重新计算 IP 校验和（如果需要）
                        ip_hdr *ipHeader = reinterpret_cast<ip_hdr *>(const_cast<uint8_t *>(pkt.packet.data()) + sizeof(ethernet_hdr));
                        ipHeader->ip_sum = 0;
                        ipHeader->ip_sum = cksum(reinterpret_cast<uint16_t *>(ipHeader), ipHeader->ip_hl * 4);

                        // 发送数据包
                        sendPacket(pkt.packet, pkt.iface);
                    }
                    else
                    {
                        std::cerr << "Interface " << pkt.iface << " not found, cannot resend packet." << std::endl;
                    }
                }
                m_arp.removeRequest(arp_req);
            }
            else
            {
                std::cout << "No queued requests for the IP/MAC" << std::endl;
            }
        }
    }

    void SimpleRouter::sendArpRequest(uint32_t ip)
    {

        // 创建一个缓冲区来存储以太网帧和 ARP 包
        Buffer req(sizeof(ethernet_hdr) + sizeof(arp_hdr));

        // 查找路由表以获取下一跳和要发送的接口
        const RoutingTableEntry entry = m_routingTable.lookup(ip);
        const Interface *outIface = findIfaceByName(entry.ifName);

        if (!outIface)
        {
            std::cerr << "Interface not found for ARP request." << std::endl;
            return;
        }

        // 广播 MAC 地址
        const uint8_t BROADCAST_ADDR[ETHER_ADDR_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

        // 填充以太网头部
        fillEthernetHeader(req, outIface->addr.data(), BROADCAST_ADDR, ethertype_arp);

        // 填充 ARP 请求头部
        fillArpHeader(req, outIface->ip, outIface->addr.data(), ip, nullptr, arp_op_request);

        // 发送 ARP 请求包
        sendPacket(req, outIface->name);
    }

    // 处理IPv4数据包
    void SimpleRouter::handleIPv4Packet(const Buffer &packet, const std::string &inIface)
    {
        std::cerr << "Enter HandleIpv4Packet" << std::endl;
        // 检查数据包长度是否足够包含 IP 头部
        if (packet.size() < sizeof(ethernet_hdr) + sizeof(ip_hdr))
        {
            std::cerr << "Packet too short for IP header" << std::endl;
            return;
        }

        // 解析 IP 头部
        const ip_hdr *ipHeader = reinterpret_cast<const ip_hdr *>(packet.data() + sizeof(ethernet_hdr));

        // 打印调试信息，包括 seq 和其他信息
        std::cerr << "[DEBUG] Received IP packet on " << inIface
                  << " | seq: " << ntohs(ipHeader->ip_id)
                  << " | src: " << ipToString(ipHeader->ip_src)
                  << " | dst: " << ipToString(ipHeader->ip_dst)
                  << " | ttl: " << static_cast<int>(ipHeader->ip_ttl)
                  << std::endl;

        // 检查 IP 头部长度
        uint8_t ipHeaderLen = ipHeader->ip_hl * 4;
        if (ipHeaderLen < sizeof(ip_hdr))
        {
            std::cerr << "Invalid IP header length: " << static_cast<int>(ipHeaderLen) << std::endl;
            return;
        }

        // 检查数据包总长度
        uint16_t totalLen = ntohs(ipHeader->ip_len);
        if (packet.size() < sizeof(ethernet_hdr) + totalLen)
        {
            std::cerr << "Incomplete IP packet" << std::endl;
            return;
        }

        // 提取检查校验和
        uint16_t receivedChecksum = ipHeader->ip_sum;
        ip_hdr tempHeader = *ipHeader;
        tempHeader.ip_sum = 0;

        // 计算校验和
        uint16_t calculatedChecksum = cksum(reinterpret_cast<uint16_t *>(&tempHeader), ipHeaderLen);

        // 转换校验和是0的情况
        if (calculatedChecksum == 0)
        {
            calculatedChecksum = 0xFFFF;
        }

        // 比较校验和是否合法
        if (receivedChecksum != calculatedChecksum)
        {
            std::cerr << "Invalid IP checksum" << std::endl;
            return;
        }

        // 检查目的 IP 地址是否为路由器自身的 IP 地址
        uint32_t destIp = ipHeader->ip_dst;
        bool isForRouter = false;
        for (const auto &iface : m_ifaces)
        {
            if (iface.ip == destIp)
            {
                isForRouter = true;
                std::cerr << "IP packet is for router" << std::endl;
                break;
            }
        }

        // 检查arp缓存表中是否有源地址的ip和mac
        const ethernet_hdr *ethHeader = reinterpret_cast<const ethernet_hdr *>(packet.data());
        uint32_t srcIp = ipHeader->ip_src;
        const uint8_t *srcMac = ethHeader->ether_shost;

        // 检查 ARP 缓存中是否已存在该 IP
        if (m_arp.lookup(srcIp))
        {
            std::cerr << "IP " << ipToString(srcIp) << " already exists in ARP cache, updating MAC address." << std::endl;
        }
        else
        {
            std::cerr << "IP " << ipToString(srcIp) << " does not exist in ARP cache, forward IP packet to destination." << std::endl;
        }

        if (isForRouter)
        {
            // 处理目的为路由器的 IP 数据包
            processLocalIpPacket(packet, inIface, ipHeader, ipHeaderLen);
        }
        else
        {
            // 转发数据包
            forwardIpPacket(packet, inIface, ipHeader, ipHeaderLen);
        }
    }

    void SimpleRouter::processLocalIpPacket(const Buffer &packet, const std::string &inIface, const ip_hdr *ipHeader, uint8_t ipHeaderLen)
    {
        // 提取协议字段
        uint8_t protocol = ipHeader->ip_p;

        if (protocol == ip_protocol_icmp)
        {
            handleIcmpPacket(packet, inIface);
        }
        else if (protocol == ip_protocol_tcp || protocol == ip_protocol_udp)
        {
            // 发送 ICMP Port Unreachable 消息
            handleIcmpPortUnreachable(packet, inIface);
        }
        else
        {
            std::cerr << "Protocol " << static_cast<int>(protocol) << " not supported, discarding packet" << std::endl;
        }
    }
    // 转发IP数据包
    void SimpleRouter::forwardIpPacket(const Buffer &packet, const std::string &inIface, const ip_hdr *ipHeader, uint8_t ipHeaderLen)
    {
        std::cerr << "Enter Forwarding IP packet" << std::endl;
        // 检查并递减 TTL
        if (ipHeader->ip_ttl <= 1)
        {
            std::cerr << "TTL expired, sending ICMP Time Exceeded" << std::endl;
            sendIcmpError(packet, inIface, ICMP_TIME_EXCEEDED, ICMP_TTL_EXCEEDED);
            return;
        }

        // 创建新的数据包缓冲区，准备修改
        Buffer newPacket = packet;
        ip_hdr *newIpHeader = reinterpret_cast<ip_hdr *>(newPacket.data() + sizeof(ethernet_hdr));

        // 递减 TTL
        newIpHeader->ip_ttl--;

        // 重新计算 IP 校验和
        newIpHeader->ip_sum = 0;
        newIpHeader->ip_sum = cksum(reinterpret_cast<uint16_t *>(newIpHeader), ipHeaderLen);

        // 使用最长前缀匹配查找路由表
        uint32_t destIp = newIpHeader->ip_dst;
        RoutingTableEntry entry = m_routingTable.lookup(destIp);
        if (entry.ifName.empty())
        {
            std::cerr << "No matching route found, sending ICMP Destination Net Unreachable" << std::endl;
            sendIcmpError(packet, inIface, ICMP_DEST_UNREACH, ICMP_CODE_NET_UNREACH);
            return;
        }

        // 确定下一跳 IP 地址
        uint32_t nextHopIp = entry.gw;
        if (nextHopIp == 0)
        {
            // 直连路由，下一跳为目的 IP
            nextHopIp = destIp;
        }

        // 查找 ARP 缓存，获取下一跳 MAC 地址
        auto arpEntry = m_arp.lookup(nextHopIp);
        Buffer nextHopMac;
        if (arpEntry)
        {
            std::cerr << "ARP entry found for IP " << ipToString(nextHopIp) << std::endl;
            nextHopMac = arpEntry->mac;

            // 更新以太网头部
            ethernet_hdr *ethHeader = reinterpret_cast<ethernet_hdr *>(newPacket.data());
            const Interface *outIface = findIfaceByName(entry.ifName);
            if (!outIface)
            {
                std::cerr << "Output interface " << entry.ifName << " not found." << std::endl;
                return;
            }

            // 设置源 MAC 地址为出接口的 MAC 地址
            memcpy(ethHeader->ether_shost, outIface->addr.data(), ETHER_ADDR_LEN);
            // 设置目的 MAC 地址为下一跳的 MAC 地址
            memcpy(ethHeader->ether_dhost, nextHopMac.data(), ETHER_ADDR_LEN);

            // 发送数据包
            sendPacket(newPacket, outIface->name);
        }
        else
        {
            // 发送 ARP 请求
            std::cerr << "ARP entry not found for IP " << ipToString(nextHopIp) << ", sending ARP request" << std::endl;
            sendArpRequest(nextHopIp);
            // 将数据包加入等待队列
            auto req = m_arp.queueRequest(nextHopIp, packet, entry.ifName);
            std::cerr << "Current queue size for IP " << ipToString(nextHopIp) << ": " << req->packets.size() << std::endl;
        }
    }
    // 发送ICMP错误消息
    void SimpleRouter::sendIcmpError(const Buffer &packet, const std::string &inIface, uint8_t type, uint8_t code)
    {
        ethernet_hdr *eth_ptr = (struct ethernet_hdr *)((uint8_t *)packet.data());
        ip_hdr *ip_ptr = (struct ip_hdr *)((uint8_t *)packet.data() + sizeof(ethernet_hdr));

        Buffer reply(sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_t3_hdr));
        const Interface *outIface = findIfaceByName(inIface);

        // 以太网帧
        ethernet_hdr *rep_eth = (ethernet_hdr *)reply.data();
        memcpy(rep_eth->ether_dhost, eth_ptr->ether_shost, ETHER_ADDR_LEN);
        memcpy(rep_eth->ether_shost, eth_ptr->ether_dhost, ETHER_ADDR_LEN);
        rep_eth->ether_type = htons(ethertype_ip);

        // ip部分
        ip_hdr *rep_ip = (ip_hdr *)(reply.data() + sizeof(ethernet_hdr));
        memcpy(rep_ip, ip_ptr, sizeof(ip_hdr));
        rep_ip->ip_tos = 0;
        rep_ip->ip_len = htons(sizeof(ip_hdr) + sizeof(icmp_t3_hdr));
        rep_ip->ip_id = 0;
        rep_ip->ip_ttl = 64;
        rep_ip->ip_p = ip_protocol_icmp;
        rep_ip->ip_sum = 0;
        rep_ip->ip_src = outIface->ip;
        rep_ip->ip_dst = ip_ptr->ip_src;
        rep_ip->ip_sum = cksum(rep_ip, sizeof(ip_hdr));

        // icmp错误类型3
        icmp_t3_hdr *rep_icmpt3 = (struct icmp_t3_hdr *)(reply.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr));
        rep_icmpt3->icmp_type = type;
        rep_icmpt3->icmp_code = code;
        rep_icmpt3->icmp_sum = 0;
        rep_icmpt3->next_mtu = 0;
        rep_icmpt3->unused = 0;
        std::memcpy(rep_icmpt3->data, ip_ptr, ICMP_DATA_SIZE);
        rep_icmpt3->icmp_sum = cksum(rep_icmpt3, sizeof(icmp_t3_hdr));
        std::cerr << "Sending ICMP error type " << static_cast<int>(type) << " code " << static_cast<int>(code) << std::endl;
        sendPacket(reply, inIface);
    }

    // 处理ICMP数据包
    void SimpleRouter::handleIcmpPacket(const Buffer &packet, const std::string &inIface)
    {
        std::cerr << "Handling ICMP packet" << std::endl;

        // 检查数据包长度是否足够
        if (packet.size() < sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_hdr))
        {
            std::cout << "Packet is too short for ICMP header, ignoring." << std::endl;
            return;
        }

        // 获取 IP 头部
        const ip_hdr *ipHdr = reinterpret_cast<const ip_hdr *>(packet.data() + sizeof(ethernet_hdr));
        uint8_t ipHdrLen = ipHdr->ip_hl * 4;

        // 检查 IP 头部长度是否合理
        if (ipHdrLen < sizeof(ip_hdr))
        {
            std::cout << "Invalid IP header length: " << static_cast<int>(ipHdrLen) << std::endl;
            return;
        }

        // 获取 ICMP 头部
        const icmp_hdr *icmpHdr = reinterpret_cast<const icmp_hdr *>(packet.data() + sizeof(ethernet_hdr) + ipHdrLen);

        // 计算 ICMP 数据长度
        size_t icmpLen = packet.size() - sizeof(ethernet_hdr) - ipHdrLen;

        // 检查数据包是否足够长
        if (icmpLen < sizeof(icmp_hdr))
        {
            std::cout << "ICMP header has insufficient length, ignoring." << std::endl;
            return;
        }

        // 检查 ICMP 类型和代码
        if (icmpHdr->icmp_type != ICMP_ECHO_REQUEST || icmpHdr->icmp_code != 0)
        {
            std::cout << "ICMP type is not echo request, ignoring." << std::endl;
            return;
        }

        // 计算校验和
        uint16_t checksum = cksum((uint8_t *)icmpHdr, icmpLen);

        // 验证校验和
        if (checksum != 0xFFFF)
        {
            std::cout << "ICMP header checksum is invalid, ignoring." << std::endl;
            return;
        }

        // 处理 Echo Reply
        sendIcmpEchoReply(packet, inIface);
    }

    void SimpleRouter::sendIcmpEchoReply(const Buffer &packet, const std::string &inIface)
    {
        // 解析 ICMP 请求
        const ethernet_hdr *origEthHdr = reinterpret_cast<const ethernet_hdr *>(packet.data());
        const ip_hdr *origIpHdr = reinterpret_cast<const ip_hdr *>(packet.data() + sizeof(ethernet_hdr));
        uint8_t origIpHdrLen = origIpHdr->ip_hl * 4;

        // 计算 ICMP 长度
        size_t icmpLen = ntohs(origIpHdr->ip_len) - origIpHdrLen;
        size_t newPacketLen = sizeof(ethernet_hdr) + origIpHdrLen + icmpLen;

        // 创建新的数据包缓冲区
        Buffer reply(newPacketLen);

        // 复制ip头部
        ip_hdr *ipHdr = reinterpret_cast<ip_hdr *>(reply.data() + sizeof(ethernet_hdr));
        memcpy(ipHdr, origIpHdr, origIpHdrLen);
        ipHdr->ip_ttl = 64;
        ipHdr->ip_src = origIpHdr->ip_dst;
        ipHdr->ip_dst = origIpHdr->ip_src;
        ipHdr->ip_sum = 0;
        ipHdr->ip_sum = cksum(reinterpret_cast<uint16_t *>(ipHdr), origIpHdrLen);

        // 复制 ICMP 请求
        icmp_hdr *icmpHdr = reinterpret_cast<icmp_hdr *>(reply.data() + sizeof(ethernet_hdr) + origIpHdrLen);
        memcpy(icmpHdr, packet.data() + sizeof(ethernet_hdr) + origIpHdrLen, icmpLen);
        icmpHdr->icmp_type = ICMP_ECHO_REPLY;
        icmpHdr->icmp_code = 0;
        icmpHdr->icmp_sum = 0;
        icmpHdr->icmp_sum = cksum(reinterpret_cast<uint16_t *>(icmpHdr), icmpLen);

        // 在路由表中查找目的IP地址
        RoutingTableEntry entry = m_routingTable.lookup(ipHdr->ip_dst);
        if (entry.ifName.empty())
        {
            std::cerr << "No route found for source IP, cannot send Echo Reply." << std::endl;
            return;
        }
        const Interface *outIface = findIfaceByName(entry.ifName);
        if (!outIface)
        {
            std::cerr << "Output interface not found." << std::endl;
            return;
        }

        // 确定下一跳的IP地址
        uint32_t nextHopIp = entry.gw == 0 ? ipHdr->ip_dst : entry.gw;

        // 查找arp缓存是否有下一跳IP的mac地址
        auto arpEntry = m_arp.lookup(nextHopIp);
        if (!arpEntry)
        {
            // 广播发送arp请求
            sendArpRequest(nextHopIp);
            m_arp.queueRequest(nextHopIp, reply, outIface->name);
            return;
        }

        // 如果存在mac地址 就直接构建以太网帧
        ethernet_hdr *ethHdr = reinterpret_cast<ethernet_hdr *>(reply.data());
        memcpy(ethHdr->ether_shost, outIface->addr.data(), ETHER_ADDR_LEN); // Our router's MAC
        memcpy(ethHdr->ether_dhost, arpEntry->mac.data(), ETHER_ADDR_LEN);  // Next-hop MAC
        ethHdr->ether_type = htons(ethertype_ip);

        // 向对应接口发送以太网帧
        sendPacket(reply, outIface->name);
    }

    //////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////
    // IMPLEMENT THIS METHOD
    void SimpleRouter::handlePacket(const Buffer &packet, const std::string &inIface)
    {
        std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

        const Interface *iface = findIfaceByName(inIface);
        if (iface == nullptr)
        {
            std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
            return;
        }

        std::cerr << getRoutingTable() << std::endl;

        // FILL THIS IN
        /*这里需要实现的功能：
        1 处理不够长的数据包
        2 解析数据包的类型 对于非Ip数据包或者arp直接丢弃
        3 分类对于ip或者arp数据包 调用对应的函数进行处理
        4 识别目的mac地址 如果不是本地接口的某个mac地址 也不是广播就丢弃
        */
        // 获取packet的长度 检查是否小于以太网帧的最小长度
        if (packet.size() < sizeof(ethernet_hdr))
        {
            std::cerr << "Packet is too short" << std::endl;
            return;
        }

        // 解析以太网帧头部
        ethernet_hdr *eth_hdr = (ethernet_hdr *)packet.data();
        uint16_t eth_type = ntohs(eth_hdr->ether_type);

        // 识别目的MAC地址
        if (memcmp(eth_hdr->ether_dhost, iface->addr.data(), ETHER_ADDR_LEN) != 0 && memcmp(eth_hdr->ether_dhost, BROADCAST_ADDR.data(), ETHER_ADDR_LEN) != 0)

        {
            std::cerr << "Destination MAC address : " << macToString(Buffer(eth_hdr->ether_dhost, eth_hdr->ether_dhost + ETHER_ADDR_LEN)) << std::endl;
            std::cerr << "Destination MAC address is not local interface's MAC address or broadcast address, ignoring" << std::endl;
            return;
        }

        // 判断以太网帧类型
        if (eth_type == ethertype_arp)
        {
            // 处理ARP数据包
            handleArpPacket(packet, inIface);
        }
        else if (eth_type == ethertype_ip)
        {
            // 处理IP数据包
            handleIPv4Packet(packet, inIface);
        }
        else
        {
            // 非IP或ARP数据包，直接丢弃
            std::cerr << "Received non-IP and non-ARP packet, ignoring" << std::endl;
        }
    }
    //////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////

    // You should not need to touch the rest of this code.
    SimpleRouter::SimpleRouter()
        : m_arp(*this)
    {
    }

    void
    SimpleRouter::sendPacket(const Buffer &packet, const std::string &outIface)
    {
        m_pox->begin_sendPacket(packet, outIface);
    }

    bool
    SimpleRouter::loadRoutingTable(const std::string &rtConfig)
    {
        return m_routingTable.load(rtConfig);
    }

    void
    SimpleRouter::loadIfconfig(const std::string &ifconfig)
    {
        std::ifstream iff(ifconfig.c_str());
        std::string line;
        while (std::getline(iff, line))
        {
            std::istringstream ifLine(line);
            std::string iface, ip;
            ifLine >> iface >> ip;

            in_addr ip_addr;
            if (inet_aton(ip.c_str(), &ip_addr) == 0)
            {
                throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
            }

            m_ifNameToIpMap[iface] = ip_addr.s_addr;
        }
    }

    void
    SimpleRouter::printIfaces(std::ostream &os)
    {
        if (m_ifaces.empty())
        {
            os << " Interface list empty " << std::endl;
            return;
        }

        for (const auto &iface : m_ifaces)
        {
            os << iface << "\n";
        }
        os.flush();
    }

    const Interface *
    SimpleRouter::findIfaceByIp(uint32_t ip) const
    {
        auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip](const Interface &iface)
                                  { return iface.ip == ip; });

        if (iface == m_ifaces.end())
        {
            return nullptr;
        }

        return &*iface;
    }

    const Interface *
    SimpleRouter::findIfaceByMac(const Buffer &mac) const
    {
        auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac](const Interface &iface)
                                  { return iface.addr == mac; });

        if (iface == m_ifaces.end())
        {
            return nullptr;
        }

        return &*iface;
    }

    const Interface *
    SimpleRouter::findIfaceByName(const std::string &name) const
    {
        auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name](const Interface &iface)
                                  { return iface.name == name; });

        if (iface == m_ifaces.end())
        {
            return nullptr;
        }

        return &*iface;
    }

    void
    SimpleRouter::reset(const pox::Ifaces &ports)
    {
        std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

        m_arp.clear();
        m_ifaces.clear();

        for (const auto &iface : ports)
        {
            auto ip = m_ifNameToIpMap.find(iface.name);
            if (ip == m_ifNameToIpMap.end())
            {
                std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
                continue;
            }

            m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
        }

        printIfaces(std::cerr);
    }

} // namespace simple_router {
