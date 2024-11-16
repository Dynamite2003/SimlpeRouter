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

    void SimpleRouter::fillEthernetHeader(Buffer &packet, const uint8_t *srcMac, const uint8_t *dstMac, uint16_t etherType)
    {
        ethernet_hdr *ethHeader = reinterpret_cast<ethernet_hdr *>(packet.data());
        memcpy(ethHeader->ether_shost, srcMac, ETHER_ADDR_LEN); // 源 MAC
        memcpy(ethHeader->ether_dhost, dstMac, ETHER_ADDR_LEN); // 目标 MAC
        ethHeader->ether_type = htons(etherType);               // 以太网类型
    }
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

        // 目标 IP 和 MAC 地址
        arpHeader->arp_tip = dstIp;

        if (opCode == arp_op_request)
        {
            // 如果是 ARP 请求，目标 MAC 设置为全 0
            memset(arpHeader->arp_tha, 0, ETHER_ADDR_LEN);
        }
        else if (opCode == arp_op_reply)
        {
            // 如果是 ARP 回复，目标 MAC 填充实际值
            memcpy(arpHeader->arp_tha, dstMac, ETHER_ADDR_LEN);
        }
    }

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
        const arp_hdr *arpHeader = reinterpret_cast<const arp_hdr *>(packet.data() + sizeof(ethernet_hdr));

        // 提取源 IP 和 MAC
        uint32_t srcIp = arpHeader->arp_sip;
        const uint8_t *srcMac = arpHeader->arp_sha;

        // 插入到 ARP 缓存中
        std::shared_ptr<ArpRequest> req = m_arp.insertArpEntry(Buffer(srcMac, srcMac + ETHER_ADDR_LEN), srcIp);

        if (!req)
        {
            std::cerr << "No pending ARP requests for IP " << ipToString(srcIp) << std::endl;
            return;
        }

        // 发送所有等待中的数据包
        for (const auto &pendingPacket : req->packets)
        {
            std::cerr << "Sending pending packet to IP " << ipToString(srcIp) << " via " << pendingPacket.iface << std::endl;
            handlePacket(pendingPacket.packet, pendingPacket.iface);
        }

        // 移除请求队列
        m_arp.removeRequest(req);
        std::cerr << "Processed all pending packets for ARP Reply." << std::endl;
    }

    void SimpleRouter::sendIcmpDestinationUnreachable(const Buffer &packet, const std::string &inface)
    {
        std::cout << "Destination Unreachable!" << std::endl;
        // 待调用统一的发送ICMP格式函数
        return;
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
