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

#ifndef SIMPLE_ROUTER_SIMPLE_ROUTER_HPP
#define SIMPLE_ROUTER_SIMPLE_ROUTER_HPP

#include "arp-cache.hpp"
#include "routing-table.hpp"
#include "core/protocol.hpp"
#include "core/interface.hpp"

#include "pox.hpp"

// 定义宏ICMP
#define ICMP_ECHO_REPLY 0
#define ICMP_ECHO_REQUEST 8
#define ICMP_DEST_UNREACH 3
#define ICMP_TIME_EXCEEDED 11
#define ICMP_TTL_EXCEEDED 0
#define ICMP_CODE_NET_UNREACH 0
// 定义宏IP
constexpr uint8_t ip_protocol_icmp = 1;
constexpr uint8_t ip_protocol_tcp = 6;
constexpr uint8_t ip_protocol_udp = 17;
namespace simple_router
{

    class SimpleRouter
    {
    public:
        SimpleRouter();

        // 处理ARP的函数
        // 处理ARP数据包
        void handleArpPacket(const Buffer &packet, const std::string &iface);
        // 辅助函数 验证arp数据包合法
        bool isValidArpHeader(const Buffer &packet, const arp_hdr *arpHeader) const;
        // 根据操作码处理arp请求
        void handleArpRequest(const Buffer &packet, const std::string &iface);
        // 根据操作码处理arp回复
        void handleArpReply(const Buffer &packet);
        // 辅助函数 填充以太网帧header
        void fillEthernetHeader(Buffer &packet, const uint8_t *srcMac, const uint8_t *dstMac, uint16_t etherType);
        // 辅助函数 填充arp帧header
        void fillArpHeader(Buffer &packet, uint32_t srcIp, const uint8_t *srcMac, uint32_t dstIp, const uint8_t *dstMac, uint16_t opCode);
        // 发送ARP请求
        void sendArpRequest(uint32_t ip);

        // 处理IP的函数
        // 处理IP数据包
        void handleIPv4Packet(const Buffer &packet, const std::string &iface);
        void processLocalIpPacket(const Buffer &packet, const std::string &inIface, const ip_hdr *ipHeader, uint8_t ipHeaderLen);
        void forwardIpPacket(const Buffer &packet, const std::string &inIface, const ip_hdr *ipHeader, uint8_t ipHeaderLen);

        // 发送ICMP消息的函数
        void sendIcmpError(const Buffer &packet, const std::string &inIface, uint8_t type, uint8_t code);
        void handleIcmpPortUnreachable(const Buffer &packet, const std::string &inIface)
        {
            // ICMP 类型 3（Destination Unreachable），代码 3（Port Unreachable）
            sendIcmpError(packet, inIface, 3, 3);
        }

        void handleIcmpTimeExceeded(const Buffer &packet, const std::string &inIface)
        {
            // ICMP 类型 11（Time Exceeded），代码 0（TTL Exceeded）
            sendIcmpError(packet, inIface, 11, 0);
        }

        void handleIcmpNetUnreachable(const Buffer &packet, const std::string &inIface)
        {
            // ICMP 类型 3（Destination Unreachable），代码 0（Network Unreachable）
            std::cerr << "handleIcmpNetUnreachable" << std::endl;
            sendIcmpError(packet, inIface, 3, 0);
        }
        void handleIcmpPacket(const Buffer &packet, const std::string &inIface);
        void sendIcmpEchoReply(const Buffer &packet, const std::string &inIface);
        /**
         * IMPLEMENT THIS METHOD
         *
         * This method is called each time the router receives a packet on
         * the interface.  The packet buffer \p packet and the receiving
         * interface \p inIface are passed in as parameters. The packet is
         * complete with ethernet headers.
         */
        void handlePacket(const Buffer &packet, const std::string &inIface);

        /**
         * USE THIS METHOD TO SEND PACKETS
         *
         * Call this method to send packet \p packt from the router on interface \p outIface
         */
        void
        sendPacket(const Buffer &packet, const std::string &outIface);

        /**
         * Load routing table information from \p rtConfig file
         */
        bool
        loadRoutingTable(const std::string &rtConfig);

        /**
         * Load local interface configuration
         */
        void
        loadIfconfig(const std::string &ifconfig);

        /**
         * Get routing table
         */
        const RoutingTable &
        getRoutingTable() const;

        /**
         * Get ARP table
         */
        const ArpCache &
        getArp() const;

        /**
         * Print router interfaces
         */
        void
        printIfaces(std::ostream &os);

        /**
         * Reset ARP cache and interface list (e.g., when mininet restarted)
         */
        void
        reset(const pox::Ifaces &ports);

        /**
         * Find interface based on interface's IP address
         */
        const Interface *
        findIfaceByIp(uint32_t ip) const;

        /**
         * Find interface based on interface's MAC address
         */
        const Interface *
        findIfaceByMac(const Buffer &mac) const;

        /**
         * Find interface based on interface's name
         */
        const Interface *
        findIfaceByName(const std::string &name) const;

    private:
        ArpCache m_arp;
        RoutingTable m_routingTable;
        std::set<Interface> m_ifaces;
        std::map<std::string, uint32_t> m_ifNameToIpMap;

        friend class Router;
        pox::PacketInjectorPrx m_pox;
    };

    inline const RoutingTable &
    SimpleRouter::getRoutingTable() const
    {
        return m_routingTable;
    }

    inline const ArpCache &
    SimpleRouter::getArp() const
    {
        return m_arp;
    }

} // namespace simple_router

#endif // SIMPLE_ROUTER_SIMPLE_ROUTER_HPP
