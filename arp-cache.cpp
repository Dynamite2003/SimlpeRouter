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

#include "arp-cache.hpp"
#include "core/utils.hpp"
#include "core/interface.hpp"
#include "simple-router.hpp"

#include <algorithm>
#include <iostream>

namespace simple_router
{

    //////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////
    // IMPLEMENT THIS METHOD

    void ArpCache::handle_arpreq(std::shared_ptr<ArpRequest> req)
    {
        // 获取当前时间
        auto now = steady_clock::now();

        // 如果上次发送时间为空或距离上次发送超过1秒
        if (req->timeSent == time_point() || now - req->timeSent > seconds(1))
        {
            // 已发送次数超过上限
            if (req->nTimesSent >= MAX_SENT_TIME)
            {
                std::cerr << "ARP request for IP " << ipToString(req->ip)
                          << " failed after " << req->nTimesSent << " attempts." << std::endl;

                // 为所有等待的包生成 ICMP Host Unreachable 消息
                for (const auto &packet : req->packets)
                {
                    m_router.sendIcmpDestinationUnreachable(packet.packet, packet.iface);
                }

                // 从队列中移除请求
                removeRequest(req);
            }
            else
            {
                // 重新发送 ARP 请求
                std::cerr << "Resending ARP request for IP " << ipToString(req->ip) << std::endl;

                // 从第一个等待包中获取接口
                m_router.sendArpRequest(req->ip);

                // 更新发送时间和发送次数
                req->timeSent = now;
                req->nTimesSent++;
            }
        }
    }

    void
    ArpCache::periodicCheckArpRequestsAndCacheEntries()
    {
        for (auto &request : m_arpRequests)
        {
            handle_arpreq(request);
        }

        // 处理remove逻辑
        std::vector<std::shared_ptr<ArpEntry>> to_remove_entires;
        for (auto &entry : m_cacheEntries)
        {
            if (!entry->isValid)
            {
                to_remove_entires.push_back(entry);
            }
        }
        for (auto &to_remove_entry : to_remove_entires)
        {
            m_cacheEntries.remove(to_remove_entry);
        }
    };
    // FILL THIS IN
    //////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////

    // You should not need to touch the rest of this code.

    ArpCache::ArpCache(SimpleRouter &router)
        : m_router(router), m_shouldStop(false), m_tickerThread(std::bind(&ArpCache::ticker, this))
    {
    }

    ArpCache::~ArpCache()
    {
        m_shouldStop = true;
        m_tickerThread.join();
    }

    std::shared_ptr<ArpEntry>
    ArpCache::lookup(uint32_t ip)
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        for (const auto &entry : m_cacheEntries)
        {
            if (entry->isValid && entry->ip == ip)
            {
                return entry;
            }
        }

        return nullptr;
    }

    std::shared_ptr<ArpRequest>
    ArpCache::queueRequest(uint32_t ip, const Buffer &packet, const std::string &iface)
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                                    [ip](const std::shared_ptr<ArpRequest> &request)
                                    {
                                        return (request->ip == ip);
                                    });

        if (request == m_arpRequests.end())
        {
            request = m_arpRequests.insert(m_arpRequests.end(), std::make_shared<ArpRequest>(ip));
        }

        // Add the packet to the list of packets for this request
        (*request)->packets.push_back({packet, iface});
        return *request;
    }

    void ArpCache::removeRequest(const std::shared_ptr<ArpRequest> &entry)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_arpRequests.remove(entry);
    }

    std::shared_ptr<ArpRequest>
    ArpCache::insertArpEntry(const Buffer &mac, uint32_t ip)
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        auto entry = std::make_shared<ArpEntry>();
        entry->mac = mac;
        entry->ip = ip;
        entry->timeAdded = steady_clock::now();
        entry->isValid = true;
        m_cacheEntries.push_back(entry);

        auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                                    [ip](const std::shared_ptr<ArpRequest> &request)
                                    {
                                        return (request->ip == ip);
                                    });
        if (request != m_arpRequests.end())
        {
            return *request;
        }
        else
        {
            return nullptr;
        }
    }

    void ArpCache::clear()
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        m_cacheEntries.clear();
        m_arpRequests.clear();
    }

    void ArpCache::ticker()
    {
        while (!m_shouldStop)
        {
            std::this_thread::sleep_for(std::chrono::seconds(1));

            {
                std::lock_guard<std::mutex> lock(m_mutex);

                auto now = steady_clock::now();

                for (auto &entry : m_cacheEntries)
                {
                    if (entry->isValid && (now - entry->timeAdded > SR_ARPCACHE_TO))
                    {
                        entry->isValid = false;
                    }
                }

                periodicCheckArpRequestsAndCacheEntries();
            }
        }
    }

    std::ostream &
    operator<<(std::ostream &os, const ArpCache &cache)
    {
        std::lock_guard<std::mutex> lock(cache.m_mutex);

        os << "\nMAC            IP         AGE                       VALID\n"
           << "-----------------------------------------------------------\n";

        auto now = steady_clock::now();
        for (const auto &entry : cache.m_cacheEntries)
        {

            os << macToString(entry->mac) << "   "
               << ipToString(entry->ip) << "   "
               << std::chrono::duration_cast<seconds>((now - entry->timeAdded)).count() << " seconds   "
               << entry->isValid
               << "\n";
        }
        os << std::endl;
        return os;
    }

} // namespace simple_router
