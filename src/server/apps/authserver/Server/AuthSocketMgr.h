/*
 * This file is part of the AzerothCore Project. See AUTHORS file for Copyright information
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef AuthSocketMgr_h__
#define AuthSocketMgr_h__

#include "AuthSession.h"
#include "Config.h"
#include "SocketMgr.h"

/**
 * @class AuthSocketMgr
 * @brief 认证服务器的网络 Socket 管理单例类
 *
 * 继承自模板基类 SocketMgr<AuthSession>，基于 Boost.Asio 框架实现对登录客户端 TCP 连接的监听与管理。
 */
class AuthSocketMgr : public SocketMgr<AuthSession>
{
    typedef SocketMgr<AuthSession> BaseSocketMgr;

public:
    /**
     * @brief 获取 AuthSocketMgr 单例对象
     */
    static AuthSocketMgr& Instance()
    {
        static AuthSocketMgr instance;
        return instance;
    }

    /**
     * @brief 启动网络监听服务
     * @param ioContext Asio 异步 IO 上下文
     * @param bindIp 监听绑定的 IP 地址（如 "0.0.0.0"）
     * @param port 监听绑定的端口号（默认 3724）
     * @param threadCount 网络工作线程数量（默认 1）
     * @return true 启动成功，false 启动失败
     */
    bool StartNetwork(Acore::Asio::IoContext& ioContext, std::string const& bindIp, uint16 port, int threadCount = 1) override
    {
        if (!BaseSocketMgr::StartNetwork(ioContext, bindIp, port, threadCount))
            return false;

        _acceptor->AsyncAcceptWithCallback<&AuthSocketMgr::OnSocketAccept>();
        return true;
    }

protected:
    /**
     * @brief 创建网络线程组（配置 Proxy 代理协议等）
     */
    NetworkThread<AuthSession>* CreateThreads() const override
    {
        NetworkThread<AuthSession>* threads = new NetworkThread<AuthSession>[1];

        bool proxyProtocolEnabled = sConfigMgr->GetOption<bool>("EnableProxyProtocol", false, true);
        if (proxyProtocolEnabled)
            threads[0].EnableProxyProtocol();

        return threads;
    }

    /**
     * @brief 当接受到新 TCP 连接时的回调处理函数
     * @param sock 新建立的 TCP Socket 实例
     * @param threadIndex 分配的网络线程索引
     */
    static void OnSocketAccept(IoContextTcpSocket&& sock, uint32 threadIndex)
    {
        Instance().OnSocketOpen(std::move(sock), threadIndex);
    }
};

/// 访问 AuthSocketMgr 单例的宏定义
#define sAuthSocketMgr AuthSocketMgr::Instance()

#endif // AuthSocketMgr_h__
