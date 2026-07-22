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

/**
* @file main.cpp
* @brief Authentication Server main program
*
* This file contains the main program for the
* authentication server
*/

#include "AppenderDB.h"
#include "AuthSocketMgr.h"
#include "Banner.h"
#include "Config.h"
#include "DatabaseEnv.h"
#include "DatabaseLoader.h"
#include "GitRevision.h"
#include "IPLocation.h"
#include "IoContext.h"
#include "Log.h"
#include "MySQLThreading.h"
#include "OpenSSLCrypto.h"
#include "ProcessPriority.h"
#include "RealmList.h"
#include "SecretMgr.h"
#include "SharedDefines.h"
#include "SteadyTimer.h"
#include "Util.h"
#include <boost/asio/signal_set.hpp>
#include <boost/program_options.hpp>
#include <boost/version.hpp>
#include <csignal>
#include <filesystem>
#include <iostream>
#include <openssl/crypto.h>
#include <openssl/opensslv.h>

#ifndef _ACORE_REALM_CONFIG
#define _ACORE_REALM_CONFIG "authserver.conf"
#endif

using boost::asio::ip::tcp;
using namespace boost::program_options;
namespace fs = std::filesystem;

/**
 * @brief 初始化登录数据库连接池
 * @return true 数据库加载并建立连接成功，false 失败
 */
bool StartDB();

/**
 * @brief 关闭登录数据库连接池并清理 MySQL 库资源
 */
void StopDB();

/**
 * @brief 操作系统信号句柄（用于响应 SIGINT/SIGTERM 实现优雅关机）
 * @param ioContextRef IoContext 的弱引用指针
 * @param error 系统错误码
 * @param signalNumber 信号编号
 */
void SignalHandler(std::weak_ptr<Acore::Asio::IoContext> ioContextRef, boost::system::error_code const& error, int signalNumber);

/**
 * @brief 保持 MySQL 连接心跳的定时回调函数
 * @param dbPingTimerRef 定时器弱引用
 * @param dbPingInterval 心跳时间间隔（分钟）
 * @param error 定时器错误码
 */
void KeepDatabaseAliveHandler(std::weak_ptr<boost::asio::steady_timer> dbPingTimerRef, int32 dbPingInterval, boost::system::error_code const& error);

/**
 * @brief 自动清理过期的 IP/账号封禁记录的定时回调函数
 * @param banExpiryCheckTimerRef 定时器弱引用
 * @param banExpiryCheckInterval 检测间隔时间（秒）
 * @param error 定时器错误码
 */
void BanExpiryHandler(std::weak_ptr<boost::asio::steady_timer> banExpiryCheckTimerRef, int32 banExpiryCheckInterval, boost::system::error_code const& error);

/**
 * @brief 解析命令行启动参数
 * @param argc 参数个数
 * @param argv 参数字符串数组
 * @param configFile 配置文件输出路径引用
 * @return 解析得到的变量映射表 (variables_map)
 */
variables_map GetConsoleArguments(int argc, char** argv, fs::path& configFile);

/**
 * @brief 认证服务器主程序入口点
 */
int main(int argc, char** argv)
{
    // 标记当前进程类型为 AuthServer
    Acore::Impl::CurrentServerProcessHolder::_type = SERVER_PROCESS_AUTHSERVER;
    signal(SIGABRT, &Acore::AbortHandler);

    // 解析命令行参数并确定配置文件路径
    auto configFile = fs::path(sConfigMgr->GetConfigPath() + std::string(_ACORE_REALM_CONFIG));
    auto vm = GetConsoleArguments(argc, argv, configFile);

    // 如果命令行包含 --help 或 --version，输出对应信息后退出
    if (vm.count("help") || vm.count("version"))
        return 0;

    // 加载和配置 App 配置文件 (authserver.conf)
    sConfigMgr->Configure(configFile.generic_string(), std::vector<std::string>(argv, argv + argc));

    if (!sConfigMgr->LoadAppConfigs())
        return 1;

    // 初始化日志子系统并注册数据库日志追加器
    sLog->RegisterAppender<AppenderDB>();
    sLog->Initialize(nullptr);

    // 显示开机 Banner 横幅及软件版本信息
    Acore::Banner::Show("authserver",
        [](std::string_view text)
        {
            LOG_INFO("server.authserver", text);
        },
        []()
        {
            LOG_INFO("server.authserver", "> Using configuration file       {}", sConfigMgr->GetFilename());
            LOG_INFO("server.authserver", "> Using SSL version:             {} (library: {})", OPENSSL_VERSION_TEXT, OpenSSL_version(OPENSSL_VERSION));
            LOG_INFO("server.authserver", "> Using Boost version:           {}.{}.{}", BOOST_VERSION / 100000, BOOST_VERSION / 100 % 1000, BOOST_VERSION % 100);
        });

    // 初始化 OpenSSL 多线程环境
    OpenSSLCrypto::threadsSetup();

    // 使用 RAII 共享指针在 main() 退出时自动清理 OpenSSL 资源
    std::shared_ptr<void> opensslHandle(nullptr, [](void*) { OpenSSLCrypto::threadsCleanup(); });

    // 创建 PID 进程号文件
    std::string pidFile = sConfigMgr->GetOption<std::string>("PidFile", "");
    if (!pidFile.empty())
    {
        if (uint32 pid = CreatePIDFile(pidFile))
            LOG_INFO("server.authserver", "Daemon PID: {}\n", pid); // 成功创建 PID 文件
        else
        {
            LOG_ERROR("server.authserver", "Cannot create PID file {} (possible error: permission)\n", pidFile);
            return 1;
        }
    }

    // 初始化数据库连接
    if (!StartDB())
        return 1;

    sSecretMgr->Initialize();

    // 加载 IP 地理位置数据库
    sIPLocation->Load();

    // 使用 RAII 保证退出时安全关闭数据库连接池
    std::shared_ptr<void> dbHandle(nullptr, [](void*) { StopDB(); });

    // 开机时将所有 Realm 服务器默认标记为 Offline 状态
    // 后续每个具体的 worldserver 节点启动成功后会自行清除离线标志位
    LoginDatabase.DirectExecute("UPDATE realmlist SET flag = flag | {}", REALM_FLAG_OFFLINE);

    std::shared_ptr<Acore::Asio::IoContext> ioContext = std::make_shared<Acore::Asio::IoContext>();

    // 初始化 Realm 列表管理器
    sRealmList->Initialize(*ioContext, sConfigMgr->GetOption<int32>("RealmsStateUpdateDelay", 20));

    std::shared_ptr<void> sRealmListHandle(nullptr, [](void*) { sRealmList->Close(); });

    if (sRealmList->GetRealms().empty())
    {
        LOG_ERROR("server.authserver", "No valid realms specified.");
        return 1;
    }

    // 若配置为 dry-run 演练模式，初始化检查完成后直接正常退出
    if (sConfigMgr->isDryRun())
    {
        LOG_INFO("server.authserver", "Dry run completed, terminating.");
        return 0;
    }

    // 启动登录连接监听端口 (默认端口 3724)
    int32 port = sConfigMgr->GetOption<int32>("RealmServerPort", 3724);
    if (port < 0 || port > 0xFFFF)
    {
        LOG_ERROR("server.authserver", "Specified port out of allowed range (1-65535)");
        return 1;
    }

    std::string bindIp = sConfigMgr->GetOption<std::string>("BindIP", "0.0.0.0");

    if (!sAuthSocketMgr.StartNetwork(*ioContext, bindIp, port))
    {
        LOG_ERROR("server.authserver", "Failed to initialize network");
        return 1;
    }

    std::shared_ptr<void> sAuthSocketMgrHandle(nullptr, [](void*) { sAuthSocketMgr.StopNetwork(); });

    // 注册操作系统信号处理程序 (SIGINT, SIGTERM)
    boost::asio::signal_set signals(*ioContext, SIGINT, SIGTERM);
#if AC_PLATFORM == AC_PLATFORM_WINDOWS
    signals.add(SIGBREAK);
#endif
    signals.async_wait(std::bind(&SignalHandler, std::weak_ptr<Acore::Asio::IoContext>(ioContext), std::placeholders::_1, std::placeholders::_2));

    // 根据配置设置进程优先级与 CPU 亲和性
    SetProcessPriority("server.authserver", sConfigMgr->GetOption<int32>(CONFIG_PROCESSOR_AFFINITY, 0), sConfigMgr->GetOption<bool>(CONFIG_HIGH_PRIORITY, false));

    // 创建并设置数据库心跳定时器
    int32 dbPingInterval = sConfigMgr->GetOption<int32>("MaxPingTime", 30);
    std::shared_ptr<boost::asio::steady_timer> dbPingTimer = std::make_shared<boost::asio::steady_timer>(*ioContext);

    dbPingTimer->expires_at(Acore::Asio::SteadyTimer::GetExpirationTime(dbPingInterval * MINUTE));
    dbPingTimer->async_wait(std::bind(&KeepDatabaseAliveHandler, std::weak_ptr<boost::asio::steady_timer>(dbPingTimer), dbPingInterval, std::placeholders::_1));

    // 创建并设置封禁过期检查定时器
    int32 banExpiryCheckInterval = sConfigMgr->GetOption<int32>("BanExpiryCheckInterval", 60);
    std::shared_ptr<boost::asio::steady_timer> banExpiryCheckTimer = std::make_shared<boost::asio::steady_timer>(*ioContext);

    banExpiryCheckTimer->expires_at(Acore::Asio::SteadyTimer::GetExpirationTime(banExpiryCheckInterval));
    banExpiryCheckTimer->async_wait(std::bind(&BanExpiryHandler, std::weak_ptr<boost::asio::steady_timer>(banExpiryCheckTimer), banExpiryCheckInterval, std::placeholders::_1));

    // 阻塞运行 Boost.Asio 事件驱动循环
    ioContext->run();

    // 清理定时器与信号处理程序并退出
    banExpiryCheckTimer->cancel();
    dbPingTimer->cancel();

    LOG_INFO("server.authserver", "Halting process...");

    signals.cancel();

    return 0;
}

/**
 * @brief 初始化登录数据库连接池
 */
bool StartDB()
{
    MySQL::Library_Init();

    // authserver 属于单线程工作，同步线程池大小设为 1
    DatabaseLoader loader("server.authserver");
    loader
        .AddDatabase(LoginDatabase, "Login");

    if (!loader.Load())
        return false;

    LOG_INFO("server.authserver", "Started auth database connection pool.");
    sLog->SetRealmId(0); // 设置全局 RealmId = 0 以启用数据库日志追加器
    return true;
}

/**
 * @brief 关闭登录数据库连接并释放资源
 */
void StopDB()
{
    LoginDatabase.Close();
    MySQL::Library_End();
}

/**
 * @brief 系统信号句柄逻辑，停止 IoContext 事件循环
 */
void SignalHandler(std::weak_ptr<Acore::Asio::IoContext> ioContextRef, boost::system::error_code const& error, int /*signalNumber*/)
{
    if (!error)
    {
        if (std::shared_ptr<Acore::Asio::IoContext> ioContext = ioContextRef.lock())
        {
            ioContext->stop();
        }
    }
}

/**
 * @brief 数据库 KeepAlive 定时器回调
 */
void KeepDatabaseAliveHandler(std::weak_ptr<boost::asio::steady_timer> dbPingTimerRef, int32 dbPingInterval, boost::system::error_code const& error)
{
    if (!error)
    {
        if (std::shared_ptr<boost::asio::steady_timer> dbPingTimer = dbPingTimerRef.lock())
        {
            LOG_DEBUG("sql.driver", "Ping MySQL to keep connection alive");
            LoginDatabase.KeepAlive();

            dbPingTimer->expires_at(Acore::Asio::SteadyTimer::GetExpirationTime(dbPingInterval));
            dbPingTimer->async_wait(std::bind(&KeepDatabaseAliveHandler, dbPingTimerRef, dbPingInterval, std::placeholders::_1));
        }
    }
}

/**
 * @brief 封禁过期检查定时器回调（清理 acore_auth 中过期的 IP 和账号 Ban 纪录）
 */
void BanExpiryHandler(std::weak_ptr<boost::asio::steady_timer> banExpiryCheckTimerRef, int32 banExpiryCheckInterval, boost::system::error_code const& error)
{
    if (!error)
    {
        if (std::shared_ptr<boost::asio::steady_timer> banExpiryCheckTimer = banExpiryCheckTimerRef.lock())
        {
            LoginDatabase.Execute(LoginDatabase.GetPreparedStatement(LOGIN_DEL_EXPIRED_IP_BANS));
            LoginDatabase.Execute(LoginDatabase.GetPreparedStatement(LOGIN_UPD_EXPIRED_ACCOUNT_BANS));

            banExpiryCheckTimer->expires_at(Acore::Asio::SteadyTimer::GetExpirationTime(banExpiryCheckInterval));
            banExpiryCheckTimer->async_wait(std::bind(&BanExpiryHandler, banExpiryCheckTimerRef, banExpiryCheckInterval, std::placeholders::_1));
        }
    }
}

/**
 * @brief 解析命令行控制台输入参数
 */
variables_map GetConsoleArguments(int argc, char** argv, fs::path& configFile)
{
    options_description all("Allowed options");
    all.add_options()
        ("help,h", "print usage message")
        ("version,v", "print version build info")
        ("dry-run,d", "Dry run")
        ("config,c", value<fs::path>(&configFile)->default_value(fs::path(sConfigMgr->GetConfigPath() + std::string(_ACORE_REALM_CONFIG))), "use <arg> as configuration file")
        ("config-policy", value<std::string>()->value_name("policy"), "override config severity policy (e.g. default=skip,critical_option=fatal)");

    variables_map variablesMap;

    try
    {
        store(command_line_parser(argc, argv).options(all).allow_unregistered().run(), variablesMap);
        notify(variablesMap);
    }
    catch (std::exception const& e)
    {
        std::cerr << e.what() << "\n";
    }

    if (variablesMap.count("help"))
        std::cout << all << "\n";
    else if (variablesMap.count("version"))
        std::cout << GitRevision::GetFullVersion() << "\n";
    else if (variablesMap.count("dry-run"))
        sConfigMgr->setDryRun(true);

    return variablesMap;
}
