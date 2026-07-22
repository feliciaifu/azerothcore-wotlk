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

#ifndef __AUTHSESSION_H__
#define __AUTHSESSION_H__

#include "AsyncCallbackProcessor.h"
#include "BigNumber.h"
#include "ByteBuffer.h"
#include "Common.h"
#include "CryptoHash.h"
#include "Optional.h"
#include "QueryResult.h"
#include "SRP6.h"
#include "Socket.h"
#include <boost/asio/ip/tcp.hpp>

using boost::asio::ip::tcp;

class Field;
struct AuthHandler;

/**
 * @enum AuthStatus
 * @brief 认证会话的状态机状态枚举
 */
enum AuthStatus
{
    STATUS_CHALLENGE = 0,           /// < 状态0：等待客户端发送 Logon Challenge (挑战请求)
    STATUS_LOGON_PROOF,             /// < 状态1：等待客户端发送 Logon Proof (密码验证凭据)
    STATUS_RECONNECT_PROOF,         /// < 状态2：等待客户端发送 Reconnect Proof (重连验证凭据)
    STATUS_AUTHED,                  /// < 状态3：认证成功，等待查询/获取服务器列表
    STATUS_WAITING_FOR_REALM_LIST,  /// < 状态4：正在异步获取服务器列表与角色数量
    STATUS_CLOSED                   /// < 状态5：会话已关闭或准备断开
};

/**
 * @struct AccountInfo
 * @brief 登录过程中存储数据库中检索到的账号详细信息的结构体
 */
// cppcheck-suppress ctuOneDefinitionRuleViolation
struct AccountInfo
{
    /**
     * @brief 从数据库查询结果的字段数组中加载账号数据
     * @param fields 数据库查询结果字段集
     */
    void LoadResult(Field* fields);

    uint32 Id = 0;                          /// < 账号唯一ID
    std::string Login;                      /// < 账号名称（已转换为大写）
    bool IsLockedToIP = false;             /// < 是否绑定并锁定了特定的 IP 地址
    std::string LockCountry;                /// < 锁定的国家代码（ISO 国家代码）
    std::string LastIP;                     /// < 上次登录的 IP 地址
    uint32 Flags;                           /// < 账号标志/权限扩展位
    uint32 FailedLogins = 0;               /// < 连续尝试失败的登录次数
    bool IsBanned = false;                  /// < 账号或当前 IP 是否处于封禁状态
    bool IsPermanentlyBanned = false;       /// < 是否处于永久封禁状态
    AccountTypes SecurityLevel = SEC_PLAYER;/// < GM 权限等级（玩家、指导员、GM、管理员等）
};

/**
 * @class AuthSession
 * @brief 处理单个客户端登录连接生命周期的会话类
 *
 * 继承自 Socket<AuthSession>，实现基于 SRP6 (Secure Remote Password) 协议的认证、IP校验、2FA验证与服务器列表获取。
 */
class AuthSession final : public Socket<AuthSession>
{
    typedef Socket<AuthSession> AuthSocket;

public:
    /**
     * @brief 初始化所有的 Opcode 指令处理函数映射表
     * @return 映射指令 opcode 到 AuthHandler 的哈希表
     */
    static std::unordered_map<uint8, AuthHandler> InitHandlers();

    /**
     * @brief 构造函数
     * @param socket 转移所有权的底层 Asio TCP Socket
     */
    AuthSession(IoContextTcpSocket&& socket);

    /**
     * @brief 会话启动入口，开始读取 IP 封禁与信息
     */
    void Start() override;

    /**
     * @brief 会话 Tick 更新函数，处理已就绪的数据库异步回调
     * @return true 保持连接，false 关闭会话
     */
    bool Update() final;

    /**
     * @brief 向客户端发送序列化后的网络数据包
     * @param packet 数据包字节缓冲区
     */
    void SendPacket(ByteBuffer& packet);

protected:
    /**
     * @brief 网络 Socket 读回调处理函数（从网络缓冲区解析 Opcode 并调度 Handler）
     */
    SocketReadCallbackResult ReadHandler() final;

private:
    /**
     * @brief 处理 AUTH_LOGON_CHALLENGE 挑战请求包
     */
    bool HandleLogonChallenge();

    /**
     * @brief 处理 AUTH_LOGON_PROOF 密码凭据包（SRP6 校验核心）
     */
    bool HandleLogonProof();

    /**
     * @brief 处理 AUTH_RECONNECT_CHALLENGE 重连挑战请求包
     */
    bool HandleReconnectChallenge();

    /**
     * @brief 处理 AUTH_RECONNECT_PROOF 重连凭据包
     */
    bool HandleReconnectProof();

    /**
     * @brief 处理 REALM_LIST 获取服务器列表请求包
     */
    bool HandleRealmList();

    /**
     * @brief IP 封禁查询的数据库异步回调
     */
    void CheckIpCallback(PreparedQueryResult result);

    /**
     * @brief 账号挑战阶段数据库查询的异步回调
     */
    void LogonChallengeCallback(PreparedQueryResult result);

    /**
     * @brief 账号重连挑战阶段数据库查询的异步回调
     */
    void ReconnectChallengeCallback(PreparedQueryResult result);

    /**
     * @brief 服务器列表角色数查询的异步回调
     */
    void RealmListCallback(PreparedQueryResult result);

    /**
     * @brief 校验客户端的可执行程序 Hash / 版本校验
     */
    bool VerifyVersion(uint8 const* a, int32 aLength, Acore::Crypto::SHA1::Digest const& versionProof, bool isReconnect);

    Optional<Acore::Crypto::SRP6> _srp6;         /// < SRP6 协议加密计算上下文
    SessionKey _sessionKey = {};                /// < 计算生成的 40 字节会话密钥 (SessionKey)
    std::array<uint8, 16> _reconnectProof = {}; /// < 重连挑战随机数

    AuthStatus _status;                          /// < 会话当前所处的认证状态
    AccountInfo _accountInfo;                    /// < 账号详细信息
    Optional<std::vector<uint8>> _totpSecret;    /// < TOTP (2FA) 二步验证密钥
    std::string _localizationName;               /// < 客户端语言（如 "zhCN", "enUS"）
    std::string _os;                             /// < 客户端操作系统（如 "Win", "OSX"）
    std::string _ipCountry;                      /// < 客户端 IP 归属国家
    uint16 _build;                               /// < 客户端 Build 号（如 12340）
    uint8 _expversion;                           /// < 资料片标记（Post-BC / Pre-BC）

    QueryCallbackProcessor _queryProcessor;      /// < 异步数据库回调处理器
};

#pragma pack(push, 1)

/**
 * @struct AuthHandler
 * @brief 每一个 Auth Opcode 指令的挂钩结构体
 */
struct AuthHandler
{
    AuthStatus status;                  /// < 允许执行该指令要求的 Session 状态
    std::size_t packetSize;             /// < 该指令数据包的预期最小字节长度
    bool (AuthSession::* handler)();    /// < 处理该指令的成员函数指针
};

#pragma pack(pop)

#endif
