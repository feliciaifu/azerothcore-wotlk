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

#include "AuthSession.h"
#include "AES.h"
#include "AuthCodes.h"
#include "Config.h"
#include "CryptoGenerics.h"
#include "CryptoHash.h"
#include "CryptoRandom.h"
#include "DatabaseEnv.h"
#include "IPLocation.h"
#include "Log.h"
#include "RealmList.h"
#include "SecretMgr.h"
#include "StringConvert.h"
#include "TOTP.h"
#include "Util.h"
#include <boost/lexical_cast.hpp>

using boost::asio::ip::tcp;

/**
 * @enum eAuthCmd
 * @brief 认证协议 Opcode 操作码枚举
 */
enum eAuthCmd
{
    AUTH_LOGON_CHALLENGE = 0x00,      /// < 客户端发送登录挑战请求
    AUTH_LOGON_PROOF = 0x01,          /// < 客户端发送登录凭证 (SRP6 验证)
    AUTH_RECONNECT_CHALLENGE = 0x02,  /// < 客户端发送重连挑战请求
    AUTH_RECONNECT_PROOF = 0x03,      /// < 客户端发送重连凭据
    REALM_LIST = 0x10,                /// < 获取服务器列表
    XFER_INITIATE = 0x30,             /// < 文件传输发起
    XFER_DATA = 0x31,                 /// < 文件传输数据包
    XFER_ACCEPT = 0x32,               /// < 文件传输接受
    XFER_RESUME = 0x33,               /// < 文件传输断点续传
    XFER_CANCEL = 0x34                /// < 文件传输取消
};

#pragma pack(push, 1)

/**
 * @struct sAuthLogonChallenge_C
 * @brief 客户端发送的 AUTH_LOGON_CHALLENGE 挑战请求包结构
 */
typedef struct AUTH_LOGON_CHALLENGE_C
{
    uint8   cmd;            /// < 操作码 (AUTH_LOGON_CHALLENGE)
    uint8   error;          /// < 错误状态
    uint16  size;           /// < 包数据总大小
    uint8   gamename[4];    /// < 游戏标识符 (例如 "WoW\0")
    uint8   version1;       /// < 主版本号 (例如 3)
    uint8   version2;       /// < 次版本号 (例如 3)
    uint8   version3;       /// < 修订版本号 (例如 5)
    uint16  build;          /// < 客户端 Build 号 (例如 12340)
    uint8   platform[4];    /// < 客户端平台架构 (例如 "x86\0")
    uint8   os[4];          /// < 客户端操作系统 (例如 "Win\0", "OSX\0")
    uint8   country[4];     /// < 客户端语言地区 (例如 "zhCN")
    uint32  timezone_bias;  /// < 时区偏移量
    uint32  ip;             /// < 客户端本地 IP 地址
    uint8   I_len;          /// < 账号名称字符串长度
    uint8   I[1];           /// < 账号名称变长字节数组 (UTF-8 编码)
} sAuthLogonChallenge_C;
static_assert(sizeof(sAuthLogonChallenge_C) == (1 + 1 + 2 + 4 + 1 + 1 + 1 + 2 + 4 + 4 + 4 + 4 + 4 + 1 + 1));

/**
 * @struct sAuthLogonProof_C
 * @brief 客户端发送的 AUTH_LOGON_PROOF 凭据验证包结构 (SRP6 算法输入)
 */
typedef struct AUTH_LOGON_PROOF_C
{
    uint8   cmd;                                    /// < 操作码 (AUTH_LOGON_PROOF)
    Acore::Crypto::SRP6::EphemeralKey A;            /// < 客户端随机生成的公钥 A (32字节)
    Acore::Crypto::SHA1::Digest clientM;            /// < 客户端算出的证明摘要 M1 (20字节)
    Acore::Crypto::SHA1::Digest crc_hash;           /// < 客户端 exe 程序的校验 Hash
    uint8   number_of_keys;                         /// < 密钥数量
    uint8   securityFlags;                          /// < 安全标志位 (PIN/Matrix/2FA Token)
} sAuthLogonProof_C;
static_assert(sizeof(sAuthLogonProof_C) == (1 + 32 + 20 + 20 + 1 + 1));

/**
 * @struct sAuthLogonProof_S
 * @brief 服务端发给 2.x/3.x 客户端的 AUTH_LOGON_PROOF 凭据验证响应包结构
 */
typedef struct AUTH_LOGON_PROOF_S
{
    uint8   cmd;                                    /// < 操作码 (AUTH_LOGON_PROOF)
    uint8   error;                                  /// < 错误码 (0 表示成功)
    Acore::Crypto::SHA1::Digest M2;                 /// < 服务端生成的证明摘要 M2 (20字节)
    uint32  AccountFlags;                           /// < 账号权限标志
    uint32  SurveyId;                               /// < 问卷调查 ID
    uint16  LoginFlags;                             /// < 登录标志
} sAuthLogonProof_S;
static_assert(sizeof(sAuthLogonProof_S) == (1 + 1 + 20 + 4 + 4 + 2));

/**
 * @struct sAuthLogonProof_S_OLD
 * @brief 服务端发给 1.x (Classic) 客户端的旧版验证响应包结构
 */
typedef struct AUTH_LOGON_PROOF_S_OLD
{
    uint8   cmd;                                    /// < 操作码
    uint8   error;                                  /// < 错误码
    Acore::Crypto::SHA1::Digest M2;                 /// < 证明摘要 M2
    uint32  unk2;                                   /// < 未定义保留字段
} sAuthLogonProof_S_Old;
static_assert(sizeof(sAuthLogonProof_S_Old) == (1 + 1 + 20 + 4));

/**
 * @struct sAuthReconnectProof_C
 * @brief 客户端发送的 AUTH_RECONNECT_PROOF 重连凭据包结构
 */
typedef struct AUTH_RECONNECT_PROOF_C
{
    uint8   cmd;                                    /// < 操作码
    uint8   R1[16];                                 /// < 客户端随机生成的 16 字节随机串
    Acore::Crypto::SHA1::Digest R2, R3;             /// < 重连 SHA1 摘要与 Version 校验摘要
    uint8   number_of_keys;                         /// < 密钥数量
} sAuthReconnectProof_C;
static_assert(sizeof(sAuthReconnectProof_C) == (1 + 16 + 20 + 20 + 1));

#pragma pack(pop)

/// 版本挑战常量随机串
std::array<uint8, 16> VersionChallenge = { { 0xBA, 0xA3, 0x1E, 0x99, 0xA0, 0x0B, 0x21, 0x57, 0xFC, 0x37, 0x3F, 0xB3, 0x69, 0xCD, 0xD2, 0xF1 } };

#define MAX_ACCEPTED_CHALLENGE_SIZE (sizeof(AUTH_LOGON_CHALLENGE_C) + 16)

#define AUTH_LOGON_CHALLENGE_INITIAL_SIZE 4
#define REALM_LIST_PACKET_SIZE 5

/**
 * @brief 初始化 AuthSession 支持的 Opcode 指令处理映射表
 */
std::unordered_map<uint8, AuthHandler> AuthSession::InitHandlers()
{
    std::unordered_map<uint8, AuthHandler> handlers;

    handlers[AUTH_LOGON_CHALLENGE] =        { STATUS_CHALLENGE,         AUTH_LOGON_CHALLENGE_INITIAL_SIZE, &AuthSession::HandleLogonChallenge };
    handlers[AUTH_LOGON_PROOF] =            { STATUS_LOGON_PROOF,       sizeof(AUTH_LOGON_PROOF_C),        &AuthSession::HandleLogonProof };
    handlers[AUTH_RECONNECT_CHALLENGE] =    { STATUS_CHALLENGE,         AUTH_LOGON_CHALLENGE_INITIAL_SIZE, &AuthSession::HandleReconnectChallenge };
    handlers[AUTH_RECONNECT_PROOF] =        { STATUS_RECONNECT_PROOF,   sizeof(AUTH_RECONNECT_PROOF_C),    &AuthSession::HandleReconnectProof };
    handlers[REALM_LIST] =                  { STATUS_AUTHED,            REALM_LIST_PACKET_SIZE,            &AuthSession::HandleRealmList };

    return handlers;
}

std::unordered_map<uint8, AuthHandler> const Handlers = AuthSession::InitHandlers();

/**
 * @brief 从数据库 SQL 查询结果加载账号详细数据到 AccountInfo 结构
 * @param fields 数据库查询结果行字段数组
 */
void AccountInfo::LoadResult(Field* fields)
{
    //          0        1          2           3             4         5            6
    // SELECT a.id, a.username, a.locked, a.lock_country, a.last_ip, a.Flags, a.failed_logins,
    //                                 7                                        8
    // ab.unbandate > UNIX_TIMESTAMP() OR ab.unbandate = ab.bandate, ab.unbandate = ab.bandate,
    //                                 9                                             10
    // ipb.unbandate > UNIX_TIMESTAMP() OR ipb.unbandate = ipb.bandate, ipb.unbandate = ipb.bandate,
    //      11
    // aa.gmlevel (, more query-specific fields)
    // FROM account a LEFT JOIN account_access aa ON a.id = aa.id LEFT JOIN account_banned ab ON ab.id = a.id AND ab.active = 1 LEFT JOIN ip_banned ipb ON ipb.ip = ? WHERE a.username = ?

    Id = fields[0].Get<uint32>();
    Login = fields[1].Get<std::string>();
    IsLockedToIP = fields[2].Get<bool>();
    LockCountry = fields[3].Get<std::string>();
    LastIP = fields[4].Get<std::string>();
    Flags = fields[5].Get<uint32>();
    FailedLogins = fields[6].Get<uint32>();
    IsBanned = fields[7].Get<bool>() || fields[9].Get<bool>();
    IsPermanentlyBanned = fields[8].Get<bool>() || fields[10].Get<bool>();
    SecurityLevel = static_cast<AccountTypes>(fields[11].Get<uint8>()) > SEC_CONSOLE ? SEC_CONSOLE : static_cast<AccountTypes>(fields[11].Get<uint8>());

    // 将账号名统一转为大写（英文大写）
    Utf8ToUpperOnlyLatin(Login);
}

/**
 * @brief AuthSession 构造函数
 */
AuthSession::AuthSession(IoContextTcpSocket&& socket) :
    Socket(std::move(socket)), _status(STATUS_CHALLENGE), _build(0), _expversion(0) { }

/**
 * @brief 会话连接建立后的初始化入口
 *
 * 记录客户端 IP，并向数据库发起 IP 封禁检查的异步查询。
 */
void AuthSession::Start()
{
    std::string ip_address = GetRemoteIpAddress().to_string();
    LOG_TRACE("session", "Accepted connection from {}", ip_address);

    LoginDatabasePreparedStatement* stmt = LoginDatabase.GetPreparedStatement(LOGIN_SEL_IP_INFO);
    stmt->SetData(0, ip_address);

    _queryProcessor.AddCallback(LoginDatabase.AsyncQuery(stmt).WithPreparedCallback(std::bind(&AuthSession::CheckIpCallback, this, std::placeholders::_1)));
}

/**
 * @brief 会话 Tick 更新函数
 *
 * 驱动底层 Socket 读写并处理异步数据库查询就绪的回调函数。
 */
bool AuthSession::Update()
{
    if (!AuthSocket::Update())
        return false;

    _queryProcessor.ProcessReadyCallbacks();

    return true;
}

/**
 * @brief IP 封禁异步查询回调
 *
 * 若当前 IP 在 ip_banned 表中处于封禁状态，发送 WOW_FAIL_BANNED 错误并拒绝连接；否则开启网络异步接收。
 */
void AuthSession::CheckIpCallback(PreparedQueryResult result)
{
    if (result)
    {
        bool banned = false;

        for (auto const& fields : *result)
        {
            if (fields[0].Get<uint64>() != 0)
            {
                banned = true;
                break;
            }
        }

        if (banned)
        {
            ByteBuffer pkt;
            pkt << uint8(AUTH_LOGON_CHALLENGE);
            pkt << uint8(0x00);
            pkt << uint8(WOW_FAIL_BANNED);
            SendPacket(pkt);
            LOG_DEBUG("session", "[AuthSession::CheckIpCallback] Banned ip '{}:{}' tries to login!", GetRemoteIpAddress().to_string(), GetRemotePort());
            return;
        }
    }

    AsyncRead();
}

/**
 * @brief 网络数据包读处理回调
 *
 * 从接收缓冲区读取 Opcode，校验会话状态与包大小合法性，并分发到对应的处理函数。
 */
SocketReadCallbackResult AuthSession::ReadHandler()
{
    MessageBuffer& packet = GetReadBuffer();

    while (packet.GetActiveSize())
    {
        uint8 cmd = packet.GetReadPointer()[0];
        auto itr = Handlers.find(cmd);
        if (itr == Handlers.end())
        {
            // 收到未知的 Opcode，重置缓冲区并忽略
            packet.Reset();
            break;
        }

        if (_status != itr->second.status)
        {
            CloseSocket();
            return SocketReadCallbackResult::Stop;
        }

        uint16 size = uint16(itr->second.packetSize);
        if (packet.GetActiveSize() < size)
            break;

        if (cmd == AUTH_LOGON_CHALLENGE || cmd == AUTH_RECONNECT_CHALLENGE)
        {
            sAuthLogonChallenge_C* challenge = reinterpret_cast<sAuthLogonChallenge_C*>(packet.GetReadPointer());
            size += challenge->size;
            if (size > MAX_ACCEPTED_CHALLENGE_SIZE)
            {
                CloseSocket();
                return SocketReadCallbackResult::Stop;
            }
        }

        if (packet.GetActiveSize() < size)
            break;

        if (!(*this.*itr->second.handler)())
        {
            CloseSocket();
            return SocketReadCallbackResult::Stop;
        }

        packet.ReadCompleted(size);
    }

    return SocketReadCallbackResult::KeepReading;
}

/**
 * @brief 向客户端发送 ByteBuffer 包
 */
void AuthSession::SendPacket(ByteBuffer& packet)
{
    if (!IsOpen())
        return;

    if (!packet.empty())
    {
        MessageBuffer buffer(packet.size());
        buffer.Write(packet.contents(), packet.size());
        QueuePacket(std::move(buffer));
    }
}

/**
 * @brief 处理 AUTH_LOGON_CHALLENGE (登录挑战请求包)
 *
 * 解析客户端系统/语言/OS/Build版本，并发起异步数据库查询获取账号 Salt 与 Verifier。
 */
bool AuthSession::HandleLogonChallenge()
{
    _status = STATUS_CLOSED;

    sAuthLogonChallenge_C* challenge = reinterpret_cast<sAuthLogonChallenge_C*>(GetReadBuffer().GetReadPointer());
    if (challenge->size - (sizeof(sAuthLogonChallenge_C) - AUTH_LOGON_CHALLENGE_INITIAL_SIZE - 1) != challenge->I_len)
        return false;

    std::string login((char const*)challenge->I, challenge->I_len);
    LOG_DEBUG("server.authserver", "[AuthChallenge] '{}'", login);

    _build = challenge->build;
    _expversion = uint8(AuthHelper::IsPostBCAcceptedClientBuild(_build) ? POST_BC_EXP_FLAG : (AuthHelper::IsPreBCAcceptedClientBuild(_build) ? PRE_BC_EXP_FLAG : NO_VALID_EXP_FLAG));
    std::array<char, 5> os;
    os.fill('\0');
    memcpy(os.data(), challenge->os, sizeof(challenge->os));
    _os = os.data();

    // 恢复操作系统字符串大写/小写序
    std::reverse(_os.begin(), _os.end());

    _localizationName.resize(4);
    for (int i = 0; i < 4; ++i)
        _localizationName[i] = challenge->country[4 - i - 1];

    // 发起 LOGIN_SEL_LOGONCHALLENGE 预编译数据库异步查询
    LoginDatabasePreparedStatement* stmt = LoginDatabase.GetPreparedStatement(LOGIN_SEL_LOGONCHALLENGE);
    stmt->SetData(0, GetRemoteIpAddress().to_string());
    stmt->SetData(1, login);

    _queryProcessor.AddCallback(LoginDatabase.AsyncQuery(stmt).WithPreparedCallback(std::bind(&AuthSession::LogonChallengeCallback, this, std::placeholders::_1)));
    return true;
}

/**
 * @brief 登录挑战请求数据库回调
 *
 * 处理 IP/国家锁定检查、账号封禁检查、2FA 解密，并构建 SRP6 挑战响应包 (公钥 B、Salt s、模数 N 等) 发送给客户端。
 */
void AuthSession::LogonChallengeCallback(PreparedQueryResult result)
{
    ByteBuffer pkt;
    pkt << uint8(AUTH_LOGON_CHALLENGE);
    pkt << uint8(0x00);

    // 账号不存在
    if (!result)
    {
        pkt << uint8(WOW_FAIL_UNKNOWN_ACCOUNT);
        SendPacket(pkt);
        return;
    }

    Field* fields = result->Fetch();

    _accountInfo.LoadResult(fields);

    std::string ipAddress = GetRemoteIpAddress().to_string();
    uint16 port = GetRemotePort();

    // 校验 IP 绑定与锁定
    if (_accountInfo.IsLockedToIP)
    {
        LOG_DEBUG("server.authserver", "[AuthChallenge] Account '{}' is locked to IP - '{}' is logging in from '{}'", _accountInfo.Login, _accountInfo.LastIP, ipAddress);
        if (_accountInfo.LastIP != ipAddress)
        {
            pkt << uint8(WOW_FAIL_LOCKED_ENFORCED);
            SendPacket(pkt);
            return;
        }
    }
    else
    {
        if (IpLocationRecord const* location = sIPLocation->GetLocationRecord(ipAddress))
            _ipCountry = location->CountryCode;

        LOG_DEBUG("server.authserver", "[AuthChallenge] Account '{}' is not locked to ip", _accountInfo.Login);
        if (_accountInfo.LockCountry.empty() || _accountInfo.LockCountry == "00")
            LOG_DEBUG("server.authserver", "[AuthChallenge] Account '{}' is not locked to country", _accountInfo.Login);
        else if (!_ipCountry.empty())
        {
            LOG_DEBUG("server.authserver", "[AuthChallenge] Account '{}' is locked to country: '{}' Player country is '{}'", _accountInfo.Login, _accountInfo.LockCountry, _ipCountry);
            if (_ipCountry != _accountInfo.LockCountry)
            {
                pkt << uint8(WOW_FAIL_UNLOCKABLE_LOCK);
                SendPacket(pkt);
                return;
            }
        }
    }

    // 校验账号封禁状态
    if (_accountInfo.IsBanned)
    {
        if (_accountInfo.IsPermanentlyBanned)
        {
            pkt << uint8(WOW_FAIL_BANNED);
            SendPacket(pkt);
            LOG_INFO("server.authserver.banned", "'{}:{}' [AuthChallenge] Banned account {} tried to login!", ipAddress, port, _accountInfo.Login);
            return;
        }
        else
        {
            pkt << uint8(WOW_FAIL_SUSPENDED);
            SendPacket(pkt);
            LOG_INFO("server.authserver.banned", "'{}:{}' [AuthChallenge] Temporarily banned account {} tried to login!", ipAddress, port, _accountInfo.Login);
            return;
        }
    }

    uint8 securityFlags = 0;

    // 校验与解密 TOTP (2FA) 密钥
    if (!fields[12].IsNull())
    {
        securityFlags = 4;
        _totpSecret = fields[12].Get<Binary>();

        if (auto const& secret = sSecretMgr->GetSecret(SECRET_TOTP_MASTER_KEY))
        {
            bool success = Acore::Crypto::AEDecrypt<Acore::Crypto::AES>(*_totpSecret, *secret);
            if (!success)
            {
                pkt << uint8(WOW_FAIL_DB_BUSY);
                LOG_ERROR("server.authserver", "[AuthChallenge] Account '{}' has invalid ciphertext for TOTP token key stored", _accountInfo.Login);
                SendPacket(pkt);
                return;
            }
        }
    }

    // 构建 SRP6 计算算法对象
    _srp6.emplace(_accountInfo.Login,
        fields[13].Get<Binary, Acore::Crypto::SRP6::SALT_LENGTH>(),
        fields[14].Get<Binary, Acore::Crypto::SRP6::VERIFIER_LENGTH>());

    // 填充响应数据包发送给客户端
    if (AuthHelper::IsAcceptedClientBuild(_build))
    {
        pkt << uint8(WOW_SUCCESS);

        pkt.append(_srp6->B);                   // SRP6 服务端临时公钥 B
        pkt << uint8(1);
        pkt.append(_srp6->g);                   // SRP6 生成元 g
        pkt << uint8(32);
        pkt.append(_srp6->N);                   // SRP6 大素数 N
        pkt.append(_srp6->s);                   // 账号密码 Salt 盐值
        pkt.append(VersionChallenge.data(), VersionChallenge.size());
        pkt << uint8(securityFlags);            // 安全标志位 (0x00..0x04)

        if (securityFlags & 0x01)               // PIN 码校验
        {
            pkt << uint32(0);
            pkt << uint64(0) << uint64(0);
        }

        if (securityFlags & 0x02)               // Matrix 矩阵卡校验
        {
            pkt << uint8(0);
            pkt << uint8(0);
            pkt << uint8(0);
            pkt << uint8(0);
            pkt << uint64(0);
        }

        if (securityFlags & 0x04)               // 安全令牌 (2FA) 校验
            pkt << uint8(1);

        LOG_DEBUG("server.authserver", "'{}:{}' [AuthChallenge] account {} is using '{}' locale ({})",
            ipAddress, port, _accountInfo.Login, _localizationName, GetLocaleByName(_localizationName));

        _status = STATUS_LOGON_PROOF;
    }
    else
        pkt << uint8(WOW_FAIL_VERSION_INVALID);

    SendPacket(pkt);
}

/**
 * @brief 处理 AUTH_LOGON_PROOF (登录证明/密码凭据校验)
 *
 * 使用 SRP6 校验客户端提交的 M1 证明。验证通过则生成 SessionKey 并更新数据库登录状态。
 */
bool AuthSession::HandleLogonProof()
{
    LOG_DEBUG("server.authserver", "Entering _HandleLogonProof");
    _status = STATUS_CLOSED;

    // 读取登录证明数据包结构
    sAuthLogonProof_C* logonProof = reinterpret_cast<sAuthLogonProof_C*>(GetReadBuffer().GetReadPointer());

    // 检查资料片版本支持标志
    if (_expversion == NO_VALID_EXP_FLAG)
    {
        LOG_DEBUG("network", "Client with invalid version, patching is not implemented");
        return false;
    }

    // 调用 SRP6::VerifyChallengeResponse 校验密码计算出的证明 M1
    if (Optional<SessionKey> K = _srp6->VerifyChallengeResponse(logonProof->A, logonProof->clientM))
    {
        _sessionKey = *K;
        // 校验 2FA 动态令牌
        bool tokenSuccess = false;
        bool sentToken = (logonProof->securityFlags & 0x04);
        if (sentToken && _totpSecret)
        {
            uint8 size = *(GetReadBuffer().GetReadPointer() + sizeof(sAuthLogonProof_C));
            std::string token(reinterpret_cast<char*>(GetReadBuffer().GetReadPointer() + sizeof(sAuthLogonProof_C) + sizeof(size)), size);
            GetReadBuffer().ReadCompleted(sizeof(size) + size);

            uint32 incomingToken = *Acore::StringTo<uint32>(token);
            tokenSuccess = Acore::Crypto::TOTP::ValidateToken(*_totpSecret, incomingToken);
            memset(_totpSecret->data(), 0, _totpSecret->size());
        }
        else if (!sentToken && !_totpSecret)
            tokenSuccess = true;

        if (!tokenSuccess)
        {
            ByteBuffer packet;
            packet << uint8(AUTH_LOGON_PROOF);
            packet << uint8(WOW_FAIL_UNKNOWN_ACCOUNT);
            packet << uint16(0);    // LoginFlags
            SendPacket(packet);
            return true;
        }

        // 校验客户端程序版本 Hash
        if (!VerifyVersion(logonProof->A.data(), logonProof->A.size(), logonProof->crc_hash, false))
        {
            ByteBuffer packet;
            packet << uint8(AUTH_LOGON_PROOF);
            packet << uint8(WOW_FAIL_VERSION_INVALID);
            SendPacket(packet);
            return true;
        }

        LOG_DEBUG("server.authserver", "'{}:{}' User '{}' successfully authenticated", GetRemoteIpAddress().to_string(), GetRemotePort(), _accountInfo.Login);

        // 更新 SessionKey、IP 地址和登录时间到数据库
        std::string address = sConfigMgr->GetOption<bool>("AllowLoggingIPAddressesInDatabase", true, true) ? GetRemoteIpAddress().to_string() : "0.0.0.0";
        LoginDatabasePreparedStatement* stmt = LoginDatabase.GetPreparedStatement(LOGIN_UPD_LOGONPROOF);
        stmt->SetData(0, _sessionKey);
        stmt->SetData(1, address);
        stmt->SetData(2, GetLocaleByName(_localizationName));
        stmt->SetData(3, _os);
        stmt->SetData(4, _accountInfo.Login);
        _queryProcessor.AddCallback(LoginDatabase.AsyncQuery(stmt)
            .WithPreparedCallback([this, M2 = Acore::Crypto::SRP6::GetSessionVerifier(logonProof->A, logonProof->clientM, _sessionKey)](PreparedQueryResult const&)
        {
            // 发送服务端的 SRP6 证明 M2 响应给客户端
            ByteBuffer packet;
            if (_expversion & POST_BC_EXP_FLAG)                 // 2.x 和 3.x (WotLK) 客户端
            {
                sAuthLogonProof_S proof;
                proof.M2 = M2;
                proof.cmd = AUTH_LOGON_PROOF;
                proof.error = 0;
                proof.AccountFlags = _accountInfo.Flags;
                proof.SurveyId = 0;
                proof.LoginFlags = 0;

                packet.resize(sizeof(proof));
                std::memcpy(packet.contents(), &proof, sizeof(proof));
            }
            else                                                // 1.x (Classic) 客户端
            {
                sAuthLogonProof_S_Old proof;
                proof.M2 = M2;
                proof.cmd = AUTH_LOGON_PROOF;
                proof.error = 0;
                proof.unk2 = 0x00;

                packet.resize(sizeof(proof));
                std::memcpy(packet.contents(), &proof, sizeof(proof));
            }

            SendPacket(packet);
            _status = STATUS_AUTHED;
        }));
    }
    else
    {
        // 密码校验失败处理
        ByteBuffer packet;
        packet << uint8(AUTH_LOGON_PROOF);
        packet << uint8(WOW_FAIL_UNKNOWN_ACCOUNT);
        packet << uint16(0);
        SendPacket(packet);

        LOG_INFO("server.authserver.hack", "'{}:{}' [AuthChallenge] account {} tried to login with invalid password!",
            GetRemoteIpAddress().to_string(), GetRemotePort(), _accountInfo.Login);

        uint32 MaxWrongPassCount = sConfigMgr->GetOption<int32>("WrongPass.MaxCount", 0);

        // 记录登录失败日志到数据库表
        if (sConfigMgr->GetOption<bool>("WrongPass.Logging", false))
        {
            LoginDatabasePreparedStatement* logstmt = LoginDatabase.GetPreparedStatement(LOGIN_INS_FALP_IP_LOGGING);
            logstmt->SetData(0, _accountInfo.Id);
            logstmt->SetData(1, GetRemoteIpAddress().to_string());
            logstmt->SetData(2, "Login to WoW Failed - Incorrect Password");

            LoginDatabase.Execute(logstmt);
        }

        // 累计密码错误次数，达到上限则自动封禁账号或 IP
        if (MaxWrongPassCount > 0)
        {
            LoginDatabasePreparedStatement* stmt = LoginDatabase.GetPreparedStatement(LOGIN_UPD_FAILEDLOGINS);
            stmt->SetData(0, _accountInfo.Login);
            LoginDatabase.Execute(stmt);

            if (++_accountInfo.FailedLogins >= MaxWrongPassCount)
            {
                uint32 WrongPassBanTime = sConfigMgr->GetOption<int32>("WrongPass.BanTime", 600);
                bool WrongPassBanType = sConfigMgr->GetOption<bool>("WrongPass.BanType", false);

                if (WrongPassBanType)
                {
                    // 自动封禁账号
                    stmt = LoginDatabase.GetPreparedStatement(LOGIN_INS_ACCOUNT_AUTO_BANNED);
                    stmt->SetData(0, _accountInfo.Id);
                    stmt->SetData(1, WrongPassBanTime);
                    LoginDatabase.Execute(stmt);

                    LOG_DEBUG("server.authserver", "'{}:{}' [AuthChallenge] account {} got banned for '{}' seconds because it failed to authenticate '{}' times",
                        GetRemoteIpAddress().to_string(), GetRemotePort(), _accountInfo.Login, WrongPassBanTime, _accountInfo.FailedLogins);
                }
                else
                {
                    // 自动封禁 IP
                    stmt = LoginDatabase.GetPreparedStatement(LOGIN_INS_IP_AUTO_BANNED);
                    stmt->SetData(0, GetRemoteIpAddress().to_string());
                    stmt->SetData(1, WrongPassBanTime);
                    LoginDatabase.Execute(stmt);

                    LOG_DEBUG("server.authserver", "'{}:{}' [AuthChallenge] IP got banned for '{}' seconds because account {} failed to authenticate '{}' times",
                        GetRemoteIpAddress().to_string(), GetRemotePort(), WrongPassBanTime, _accountInfo.Login, _accountInfo.FailedLogins);
                }
            }
        }
    }

    return true;
}

/**
 * @brief 处理 AUTH_RECONNECT_CHALLENGE (重连挑战请求)
 */
bool AuthSession::HandleReconnectChallenge()
{
    _status = STATUS_CLOSED;

    sAuthLogonChallenge_C* challenge = reinterpret_cast<sAuthLogonChallenge_C*>(GetReadBuffer().GetReadPointer());
    if (challenge->size - (sizeof(sAuthLogonChallenge_C) - AUTH_LOGON_CHALLENGE_INITIAL_SIZE - 1) != challenge->I_len)
        return false;

    std::string login((char const*)challenge->I, challenge->I_len);
    LOG_DEBUG("server.authserver", "[ReconnectChallenge] '{}'", login);

    _build = challenge->build;
    _expversion = uint8(AuthHelper::IsPostBCAcceptedClientBuild(_build) ? POST_BC_EXP_FLAG : (AuthHelper::IsPreBCAcceptedClientBuild(_build) ? PRE_BC_EXP_FLAG : NO_VALID_EXP_FLAG));

    std::array<char, 5> os;
    os.fill('\0');
    memcpy(os.data(), challenge->os, sizeof(challenge->os));
    _os = os.data();

    // 恢复操作系统字符串
    std::reverse(_os.begin(), _os.end());

    _localizationName.resize(4);
    for (int i = 0; i < 4; ++i)
        _localizationName[i] = challenge->country[4 - i - 1];

    // 从数据库查询该账号历史保存的 SessionKey
    LoginDatabasePreparedStatement* stmt = LoginDatabase.GetPreparedStatement(LOGIN_SEL_RECONNECTCHALLENGE);
    stmt->SetData(0, GetRemoteIpAddress().to_string());
    stmt->SetData(1, login);

    _queryProcessor.AddCallback(LoginDatabase.AsyncQuery(stmt).WithPreparedCallback(std::bind(&AuthSession::ReconnectChallengeCallback, this, std::placeholders::_1)));
    return true;
}

/**
 * @brief 重连挑战请求的数据库回调
 */
void AuthSession::ReconnectChallengeCallback(PreparedQueryResult result)
{
    ByteBuffer pkt;
    pkt << uint8(AUTH_RECONNECT_CHALLENGE);

    if (!result)
    {
        pkt << uint8(WOW_FAIL_UNKNOWN_ACCOUNT);
        SendPacket(pkt);
        return;
    }

    Field* fields = result->Fetch();

    _accountInfo.LoadResult(fields);
    _sessionKey = fields[12].Get<Binary, SESSION_KEY_LENGTH>();
    Acore::Crypto::GetRandomBytes(_reconnectProof);
    _status = STATUS_RECONNECT_PROOF;

    pkt << uint8(WOW_SUCCESS);
    pkt.append(_reconnectProof);
    pkt.append(VersionChallenge.data(), VersionChallenge.size());

    SendPacket(pkt);
}

/**
 * @brief 处理 AUTH_RECONNECT_PROOF (重连凭据验证)
 */
bool AuthSession::HandleReconnectProof()
{
    LOG_DEBUG("server.authserver", "Entering _HandleReconnectProof");
    _status = STATUS_CLOSED;

    sAuthReconnectProof_C* reconnectProof = reinterpret_cast<sAuthReconnectProof_C*>(GetReadBuffer().GetReadPointer());

    if (_accountInfo.Login.empty())
        return false;

    // 根据账号名、R1 随机数、重连随机数与历史 SessionKey 校验 SHA1 摘要
    Acore::Crypto::SHA1 sha;
    sha.UpdateData(_accountInfo.Login);
    sha.UpdateData(reconnectProof->R1, 16);
    sha.UpdateData(_reconnectProof);
    sha.UpdateData(_sessionKey);
    sha.Finalize();

    if (sha.GetDigest() == reconnectProof->R2)
    {
        if (!VerifyVersion(reconnectProof->R1, sizeof(reconnectProof->R1), reconnectProof->R3, true))
        {
            ByteBuffer packet;
            packet << uint8(AUTH_RECONNECT_PROOF);
            packet << uint8(WOW_FAIL_VERSION_INVALID);
            SendPacket(packet);
            return true;
        }

        // 发送重连验证成功响应
        ByteBuffer pkt;
        pkt << uint8(AUTH_RECONNECT_PROOF);
        pkt << uint8(WOW_SUCCESS);
        pkt << uint16(0);
        SendPacket(pkt);
        _status = STATUS_AUTHED;
        return true;
    }
    else
    {
        LOG_ERROR("server.authserver.hack", "'{}:{}' [ERROR] user {} tried to login, but session is invalid.", GetRemoteIpAddress().to_string(),
            GetRemotePort(), _accountInfo.Login);
        return false;
    }
}

/**
 * @brief 处理 REALM_LIST (获取服务器列表请求)
 *
 * 异步查询数据库中该账号在各个区服的角色数量。
 */
bool AuthSession::HandleRealmList()
{
    LOG_DEBUG("server.authserver", "Entering _HandleRealmList");

    LoginDatabasePreparedStatement* stmt = LoginDatabase.GetPreparedStatement(LOGIN_SEL_REALM_CHARACTER_COUNTS);
    stmt->SetData(0, _accountInfo.Id);

    _queryProcessor.AddCallback(LoginDatabase.AsyncQuery(stmt).WithPreparedCallback(std::bind(&AuthSession::RealmListCallback, this, std::placeholders::_1)));
    _status = STATUS_WAITING_FOR_REALM_LIST;
    return true;
}

/**
 * @brief 服务器列表查询数据库回调
 *
 * 遍历内存中 `sRealmList` 收集的所有服务器节点，按协议序列化发送给客户端。
 */
void AuthSession::RealmListCallback(PreparedQueryResult result)
{
    std::map<uint32, uint8> characterCounts;
    if (result)
    {
        do
        {
            Field* fields = result->Fetch();
            characterCounts[fields[0].Get<uint32>()] = fields[1].Get<uint8>();
        } while (result->NextRow());
    }

    // 循环遍历 RealmList 中的服务器，构建包含各服务器负载及玩家角色数量的返回包
    ByteBuffer pkt;

    std::size_t RealmListSize = 0;
    for (auto const& [realmHandle, realm] : sRealmList->GetRealms())
    {
        // 检查客户端版本与服务器 Build 是否兼容匹配
        bool okBuild = ((_expversion & POST_BC_EXP_FLAG) && realm.Build == _build) || ((_expversion & PRE_BC_EXP_FLAG) && !AuthHelper::IsPreBCAcceptedClientBuild(realm.Build));

        uint32 flag = realm.Flags;
        RealmBuildInfo const* buildInfo = sRealmList->GetBuildInfo(realm.Build);
        if (!okBuild)
        {
            if (!buildInfo)
                continue;

            flag |= REALM_FLAG_OFFLINE | REALM_FLAG_SPECIFYBUILD;   // 告知客户端该服务器所需的版本 Build
        }

        if (!buildInfo)
            flag &= ~REALM_FLAG_SPECIFYBUILD;

        std::string name = realm.Name;
        if (_expversion & PRE_BC_EXP_FLAG && flag & REALM_FLAG_SPECIFYBUILD)
        {
            std::ostringstream ss;
            ss << name << " (" << buildInfo->MajorVersion << '.' << buildInfo->MinorVersion << '.' << buildInfo->BugfixVersion << ')';
            name = ss.str();
        }

        uint8 lock = (realm.AllowedSecurityLevel > _accountInfo.SecurityLevel) ? 1 : 0;

        pkt << uint8(realm.Type);                           // 服务器类型 (PvP, Normal, RP 等)
        if (_expversion & POST_BC_EXP_FLAG)                 // 仅 2.x 和 3.x 客户端支持
            pkt << uint8(lock);                             // 若为 1，表示服务器锁定（权限不足）

        pkt << uint8(flag);                                 // 服务器标志位 (REALM_FLAG)
        pkt << name;                                        // 服务器名称
        pkt << boost::lexical_cast<std::string>(realm.GetAddressForClient(GetRemoteIpAddress())); // IP:Port 地址
        pkt << float(realm.PopulationLevel);                // 人口负载比率
        pkt << uint8(characterCounts[realm.Id.Realm]);      // 该账号在该服务器上的角色数量
        pkt << uint8(realm.Timezone);                       // 时区/分类

        if (_expversion & POST_BC_EXP_FLAG)                 // 2.x 和 3.x 客户端
            pkt << uint8(realm.Id.Realm);
        else
            pkt << uint8(0x0);                              // 1.12.x 经典客户端

        if (_expversion & POST_BC_EXP_FLAG && flag & REALM_FLAG_SPECIFYBUILD)
        {
            pkt << uint8(buildInfo->MajorVersion);
            pkt << uint8(buildInfo->MinorVersion);
            pkt << uint8(buildInfo->BugfixVersion);
            pkt << uint16(buildInfo->Build);
        }

        ++RealmListSize;
    }

    if (_expversion & POST_BC_EXP_FLAG)                     // 2.x 和 3.x 客户端尾部包
    {
        pkt << uint8(0x10);
        pkt << uint8(0x00);
    }
    else                                                    // 1.12.x 客户端尾部包
    {
        pkt << uint8(0x00);
        pkt << uint8(0x02);
    }

    // 构建包头并发送 RealmList 整个响应数据包
    ByteBuffer RealmListSizeBuffer;
    RealmListSizeBuffer << uint32(0);

    if (_expversion & POST_BC_EXP_FLAG)
        RealmListSizeBuffer << uint16(RealmListSize);
    else
        RealmListSizeBuffer << uint32(RealmListSize);

    ByteBuffer hdr;
    hdr << uint8(REALM_LIST);
    hdr << uint16(pkt.size() + RealmListSizeBuffer.size());
    hdr.append(RealmListSizeBuffer);
    hdr.append(pkt);
    SendPacket(hdr);

    _status = STATUS_AUTHED;
}

/**
 * @brief 校验客户端可执行程序二进制 Version Hash
 * @param a 随机公钥 A 或 R1 数组指针
 * @param aLength 字节长度
 * @param versionProof 客户端发送的版本 Hash
 * @param isReconnect 是否为重连阶段
 * @return true 版本校验成功或配置关闭了严格校验，false 校验失败
 */
bool AuthSession::VerifyVersion(uint8 const* a, int32 aLength, Acore::Crypto::SHA1::Digest const& versionProof, bool isReconnect)
{
    // 如果配置中关闭了严格版本校验，则直接返回成功
    if (!sConfigMgr->GetOption<bool>("StrictVersionCheck", false))
        return true;

    Acore::Crypto::SHA1::Digest zeros{};
    Acore::Crypto::SHA1::Digest const* versionHash{ nullptr };

    if (!isReconnect)
    {
        RealmBuildInfo const* buildInfo = sRealmList->GetBuildInfo(_build);
        if (!buildInfo)
            return false;

        if (_os == "Win")
            versionHash = &buildInfo->WindowsHash;
        else if (_os == "OSX")
            versionHash = &buildInfo->MacHash;

        if (!versionHash)
            return false;

        if (zeros == *versionHash)
            return true;
    }
    else
        versionHash = &zeros;

    Acore::Crypto::SHA1 version;
    version.UpdateData(a, aLength);
    version.UpdateData(*versionHash);
    version.Finalize();

    return (versionProof == version.GetDigest());
}
