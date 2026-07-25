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

#ifndef _LOGINDATABASE_H
#define _LOGINDATABASE_H

#include "MySQLConnection.h"

/**
 * @enum LoginDatabaseStatements
 * @brief 认证数据库 (acore_auth) 预编译 SQL 语句枚举列表
 *
 * 包含所有用于账号管理、IP/账号封禁、服务器列表、公告、RBAC权限、安全日志等操作的 SQL 语句索引。
 * 命名规范：{DB}_{SEL/INS/UPD/DEL/REP}_{数据功能描述}
 */
enum LoginDatabaseStatements : uint32
{
    LOGIN_SEL_REALMLIST,                         ///< 查询服务器列表 (realmlist)
    LOGIN_DEL_EXPIRED_IP_BANS,                   ///< 删除已到期的 IP 封禁记录
    LOGIN_UPD_EXPIRED_ACCOUNT_BANS,              ///< 更新已到期的账号封禁状态为非激活
    LOGIN_SEL_IP_INFO,                           ///< 查询 IP 封禁及归属地信息
    LOGIN_SEL_IP_BANNED,                         ///< 查询指定 IP 是否处于封禁状态
    LOGIN_INS_IP_AUTO_BANNED,                    ///< 插入自动 IP 封禁记录（连续登录失败触发）
    LOGIN_SEL_ACCOUNT_BANNED,                    ///< 查询指定账号 ID 的有效封禁记录
    LOGIN_SEL_ACCOUNT_BANNED_ALL,                ///< 查询所有处于封禁状态的账号
    LOGIN_SEL_ACCOUNT_BANNED_BY_USERNAME,        ///< 根据用户名模糊查询封禁的账号
    LOGIN_INS_ACCOUNT_AUTO_BANNED,               ///< 插入自动账号封禁记录（连续登录失败触发）
    LOGIN_DEL_ACCOUNT_BANNED,                    ///< 解除/删除账号封禁记录
    LOGIN_UPD_LOGON,                             ///< 更新账号 SRP6 凭证 (salt, verifier)
    LOGIN_UPD_LOGONPROOF,                        ///< 更新登录凭证认证成功后的账号状态
    LOGIN_SEL_LOGONCHALLENGE,                    ///< 登录挑战阶段：获取账号验证数据 (salt, verifier, 2FA, 封禁状态等)
    LOGIN_SEL_RECONNECTCHALLENGE,                ///< 重连挑战阶段：获取账号历史 session_key 及验证数据
    LOGIN_UPD_FAILEDLOGINS,                      ///< 增加账号连续登录失败计数
    LOGIN_SEL_FAILEDLOGINS,                      ///< 查询账号连续登录失败次数
    LOGIN_SEL_ACCOUNT_ID_BY_NAME,                ///< 根据用户名查询账号 ID
    LOGIN_SEL_ACCOUNT_LIST_BY_NAME,              ///< 根据用户名查询账号 ID 和用户名列表
    LOGIN_SEL_ACCOUNT_INFO_BY_NAME,              ///< 根据用户名查询账号完整信息 (登录验证用)
    LOGIN_SEL_ACCOUNT_LIST_BY_EMAIL,             ///< 根据电子邮箱查询账号列表
    LOGIN_SEL_NUM_CHARS_ON_REALM,                ///< 查询账号在特定服务器上的角色数量
    LOGIN_SEL_REALM_CHARACTER_COUNTS,            ///< 查询账号在所有服务器上的角色数量列表
    LOGIN_SEL_ACCOUNT_BY_IP,                     ///< 根据最后登录 IP 查询账号列表
    LOGIN_INS_IP_BANNED,                         ///< 插入手动 IP 封禁记录
    LOGIN_DEL_IP_NOT_BANNED,                     ///< 解除/删除 IP 封禁记录
    LOGIN_SEL_IP_BANNED_ALL,                     ///< 查询所有有效的 IP 封禁记录
    LOGIN_SEL_IP_BANNED_BY_IP,                   ///< 根据 IP 模糊查询封禁记录
    LOGIN_SEL_ACCOUNT_BY_ID,                     ///< 检查指定账号 ID 是否存在
    LOGIN_INS_ACCOUNT_BANNED,                    ///< 插入手动账号封禁记录
    LOGIN_UPD_ACCOUNT_NOT_BANNED,                ///< 解除账号封禁状态 (设置 active = 0)
    LOGIN_DEL_REALM_CHARACTERS,                  ///< 删除账号的服务器角色统计记录
    LOGIN_REP_REALM_CHARACTERS,                  ///< 替换/更新账号在服务器上的角色统计数据
    LOGIN_SEL_SUM_REALM_CHARACTERS,              ///< 查询账号在所有服务器上的总角色数量
    LOGIN_INS_ACCOUNT,                           ///< 创建新账号记录
    LOGIN_INS_REALM_CHARACTERS_INIT,             ///< 初始化账号在各大区/服务器的角色统计信息
    LOGIN_UPD_EXPANSION,                         ///< 更新账号游戏资料片版本标识 (Vanilla/TBC/WotLK)
    LOGIN_UPD_ACCOUNT_LOCK,                      ///< 更新账号 IP 锁定状态
    LOGIN_UPD_ACCOUNT_LOCK_COUNTRY,              ///< 更新账号国家/地区锁定状态
    LOGIN_UPD_EMAIL,                             ///< 更新账号绑定的电子邮箱
    LOGIN_UPD_USERNAME,                          ///< 更新账号名称
    LOGIN_UPD_MUTE_TIME,                         ///< 更新账号禁言剩余时间与原因
    LOGIN_UPD_MUTE_TIME_LOGIN,                   ///< 登录时更新账号禁言时间
    LOGIN_UPD_LAST_IP,                           ///< 更新账号最后登录 IP
    LOGIN_UPD_LAST_ATTEMPT_IP,                   ///< 更新账号最后尝试登录 IP
    LOGIN_UPD_ACCOUNT_ONLINE,                    ///< 更新账号在线状态 (online 标记)
    LOGIN_UPD_UPTIME_PLAYERS,                    ///< 更新服务器运行时间 (uptime) 与峰值在线玩家数
    LOGIN_UPD_REALM_ONLINE,                      ///< 更新服务器在线状态标志 (realmlist flag)
    LOGIN_DEL_OLD_LOGS,                          ///< 清理过期的数据库日志记录
    LOGIN_DEL_ACCOUNT_ACCESS,                    ///< 删除账号的所有 GM 权限设置
    LOGIN_DEL_ACCOUNT_ACCESS_BY_REALM,           ///< 删除账号在指定服务器上的 GM 权限设置
    LOGIN_INS_ACCOUNT_ACCESS,                    ///< 赋予账号特定的 GM 权限等级 (gmlevel)
    LOGIN_GET_ACCOUNT_ID_BY_USERNAME,            ///< 精确查询用户名对应的账号 ID
    LOGIN_GET_ACCOUNT_ACCESS_GMLEVEL,            ///< 查询账号的最高 GM 权限等级
    LOGIN_GET_GMLEVEL_BY_REALMID,                ///< 查询账号在特定服务器上的 GM 权限等级
    LOGIN_GET_USERNAME_BY_ID,                    ///< 根据账号 ID 查询用户名
    LOGIN_SEL_CHECK_PASSWORD,                    ///< 根据账号 ID 查询密码凭证 (salt, verifier)
    LOGIN_SEL_CHECK_PASSWORD_BY_NAME,            ///< 根据用户名查询密码凭证 (salt, verifier)
    LOGIN_SEL_ACCOUNT_FLAG,                      ///< 查询账号标志位 (Flags)
    LOGIN_UPD_SET_ACCOUNT_FLAG,                  ///< 更新账号标志位 (Flags)
    LOGIN_SEL_PINFO,                             ///< 查询账号详细面板信息 (pinfo 指令用)
    LOGIN_SEL_PINFO_BANS,                        ///< 查询账号的封禁历史信息 (pinfo 指令用)
    LOGIN_SEL_GM_ACCOUNTS,                       ///< 查询达到指定 GM 等级的账号列表
    LOGIN_SEL_ACCOUNT_INFO,                      ///< 查询账号在在线列表中的基本信息
    LOGIN_SEL_ACCOUNT_ACCESS_GMLEVEL_TEST,       ///< 校验账号是否拥有高于特定等级的 GM 权限
    LOGIN_SEL_ACCOUNT_ACCESS,                    ///< 查询账号的所有 GM 权限及对应的 RealmID
    LOGIN_SEL_ACCOUNT_RECRUITER,                 ///< 检查账号是否招募过其他玩家 (招募系统)
    LOGIN_SEL_BANS,                              ///< 校验账号或 IP 是否处于封禁状态
    LOGIN_SEL_ACCOUNT_WHOIS,                     ///< 查询账号的用户名、邮箱及最后登录 IP
    LOGIN_SEL_REALMLIST_SECURITY_LEVEL,          ///< 查询服务器允许的最低安全/GM等级
    LOGIN_UPD_REALMLIST_SECURITY_LEVEL,          ///< 更新服务器允许的最低安全/GM等级
    LOGIN_DEL_ACCOUNT,                           ///< 删除账号记录
    LOGIN_SEL_AUTOBROADCAST,                     ///< 查询自动广播公告消息列表
    LOGIN_SEL_AUTOBROADCAST_LOCALIZED,           ///< 查询多语言自动广播公告消息
    LOGIN_INS_AUTOBROADCAST,                     ///< 插入新的自动广播公告消息
    LOGIN_DEL_AUTOBROADCAST,                     ///< 删除自动广播公告消息
    LOGIN_INS_AUTOBROADCAST_LOCALE,              ///< 替换/插入多语言自动广播公告
    LOGIN_DEL_AUTOBROADCAST_LOCALE,              ///< 删除多语言自动广播公告
    LOGIN_SEL_AUTOBROADCAST_BY_ID,               ///< 检查指定 ID 的自动广播公告是否存在
    LOGIN_SEL_AUTOBROADCAST_LOCALE_BY_ID,        ///< 根据 ID 查询多语言自动广播内容
    LOGIN_SEL_AUTOBROADCAST_MAX_ID,              ///< 查询自动广播公告的最大 ID
    LOGIN_SEL_MOTD,                              ///< 查询每日消息 (MOTD)
    LOGIN_SEL_MOTD_LOCALE,                       ///< 查询多语言每日消息 (MOTD)
    LOGIN_REP_MOTD,                              ///< 替换/更新每日消息 (MOTD)
    LOGIN_REP_MOTD_LOCALE,                       ///< 替换/更新多语言每日消息 (MOTD)
    LOGIN_SEL_LAST_ATTEMPT_IP,                   ///< 查询账号最后尝试登录的 IP
    LOGIN_SEL_LAST_IP,                           ///< 查询账号最后成功登录的 IP
    LOGIN_INS_ALDL_IP_LOGGING,                   ///< 记录账号成功登录/删除相关 IP 日志
    LOGIN_INS_FACL_IP_LOGGING,                   ///< 记录账号登录失败尝试的 IP 日志
    LOGIN_INS_CHAR_IP_LOGGING,                   ///< 记录角色删除操作的 IP 日志
    LOGIN_INS_FALP_IP_LOGGING,                   ///< 记录因密码错误导致的登录失败 IP 日志

    LOGIN_INS_ACCOUNT_MUTE,                      ///< 插入账号禁言记录
    LOGIN_SEL_ACCOUNT_MUTE_INFO,                 ///< 查询账号的历史禁言记录
    LOGIN_DEL_ACCOUNT_MUTED,                     ///< 解除/删除账号禁言记录

    LOGIN_INS_LOG,                               ///< 写入数据库系统日志记录

    LOGIN_SEL_SECRET_DIGEST,                     ///< 查询安全摘要 (Secret Digest)
    LOGIN_INS_SECRET_DIGEST,                     ///< 写入安全摘要 (Secret Digest)
    LOGIN_DEL_SECRET_DIGEST,                     ///< 删除安全摘要 (Secret Digest)

    LOGIN_SEL_ACCOUNT_TOTP_SECRET,               ///< 查询账号 2FA (TOTP) 二步验证密钥
    LOGIN_UPD_ACCOUNT_TOTP_SECRET,               ///< 更新账号 2FA (TOTP) 二步验证密钥

    LOGIN_INS_UPTIME,                            ///< 插入服务器运行时间 (uptime) 记录

    LOGIN_GET_EMAIL_BY_ID,                       ///< 根据账号 ID 获取关联的电子邮箱

    // 基于角色的权限控制 (RBAC - Role-Based Access Control)
    LOGIN_SEL_RBAC_ACCOUNT_PERMISSIONS,          ///< 查询账号的 RBAC 独立自定义权限
    LOGIN_INS_RBAC_ACCOUNT_PERMISSION,           ///< 授予/变更账号的特定 RBAC 权限
    LOGIN_DEL_RBAC_ACCOUNT_PERMISSION,           ///< 撤销账号的特定 RBAC 权限
    LOGIN_SEL_RBAC_DEFAULT_PERMISSIONS,          ///< 查询安全等级 (GM 等级) 对应的默认 RBAC 权限表

    MAX_LOGINDATABASE_STATEMENTS                 ///< 预编译语句总数量上限
};

/**
 * @class LoginDatabaseConnection
 * @brief 认证数据库 (acore_auth) 的连接类
 *
 * 继承自 MySQLConnection，封装连接创建、初始化以及全套预编译 SQL 语句 (Prepared Statements) 的加载。
 */
class AC_DATABASE_API LoginDatabaseConnection : public MySQLConnection
{
public:
    typedef LoginDatabaseStatements Statements;

    /**
     * @brief 同步连接构造函数
     * @param connInfo MySQL 连接配置参数 (主机、端口、数据库名、用户名密码等)
     */
    LoginDatabaseConnection(MySQLConnectionInfo& connInfo);

    /**
     * @brief 异步连接构造函数 (使用生产者-消费者队列处理 SQL 操作)
     * @param q SQL 操作异步处理队列
     * @param connInfo MySQL 连接配置参数
     */
    LoginDatabaseConnection(ProducerConsumerQueue<SQLOperation*>* q, MySQLConnectionInfo& connInfo);

    /**
     * @brief 虚析构函数
     */
    ~LoginDatabaseConnection() override;

    /**
     * @brief 初始化并加载认证数据库专用的所有预编译 SQL 语句
     */
    void DoPrepareStatements() override;
};

#endif
