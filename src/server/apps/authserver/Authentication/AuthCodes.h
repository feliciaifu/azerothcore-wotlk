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

#ifndef _AUTHCODES_H
#define _AUTHCODES_H

#include "Define.h"

/**
 * @enum AuthResult
 * @brief 认证结果返回码枚举（客户端响应协议中的 AuthResult 错误码）
 */
enum AuthResult
{
    WOW_SUCCESS                                  = 0x00, /// < 登录/验证成功
    WOW_FAIL_BANNED                              = 0x03, /// < 账号已被永久封禁
    WOW_FAIL_UNKNOWN_ACCOUNT                     = 0x04, /// < 账号不存在或密码错误
    WOW_FAIL_INCORRECT_PASSWORD                  = 0x05, /// < 密码不正确
    WOW_FAIL_ALREADY_ONLINE                      = 0x06, /// < 该账号已在在线状态
    WOW_FAIL_NO_TIME                             = 0x07, /// < 游戏时间不足（游戏卡点数耗尽）
    WOW_FAIL_DB_BUSY                             = 0x08, /// < 数据库繁忙
    WOW_FAIL_VERSION_INVALID                     = 0x09, /// < 客户端版本不匹配/无效
    WOW_FAIL_VERSION_UPDATE                      = 0x0A, /// < 需要更新客户端版本
    WOW_FAIL_INVALID_SERVER                      = 0x0B, /// < 无效的服务器
    WOW_FAIL_SUSPENDED                           = 0x0C, /// < 账号被临时冻结/封禁
    WOW_FAIL_FAIL_NOACCESS                       = 0x0D, /// < 权限拒绝（拒绝访问）
    WOW_SUCCESS_SURVEY                           = 0x0E, /// < 登录成功并弹出调查问卷
    WOW_FAIL_PARENTCONTROL                       = 0x0F, /// < 家长控制规则限制
    WOW_FAIL_LOCKED_ENFORCED                     = 0x10, /// < 账号被强制锁定了 IP/国家
    WOW_FAIL_TRIAL_ENDED                         = 0x11, /// < 试用期已结束
    WOW_FAIL_USE_BATTLENET                       = 0x12, /// < 需要使用战网账号登录
    WOW_FAIL_ANTI_INDULGENCE                     = 0x13, /// < 防沉迷系统限制
    WOW_FAIL_EXPIRED                             = 0x14, /// < 账号服务已过期
    WOW_FAIL_NO_GAME_ACCOUNT                     = 0x15, /// < 未找到魔兽世界子账号
    WOW_FAIL_CHARGEBACK                          = 0x16, /// < 因退款退费问题导致账号锁定
    WOW_FAIL_INTERNET_GAME_ROOM_WITHOUT_BNET     = 0x17, /// < 网吧无战网账号登录模式限制
    WOW_FAIL_GAME_ACCOUNT_LOCKED                 = 0x18, /// < 游戏子账号已被锁定
    WOW_FAIL_UNLOCKABLE_LOCK                     = 0x19, /// < 账号锁定且无法解锁（如国家锁定不符）
    WOW_FAIL_CONVERSION_REQUIRED                 = 0x20, /// < 账号需要转换升级为战网账号
    WOW_FAIL_DISCONNECTED                        = 0xFF  /// < 连接已断开
};

/**
 * @enum LoginResult
 * @brief 内部登录校验状态枚举
 */
enum LoginResult
{
    LOGIN_OK                                     = 0x00, /// < 登录正常
    LOGIN_FAILED                                 = 0x01, /// < 登录失败（通用）
    LOGIN_FAILED2                                = 0x02, /// < 登录失败状态 2
    LOGIN_BANNED                                 = 0x03, /// < 账号已封禁
    LOGIN_UNKNOWN_ACCOUNT                        = 0x04, /// < 未知账号
    LOGIN_UNKNOWN_ACCOUNT3                       = 0x05, /// < 未知账号状态 3
    LOGIN_ALREADYONLINE                          = 0x06, /// < 账号已在线
    LOGIN_NOTIME                                 = 0x07, /// < 游戏时间不足
    LOGIN_DBBUSY                                 = 0x08, /// < 数据库繁忙
    LOGIN_BADVERSION                             = 0x09, /// < 版本错误
    LOGIN_DOWNLOAD_FILE                          = 0x0A, /// < 需要下载文件/更新
    LOGIN_FAILED3                                = 0x0B, /// < 登录失败状态 3
    LOGIN_SUSPENDED                              = 0x0C, /// < 账号已被冻结
    LOGIN_FAILED4                                = 0x0D, /// < 登录失败状态 4
    LOGIN_CONNECTED                              = 0x0E, /// < 已建立连接
    LOGIN_PARENTALCONTROL                        = 0x0F, /// < 家长控制限制
    LOGIN_LOCKED_ENFORCED                        = 0x10  /// < 强制锁定限制
};

/**
 * @enum ExpansionFlags
 * @brief 资料片版本标志（用于标识客户端支持的资料片版本）
 */
enum ExpansionFlags
{
    POST_BC_EXP_FLAG                            = 0x2, /// < TBC (2.x) 或 WotLK (3.x) 资料片客户端
    PRE_BC_EXP_FLAG                             = 0x1, /// < 经典旧世 (1.x Classic/Vanilla) 资料片客户端
    NO_VALID_EXP_FLAG                           = 0x0  /// < 无效/不支持的资料片客户端版本
};

struct RealmBuildInfo;

/**
 * @namespace AuthHelper
 * @brief 认证辅助工具函数命名空间
 */
namespace AuthHelper
{
    /**
     * @brief 检查客户端 Build 号是否被服务器允许/支持
     * @param build 客户端 Build 版本号 (如 12340 对应 3.3.5a)
     * @return true 如果支持该 Build 号
     */
    bool IsAcceptedClientBuild(uint32 build);

    /**
     * @brief 检查客户端 Build 号是否为 TBC/WotLK（燃烧的远征/巫妖王之怒，即 Post-BC）所接受的版本
     * @param build 客户端 Build 版本号
     * @return true 如果为有效的 Post-BC 版本
     */
    bool IsPostBCAcceptedClientBuild(uint32 build);

    /**
     * @brief 检查客户端 Build 号是否为 1.x 经典旧世 (Pre-BC) 所接受的版本
     * @param build 客户端 Build 版本号
     * @return true 如果为有效的 Pre-BC 版本
     */
    bool IsPreBCAcceptedClientBuild(uint32 build);
};

#endif
