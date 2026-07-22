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

#include "AuthCodes.h"
#include "RealmList.h"

namespace AuthHelper
{
    /// 经典旧世 (Pre-BC / 1.x) 客户端的最大 Build 版本号 (1.12.1/1.12.2 对应 6141)
    constexpr static uint32 MAX_PRE_BC_CLIENT_BUILD = 6141;

    /**
     * @brief 判断给定的 Build 版本号是否为有效且可接受的 Pre-BC (经典旧世 1.x) 客户端版本
     * @param build 客户端 Build 号
     */
    bool IsPreBCAcceptedClientBuild(uint32 build)
    {
        return build <= MAX_PRE_BC_CLIENT_BUILD && sRealmList->GetBuildInfo(build);
    }

    /**
     * @brief 判断给定的 Build 版本号是否为有效且可接受的 Post-BC (TBC 2.x 或 WotLK 3.x) 客户端版本
     * @param build 客户端 Build 号
     */
    bool IsPostBCAcceptedClientBuild(uint32 build)
    {
        return build > MAX_PRE_BC_CLIENT_BUILD && sRealmList->GetBuildInfo(build);
    }

    /**
     * @brief 判断给定的 Build 版本号是否存在于服务器支持列表中
     * @param build 客户端 Build 号
     */
    bool IsAcceptedClientBuild(uint32 build)
    {
        return sRealmList->GetBuildInfo(build) != nullptr;
    }
};
