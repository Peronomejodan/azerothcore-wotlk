/*
 * Copyright (C) 2016+     AzerothCore <www.azerothcore.org>, released under GNU GPL v2 license: http://github.com/azerothcore/azerothcore-wotlk/LICENSE-GPL2
 * Copyright (C) 2008-2016 TrinityCore <http://www.trinitycore.org/>
 * Copyright (C) 2005-2009 MaNGOS <http://getmangos.com/>
 */

#ifndef _ACCMGR_H
#define _ACCMGR_H

#include "Define.h"
#include <string>
#include "RBAC.h"

enum AccountOpResult
{
    AOR_OK,
    AOR_NAME_TOO_LONG,
    AOR_PASS_TOO_LONG,
    AOR_NAME_ALREDY_EXIST,
    AOR_NAME_NOT_EXIST,
    AOR_DB_INTERNAL_ERROR
};

#define MAX_ACCOUNT_STR 20

namespace rbac
{
typedef std::map<uint32, rbac::RBACPermission*> RBACPermissionsContainer;
typedef std::map<uint8, rbac::RBACPermissionContainer> RBACDefaultPermissionsContainer;
}

class AccountMgr
{
    private:
        AccountMgr();
        ~AccountMgr();
    public:
        static AccountMgr* instance();

        AccountOpResult CreateAccount(std::string username, std::string password);
        AccountOpResult DeleteAccount(uint32 accountId);
        AccountOpResult ChangeUsername(uint32 accountId, std::string newUsername, std::string newPassword);
        AccountOpResult ChangePassword(uint32 accountId, std::string newPassword);
        bool CheckPassword(uint32 accountId, std::string password);

        uint32 GetId(std::string const& username);
        uint32 GetSecurity(uint32 accountId);
        uint32 GetSecurity(uint32 accountId, int32 realmId);
        bool GetName(uint32 accountId, std::string& name);
        uint32 GetCharactersCount(uint32 accountId);
        std::string CalculateShaPassHash(std::string const& name, std::string const& password);

        bool normalizeString(std::string& utf8String);
        bool IsPlayerAccount(uint32 gmlevel);
        bool IsGMAccount(uint32 gmlevel);
        bool IsAdminAccount(uint32 gmlevel);
        bool IsConsoleAccount(uint32 gmlevel);
        static bool HasPermission(uint32 accountId, uint32 permission, uint32 realmId);

        void UpdateAccountAccess(rbac::RBACData* rbac, uint32 accountId, uint8 securityLevel, int32 realmId);

        void LoadRBAC();
        rbac::RBACPermission const* GetRBACPermission(uint32 permission) const;

        rbac::RBACPermissionsContainer const& GetRBACPermissionList() const { return _permissions; }
        rbac::RBACPermissionContainer const& GetRBACDefaultPermissions(uint8 secLevel);
    private:
        void ClearRBAC();
        rbac::RBACPermissionsContainer _permissions;
        rbac::RBACDefaultPermissionsContainer _defaultPermissions;
};
#define sAccountMgr AccountMgr::instance()
#endif
