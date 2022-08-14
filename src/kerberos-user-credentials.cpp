/**
 * @file kerberos-user-credentials.cpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-14
 *
 * @copyright Copyright (c) 2022
 *
 */

#include "octo-kerberos-cpp/kerberos-user-credentials.hpp"

namespace octo::kerberos
{
KerberosUserCredentials::KerberosUserCredentials(std::string username, encryption::SecureStringUniquePtr password)
    : username_(std::move(username)), password_(std::move(password))
{
}

const encryption::SecureString& KerberosUserCredentials::password() const
{
    return *password_;
}

const std::string& KerberosUserCredentials::username() const
{
    return username_;
}

void KerberosUserCredentials::set_password(encryption::SecureStringUniquePtr password)
{
    password_ = std::move(password);
}

void KerberosUserCredentials::set_username(std::string username)
{
    username_ = std::move(username);
}
} // namespace octo::kerberos
