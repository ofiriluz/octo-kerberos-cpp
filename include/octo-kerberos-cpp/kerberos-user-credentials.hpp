/**
 * @file kerberos-user-credentials.hpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-14
 *
 * @copyright Copyright (c) 2022
 *
 */

#ifndef KERBEROS_USER_CREDENTIALS_HPP_
#define KERBEROS_USER_CREDENTIALS_HPP_

#include <octo-encryption-cpp/encryptors/encrypted-string.hpp>
#include <memory>
#include <string>

namespace octo::kerberos
{
class KerberosUserCredentials
{
  private:
    encryption::SecureStringUniquePtr password_;
    std::string username_;

  public:
    KerberosUserCredentials(std::string username = "", encryption::SecureStringUniquePtr password = nullptr);
    virtual ~KerberosUserCredentials() = default;

    [[nodiscard]] const encryption::SecureString& password() const;
    [[nodiscard]] const std::string& username() const;

    void set_password(encryption::SecureStringUniquePtr password);
    void set_username(std::string username);
};
typedef std::unique_ptr<KerberosUserCredentials> KerberosUserCredentialsUniquePtr;
} // namespace octo::kerberos

#endif
