/**
 * @file krb5-kerberos-tgt-ticket.hpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-14
 *
 * @copyright Copyright (c) 2022
 *
 */

#ifndef KRB5_KERBEROS_TGT_TICKET_HPP_
#define KRB5_KERBEROS_TGT_TICKET_HPP_

#include "octo-kerberos-cpp/kerberos-ticket.hpp"
#include <krb5/krb5.h>
#include <memory>
#include <chrono>
#include <string>

namespace octo::kerberos::krb5
{
class KRB5KerberosTGTTicket : public KerberosTicket
{
  private:
    std::string tgt_user_;
    krb5_creds tgt_ticket_;
    std::chrono::time_point<std::chrono::system_clock> tgt_expiration_;
    krb5_context ctx_;

  public:
    explicit KRB5KerberosTGTTicket(
        std::string tgt_user = "",
        const std::chrono::time_point<std::chrono::system_clock>& tgt_expiration = std::chrono::system_clock::now());
    ~KRB5KerberosTGTTicket() override = default;

    [[nodiscard]] encryption::SecureString ticket() const override;
    [[nodiscard]] encryption::SecureString encoded_ticket() const override;
    [[nodiscard]] std::string ticket_purpose() const override;
    [[nodiscard]] KerberosTicket::Type ticket_type() const override;
    [[nodiscard]] const std::chrono::time_point<std::chrono::system_clock>& ticket_expiration_time() const override;

    [[nodiscard]] nlohmann::json serialize() const override;
    [[nodiscard]] bool deserialize(const nlohmann::json& json) override;

    [[nodiscard]] std::string tgt_user() const;
    [[nodiscard]] krb5_context krb_context() const;

    friend class KRB5KerberosAuthenticator;
};
typedef std::unique_ptr<KRB5KerberosTGTTicket> KRB5KerberosTGTTicketUniquePtr;
} // namespace octo::kerberos::krb5

#endif
