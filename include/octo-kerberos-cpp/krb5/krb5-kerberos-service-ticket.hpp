/**
 * @file krb5-kerberos-service-ticket.hpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-14
 *
 * @copyright Copyright (c) 2022
 *
 */

#ifndef KRB5_KERBEROS_SERVICE_TICKET_HPP_
#define KRB5_KERBEROS_SERVICE_TICKET_HPP_

#include "octo-kerberos-cpp/kerberos-ticket.hpp"
#include <krb5/krb5.h>
#include <memory>
#include <chrono>
#include <string>

namespace octo::kerberos::krb5
{
class KRB5KerberosServiceTicket : public KerberosTicket
{
  private:
    std::string service_;
    krb5_creds* service_ticket_;
    std::chrono::time_point<std::chrono::system_clock> service_ticket_expiration_;
    krb5_context ctx_;

  public:
    explicit KRB5KerberosServiceTicket(std::string service = "",
                                       const std::chrono::time_point<std::chrono::system_clock>&
                                           service_ticket_expiration = std::chrono::system_clock::now());
    ~KRB5KerberosServiceTicket() override;

    [[nodiscard]] encryption::SecureString ticket() const override;
    [[nodiscard]] encryption::SecureString encoded_ticket() const override;
    [[nodiscard]] std::string ticket_purpose() const override;
    [[nodiscard]] KerberosTicket::Type ticket_type() const override;
    [[nodiscard]] const std::chrono::time_point<std::chrono::system_clock>& ticket_expiration_time() const override;

    [[nodiscard]] nlohmann::json serialize() const override;
    [[nodiscard]] bool deserialize(const nlohmann::json& json) override;

    [[nodiscard]] std::string service() const;
    [[nodiscard]] krb5_context krb_context() const;

    friend class KRB5KerberosAuthenticator;
};
typedef std::unique_ptr<KRB5KerberosServiceTicket> KRB5KerberosServiceTicketUniquePtr;
} // namespace octo::kerberos::krb5

#endif
