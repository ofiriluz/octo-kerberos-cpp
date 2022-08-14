/**
 * @file kerberos-ticket.hpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-14
 *
 * @copyright Copyright (c) 2022
 *
 */

#ifndef KERBEROS_TICKET_HPP_
#define KERBEROS_TICKET_HPP_

#include <octo-encryption-cpp/encryptors/encrypted-string.hpp>
#include <memory>
#include <chrono>
#include <string>
#include <nlohmann/json.hpp>

namespace octo::kerberos
{
class KerberosTicket
{
  public:
    enum class Type : std::uint8_t
    {
        TicketGrantingTicket,
        ServiceTicket
    };

  public:
    KerberosTicket() = default;
    virtual ~KerberosTicket() = default;

    [[nodiscard]] virtual encryption::SecureString ticket() const = 0;
    [[nodiscard]] virtual encryption::SecureString encoded_ticket() const = 0;
    [[nodiscard]] virtual std::string ticket_purpose() const = 0;
    [[nodiscard]] virtual Type ticket_type() const = 0;
    [[nodiscard]] virtual const std::chrono::time_point<std::chrono::system_clock>& ticket_expiration_time() const = 0;

    [[nodiscard]] virtual nlohmann::json serialize() const = 0;
    [[nodiscard]] virtual bool deserialize(const nlohmann::json& json) = 0;
};
typedef std::unique_ptr<KerberosTicket> KerberosTicketUniquePtr;
typedef std::shared_ptr<KerberosTicket> KerberosTicketPtr;
} // namespace octo::kerberos

#endif
