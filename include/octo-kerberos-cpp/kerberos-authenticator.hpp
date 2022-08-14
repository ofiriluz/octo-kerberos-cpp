/**
 * @file kerberos-authenticator.hpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-14
 *
 * @copyright Copyright (c) 2022
 *
 */

#ifndef KERBEROS_AUTHENTICATOR_HPP_
#define KERBEROS_AUTHENTICATOR_HPP_

#include "kerberos-ticket.hpp"
#include "kerberos-user-credentials.hpp"
#include <nlohmann/json.hpp>
#include <string>
#include <chrono>

namespace
{
constexpr auto DEFAULT_TGT_LIFETIME_SECONDS = 5 * 60;
constexpr auto DEFAULT_SERVICE_TICKET_LIFETIME_SECONDS = 5 * 60;
} // namespace

namespace octo::kerberos
{
class KerberosAuthenticator
{
  public:
    struct Settings
    {
        std::string host;
        std::uint32_t port;
        std::string server_principal, client_principal;
    };

  public:
    KerberosAuthenticator() = default;
    virtual ~KerberosAuthenticator() = default;

    [[nodiscard]] virtual bool initialize_authenticator() = 0;
    [[nodiscard]] virtual bool cleanup_authenticator() = 0;
    [[nodiscard]] virtual bool is_initialized() const = 0;
    [[nodiscard]] virtual KerberosTicketUniquePtr generate_tgt(
        const KerberosUserCredentials* const creds,
        std::chrono::seconds lifetime = std::chrono::seconds(DEFAULT_TGT_LIFETIME_SECONDS)) = 0;
    [[nodiscard]] virtual KerberosTicketUniquePtr deserialize_tgt(const nlohmann::json& json) = 0;
    [[nodiscard]] virtual KerberosTicketUniquePtr generate_service_ticket(
        KerberosTicket* const tgt,
        const std::string& service,
        std::chrono::seconds lifetime = std::chrono::seconds(DEFAULT_SERVICE_TICKET_LIFETIME_SECONDS)) = 0;
    [[nodiscard]] virtual KerberosTicketUniquePtr deserialize_service_ticket(const nlohmann::json& json) = 0;
};
} // namespace octo::kerberos

#endif
