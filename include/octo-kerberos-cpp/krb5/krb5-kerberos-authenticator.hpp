/**
 * @file krb5-kerberos-authenticator.hpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-14
 *
 * @copyright Copyright (c) 2022
 *
 */

#ifndef KRB5_KERBEROS_AUTHENTICATOR_HPP_
#define KRB5_KERBEROS_AUTHENTICATOR_HPP_

#include "octo-kerberos-cpp/kerberos-authenticator.hpp"
#include "octo-kerberos-cpp/kerberos-ticket.hpp"
#include "octo-kerberos-cpp/kerberos-user-credentials.hpp"
#include "octo-kerberos-cpp/krb5/krb5-kerberos-tgt-ticket.hpp"
#include <octo-logger-cpp/logger.hpp>
#include <nlohmann/json.hpp>
#include <krb5/krb5.h>
#include <string>
#include <profile.h>

namespace
{
constexpr const auto DEFAULT_KERBEROS_PORT = 88;
constexpr const auto DEFAULT_KERBEROS_STREAMLINED = true;
} // namespace

namespace octo::kerberos::krb5
{
class KRB5KerberosAuthenticator : public KerberosAuthenticator
{
  public:
    struct Settings
    {
        std::string realm;
        std::string kdc_host;
        std::uint32_t kdc_port = DEFAULT_KERBEROS_PORT;
        std::string session_id;
        bool streamlined = DEFAULT_KERBEROS_STREAMLINED;
    };

  private:
    Settings settings_;
    struct profile_vtable* profile_vtable_;
    profile_t profile_;
    krb5_context ctx_;
    krb5_ccache cache_;
    krb5_principal server_;
    bool is_initialized_;
    logger::Logger logger_;
    int kdc_fd_;

  private:
    [[nodiscard]] bool create_streamlined_kdc_connection();
    void close_streamlined_kdc_connection();
    [[nodiscard]] int kdc_net_read(char* buf, int len);
    [[nodiscard]] int kdc_net_write(char* buf, int len);
    [[nodiscard]] krb5_error_code kdc_read(krb5_data* inbuf);
    [[nodiscard]] krb5_error_code kdc_write(krb5_data* outbuf);
    [[nodiscard]] bool convert_to_krb_address(const std::string& host, int port, krb5_address** outaddr);

    [[nodiscard]] krb5_get_init_creds_opt* allocate_init_creds_options(std::chrono::seconds lifetime);
    [[nodiscard]] KerberosTicketUniquePtr generate_tgt_direct(
        const KerberosUserCredentials* const creds,
        std::chrono::seconds lifetime = std::chrono::seconds(DEFAULT_TGT_LIFETIME_SECONDS));
    [[nodiscard]] KerberosTicketUniquePtr generate_tgt_streamlined(
        const KerberosUserCredentials* const creds,
        std::chrono::seconds lifetime = std::chrono::seconds(DEFAULT_TGT_LIFETIME_SECONDS));

    [[nodiscard]] bool prepare_tgt_for_st_generation(KRB5KerberosTGTTicket* const krb5_tgt,
                                                     const std::string& service,
                                                     std::chrono::seconds lifetime);
    [[nodiscard]] KerberosTicketUniquePtr generate_service_ticket_direct(
        KRB5KerberosTGTTicket* const krb5_tgt,
        const std::string& service,
        std::chrono::seconds lifetime = std::chrono::seconds(DEFAULT_SERVICE_TICKET_LIFETIME_SECONDS));
    [[nodiscard]] KerberosTicketUniquePtr generate_service_ticket_streamlined(
        KRB5KerberosTGTTicket* const krb5_tgt,
        const std::string& service,
        std::chrono::seconds lifetime = std::chrono::seconds(DEFAULT_SERVICE_TICKET_LIFETIME_SECONDS));

  public:
    explicit KRB5KerberosAuthenticator(Settings settings);
    ~KRB5KerberosAuthenticator() override;

    [[nodiscard]] bool initialize_authenticator() override;
    [[nodiscard]] bool cleanup_authenticator() override;
    [[nodiscard]] bool is_initialized() const override;
    [[nodiscard]] KerberosTicketUniquePtr generate_tgt(
        const KerberosUserCredentials* const creds,
        std::chrono::seconds lifetime = std::chrono::seconds(DEFAULT_TGT_LIFETIME_SECONDS)) override;
    [[nodiscard]] KerberosTicketUniquePtr deserialize_tgt(const nlohmann::json& json) override;
    [[nodiscard]] KerberosTicketUniquePtr generate_service_ticket(
        KerberosTicket* const tgt,
        const std::string& service,
        std::chrono::seconds lifetime = std::chrono::seconds(DEFAULT_SERVICE_TICKET_LIFETIME_SECONDS)) override;
    [[nodiscard]] KerberosTicketUniquePtr deserialize_service_ticket(const nlohmann::json& json) override;

    long get_profile_values(const char* const* names, char*** ret_values);
    void free_profile_values(char** values);
    void cleanup_profile();

    bool is_streamlined() const;
};
} // namespace octo::kerberos::krb5

#endif
