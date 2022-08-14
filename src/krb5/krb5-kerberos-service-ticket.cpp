/**
 * @file krb5-kerberos-service-ticket.cpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-14
 *
 * @copyright Copyright (c) 2022
 *
 */

#include "octo-kerberos-cpp/krb5/krb5-kerberos-service-ticket.hpp"
#include "octo-kerberos-cpp/krb5/krb5-kerberos-serializer.hpp"
#include <octo-encryption-cpp/base64.hpp>
#include <fmt/format.h>

namespace octo::kerberos::krb5
{
KRB5KerberosServiceTicket::KRB5KerberosServiceTicket(
    std::string service, const std::chrono::time_point<std::chrono::system_clock>& service_ticket_expiration)
    : service_(std::move(service)),
      service_ticket_(nullptr),
      service_ticket_expiration_(service_ticket_expiration),
      ctx_(nullptr)
{
}

KRB5KerberosServiceTicket::~KRB5KerberosServiceTicket()
{
    if (service_ticket_)
    {
        krb5_free_creds(ctx_, service_ticket_);
    }
}

encryption::SecureString KRB5KerberosServiceTicket::ticket() const
{
    return {std::string(service_ticket_->ticket.data, service_ticket_->ticket.length)};
}

encryption::SecureString KRB5KerberosServiceTicket::encoded_ticket() const
{
    return {
        encryption::Base64::base64_encode(std::string(service_ticket_->ticket.data, service_ticket_->ticket.length))};
}

std::string KRB5KerberosServiceTicket::ticket_purpose() const
{
    return fmt::format("Service Ticket for Service {}", service_);
}

KerberosTicket::Type KRB5KerberosServiceTicket::ticket_type() const
{
    return KerberosTicket::Type::ServiceTicket;
}

const std::chrono::time_point<std::chrono::system_clock>& KRB5KerberosServiceTicket::ticket_expiration_time() const
{
    return service_ticket_expiration_;
}

nlohmann::json KRB5KerberosServiceTicket::serialize() const
{
    nlohmann::json j;
    j["service"] = service_;
    j["service_ticket"] = KRB5KerberosSerializer::serialize_creds(*service_ticket_);
    j["service_ticket_expiration"] =
        std::chrono::duration_cast<std::chrono::seconds>(service_ticket_expiration_.time_since_epoch()).count();
    return j;
}

bool KRB5KerberosServiceTicket::deserialize(const nlohmann::json& json)
{
    if (!json.contains("service") || !json.contains("service_ticket") || !json.contains("service_ticket_expiration"))
    {
        return false;
    }
    service_ = json["service"];
    if (service_ticket_)
    {
        krb5_free_creds(ctx_, service_ticket_);
    }
    service_ticket_ = reinterpret_cast<krb5_creds*>(calloc(1, sizeof(krb5_creds)));
    if (!KRB5KerberosSerializer::deserialize_creds(json["service_ticket"], service_ticket_, ctx_))
    {
        return false;
    }
    service_ticket_expiration_ =
        std::chrono::time_point<std::chrono::system_clock>(std::chrono::seconds(json["service_ticket_expiration"]));
    return true;
}

std::string KRB5KerberosServiceTicket::service() const
{
    return service_;
}

krb5_context KRB5KerberosServiceTicket::krb_context() const
{
    return ctx_;
}
} // namespace octo::kerberos::krb5
