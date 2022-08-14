/**
 * @file krb5-kerberos-tgt-ticket.cpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-14
 *
 * @copyright Copyright (c) 2022
 *
 */

#include "octo-kerberos-cpp/krb5/krb5-kerberos-tgt-ticket.hpp"
#include "octo-kerberos-cpp/krb5/krb5-kerberos-serializer.hpp"
#include <octo-encryption-cpp/base64.hpp>
#include <fmt/format.h>

namespace octo::kerberos::krb5
{
KRB5KerberosTGTTicket::KRB5KerberosTGTTicket(std::string tgt_user,
                                             const std::chrono::time_point<std::chrono::system_clock>& tgt_expiration)
    : tgt_user_(std::move(tgt_user)), tgt_ticket_({}), tgt_expiration_(tgt_expiration), ctx_(nullptr)
{
}

encryption::SecureString KRB5KerberosTGTTicket::ticket() const
{
    return {std::string(tgt_ticket_.ticket.data, tgt_ticket_.ticket.length)};
}

encryption::SecureString KRB5KerberosTGTTicket::encoded_ticket() const
{
    return {encryption::Base64::base64_encode(std::string(tgt_ticket_.ticket.data, tgt_ticket_.ticket.length))};
}

std::string KRB5KerberosTGTTicket::ticket_purpose() const
{
    return fmt::format("Ticket Granting Ticket for User {}", tgt_user_);
}

KerberosTicket::Type KRB5KerberosTGTTicket::ticket_type() const
{
    return KerberosTicket::Type::TicketGrantingTicket;
}

const std::chrono::time_point<std::chrono::system_clock>& KRB5KerberosTGTTicket::ticket_expiration_time() const
{
    return tgt_expiration_;
}

nlohmann::json KRB5KerberosTGTTicket::serialize() const
{
    nlohmann::json j;
    j["tgt_user"] = tgt_user_;
    j["tgt_ticket"] = KRB5KerberosSerializer::serialize_creds(tgt_ticket_);
    j["tgt_expiration"] = std::chrono::duration_cast<std::chrono::seconds>(tgt_expiration_.time_since_epoch()).count();
    return j;
}

bool KRB5KerberosTGTTicket::deserialize(const nlohmann::json& json)
{
    if (!json.contains("tgt_user") || !json.contains("tgt_ticket") || !json.contains("tgt_expiration"))
    {
        return false;
    }
    tgt_user_ = json["tgt_user"];
    if (!KRB5KerberosSerializer::deserialize_creds(json["tgt_ticket"], &tgt_ticket_, ctx_))
    {
        return false;
    }
    tgt_expiration_ = std::chrono::time_point<std::chrono::system_clock>(std::chrono::seconds(json["tgt_expiration"]));
    return true;
}

std::string KRB5KerberosTGTTicket::tgt_user() const
{
    return tgt_user_;
}

krb5_context KRB5KerberosTGTTicket::krb_context() const
{
    return ctx_;
}
} // namespace octo::kerberos::krb5
