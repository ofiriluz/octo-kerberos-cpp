/**
 * @file krb5-kerberos-serializer.hpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-14
 *
 * @copyright Copyright (c) 2022
 *
 */

#ifndef KRB5_KERBEROS_SERIALIZER_HPP_
#define KRB5_KERBEROS_SERIALIZER_HPP_

#include <nlohmann/json.hpp>
#include <krb5/krb5.h>

namespace octo::kerberos::krb5
{
class KRB5KerberosSerializer
{
  private:
    static void cleanup_creds(krb5_creds* creds);

  public:
    KRB5KerberosSerializer() = default;
    ~KRB5KerberosSerializer() = default;

    // Serialize
    [[nodiscard]] static nlohmann::json serialize_principal_data(const krb5_principal_data& principal_data);
    [[nodiscard]] static nlohmann::json serialize_data(const krb5_data& data);
    [[nodiscard]] static nlohmann::json serialize_keyblock(const krb5_keyblock& keyblock);
    [[nodiscard]] static nlohmann::json serialize_times(const krb5_ticket_times& times);
    [[nodiscard]] static nlohmann::json serialize_address(const krb5_address& address);
    [[nodiscard]] static nlohmann::json serialize_authdata(const krb5_authdata& authdata);
    [[nodiscard]] static nlohmann::json serialize_creds(const krb5_creds& creds);

    // Deserialize
    [[nodiscard]] static bool deserialize_principal_data(const nlohmann::json& j, krb5_principal_data* principal_data);
    [[nodiscard]] static bool deserialize_data(const nlohmann::json& j, krb5_data* data);
    [[nodiscard]] static bool deserialize_keyblock(const nlohmann::json& j, krb5_keyblock* keyblock);
    [[nodiscard]] static bool deserialize_times(const nlohmann::json& j, krb5_ticket_times* times);
    [[nodiscard]] static bool deserialize_address(const nlohmann::json& j, krb5_address* address);
    [[nodiscard]] static bool deserialize_authdata(const nlohmann::json& j, krb5_authdata* authdata);
    [[nodiscard]] static bool deserialize_creds(const nlohmann::json& j, krb5_creds* creds, krb5_context ctx);
};
} // namespace octo::kerberos::krb5
#endif
