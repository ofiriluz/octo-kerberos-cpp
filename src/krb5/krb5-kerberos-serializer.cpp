/**
 * @file krb5-kerberos-serializer.cpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-14
 *
 * @copyright Copyright (c) 2022
 *
 */

#include "octo-kerberos-cpp/krb5/krb5-kerberos-serializer.hpp"
#include <octo-encryption-cpp/base64.hpp>
#include <vector>

#define SAFE_FREE(X)                                                                                                   \
    free(X);                                                                                                           \
    (X) = nullptr

namespace octo::kerberos::krb5
{
nlohmann::json KRB5KerberosSerializer::serialize_principal_data(const krb5_principal_data& principal_data)
{
    nlohmann::json client;
    client["magic"] = principal_data.magic;
    client["realm"] = KRB5KerberosSerializer::serialize_data(principal_data.realm);
    if (principal_data.data && principal_data.length > 0)
    {
        client["data"] = nlohmann::json::array();
        for (auto i = 0; i < principal_data.length; ++i)
        {
            client["data"].push_back(KRB5KerberosSerializer::serialize_data(principal_data.data[i]));
        }
    }
    client["length"] = principal_data.length;
    client["type"] = principal_data.type;
    return client;
}

nlohmann::json KRB5KerberosSerializer::serialize_data(const krb5_data& data)
{
    nlohmann::json j_data;
    j_data["magic"] = data.magic;
    j_data["length"] = data.length;
    j_data["data"] = encryption::Base64::base64_encode(std::string(data.data, data.length));
    return j_data;
}

nlohmann::json KRB5KerberosSerializer::serialize_keyblock(const krb5_keyblock& keyblock)
{
    nlohmann::json j_keyblock;
    j_keyblock["magic"] = keyblock.magic;
    j_keyblock["enctype"] = keyblock.enctype;
    j_keyblock["length"] = keyblock.length;
    j_keyblock["contents"] =
        encryption::Base64::base64_encode(std::string(reinterpret_cast<char*>(keyblock.contents), keyblock.length));
    return j_keyblock;
}

nlohmann::json KRB5KerberosSerializer::serialize_times(const krb5_ticket_times& times)
{
    nlohmann::json j_times;
    j_times["authtime"] = times.authtime;
    j_times["starttime"] = times.starttime;
    j_times["endtime"] = times.endtime;
    j_times["renew_till"] = times.renew_till;
    return j_times;
}

nlohmann::json KRB5KerberosSerializer::serialize_address(const krb5_address& address)
{
    nlohmann::json j_address;
    j_address["magic"] = address.magic;
    j_address["addrtype"] = address.addrtype;
    j_address["length"] = address.length;
    j_address["contents"] =
        encryption::Base64::base64_encode(std::string(reinterpret_cast<char*>(address.contents), address.length));
    return j_address;
}

nlohmann::json KRB5KerberosSerializer::serialize_authdata(const krb5_authdata& authdata)
{
    nlohmann::json j_authdata;
    j_authdata["magic"] = authdata.magic;
    j_authdata["ad_type"] = authdata.ad_type;
    j_authdata["length"] = authdata.length;
    j_authdata["contents"] =
        encryption::Base64::base64_encode(std::string(reinterpret_cast<char*>(authdata.contents), authdata.length));
    return j_authdata;
}

nlohmann::json KRB5KerberosSerializer::serialize_creds(const krb5_creds& creds)
{
    nlohmann::json j;
    j["magic"] = creds.magic;
    if (creds.client)
    {
        j["client"] = KRB5KerberosSerializer::serialize_principal_data(*creds.client);
    }
    if (creds.server)
    {
        j["server"] = KRB5KerberosSerializer::serialize_principal_data(*creds.server);
    }
    j["keyblock"] = KRB5KerberosSerializer::serialize_keyblock(creds.keyblock);
    j["times"] = KRB5KerberosSerializer::serialize_times(creds.times);
    j["is_skey"] = creds.is_skey;
    j["ticket_flags"] = creds.ticket_flags;
    if (creds.addresses)
    {
        j["addresses"] = nlohmann::json::array();
        krb5_address** curr_addr = creds.addresses;
        while (*curr_addr)
        {
            j["addresses"].push_back(KRB5KerberosSerializer::serialize_address(**curr_addr));
            ++curr_addr;
        }
    }
    j["ticket"] = KRB5KerberosSerializer::serialize_data(creds.ticket);
    j["second_ticket"] = KRB5KerberosSerializer::serialize_data(creds.second_ticket);
    if (creds.authdata)
    {
        j["authdata"] = nlohmann::json::array();
        krb5_authdata** curr_authdata = creds.authdata;
        while (*curr_authdata)
        {
            j["authdata"].push_back(KRB5KerberosSerializer::serialize_authdata(**curr_authdata));
            ++curr_authdata;
        }
    }
    return j;
}

bool KRB5KerberosSerializer::deserialize_principal_data(const nlohmann::json& j, krb5_principal_data* principal_data)
{
    if (!principal_data || !j.contains("magic") || !j.contains("realm") || !j.contains("type"))
    {
        return false;
    }
    principal_data->magic = j["magic"];
    if (!KRB5KerberosSerializer::deserialize_data(j["realm"], &principal_data->realm))
    {
        return false;
    }
    if (principal_data->data && principal_data->length > 0)
    {
        for (auto i = 0; i < principal_data->length; ++i)
        {
            if (principal_data->data[i].data && principal_data->data[i].length > 0)
            {
                std::memset(reinterpret_cast<void*>(principal_data->data[i].data), 0, principal_data->data[i].length);
                SAFE_FREE(principal_data->data[i].data);
            }
        }
        SAFE_FREE(principal_data->data);
    }
    principal_data->data = nullptr;
    principal_data->length = 0;
    if (j.contains("data") && j.contains("length"))
    {
        std::vector<nlohmann::json> j_data = j["data"];
        principal_data->length = j["length"];
        principal_data->data = reinterpret_cast<krb5_data*>(calloc(principal_data->length, sizeof(krb5_data)));
        for (auto i = 0; i < principal_data->length; ++i)
        {
            if (!KRB5KerberosSerializer::deserialize_data(j_data[i], &principal_data->data[i]))
            {
                SAFE_FREE(principal_data->data);
                return false;
            }
        }
    }
    principal_data->type = j["type"];
    return true;
}

bool KRB5KerberosSerializer::deserialize_data(const nlohmann::json& j, krb5_data* data)
{
    if (!data || !j.contains("magic") || !j.contains("length") || !j.contains("data"))
    {
        return false;
    }
    if (data->data && data->length > 0)
    {
        std::memset(reinterpret_cast<void*>(data->data), 0, data->length);
        SAFE_FREE(data->data);
    }
    data->magic = j["magic"];
    data->length = j["length"];
    const auto decoded = encryption::Base64::base64_decode(j["data"].get<std::string>());
    data->data = reinterpret_cast<char*>(calloc(decoded.size(), sizeof(char)));
    std::memcpy(data->data, decoded.c_str(), decoded.size());
    return true;
}

bool KRB5KerberosSerializer::deserialize_keyblock(const nlohmann::json& j, krb5_keyblock* keyblock)
{
    if (!keyblock || !j.contains("magic") || !j.contains("enctype") || !j.contains("length") || !j.contains("contents"))
    {
        return false;
    }
    if (keyblock->contents && keyblock->length > 0)
    {
        std::memset(reinterpret_cast<void*>(keyblock->contents), 0, keyblock->length);
        SAFE_FREE(keyblock->contents);
    }
    keyblock->magic = j["magic"];
    keyblock->enctype = j["enctype"];
    keyblock->length = j["length"];
    const auto decoded = encryption::Base64::base64_decode(j["contents"].get<std::string>());
    keyblock->contents = reinterpret_cast<krb5_octet*>(calloc(decoded.size(), sizeof(krb5_octet)));
    std::memcpy(keyblock->contents, decoded.c_str(), decoded.size());
    return true;
}

bool KRB5KerberosSerializer::deserialize_times(const nlohmann::json& j, krb5_ticket_times* times)
{
    if (!times || !j.contains("authtime") || !j.contains("starttime") || !j.contains("endtime")
        || !j.contains("renew_till"))
    {
        return false;
    }
    times->authtime = j["authtime"];
    times->starttime = j["starttime"];
    times->endtime = j["endtime"];
    times->renew_till = j["renew_till"];
    return true;
}

bool KRB5KerberosSerializer::deserialize_address(const nlohmann::json& j, krb5_address* address)
{
    if (!address || !j.contains("magic") || !j.contains("addrtype") || !j.contains("length") || !j.contains("contents"))
    {
        return false;
    }
    if (address->contents && address->length > 0)
    {
        std::memset(reinterpret_cast<void*>(address->contents), 0, address->length);
        SAFE_FREE(address->contents);
    }
    address->magic = j["magic"];
    address->addrtype = j["addrtype"];
    address->length = j["length"];
    const auto decoded = encryption::Base64::base64_decode(j["contents"].get<std::string>());
    address->contents = reinterpret_cast<krb5_octet*>(calloc(decoded.size(), sizeof(krb5_octet)));
    std::memcpy(address->contents, decoded.c_str(), decoded.size());
    return true;
}

bool KRB5KerberosSerializer::deserialize_authdata(const nlohmann::json& j, krb5_authdata* authdata)
{
    if (!authdata || !j.contains("magic") || !j.contains("ad_type") || !j.contains("length") || !j.contains("contents"))
    {
        return false;
    }
    if (authdata->contents && authdata->length > 0)
    {
        std::memset(reinterpret_cast<void*>(authdata->contents), 0, authdata->length);
        SAFE_FREE(authdata->contents);
    }
    authdata->magic = j["magic"];
    authdata->ad_type = j["ad_type"];
    authdata->length = j["length"];
    const auto decoded = encryption::Base64::base64_decode(j["contents"].get<std::string>());
    authdata->contents = reinterpret_cast<krb5_octet*>(calloc(decoded.size(), sizeof(krb5_octet)));
    std::memcpy(authdata->contents, decoded.c_str(), decoded.size());
    return true;
}

void KRB5KerberosSerializer::cleanup_creds(krb5_creds* creds)
{
    if (creds->client)
    {
        SAFE_FREE(creds->client->data);
        SAFE_FREE(creds->client);
    }
    if (creds->server)
    {
        SAFE_FREE(creds->server->data);
        SAFE_FREE(creds->server);
    }
    if (creds->keyblock.contents)
    {
        SAFE_FREE(creds->keyblock.contents);
    }
    if (creds->addresses)
    {
        auto curr_addr = creds->addresses;
        while (*curr_addr)
        {
            SAFE_FREE(*curr_addr);
            ++curr_addr;
        }
        SAFE_FREE(creds->addresses);
    }
    if (creds->ticket.data)
    {
        SAFE_FREE(creds->ticket.data);
    }
    if (creds->second_ticket.data)
    {
        SAFE_FREE(creds->second_ticket.data);
    }
    if (creds->authdata)
    {
        auto curr_authdata = creds->authdata;
        while (*curr_authdata)
        {
            SAFE_FREE(*curr_authdata);
            ++curr_authdata;
        }
        SAFE_FREE(creds->authdata);
    }
}

bool KRB5KerberosSerializer::deserialize_creds(const nlohmann::json& j, krb5_creds* creds, krb5_context ctx)
{
    if (!creds || !j.contains("magic") || !j.contains("keyblock") || !j.contains("times") || !j.contains("is_skey")
        || !j.contains("ticket_flags") || !j.contains("ticket") || !j.contains("second_ticket"))
    {
        return false;
    }
    creds->magic = j["magic"];
    if (creds->client)
    {
        krb5_free_principal(ctx, creds->client);
    }
    creds->client = nullptr;
    if (j.contains("client"))
    {
        creds->client = reinterpret_cast<krb5_principal_data*>(calloc(1, sizeof(krb5_principal_data)));
        if (!KRB5KerberosSerializer::deserialize_principal_data(j["client"], creds->client))
        {
            cleanup_creds(creds);
            return false;
        }
    }
    if (creds->server)
    {
        krb5_free_principal(ctx, creds->server);
    }
    creds->server = nullptr;
    if (j.contains("server"))
    {
        creds->server = reinterpret_cast<krb5_principal_data*>(calloc(1, sizeof(krb5_principal_data)));
        if (!KRB5KerberosSerializer::deserialize_principal_data(j["server"], creds->server))
        {
            cleanup_creds(creds);
            return false;
        }
    }
    if (!KRB5KerberosSerializer::deserialize_keyblock(j["keyblock"], &creds->keyblock))
    {
        cleanup_creds(creds);
        return false;
    }
    if (!KRB5KerberosSerializer::deserialize_times(j["times"], &creds->times))
    {
        cleanup_creds(creds);
        return false;
    }
    creds->is_skey = j["is_skey"];
    creds->ticket_flags = j["ticket_flags"];
    if (creds->addresses)
    {
        krb5_free_addresses(ctx, creds->addresses);
    }
    creds->addresses = nullptr;
    if (j.contains("addresses"))
    {
        const std::vector<nlohmann::json> j_addresses = j["addresses"];
        creds->addresses = reinterpret_cast<krb5_address**>(calloc(j_addresses.size() + 1, sizeof(krb5_address*)));
        creds->addresses[j_addresses.size()] = nullptr;
        for (auto i = 0; i < j_addresses.size(); ++i)
        {
            creds->addresses[i] = reinterpret_cast<krb5_address*>(calloc(1, sizeof(krb5_address)));
            if (!KRB5KerberosSerializer::deserialize_address(j_addresses[i], creds->addresses[i]))
            {
                cleanup_creds(creds);
                return false;
            }
        }
    }
    if (!KRB5KerberosSerializer::deserialize_data(j["ticket"], &creds->ticket)
        || !KRB5KerberosSerializer::deserialize_data(j["second_ticket"], &creds->second_ticket))
    {
        cleanup_creds(creds);
        return false;
    }
    if (creds->authdata)
    {
        krb5_free_authdata(ctx, creds->authdata);
    }
    creds->authdata = nullptr;
    if (j.contains("authdata"))
    {
        const std::vector<nlohmann::json> j_authdata = j["authdata"];
        creds->authdata = reinterpret_cast<krb5_authdata**>(calloc(j_authdata.size() + 1, sizeof(krb5_authdata*)));
        creds->authdata[j_authdata.size()] = nullptr;
        for (auto i = 0; i < j_authdata.size(); ++i)
        {
            creds->authdata[i] = reinterpret_cast<krb5_authdata*>(calloc(1, sizeof(krb5_authdata)));
            if (!KRB5KerberosSerializer::deserialize_authdata(j_authdata[i], creds->authdata[i]))
            {
                cleanup_creds(creds);
                return false;
            }
        }
    }
    return true;
}
} // namespace octo::kerberos::krb5
