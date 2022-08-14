/**
 * @file krb5-kerberos-authenticator.cpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-14
 *
 * @copyright Copyright (c) 2022
 *
 */

#include "octo-kerberos-cpp/krb5/krb5-kerberos-authenticator.hpp"
#include "octo-kerberos-cpp/krb5/krb5-kerberos-tgt-ticket.hpp"
#include "octo-kerberos-cpp/krb5/krb5-kerberos-service-ticket.hpp"
#include <netdb.h>
#include <cstdlib>
#include <netinet/in.h>
#include <stdexcept>
#include <unistd.h>

namespace octo::kerberos::krb5
{
bool KRB5KerberosAuthenticator::create_streamlined_kdc_connection()
{
    logger_.info(settings_.session_id).formatted("Creating streamlined kdc connection");
    auto const port_str(std::to_string(settings_.kdc_port));
    struct addrinfo *ap, aihints{}, *apstart;
    int aierr;
    std::memset(&aihints, 0, sizeof(aihints));
    aihints.ai_socktype = SOCK_STREAM;
    aihints.ai_flags = AI_ADDRCONFIG;
    aierr = getaddrinfo(settings_.kdc_host.c_str(), port_str.c_str(), &aihints, &ap);
    if (aierr)
    {
        logger_.warning(settings_.session_id)
            .formatted("Failed running getaddrinfo to resolve ip / port [{}] [{}]", aierr, gai_strerror(aierr));
        return false;
    }
    if (!ap)
    {
        logger_.warning(settings_.session_id).formatted("Failed resolving ip / port using getaddrinfo");
        return false;
    }
    apstart = ap;
    for (kdc_fd_ = -1; ap && kdc_fd_ == -1; ap = ap->ai_next)
    {
        kdc_fd_ = socket(ap->ai_family, SOCK_STREAM, 0);
        if (kdc_fd_ < 0)
        {
            continue;
        }
        if (connect(kdc_fd_, ap->ai_addr, ap->ai_addrlen) < 0)
        {
            close(kdc_fd_);
            kdc_fd_ = -1;
            continue;
        }
    }
    if (kdc_fd_ == -1)
    {
        logger_.warning(settings_.session_id)
            .formatted("Failed to connect to host [{}] on port [{}]", settings_.kdc_host, settings_.kdc_port);
        freeaddrinfo(apstart);
        return false;
    }
    freeaddrinfo(apstart);
    logger_.info(settings_.session_id).formatted("Streamlined connected successfully to host [{}] on port [{}]",
                                                 settings_.kdc_host, settings_.kdc_port);
    return true;
}

void KRB5KerberosAuthenticator::close_streamlined_kdc_connection()
{
    if (kdc_fd_ != -1)
    {
        close(kdc_fd_);
        kdc_fd_ = -1;
    }
    logger_.info(settings_.session_id).formatted("Streamlined disconnected successfully");
}

int KRB5KerberosAuthenticator::kdc_net_read(char* buf, int len)
{
    int ret, bytes_read = 0;
    do
    {
        ret = ::read(kdc_fd_, buf, len);
        if (ret == 0)
        {
            return bytes_read;
        }
        if (ret < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            return ret;
        }
        buf += ret;
        bytes_read += ret;
        len -= ret;
    } while (len > 0);
    return bytes_read;
}

int KRB5KerberosAuthenticator::kdc_net_write(char* buf, int len)
{
    const char* buffer = static_cast<const char*>(buf);
    size_t bytes_written = 0;
    while (bytes_written < len)
    {
        ssize_t nbytes = ::write(kdc_fd_, buffer, len - bytes_written);
        if (nbytes == 0)
        {
            return -1;
        }
        if (nbytes == -1 && errno != EINTR)
        {
            return -1;
        }
        bytes_written += static_cast<size_t>(nbytes);
        buffer += nbytes;
    }
    return len;
}

krb5_error_code KRB5KerberosAuthenticator::kdc_read(krb5_data* inbuf)
{
    krb5_int32 len;
    int len2, ilen;
    char *buf = nullptr;

    std::memset(reinterpret_cast<void*>(inbuf), 0, sizeof(krb5_data));
    inbuf->magic = KV5M_DATA;
    if ((len2 = kdc_net_read(reinterpret_cast<char *>(&len), sizeof(krb5_int32))) != sizeof(krb5_int32))
    {
        return (len2 < 0) ? errno : ECONNABORTED;
    }
    len = ntohl(len);

    if ((len & VALID_UINT_BITS) != (krb5_ui_4)len)
    {
        return ENOMEM;
    }

    ilen = (int)len;
    if (ilen)
    {
        if (!(buf = static_cast<char*>(malloc(ilen))))
        {
            return (ENOMEM);
        }
        if ((len2 = kdc_net_read(buf, ilen)) != ilen)
        {
            free(buf);
            return len2 < 0 ? errno : ECONNABORTED;
        }
    }
    inbuf->data = buf;
    inbuf->length = ilen;
    return 0;
}

krb5_error_code KRB5KerberosAuthenticator::kdc_write(krb5_data* outbuf)
{
    auto len = htonl(outbuf->length);
    auto bytes_written = kdc_net_write(reinterpret_cast<char*>(&len), sizeof(unsigned int));
    if (bytes_written != sizeof(unsigned int))
    {
        return bytes_written < 0 ? errno : ECONNABORTED;
    }
    bytes_written = kdc_net_write(outbuf->data, outbuf->length);
    if (bytes_written != outbuf->length)
    {
        return bytes_written < 0 ? errno : ECONNABORTED;
    }
    return 0;
}

bool KRB5KerberosAuthenticator::convert_to_krb_address(const std::string& host, int port, krb5_address** outaddr)
{
    // Convert the host to netaddr format
    auto hostinfo = gethostbyname(host.c_str());
    if (!hostinfo || hostinfo->h_length == 0)
    {
        return false;
    }
    auto info = reinterpret_cast<struct in_addr*>(hostinfo->h_addr_list[0]);

    auto smushaddr = static_cast<unsigned long>(info->s_addr);
    auto smushport = static_cast<unsigned short>(port);
    krb5_address* retaddr;
    krb5_octet* marshal;
    krb5_addrtype temptype;
    krb5_int32 templength;

    if (!(retaddr = static_cast<krb5_address*>(malloc(sizeof(*retaddr)))))
    {
        return ENOMEM;
    }
    retaddr->magic = KV5M_ADDRESS;
    retaddr->addrtype = ADDRTYPE_ADDRPORT;
    retaddr->length = sizeof(smushaddr) + sizeof(smushport) + 2 * sizeof(temptype) + 2 * sizeof(templength);

    if (!(retaddr->contents = static_cast<krb5_octet*>(malloc(retaddr->length))))
    {
        free(retaddr);
        return ENOMEM;
    }
    marshal = retaddr->contents;

    temptype = htons(ADDRTYPE_INET);
    memcpy(marshal, &temptype, sizeof(temptype));
    marshal += sizeof(temptype);

    templength = htonl(sizeof(smushaddr));
    memcpy(marshal, &templength, sizeof(templength));
    marshal += sizeof(templength);

    memcpy(marshal, &smushaddr, sizeof(smushaddr));
    marshal += sizeof(smushaddr);

    temptype = htons(ADDRTYPE_IPPORT);
    memcpy(marshal, &temptype, sizeof(temptype));
    marshal += sizeof(temptype);

    templength = htonl(sizeof(smushport));
    memcpy(marshal, &templength, sizeof(templength));
    marshal += sizeof(templength);

    memcpy(marshal, &smushport, sizeof(smushport));
    marshal += sizeof(smushport);

    *outaddr = retaddr;
    return true;
}

krb5_get_init_creds_opt* KRB5KerberosAuthenticator::allocate_init_creds_options(std::chrono::seconds lifetime)
{
    krb5_get_init_creds_opt* options;
    auto ret = krb5_get_init_creds_opt_alloc(ctx_, &options);
    if (ret)
    {
        logger_.error(settings_.session_id)
            .formatted("Failed initializing krb5 init creds options [{}] [{}]", ret, krb5_get_error_message(ctx_, ret));
        return nullptr;
    }
    krb5_get_init_creds_opt_set_tkt_life(options, lifetime.count());
    krb5_get_init_creds_opt_set_renew_life(options, 0);
    krb5_get_init_creds_opt_set_forwardable(options, 0);
    krb5_get_init_creds_opt_set_proxiable(options, 0);
    krb5_get_init_creds_opt_set_out_ccache(ctx_, options, cache_);

    auto addr = static_cast<krb5_address**>(malloc(sizeof(krb5_address*) * 2));
    addr[1] = nullptr;
    if (!convert_to_krb_address(settings_.kdc_host, settings_.kdc_port, &addr[0]))
    {
        logger_.warning(settings_.session_id)
            .formatted("Failed converting [{}] to krb address, trying to continue without", settings_.kdc_host);
        free(addr);
    }
    else
    {
        krb5_get_init_creds_opt_set_address_list(options, addr);
    }
    return options;
}

KerberosTicketUniquePtr KRB5KerberosAuthenticator::generate_tgt_direct(const KerberosUserCredentials* const creds,
                                                                       std::chrono::seconds lifetime)
{
    krb5_principal client;
    logger_.info(settings_.session_id)
        .formatted("Generating KRB5 tgt for user [{}] with lifetime of [{}]", creds->username(), lifetime.count());

    auto options = allocate_init_creds_options(lifetime);
    if (!options)
    {
        logger_.error(settings_.session_id).formatted("Failed creating krb5 init creds options");
        return nullptr;
    }

    // Create the client principal
    auto ret = krb5_parse_name(ctx_, creds->username().c_str(), &client);
    if (ret)
    {
        logger_.error(settings_.session_id)
            .formatted("Failed initializing krb5 client principal [{}] [{}]", ret, krb5_get_error_message(ctx_, ret));
        krb5_get_init_creds_opt_free(ctx_, options);
        return nullptr;
    }

    auto ticket =
        std::make_unique<KRB5KerberosTGTTicket>(creds->username(), std::chrono::system_clock::now() + lifetime);
    ticket->ctx_ = ctx_;

    ret = krb5_get_init_creds_password(
        ctx_, &ticket->tgt_ticket_, client, creds->password().get().data(), nullptr, nullptr, 0, nullptr, options);
    if (ret)
    {
        logger_.error(settings_.session_id)
            .formatted(
                "Failed getting krb5 init creds with password [{}] [{}]", ret, krb5_get_error_message(ctx_, ret));
        krb5_get_init_creds_opt_free(ctx_, options);
        krb5_free_principal(ctx_, client);
        return nullptr;
    }
    krb5_get_init_creds_opt_free(ctx_, options);
    krb5_free_principal(ctx_, client);
    logger_.info(settings_.session_id).formatted("Successfully generated a tgt for user [{}]", creds->username());
    return ticket;
}

KerberosTicketUniquePtr KRB5KerberosAuthenticator::generate_tgt_streamlined(const KerberosUserCredentials* const creds,
                                                                            std::chrono::seconds lifetime)
{
    krb5_principal client;
    krb5_init_creds_context init_ctx;
    krb5_data step_response, step_request, step_realm;
    unsigned int flags_out;
    bool finished_steps = false;

    auto options = allocate_init_creds_options(lifetime);
    if (!options)
    {
        logger_.error(settings_.session_id).formatted("Failed creating krb5 init creds options");
        return nullptr;
    }

    // Create the client principal
    auto ret = krb5_parse_name(ctx_, creds->username().c_str(), &client);
    if (ret)
    {
        logger_.error(settings_.session_id)
            .formatted("Failed initializing krb5 client principal [{}] [{}]", ret, krb5_get_error_message(ctx_, ret));
        return nullptr;
    }
    ret = krb5_init_creds_init(ctx_, client, nullptr, nullptr, 0, options, &init_ctx);
    if (ret)
    {
        logger_.error(settings_.session_id)
            .formatted("Failed initializing krb5 init ctx [{}] [{}]", ret, krb5_get_error_message(ctx_, ret));
        return nullptr;
    }
    ret = krb5_init_creds_set_password(ctx_, init_ctx, creds->password().get().data());
    if (ret)
    {
        logger_.error(settings_.session_id)
            .formatted("Failed setting password for krb5 init ctx [{}] [{}]", ret, krb5_get_error_message(ctx_, ret));
        return nullptr;
    }
    std::memset(reinterpret_cast<void*>(&step_response), 0, sizeof(krb5_data));
    std::memset(reinterpret_cast<void*>(&step_request), 0, sizeof(krb5_data));
    std::memset(reinterpret_cast<void*>(&step_realm), 0, sizeof(krb5_data));
    step_request.magic = KV5M_DATA;
    step_response.magic = KV5M_DATA;
    step_realm.magic = KV5M_DATA;
    auto step = 0;
    while (true)
    {
        logger_.info(settings_.session_id).formatted("Running krb5 init cred step #{}", step + 1);
        ret = krb5_init_creds_step(ctx_, init_ctx, &step_response, &step_request, &step_realm, &flags_out);
        if (ret)
        {
            logger_.error(settings_.session_id)
                .formatted("Failed to run krb5 init creds step [{}] [{}]", ret, krb5_get_error_message(ctx_, ret));
            break;
        }
        if (!(flags_out & KRB5_INIT_CREDS_STEP_FLAG_CONTINUE))
        {
            logger_.info(settings_.session_id) << "Finished streamlined steps for tgt";
            finished_steps = true;
            break;
        }
        krb5_free_data_contents(ctx_, &step_response);
        ret = kdc_write(&step_request);
        if (ret)
        {
            logger_.error(settings_.session_id)
                .formatted("Failed to write krb5 init creds step [{}] [{}]", ret, krb5_get_error_message(ctx_, ret));
            break;
        }
        ret = kdc_read(&step_response);
        if (ret)
        {
            logger_.error(settings_.session_id)
                .formatted("Failed to read krb5 init creds step [{}] [{}]", ret, krb5_get_error_message(ctx_, ret));
            break;
        }
        krb5_free_data_contents(ctx_, &step_request);
        krb5_free_data_contents(ctx_, &step_realm);
        logger_.info(settings_.session_id).formatted("Finished running krb5 init cred step #{}", step + 1);
        ++step;
    }
    krb5_free_data_contents(ctx_, &step_response);
    krb5_free_data_contents(ctx_, &step_request);
    krb5_free_data_contents(ctx_, &step_realm);
    if (!finished_steps)
    {
        return nullptr;
    }
    auto ticket =
        std::make_unique<KRB5KerberosTGTTicket>(creds->username(), std::chrono::system_clock::now() + lifetime);
    ticket->ctx_ = ctx_;
    ret = krb5_init_creds_get_creds(ctx_, init_ctx, &ticket->tgt_ticket_);
    if (ret)
    {
        logger_.error(settings_.session_id)
            .formatted("Failed to get krb5 tgt creds [{}] [{}]", ret, krb5_get_error_message(ctx_, ret));
        krb5_init_creds_free(ctx_, init_ctx);
        return nullptr;
    }
    krb5_init_creds_free(ctx_, init_ctx);
    logger_.info(settings_.session_id).formatted("Successfully generated a tgt for user [{}]", creds->username());
    return ticket;
}

bool KRB5KerberosAuthenticator::prepare_tgt_for_st_generation(KRB5KerberosTGTTicket* const krb5_tgt,
                                                              const std::string& service,
                                                              std::chrono::seconds lifetime)
{
    // Set the tgt ticket client and server principals
    // Create the client principal
    auto ret = krb5_parse_name(ctx_, krb5_tgt->tgt_user().c_str(), &krb5_tgt->tgt_ticket_.client);
    if (ret)
    {
        logger_.error().formatted(
            "Failed initializing krb5 client principal [{}] [{}]", ret, krb5_get_error_message(ctx_, ret));
        return false;
    }

    // Create the server principal
    ret = krb5_parse_name(ctx_, service.c_str(), &krb5_tgt->tgt_ticket_.server);
    if (ret)
    {
        logger_.error().formatted(
            "Failed initializing krb5 server principal [{}] [{}]", ret, krb5_get_error_message(ctx_, ret));
        return false;
    }

    // Set the ticket expiration
    ret = krb5_timeofday(ctx_, &krb5_tgt->tgt_ticket_.times.endtime);
    if (ret)
    {
        logger_.error().formatted(
            "Failed initializing krb5 end time [{}] [{}]", ret, krb5_get_error_message(ctx_, ret));
        return false;
    }
    krb5_tgt->tgt_ticket_.times.endtime += lifetime.count();
    return true;
}

KerberosTicketUniquePtr KRB5KerberosAuthenticator::generate_service_ticket_direct(KRB5KerberosTGTTicket* const krb5_tgt,
                                                                                  const std::string& service,
                                                                                  std::chrono::seconds lifetime)
{
    logger_.info(settings_.session_id).formatted("Generating KRB5 service ticket for service [{}]", service);

    if (!prepare_tgt_for_st_generation(krb5_tgt, service, lifetime))
    {
        logger_.error(settings_.session_id).formatted("Failed preparing tgt ticket for service ticket generation");
        return nullptr;
    }

    // Get the service ticket
    auto ticket = std::make_unique<KRB5KerberosServiceTicket>(
        service,
        std::chrono::time_point<std::chrono::system_clock>(std::chrono::seconds(krb5_tgt->tgt_ticket_.times.endtime)));
    ticket->ctx_ = ctx_;

    auto ret = krb5_get_credentials(ctx_, 0, cache_, &krb5_tgt->tgt_ticket_, &ticket->service_ticket_);
    if (ret)
    {
        logger_.error().formatted(
            "Failed getting credentials service ticket [{}] [{}]", ret, krb5_get_error_message(ctx_, ret));
        return nullptr;
    }
    logger_.info(settings_.session_id)
        .formatted("Successfully generated a KRB5 service ticket for service [{}]", service);
    return ticket;
}

KerberosTicketUniquePtr KRB5KerberosAuthenticator::generate_service_ticket_streamlined(
    KRB5KerberosTGTTicket* const krb5_tgt, const std::string& service, std::chrono::seconds lifetime)
{
    krb5_tkt_creds_context tkt_ctx;
    krb5_data step_response, step_request, step_realm;
    unsigned int flags_out;
    bool finished_steps = false;

    logger_.info(settings_.session_id).formatted("Generating KRB5 service ticket for service [{}]", service);

    if (!prepare_tgt_for_st_generation(krb5_tgt, service, lifetime))
    {
        logger_.error(settings_.session_id).formatted("Failed preparing tgt ticket for service ticket generation");
        return nullptr;
    }

    auto ret = krb5_tkt_creds_init(ctx_, cache_, &krb5_tgt->tgt_ticket_, 0, &tkt_ctx);
    if (ret)
    {
        logger_.error(settings_.session_id)
            .formatted("Failed preparing krb5 tkt creds init [{}] [{}]", ret, krb5_get_error_message(ctx_, ret));
        return nullptr;
    }
    std::memset(reinterpret_cast<void*>(&step_response), 0, sizeof(krb5_data));
    std::memset(reinterpret_cast<void*>(&step_request), 0, sizeof(krb5_data));
    std::memset(reinterpret_cast<void*>(&step_realm), 0, sizeof(krb5_data));
    step_request.magic = KV5M_DATA;
    step_response.magic = KV5M_DATA;
    step_realm.magic = KV5M_DATA;
    auto step = 0;
    while (true)
    {
        logger_.info(settings_.session_id).formatted("Running krb5 tkt cred step #{}", step + 1);
        ret = krb5_tkt_creds_step(ctx_, tkt_ctx, &step_response, &step_request, &step_realm, &flags_out);
        if (ret)
        {
            logger_.error(settings_.session_id)
                .formatted("Failed to run krb5 tkt creds step [{}] [{}]", ret, krb5_get_error_message(ctx_, ret));
            break;
        }
        if (!(flags_out & KRB5_INIT_CREDS_STEP_FLAG_CONTINUE))
        {
            logger_.info(settings_.session_id) << "Finished streamlined steps for service ticket";
            finished_steps = true;
            break;
        }
        krb5_free_data_contents(ctx_, &step_response);
        ret = kdc_write(&step_request);
        if (ret)
        {
            logger_.error(settings_.session_id)
                .formatted("Failed to write krb5 tkt creds step [{}] [{}]", ret, krb5_get_error_message(ctx_, ret));
            break;
        }
        ret = kdc_read(&step_response);
        if (ret)
        {
            logger_.error(settings_.session_id)
                .formatted("Failed to read krb5 tkt creds step [{}] [{}]", ret, krb5_get_error_message(ctx_, ret));
            break;
        }
        krb5_free_data_contents(ctx_, &step_request);
        krb5_free_data_contents(ctx_, &step_realm);
        logger_.info(settings_.session_id).formatted("Finished running krb5 tkt cred step #{}", step + 1);
        ++step;
    }
    krb5_free_data_contents(ctx_, &step_response);
    krb5_free_data_contents(ctx_, &step_request);
    krb5_free_data_contents(ctx_, &step_realm);
    if (!finished_steps)
    {
        return nullptr;
    }
    // Get the service ticket
    auto ticket = std::make_unique<KRB5KerberosServiceTicket>(
        service,
        std::chrono::time_point<std::chrono::system_clock>(std::chrono::seconds(krb5_tgt->tgt_ticket_.times.endtime)));
    ticket->ctx_ = ctx_;
    ticket->service_ticket_ = static_cast<krb5_creds*>(calloc(1, sizeof(krb5_creds)));

    ret = krb5_tkt_creds_get_creds(ctx_, tkt_ctx, ticket->service_ticket_);
    if (ret)
    {
        logger_.error(settings_.session_id)
            .formatted("Failed to get krb5 service ticket creds [{}] [{}]", ret, krb5_get_error_message(ctx_, ret));
        krb5_tkt_creds_free(ctx_, tkt_ctx);
        return nullptr;
    }
    krb5_tkt_creds_free(ctx_, tkt_ctx);
    logger_.info(settings_.session_id)
        .formatted("Successfully generated a KRB5 service ticket for service [{}]", service);
    return ticket;
}

KRB5KerberosAuthenticator::KRB5KerberosAuthenticator(KRB5KerberosAuthenticator::Settings settings)
    : settings_(std::move(settings)),
      ctx_(nullptr),
      cache_(nullptr),
      server_(nullptr),
      is_initialized_(false),
      logger_("KRB5KerberosAuthenticator"),
      profile_vtable_(nullptr),
      kdc_fd_(-1)
{
    if (settings_.realm.empty())
    {
        throw std::runtime_error("Realm must be supplied for kerberos authentication");
    }
    if (settings_.kdc_host.empty())
    {
        // Fallback to using the realm as KDC host resolving
        settings_.kdc_host = settings_.realm;
    }
    logger_.info(settings_.session_id)
        .formatted("Working with kdc host [{}], kdc port [{}] and realm [{}] as krb configurations",
                   settings_.kdc_host,
                   settings_.kdc_port,
                   settings_.realm);
}

KRB5KerberosAuthenticator::~KRB5KerberosAuthenticator()
{
    if (is_initialized_)
    {
        if (!cleanup_authenticator())
        {
            logger_.warning(settings_.session_id) << "Failed to cleanup krb5 authenticator";
        }
    }
}

bool KRB5KerberosAuthenticator::initialize_authenticator()
{
    // Create a profile with callbacks
    logger_.info(settings_.session_id) << "Initializing KRB5 authenticator";
    profile_vtable_ = static_cast<struct profile_vtable*>(calloc(1, sizeof(struct profile_vtable)));
    profile_vtable_->minor_ver = 1;
    profile_vtable_->get_values = +[](void* cbdata, const char* const* names, char*** ret_values) -> long {
        auto authenticator = static_cast<KRB5KerberosAuthenticator*>(cbdata);
        return authenticator->get_profile_values(names, ret_values);
    };
    profile_vtable_->free_values = +[](void* cbdata, char** values) -> void {
        auto authenticator = static_cast<KRB5KerberosAuthenticator*>(cbdata);
        authenticator->free_profile_values(values);
    };
    profile_vtable_->copy = +[](void* cbdata, void** ret_cbdata) -> long {
        *ret_cbdata = cbdata;
        return 0;
    };
    profile_vtable_->cleanup = +[](void* cbdata) -> void {
        auto authenticator = static_cast<KRB5KerberosAuthenticator*>(cbdata);
        authenticator->cleanup_profile();
    };
    auto ret = profile_init_vtable(profile_vtable_, this, &profile_);
    if (ret)
    {
        logger_.error().formatted("Failed initializing krb5 profile [{}]", ret);
        return false;
    }

    // Create context
    ret = krb5_init_context_profile(profile_, KRB5_INIT_CONTEXT_SECURE | KRB5_INIT_CONTEXT_KDC, &ctx_);
    if (ret)
    {
        logger_.error().formatted("Failed initializing krb5 context [{}]", ret);
        return false;
    }
    logger_.info(settings_.session_id).formatted("Setting default realm to [{}]", settings_.realm);
    // Set default realm
    ret = krb5_set_default_realm(ctx_, settings_.realm.c_str());
    if (ret)
    {
        logger_.error().formatted(
            "Failed setting krb5 default realm [{}] [{}]", ret, krb5_get_error_message(ctx_, ret));
        return false;
    }
    // Parse principals
    ret = krb5_sname_to_principal(ctx_, settings_.kdc_host.c_str(), "host", KRB5_NT_SRV_HST, &server_);
    if (ret)
    {
        logger_.error().formatted(
            "Failed parsing krb5 server principal [{}] [{}]", ret, krb5_get_error_message(ctx_, ret));
        return false;
    }
    // Create cache inmemory
    logger_.info(settings_.session_id) << "Creating inmemory krb5 cache";
    ret = krb5_cc_new_unique(ctx_, "MEMORY", nullptr, &cache_);
    if (ret)
    {
        logger_.error().formatted("Failed creating new krb5 cache [{}] [{}]", ret, krb5_get_error_message(ctx_, ret));
        return false;
    }
    ret = krb5_cc_initialize(ctx_, cache_, server_);
    if (ret)
    {
        logger_.error().formatted("Failed initializing krb5 cache [{}] [{}]", ret, krb5_get_error_message(ctx_, ret));
        return false;
    }
    if (settings_.streamlined && !create_streamlined_kdc_connection())
    {
        logger_.error().formatted("Failed initializing streamlined connection");
        return false;
    }
    is_initialized_ = true;
    logger_.info(settings_.session_id) << "Finished initializing KRB5 authenticator";
    return true;
}

bool KRB5KerberosAuthenticator::cleanup_authenticator()
{
    if (is_initialized_)
    {
        logger_.info(settings_.session_id) << "Cleaning KRB5 authenticator";
        // Cleanup principals
        krb5_free_principal(ctx_, server_);

        // Cleanup cache
        krb5_cc_destroy(ctx_, cache_);

        // Cleanup context
        krb5_free_context(ctx_);

        // Close streamlined connection
        if (settings_.streamlined)
        {
            close_streamlined_kdc_connection();
        }
        is_initialized_ = false;
    }
    logger_.info(settings_.session_id) << "Finished cleaning KRB5 authenticator";
    return true;
}

bool KRB5KerberosAuthenticator::is_initialized() const
{
    return is_initialized_;
}

bool KRB5KerberosAuthenticator::is_streamlined() const
{
    return settings_.streamlined;
}

KerberosTicketUniquePtr KRB5KerberosAuthenticator::generate_tgt(const KerberosUserCredentials* const creds,
                                                                std::chrono::seconds lifetime)
{
    if (!is_initialized_)
    {
        logger_.warning(settings_.session_id) << "Cannot generate TGT when authenticator is not initialized";
        return nullptr;
    }
    if (settings_.streamlined)
    {
        return generate_tgt_streamlined(creds, lifetime);
    }
    return generate_tgt_direct(creds, lifetime);
}

KerberosTicketUniquePtr KRB5KerberosAuthenticator::deserialize_tgt(const nlohmann::json& json)
{
    if (!is_initialized_)
    {
        logger_.warning(settings_.session_id) << "Cannot deserialize TGT when authenticator is not initialized";
        return nullptr;
    }
    auto ticket = std::make_unique<KRB5KerberosTGTTicket>();
    ticket->ctx_ = ctx_;
    if (!ticket->deserialize(json))
    {
        logger_.warning(settings_.session_id) << "Failed to deserialize tgt";
        return nullptr;
    }
    return ticket;
}

KerberosTicketUniquePtr KRB5KerberosAuthenticator::generate_service_ticket(KerberosTicket* const tgt,
                                                                           const std::string& service,
                                                                           std::chrono::seconds lifetime)
{
    if (!is_initialized_)
    {
        logger_.warning(settings_.session_id) << "Cannot generate service token when authenticator is not initialized";
        return nullptr;
    }
    if (tgt->ticket_type() != KerberosTicket::Type::TicketGrantingTicket)
    {
        logger_.error(settings_.session_id) << "Cannot generate a service ticket using a non-tgt ticket";
        return nullptr;
    }
    auto const krb5_tgt = dynamic_cast<KRB5KerberosTGTTicket* const>(tgt);
    if (settings_.streamlined)
    {
        return generate_service_ticket_streamlined(krb5_tgt, service, lifetime);
    }
    return generate_service_ticket_direct(krb5_tgt, service, lifetime);
}

KerberosTicketUniquePtr KRB5KerberosAuthenticator::deserialize_service_ticket(const nlohmann::json& json)
{
    if (!is_initialized_)
    {
        logger_.warning(settings_.session_id)
            << "Cannot deserialize service ticket when authenticator is not initialized";
        return nullptr;
    }
    auto ticket = std::make_unique<KRB5KerberosServiceTicket>();
    ticket->ctx_ = ctx_;
    if (!ticket->deserialize(json))
    {
        logger_.warning(settings_.session_id) << "Failed to deserialize service ticket";
        return nullptr;
    }
    return ticket;
}

long KRB5KerberosAuthenticator::get_profile_values(const char* const* names, char*** ret_values)
{
    auto curr_name = names;
    std::vector<std::string> values;
    while (*curr_name)
    {
        const auto curr_name_str = std::string(*curr_name);
        if (curr_name_str == "realms")
        {
            const auto realm_name = std::string(*(++curr_name));
            if (realm_name == settings_.realm)
            {
                // Realm specific params
                const auto param_name = std::string(*(++curr_name));
                if (param_name == "kdc" || param_name == "primary_kdc" || param_name == "admin_server"
                    || param_name == "default_domain")
                {
                    logger_.info(settings_.session_id)
                        .formatted("Setting kdc param [{}] to value [{}:{}]",
                                   param_name,
                                   settings_.kdc_host,
                                   settings_.kdc_port);
                    values.push_back(fmt::format("{}:{}", settings_.kdc_host, settings_.kdc_port));
                }
            }
        }
        else if (curr_name_str == "domain_realm")
        {
            const auto domain_name = std::string(*(++curr_name));
            if (domain_name.find(settings_.kdc_host) != std::string::npos)
            {
                logger_.info(settings_.session_id).formatted("Setting domain realm to value [{}:{}]", settings_.realm);
                values.push_back(settings_.realm);
            }
        }
        else if (curr_name_str == "libdefaults")
        {
            const auto property_name = std::string(*(++curr_name));
            if (property_name == "dns_lookup_realm")
            {
                values.emplace_back("true");
            }
            else if (property_name == "dns_lookup_kdc")
            {
                values.emplace_back("true");
            }
            else if (property_name == "dns_fallback")
            {
                values.emplace_back("yes");
            }
            else if (property_name == "udp_preference_limit")
            {
                values.emplace_back("1");
            }
            else if (property_name == "dns_canonicalize_hostname")
            {
                values.emplace_back("true");
            }
            else if (property_name == "rdns")
            {
                values.emplace_back("true");
            }
        }
        ++curr_name;
    }
    if (values.empty())
    {
        return PROF_NO_RELATION;
    }
    *ret_values = static_cast<char**>(malloc((1 + values.size()) * sizeof(char*)));
    for (size_t i = 0; i < values.size(); ++i)
    {
        (*ret_values)[i] = strdup(values[i].c_str());
    }
    (*ret_values)[values.size()] = nullptr;
    return 0;
}

void KRB5KerberosAuthenticator::free_profile_values(char** values)
{
    for (char** v = values; *v; ++v)
    {
        free(*v);
    }
    free(values);
}

void KRB5KerberosAuthenticator::cleanup_profile()
{
    // Nothing to do here
}
} // namespace octo::kerberos::krb5
