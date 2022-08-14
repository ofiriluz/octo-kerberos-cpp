/**
 * @file tct_example.cpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-14
 *
 * @copyright Copyright (c) 2022
 *
 */

#include "octo-kerberos-cpp/krb5/krb5-kerberos-authenticator.hpp"
#include <octo-logger-cpp/manager.hpp>
#include <octo-logger-cpp/logger.hpp>
#include <iostream>

int main(int argc, char** argv)
{
    if (argc != 6)
    {
        std::cout << "Example usage: ./tgt-example host username password realm service" << std::endl;
        std::exit(1);
    }
    auto config = std::make_shared<octo::logger::ManagerConfig>();
    config->set_option(octo::logger::ManagerConfig::LoggerOption::DEFAULT_CHANNEL_LEVEL,
                       static_cast<int>(octo::logger::Log::LogLevel::TRACE));
    octo::logger::SinkConfig console_sink("Console", octo::logger::SinkConfig::SinkType::CONSOLE_SINK);
    config->add_sink(console_sink);
    octo::logger::Manager::instance().configure(config);
    auto logger = octo::logger::Logger("main");

    octo::kerberos::krb5::KRB5KerberosAuthenticator authenticator(
        octo::kerberos::krb5::KRB5KerberosAuthenticator::Settings{argv[4], argv[1], DEFAULT_KERBEROS_PORT});
    if (!authenticator.initialize_authenticator())
    {
        logger.error() << "Failed to initialize krb5 authenticator";
        return -1;
    }
    auto creds = std::make_unique<octo::kerberos::KerberosUserCredentials>(
        argv[2], std::make_unique<octo::encryption::SecureString>(argv[3]));
    auto tgt = authenticator.generate_tgt(creds.get());
    if (tgt)
    {
        logger.info().formatted("TGT Ticket Info: \n{},{},{}",
                                tgt->ticket().get(),
                                tgt->ticket_purpose(),
                                static_cast<std::uint8_t>(tgt->ticket_type()));
        auto service_ticket = authenticator.generate_service_ticket(tgt.get(), argv[5]);
        if (service_ticket)
        {
            logger.info().formatted("Service Ticket Info: \n{},{},{}",
                                    service_ticket->ticket().get(),
                                    service_ticket->ticket_purpose(),
                                    static_cast<std::uint8_t>(service_ticket->ticket_type()));
        }
        else
        {
            logger.error() << "Failed generating service ticket";
            return -1;
        }
    }
    else
    {
        logger.error() << "Failed generating TGT";
        return -1;
    }
    return 0;
}
