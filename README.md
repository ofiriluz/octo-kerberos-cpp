octo-kerberos-cpp
===============

[![Kerberos Linux Build Pipeline](https://github.com/ofiriluz/octo-kerberos-cpp/actions/workflows/linux.yml/badge.svg)](https://github.com/ofiriluz/octo-kerberos-cpp/actions/workflows/linux.yml)

Kerbeors library, implementating a base interface for generating TGT's and ST's for accessing machines

The library itself is based on libkrb5, and is used as a CPP wrapper alongside python bindings for ease of use

The main purpose is accessing and managing tickets for machines via kerberos in a simplified manner

The library currently supports the following:
- CPP Implementation of kerberos with the abilitiy to generate a TGT and from that generate ST's to a certain resource
- Python bindings to perform the above in python
- Serialization and deserialization of the tickets to json for transfer between machines

Currently only supported in linux

Install
-------

Octo-kerberos can be installed from both conan and pypi, depending on your need:

Conan:
```python
self.requires("octo-kerberos-cpp@1.0.0")
```

Pypi:
```bash
pip instal octo_krb5
```

Usage
-----

In order to use the library, you must link to both it and krb5 library

krb5 can be installed on most linux machines via the standard package manager

CPP Usage can be seen as follows:
```cpp
octo::kerberos::krb5::KRB5KerberosAuthenticator authenticator(
    octo::kerberos::krb5::KRB5KerberosAuthenticator::Settings{"realm", "kdc_host", 88});
if (!authenticator.initialize_authenticator())
{
    std::cout << "Failed to initialize krb5 authenticator" std::endl;
    return -1;
}
auto creds = std::make_unique<octo::kerberos::KerberosUserCredentials>(
    "tgt_user", std::make_unique<octo::encryption::SecureString>("tgt_password"));
auto tgt = authenticator.generate_tgt(creds.get());
if (tgt)
{
    std::cout << fmt::format("TGT Ticket Info: \n{},{},{}",
                             tgt->ticket().get(),
                             tgt->ticket_purpose(),
                             static_cast<std::uint8_t>(tgt->ticket_type())) << std::endl;
    auto service_ticket = authenticator.generate_service_ticket(tgt.get(), "machine");
    if (service_ticket)
    {
        std::cout << fmt::format("Service Ticket Info: \n{},{},{}",
                                 service_ticket->ticket().get(),
                                 service_ticket->ticket_purpose(),
                                 static_cast<std::uint8_t>(service_ticket->ticket_type())) << std::endl;
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
```

The above generates an authenticator class, which is the main class responsible to generate the tickets

The class is inputted with a settings struct that can configure the authenticator accordingly

Once initialized, the authenticator can authenticate a user capable of generating TGT's and from him, generate service tickets upon need for resources

The same idea above applies to the python bindings as follows:

```python
creds = KRB5UserCredentials("tgt_user", "tgt_password")
auth = KRB5Authenticator("realm", "kdc_host", 88)
auth.initialize_authenticator()
tgt = auth.generate_tgt(creds)

serialized_tgt = tgt.serialize()
pprint.pprint(serialized_tgt)
tgt = auth.deserialize_tgt(serialized_tgt)
pprint.pprint(tgt.serialize())

st = auth.generate_service_ticket(tgt, args.service)

serialized_st = st.serialize()
pprint.pprint(serialized_st)
st = auth.deserialize_service_ticket(serialized_st)
pprint.pprint(st.serialize())
```
