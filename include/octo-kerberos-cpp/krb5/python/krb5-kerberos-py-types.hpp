/**
 * @file krb5-kerberos-py-types.hpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-14
 *
 * @copyright Copyright (c) 2022
 *
 */

#ifndef KRB5_KERBEROS_PY_TYPES_HPP_
#define KRB5_KERBEROS_PY_TYPES_HPP_

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "octo-kerberos-cpp/krb5/krb5-kerberos-authenticator.hpp"
#include "octo-kerberos-cpp/krb5/krb5-kerberos-tgt-ticket.hpp"
#include "octo-kerberos-cpp/krb5/krb5-kerberos-service-ticket.hpp"
#include "octo-kerberos-cpp/kerberos-user-credentials.hpp"
#include <structmember.h>
#include <string>
#include <unordered_map>

#define PY_C_FUNC(_f) reinterpret_cast<PyCFunction>(_f)

namespace octo::kerberos::krb5::python
{
extern "C"
{
    // User Credentials
    // Class
    typedef struct
    {
        PyObject_HEAD;
        KerberosUserCredentials* krb5_user_creds_;
    } KRB5UserCredentials;
    extern PyTypeObject KRB5UserCredentialsType;

    // TGT
    // Class
    typedef struct
    {
        PyObject_HEAD;
        KRB5KerberosTGTTicket* krb5_tgt_ticket_;
    } KRB5TGTTicket;
    extern PyTypeObject KRB5TGTTicketType;

    // Service Ticket
    // Class
    typedef struct
    {
        PyObject_HEAD;
        KRB5KerberosServiceTicket* krb5_service_ticket_;
    } KRB5ServiceTicket;
    extern PyTypeObject KRB5ServiceTicketType;

    // Authenticator
    // Class
    typedef struct
    {
        PyObject_HEAD;
        KRB5KerberosAuthenticator* krb5_authenticator_;
    } KRB5Authenticator;
    extern PyTypeObject KRB5AuthenticatorType;

    typedef struct
    {
        const char* name_;
        PyTypeObject* type_;
    } KRB5TypeObject;

    // Types
    static KRB5TypeObject KRB5Types[] = {{"KRB5UserCredentials", &KRB5UserCredentialsType},
                                         {"KRB5TGTTicket", &KRB5TGTTicketType},
                                         {"KRB5ServiceTicket", &KRB5ServiceTicketType},
                                         {"KRB5Authenticator", &KRB5AuthenticatorType}};
}
} // namespace octo::kerberos::krb5::python

#endif // KRB5_KERBEROS_PY_TYPES_HPP_
