/**
 * @file krb5-kerberos-py-types-authenticator.cpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-14
 *
 * @copyright Copyright (c) 2022
 *
 */

#include "octo-kerberos-cpp/krb5/python/krb5-kerberos-py-types.hpp"
#include "octo-kerberos-cpp/krb5/python/krb5-kerberos-py-serializer.hpp"
#include <octo-logger-cpp/log.hpp>
#include <octo-logger-cpp/trace-logger.hpp>

namespace octo::kerberos::krb5::python
{
extern "C"
{
    static int KRB5AuthenticatorInit(KRB5Authenticator* self, PyObject* args)
    {
        METHOD_LOG_TRACE_GLOBAL
        char const* realm = nullptr;
        char const* kdc_host = nullptr;
        char const* session_id = nullptr;
        int kdc_port = -1;
        int streamlined = DEFAULT_KERBEROS_STREAMLINED;

        if (!PyArg_ParseTuple(args, "s|zizp", &realm, &kdc_host, &kdc_port, &session_id, &streamlined))
        {
            return -1;
        }

        if (!realm || strlen(realm) == 0)
        {
            PyErr_SetString(PyExc_RuntimeError, "At least a realm must be provided");
            PyErr_Print();
            PyErr_SetNone(PyExc_RuntimeError);
            return -1;
        }

        KRB5KerberosAuthenticator::Settings settings;
        settings.realm = realm;
        settings.kdc_host = kdc_host && strlen(kdc_host) > 0 ? kdc_host : realm;
        settings.kdc_port = kdc_port > 0 ? kdc_port : DEFAULT_KERBEROS_PORT;
        settings.session_id = session_id && strlen(session_id) > 0 ? session_id : "";
        settings.streamlined = streamlined;

        self->krb5_authenticator_ = new KRB5KerberosAuthenticator(settings);

        if (!self->krb5_authenticator_)
        {
            return -1;
        }
        return 0;
    }

    static void KRB5AuthenticatorDealloc(KRB5Authenticator* self)
    {
        METHOD_LOG_TRACE_GLOBAL
        if (!self)
        {
            return;
        }
        if (self->krb5_authenticator_)
        {
            delete self->krb5_authenticator_;
        }
        PyObject_Del(self);
    }

    static PyObject* KRB5AuthenticatorInitializeAuthenticator(KRB5Authenticator* self)
    {
        METHOD_LOG_TRACE_GLOBAL
        return self->krb5_authenticator_->initialize_authenticator() ? Py_True : Py_False;
    }

    static PyObject* KRB5AuthenticatorCleanupAuthenticator(KRB5Authenticator* self)
    {
        METHOD_LOG_TRACE_GLOBAL
        return self->krb5_authenticator_->cleanup_authenticator() ? Py_True : Py_False;
    }

    static PyObject* KRB5AuthenticatorIsInitialized(KRB5Authenticator* self)
    {
        // METHOD_LOG_TRACE_GLOBAL //
        return self->krb5_authenticator_->is_initialized() ? Py_True : Py_False;
    }

    static PyObject* KRB5AuthenticatorIsStreamlined(KRB5Authenticator* self)
    {
        // METHOD_LOG_TRACE_GLOBAL //
        return self->krb5_authenticator_->is_streamlined() ? Py_True : Py_False;
    }

    static PyObject* KRB5AuthenticatorGenerateTGT(KRB5Authenticator* self, PyObject* args)
    {
        METHOD_LOG_TRACE_GLOBAL
        PyObject* py_creds = nullptr;
        int ticket_lifetime = -1;

        if (!PyArg_ParseTuple(args, "O|i", &py_creds, &ticket_lifetime))
        {
            return nullptr;
        }
        if (!py_creds || (py_creds)->ob_type != &KRB5UserCredentialsType)
        {
            PyErr_SetString(PyExc_RuntimeError, "Input creds cannot be empty");
            return nullptr;
        }
        auto creds = reinterpret_cast<KRB5UserCredentials*>(py_creds);
        auto tgt = self->krb5_authenticator_->generate_tgt(creds->krb5_user_creds_,
                                                           ticket_lifetime > 0
                                                               ? std::chrono::seconds(ticket_lifetime)
                                                               : std::chrono::seconds(DEFAULT_TGT_LIFETIME_SECONDS));
        if (!tgt)
        {
            PyErr_SetString(PyExc_RuntimeError, "Failed to generate tgt");
            return nullptr;
        }
        auto py_tgt = PyObject_New(KRB5TGTTicket, &KRB5TGTTicketType);
        if (!py_tgt)
        {
            PyErr_SetString(PyExc_RuntimeError, "Failed to allocate tgt");
            return nullptr;
        }
        py_tgt->krb5_tgt_ticket_ = dynamic_cast<KRB5KerberosTGTTicket*>(tgt.release());
        return reinterpret_cast<PyObject*>(py_tgt);
    }

    static PyObject* KRB5AuthenticatorDeserializeTGT(KRB5Authenticator* self, PyObject* args)
    {
        METHOD_LOG_TRACE_GLOBAL
        PyObject* py_dict = nullptr;

        if (!PyArg_ParseTuple(args, "O", &py_dict))
        {
            return nullptr;
        }
        if (!py_dict)
        {
            PyErr_SetString(PyExc_RuntimeError, "Input dict cannot be empty");
            return nullptr;
        }
        auto tgt = self->krb5_authenticator_->deserialize_tgt(deserialize_py_json(py_dict));
        if (!tgt)
        {
            PyErr_SetString(PyExc_RuntimeError, "Failed to deserialize tgt");
            return nullptr;
        }
        auto py_tgt = PyObject_New(KRB5TGTTicket, &KRB5TGTTicketType);
        if (!py_tgt)
        {
            PyErr_SetString(PyExc_RuntimeError, "Failed to allocate tgt");
            return nullptr;
        }
        py_tgt->krb5_tgt_ticket_ = dynamic_cast<KRB5KerberosTGTTicket*>(tgt.release());
        return reinterpret_cast<PyObject*>(py_tgt);
    }

    static PyObject* KRB5AuthenticatorGenerateServiceTicket(KRB5Authenticator* self, PyObject* args)
    {
        METHOD_LOG_TRACE_GLOBAL
        PyObject* py_tgt = nullptr;
        const char* service = nullptr;
        int ticket_lifetime = -1;

        if (!PyArg_ParseTuple(args, "Os|i", &py_tgt, &service, &ticket_lifetime))
        {
            return nullptr;
        }
        if (!py_tgt || (py_tgt)->ob_type != &KRB5TGTTicketType)
        {
            PyErr_SetString(PyExc_RuntimeError, "Input tgt cannot be empty");
            return nullptr;
        }
        auto tgt = reinterpret_cast<KRB5TGTTicket*>(py_tgt);
        auto service_ticket = self->krb5_authenticator_->generate_service_ticket(
            tgt->krb5_tgt_ticket_,
            service,
            ticket_lifetime > 0 ? std::chrono::seconds(ticket_lifetime)
                                : std::chrono::seconds(DEFAULT_SERVICE_TICKET_LIFETIME_SECONDS));
        if (!service_ticket)
        {
            PyErr_SetString(PyExc_RuntimeError, "Failed to generate service ticket");
            return nullptr;
        }
        auto py_service_ticket = PyObject_New(KRB5ServiceTicket, &KRB5ServiceTicketType);
        if (!py_service_ticket)
        {
            PyErr_SetString(PyExc_RuntimeError, "Failed to allocate service ticket");
            return nullptr;
        }
        py_service_ticket->krb5_service_ticket_ = dynamic_cast<KRB5KerberosServiceTicket*>(service_ticket.release());
        return reinterpret_cast<PyObject*>(py_service_ticket);
    }

    static PyObject* KRB5AuthenticatorDeserializeServiceTicket(KRB5Authenticator* self, PyObject* args)
    {
        METHOD_LOG_TRACE_GLOBAL
        PyObject* py_dict = nullptr;

        if (!PyArg_ParseTuple(args, "O", &py_dict))
        {
            return nullptr;
        }
        if (!py_dict)
        {
            PyErr_SetString(PyExc_RuntimeError, "Input dict cannot be empty");
            return nullptr;
        }
        auto service_ticket = self->krb5_authenticator_->deserialize_service_ticket(deserialize_py_json(py_dict));
        if (!service_ticket)
        {
            PyErr_SetString(PyExc_RuntimeError, "Failed to deserialize service ticket");
            return nullptr;
        }
        auto py_service_ticket = PyObject_New(KRB5ServiceTicket, &KRB5ServiceTicketType);
        if (!py_service_ticket)
        {
            PyErr_SetString(PyExc_RuntimeError, "Failed to allocate service ticket");
            return nullptr;
        }
        py_service_ticket->krb5_service_ticket_ = dynamic_cast<KRB5KerberosServiceTicket*>(service_ticket.release());
        return reinterpret_cast<PyObject*>(py_service_ticket);
    }

    // Definitions
    static PyMemberDef krb5_authenticator_members[] = {
        {nullptr, 0, 0, 0, nullptr}, /* Sentinel */
    };

    static PyMethodDef krb5_authenticator_methods[] = {
        {"initialize_authenticator",
         PY_C_FUNC(KRB5AuthenticatorInitializeAuthenticator),
         METH_NOARGS,
         "Initializes the authenticator class."},
        {"cleanup_authenticator",
         PY_C_FUNC(KRB5AuthenticatorCleanupAuthenticator),
         METH_NOARGS,
         "Cleans the authenticator class."},
        {"is_initialized",
         PY_C_FUNC(KRB5AuthenticatorIsInitialized),
         METH_NOARGS,
         "Getter for whether the authenticator was initialized."},
        {"is_streamlined",
         PY_C_FUNC(KRB5AuthenticatorIsStreamlined),
         METH_NOARGS,
         "Getter for whether the authenticator is streamlined."},
        {"generate_tgt",
         PY_C_FUNC(KRB5AuthenticatorGenerateTGT),
         METH_VARARGS,
         "Generates a TGT for given credentials."},
        {"deserialize_tgt",
         PY_C_FUNC(KRB5AuthenticatorDeserializeTGT),
         METH_VARARGS,
         "Deserializes a TGT for given json contexted to the authenticator."},
        {"generate_service_ticket",
         PY_C_FUNC(KRB5AuthenticatorGenerateServiceTicket),
         METH_VARARGS,
         "Generates a service ticket for given tgt and service."},
        {"deserialize_service_ticket",
         PY_C_FUNC(KRB5AuthenticatorDeserializeServiceTicket),
         METH_VARARGS,
         "Deserializes a service ticket for given json contexted to the authenticator."},
        {nullptr, nullptr, 0, nullptr}, /* Sentinel */
    };

    PyTypeObject KRB5AuthenticatorType = {
        PyVarObject_HEAD_INIT(nullptr, 0)
        //  Comment to avoid auto format from removing newline.
        "octo_krb5.KRB5Authenticator",                           /* tp_name */
        sizeof(KRB5Authenticator),                               /* tp_basicsize */
        0,                                                       /* tp_itemsize */
        reinterpret_cast<destructor>(KRB5AuthenticatorDealloc),  /* tp_dealloc */
        0,                                                       /* tp_vectorcall_offset */
        nullptr,                                                 /* tp_getattr */
        nullptr,                                                 /* tp_setattr */
        nullptr,                                                 /* tp_as_async */
        nullptr,                                                 /* tp_repr */
        nullptr,                                                 /* tp_as_number */
        nullptr,                                                 /* tp_as_sequence */
        nullptr,                                                 /* tp_as_mapping */
        nullptr,                                                 /* tp_hash */
        nullptr,                                                 /* tp_call */
        nullptr,                                                 /* tp_str */
        nullptr,                                                 /* tp_getattro */
        nullptr,                                                 /* tp_setattro */
        nullptr,                                                 /* tp_as_buffer */
        Py_TPFLAGS_DEFAULT,                                      /* tp_flags */
        "Octo KRB5 Authenticator.",                              /* tp_doc */
        nullptr,                                                 /* tp_traverse */
        nullptr,                                                 /* tp_clear */
        nullptr,                                                 /* tp_richcompare */
        0,                                                       /* tp_weaklistoffset */
        nullptr,                                                 /* tp_iter */
        nullptr,                                                 /* tp_iternext */
        krb5_authenticator_methods,                              /* tp_methods */
        krb5_authenticator_members,                              /* tp_members */
        nullptr,                                                 /* tp_getset */
        nullptr,                                                 /* tp_base */
        nullptr,                                                 /* tp_dict */
        nullptr,                                                 /* tp_descr_get */
        nullptr,                                                 /* tp_descr_set */
        0,                                                       /* tp_dictoffset */
        reinterpret_cast<initproc>(KRB5AuthenticatorInit),       /* tp_init */
        nullptr,                                                 /* tp_alloc */
        PyType_GenericNew,                                       /* tp_new */
        nullptr,                                                 /* tp_free */
        nullptr,                                                 /* tp_is_gc */
        nullptr,                                                 /* tp_bases */
        nullptr,                                                 /* tp_mro */
        nullptr,                                                 /* tp_cache */
        nullptr,                                                 /* tp_subclasses */
        nullptr,                                                 /* tp_weaklist */
        nullptr,                                                 /* tp_del */
        0,                                                       /* tp_version_tag */
        nullptr,                                                 /* tp_finalize */
        nullptr,                                                 /* tp_vectorcall */
    };
}
} // namespace octo::kerberos::krb5::python
