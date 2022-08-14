/**
 * @file krb5-kerberos-py-types-user-credentials.cpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-14
 *
 * @copyright Copyright (c) 2022
 *
 */

#include "octo-kerberos-cpp/krb5/python/krb5-kerberos-py-types.hpp"
#include <octo-logger-cpp/log.hpp>
#include <octo-logger-cpp/trace-logger.hpp>

namespace octo::kerberos::krb5::python
{
extern "C"
{
    static int KRB5UserCredentialsInit(KRB5UserCredentials* self, PyObject* args)
    {
        METHOD_LOG_TRACE_GLOBAL
        char const* username = nullptr;
        char const* password = nullptr;

        if (!PyArg_ParseTuple(args, "ss", &username, &password))
        {
            return -1;
        }

        self->krb5_user_creds_ =
            new KerberosUserCredentials(username, std::make_unique<encryption::SecureString>(password));

        if (!self->krb5_user_creds_)
        {
            return -1;
        }
        return 0;
    }

    static void KRB5UserCredentialsDealloc(KRB5UserCredentials* self)
    {
        METHOD_LOG_TRACE_GLOBAL
        if (!self)
        {
            return;
        }
        if (self->krb5_user_creds_)
        {
            delete self->krb5_user_creds_;
        }
        PyObject_Del(self);
    }

    static PyObject* KRB5UserCredentialsUsername(KRB5UserCredentials* self)
    {
        // METHOD_LOG_TRACE_GLOBAL //
        return Py_BuildValue("s", self->krb5_user_creds_->username().c_str());
    }

    static PyObject* KRB5UserCredentialsPassword(KRB5UserCredentials* self)
    {
        // METHOD_LOG_TRACE_GLOBAL //
        return Py_BuildValue("s", self->krb5_user_creds_->password().get().data());
    }

    static PyObject* KRB5UserCredentialsSetUsername(KRB5UserCredentials* self, PyObject* args)
    {
        METHOD_LOG_TRACE_GLOBAL
        char const* username;
        if (!PyArg_ParseTuple(args, "s", &username))
        {
            return nullptr;
        }
        self->krb5_user_creds_->set_username(username);
        Py_INCREF(Py_None);
        return Py_None;
    }

    static PyObject* KRB5UserCredentialsSetPassword(KRB5UserCredentials* self, PyObject* args)
    {
        METHOD_LOG_TRACE_GLOBAL
        char const* password;
        if (!PyArg_ParseTuple(args, "s", &password))
        {
            return nullptr;
        }
        self->krb5_user_creds_->set_password(std::make_unique<encryption::SecureString>(password));
        Py_INCREF(Py_None);
        return Py_None;
    }

    // Definitions
    static PyMemberDef krb5_user_credentials_members[] = {
        {nullptr, 0, 0, 0, nullptr}, /* Sentinel */
    };

    static PyMethodDef krb5_user_credentials_methods[] = {
        {"username", PY_C_FUNC(KRB5UserCredentialsUsername), METH_NOARGS, "Getter for the credentials username."},
        {"password", PY_C_FUNC(KRB5UserCredentialsPassword), METH_NOARGS, "Getter for the credentials password."},
        {"set_username",
         PY_C_FUNC(KRB5UserCredentialsSetUsername),
         METH_VARARGS,
         "Setter for the credentials username."},
        {"set_password",
         PY_C_FUNC(KRB5UserCredentialsSetPassword),
         METH_VARARGS,
         "Setter for the credentials username."},
        {nullptr, nullptr, 0, nullptr}, /* Sentinel */
    };

    PyTypeObject KRB5UserCredentialsType = {
        PyVarObject_HEAD_INIT(nullptr, 0)
        //  Comment to avoid auto format from removing newline.
        "octo_krb5.KRB5UserCredentials",                           /* tp_name */
        sizeof(KRB5UserCredentials),                               /* tp_basicsize */
        0,                                                         /* tp_itemsize */
        reinterpret_cast<destructor>(KRB5UserCredentialsDealloc),  /* tp_dealloc */
        0,                                                         /* tp_vectorcall_offset */
        nullptr,                                                   /* tp_getattr */
        nullptr,                                                   /* tp_setattr */
        nullptr,                                                   /* tp_as_async */
        nullptr,                                                   /* tp_repr */
        nullptr,                                                   /* tp_as_number */
        nullptr,                                                   /* tp_as_sequence */
        nullptr,                                                   /* tp_as_mapping */
        nullptr,                                                   /* tp_hash */
        nullptr,                                                   /* tp_call */
        nullptr,                                                   /* tp_str */
        nullptr,                                                   /* tp_getattro */
        nullptr,                                                   /* tp_setattro */
        nullptr,                                                   /* tp_as_buffer */
        Py_TPFLAGS_DEFAULT,                                        /* tp_flags */
        "Octo KRB5 User Credentials.",                             /* tp_doc */
        nullptr,                                                   /* tp_traverse */
        nullptr,                                                   /* tp_clear */
        nullptr,                                                   /* tp_richcompare */
        0,                                                         /* tp_weaklistoffset */
        nullptr,                                                   /* tp_iter */
        nullptr,                                                   /* tp_iternext */
        krb5_user_credentials_methods,                             /* tp_methods */
        krb5_user_credentials_members,                             /* tp_members */
        nullptr,                                                   /* tp_getset */
        nullptr,                                                   /* tp_base */
        nullptr,                                                   /* tp_dict */
        nullptr,                                                   /* tp_descr_get */
        nullptr,                                                   /* tp_descr_set */
        0,                                                         /* tp_dictoffset */
        reinterpret_cast<initproc>(KRB5UserCredentialsInit),       /* tp_init */
        nullptr,                                                   /* tp_alloc */
        PyType_GenericNew,                                         /* tp_new */
        nullptr,                                                   /* tp_free */
        nullptr,                                                   /* tp_is_gc */
        nullptr,                                                   /* tp_bases */
        nullptr,                                                   /* tp_mro */
        nullptr,                                                   /* tp_cache */
        nullptr,                                                   /* tp_subclasses */
        nullptr,                                                   /* tp_weaklist */
        nullptr,                                                   /* tp_del */
        0,                                                         /* tp_version_tag */
        nullptr,                                                   /* tp_finalize */
        nullptr,                                                   /* tp_vectorcall */
    };
}
} // namespace octo::kerberos::krb5::python
