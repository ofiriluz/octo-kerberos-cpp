/**
 * @file krb5-kerberos-py-types-tgt-ticket.cpp
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

    static int KRB5TGTTicketInit(KRB5TGTTicket* self, PyObject* args)
    {
        METHOD_LOG_TRACE_GLOBAL
        char const* tgt_user = nullptr;

        if (!PyArg_ParseTuple(args, "s", &tgt_user))
        {
            return -1;
        }

        self->krb5_tgt_ticket_ = new KRB5KerberosTGTTicket(tgt_user);

        if (!self->krb5_tgt_ticket_)
        {
            return -1;
        }
        return 0;
    }

    static void KRB5TGTTicketDealloc(KRB5TGTTicket* self)
    {
        METHOD_LOG_TRACE_GLOBAL
        if (!self)
        {
            return;
        }
        if (self->krb5_tgt_ticket_)
        {
            delete self->krb5_tgt_ticket_;
        }
        PyObject_Del(self);
    }

    static PyObject* KRB5TGTTicketTicket(KRB5TGTTicket* self)
    {
        // METHOD_LOG_TRACE_GLOBAL //
        auto ticket = self->krb5_tgt_ticket_->ticket();
        return Py_BuildValue("s#", ticket.get().data(), ticket.get().size());
    }

    static PyObject* KRB5TGTTicketEncodedTicket(KRB5TGTTicket* self)
    {
        // METHOD_LOG_TRACE_GLOBAL //
        return Py_BuildValue("s", self->krb5_tgt_ticket_->encoded_ticket().get().data());
    }

    static PyObject* KRB5TGTTicketTicketPurpose(KRB5TGTTicket* self)
    {
        // METHOD_LOG_TRACE_GLOBAL //
        return Py_BuildValue("s", self->krb5_tgt_ticket_->ticket_purpose().c_str());
    }

    static PyObject* KRB5TGTTicketTicketType(KRB5TGTTicket* self)
    {
        // METHOD_LOG_TRACE_GLOBAL //
        return Py_BuildValue("s", "TicketGrantingTicket");
    }

    static PyObject* KRB5TGTTicketTgtUser(KRB5TGTTicket* self)
    {
        // METHOD_LOG_TRACE_GLOBAL //
        return Py_BuildValue("s", self->krb5_tgt_ticket_->tgt_user().c_str());
    }

    static PyObject* KRB5TGTTicketTicketExpirationTime(KRB5TGTTicket* self)
    {
        // METHOD_LOG_TRACE_GLOBAL //
        return Py_BuildValue("i",
                             std::chrono::duration_cast<std::chrono::seconds>(
                                 self->krb5_tgt_ticket_->ticket_expiration_time().time_since_epoch())
                                 .count());
    }

    static PyObject* KRB5TGTTicketSerialize(KRB5TGTTicket* self)
    {
        METHOD_LOG_TRACE_GLOBAL
        return Py_BuildValue("O", serialize_py_json(self->krb5_tgt_ticket_->serialize()));
    }

    static PyObject* KRB5TGTTicketDeserialize(KRB5TGTTicket* self, PyObject* args)
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
        return self->krb5_tgt_ticket_->deserialize(deserialize_py_json(py_dict)) ? Py_True : Py_False;
    }

    // Definitions
    static PyMemberDef krb5_tgt_ticket_members[] = {
        {nullptr, 0, 0, 0, nullptr}, /* Sentinel */
    };

    static PyMethodDef krb5_tgt_ticket_methods[] = {
        {"ticket", PY_C_FUNC(KRB5TGTTicketTicket), METH_NOARGS, "Getter for the tgt ticket data."},
        {"encoded_ticket",
         PY_C_FUNC(KRB5TGTTicketEncodedTicket),
         METH_NOARGS,
         "Getter for the tgt base64 encoded ticket data."},
        {"ticket_purpose", PY_C_FUNC(KRB5TGTTicketTicketPurpose), METH_NOARGS, "Getter for the ticket purpose."},
        {"ticket_type", PY_C_FUNC(KRB5TGTTicketTicketType), METH_NOARGS, "Getter for the ticket type."},
        {"ticket_expiration_time",
         PY_C_FUNC(KRB5TGTTicketTicketExpirationTime),
         METH_NOARGS,
         "Getter for the ticket expiration time in seconds since epoch."},
        {"tgt_user", PY_C_FUNC(KRB5TGTTicketTgtUser), METH_NOARGS, "Getter for the tgt user."},
        {"serialize", PY_C_FUNC(KRB5TGTTicketSerialize), METH_NOARGS, "Serializes the tgt object to dict."},
        {"deserialize", PY_C_FUNC(KRB5TGTTicketDeserialize), METH_VARARGS, "Deserializes the tgt object from dict."},
        {nullptr, nullptr, 0, nullptr}, /* Sentinel */
    };

    PyTypeObject KRB5TGTTicketType = {
        PyVarObject_HEAD_INIT(nullptr, 0)
        //  Comment to avoid auto format from removing newline.
        "octo_krb5.KRB5TGTTicket",                           /* tp_name */
        sizeof(KRB5TGTTicket),                               /* tp_basicsize */
        0,                                                   /* tp_itemsize */
        reinterpret_cast<destructor>(KRB5TGTTicketDealloc),  /* tp_dealloc */
        0,                                                   /* tp_vectorcall_offset */
        nullptr,                                             /* tp_getattr */
        nullptr,                                             /* tp_setattr */
        nullptr,                                             /* tp_as_async */
        nullptr,                                             /* tp_repr */
        nullptr,                                             /* tp_as_number */
        nullptr,                                             /* tp_as_sequence */
        nullptr,                                             /* tp_as_mapping */
        nullptr,                                             /* tp_hash */
        nullptr,                                             /* tp_call */
        nullptr,                                             /* tp_str */
        nullptr,                                             /* tp_getattro */
        nullptr,                                             /* tp_setattro */
        nullptr,                                             /* tp_as_buffer */
        Py_TPFLAGS_DEFAULT,                                  /* tp_flags */
        "Octo KRB5 TGT Ticket.",                             /* tp_doc */
        nullptr,                                             /* tp_traverse */
        nullptr,                                             /* tp_clear */
        nullptr,                                             /* tp_richcompare */
        0,                                                   /* tp_weaklistoffset */
        nullptr,                                             /* tp_iter */
        nullptr,                                             /* tp_iternext */
        krb5_tgt_ticket_methods,                             /* tp_methods */
        krb5_tgt_ticket_members,                             /* tp_members */
        nullptr,                                             /* tp_getset */
        nullptr,                                             /* tp_base */
        nullptr,                                             /* tp_dict */
        nullptr,                                             /* tp_descr_get */
        nullptr,                                             /* tp_descr_set */
        0,                                                   /* tp_dictoffset */
        reinterpret_cast<initproc>(KRB5TGTTicketInit),       /* tp_init */
        nullptr,                                             /* tp_alloc */
        PyType_GenericNew,                                   /* tp_new */
        nullptr,                                             /* tp_free */
        nullptr,                                             /* tp_is_gc */
        nullptr,                                             /* tp_bases */
        nullptr,                                             /* tp_mro */
        nullptr,                                             /* tp_cache */
        nullptr,                                             /* tp_subclasses */
        nullptr,                                             /* tp_weaklist */
        nullptr,                                             /* tp_del */
        0,                                                   /* tp_version_tag */
        nullptr,                                             /* tp_finalize */
        nullptr,                                             /* tp_vectorcall */
    };
}
} // namespace octo::kerberos::krb5::python
