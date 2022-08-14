/**
 * @file krb5-kerberos-py-module.hpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-14
 *
 * @copyright Copyright (c) 2022
 *
 */

#ifndef KRB5_KERBEROS_PY_MODULE_HPP_
#define KRB5_KERBEROS_PY_MODULE_HPP_

#define PY_SSIZE_T_CLEAN
#include <Python.h>

namespace octo::kerberos::krb5::python
{

static PyMethodDef octo_krb5_methods[] = {
    {nullptr, nullptr, 0, nullptr}, /* Sentinel */
};

static struct PyModuleDef OctoKRB5Module = {
    PyModuleDef_HEAD_INIT,
    "octo_krb5",          /* m_name */
    "Octo KRB5 module.",  /* m_doc */
    -1,                   /* m_size */
    octo_krb5_methods,    /* m_methods */
    nullptr,              /* m_slots */
    nullptr,              /* m_traverse */
    nullptr,              /* m_clear */
    nullptr,              /* m_free */
};

} // namespace octo::kerberos::krb5::python

#endif // KRB5_KERBEROS_PY_MODULE_HPP_
