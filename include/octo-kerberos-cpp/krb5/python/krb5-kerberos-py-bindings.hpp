/**
 * @file krb5-kerberos-py-bindings.hpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-14
 *
 * @copyright Copyright (c) 2022
 *
 */

#ifndef KRB5_KERBEROS_PY_BINDINGS_HPP_
#define KRB5_KERBEROS_PY_BINDINGS_HPP_

#define PY_SSIZE_T_CLEAN
#include <Python.h>

namespace octo::kerberos::krb5::python
{
extern "C"
{
    PyMODINIT_FUNC PyInit_octo_krb5(void);
}
} // namespace octo::kerberos::krb5::python

#endif // KRB5_KERBEROS_PY_BINDINGS_HPP_
