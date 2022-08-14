/**
 * @file krb5-kerberos-py-serializer.hpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-14
 *
 * @copyright Copyright (c) 2022
 *
 */

#ifndef KRB5_KERBEROS_PY_SERIALIZER_HPP_
#define KRB5_KERBEROS_PY_SERIALIZER_HPP_

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <nlohmann/json.hpp>

namespace octo::kerberos::krb5::python
{
PyObject* serialize_py_json(const nlohmann::json& json);
nlohmann::json deserialize_py_json(PyObject* dict);
} // namespace octo::kerberos::krb5::python

#endif // KRB5_KERBEROS_PY_SERIALIZER_HPP_
