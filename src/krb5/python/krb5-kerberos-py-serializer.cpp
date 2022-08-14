/**
 * @file krb5-kerberos-py-serializer.cpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-14
 *
 * @copyright Copyright (c) 2022
 *
 */

#include "octo-kerberos-cpp/krb5/python/krb5-kerberos-py-serializer.hpp"
#include <fmt/format.h>

namespace octo::kerberos::krb5::python
{
PyObject* serialize_py_json(const nlohmann::json& json)
{
    if (json.is_null())
    {
        Py_INCREF(Py_None);
        return Py_None;
    }
    if (json.is_boolean())
    {
        if (json.get<bool>())
        {
            Py_RETURN_TRUE;
        }
        Py_RETURN_FALSE;
    }
    if (json.is_number())
    {
        if (json.is_number_integer())
        {
            return Py_BuildValue("i", json.get<int>());
        }
        else
        {
            return Py_BuildValue("d", json.get<double>());
        }
    }
    if (json.is_string())
    {
        return Py_BuildValue("s", json.get<std::string>().c_str());
    }
    if (json.is_array())
    {
        PyObject* arr = PyList_New(json.size());
        for (auto i = 0; i < json.size(); ++i)
        {
            PyList_SetItem(arr, i, serialize_py_json(json[i]));
        }
        return arr;
    }
    if (json.is_object())
    {
        PyObject* dict = PyDict_New();
        for (auto it = json.cbegin(); it != json.cend(); ++it)
        {
            PyDict_SetItem(dict, Py_BuildValue("s", it.key().c_str()), serialize_py_json(it.value()));
        }
        return dict;
    }
    Py_INCREF(Py_None);
    return Py_None;
}

nlohmann::json deserialize_py_json(PyObject* dict)
{
    if (dict == Py_None)
    {
        return nullptr;
    }
    if (PyBool_Check(dict))
    {
        return dict == Py_True;
    }
    if (PyFloat_Check(dict))
    {
        return PyFloat_AsDouble(dict);
    }
    if (PyLong_Check(dict))
    {
        return PyLong_AsLong(dict);
    }
    if (PyUnicode_Check(dict))
    {
        return PyUnicode_AsUTF8(dict);
    }
    if (PyTuple_Check(dict))
    {
        nlohmann::json out;
        for (auto i = 0; i < PyTuple_Size(dict); ++i)
        {
            out.push_back(deserialize_py_json(PyTuple_GetItem(dict, i)));
        }
        return out;
    }
    if (PyList_Check(dict))
    {
        nlohmann::json out;
        for (auto i = 0; i < PyList_Size(dict); ++i)
        {
            out.push_back(deserialize_py_json(PyList_GetItem(dict, i)));
        }
        return out;
    }
    if (PyDict_Check(dict))
    {
        nlohmann::json out;
        PyObject *key, *value;
        Py_ssize_t pos = 0;

        while (PyDict_Next(dict, &pos, &key, &value))
        {
            out[PyUnicode_AsUTF8(key)] = deserialize_py_json(value);
        }
        return out;
    }
    throw std::runtime_error(
        fmt::format("Deserialize not implemented for this type of object [{}]", dict->ob_type->tp_name));
}
} // namespace octo::kerberos::krb5::python
