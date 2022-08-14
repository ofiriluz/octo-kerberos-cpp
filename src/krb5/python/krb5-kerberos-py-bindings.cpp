/**
 * @file krb5-kerberos-py-bindings.cpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-14
 *
 * @copyright Copyright (c) 2022
 *
 */

#include "octo-kerberos-cpp/krb5/python/krb5-kerberos-py-bindings.hpp"
#include "octo-kerberos-cpp/krb5/python/krb5-kerberos-py-module.hpp"
#include "octo-kerberos-cpp/krb5/python/krb5-kerberos-py-types.hpp"
#include <octo-logger-cpp/log.hpp>
#include <octo-logger-cpp/manager-config.hpp>
#include <octo-logger-cpp/manager.hpp>
#include <octo-logger-cpp/sink-config.hpp>

namespace
{
using ::octo::logger::Log;
using ::octo::logger::Manager;
using ::octo::logger::ManagerConfig;
using ::octo::logger::SinkConfig;
} // namespace

namespace octo::kerberos::krb5::python
{
extern "C"
{
    PyMODINIT_FUNC PyInit_octo_krb5(void)
    {
        Py_Initialize();
        PyObject* m;
        for (int i = 0; i < sizeof(KRB5Types) / sizeof(KRB5TypeObject); ++i)
        {
            if (PyType_Ready(KRB5Types[i].type_) < 0)
            {
                return nullptr;
            }
        }

        m = PyModule_Create(&OctoKRB5Module);
        if (!m)
        {
            return nullptr;
        }

        for (int i = 0; i < sizeof(KRB5Types) / sizeof(KRB5TypeObject); ++i)
        {
            Py_INCREF(KRB5Types[i].type_);
            if (PyModule_AddObject(m, KRB5Types[i].name_, (PyObject*)KRB5Types[i].type_) < 0)
            {
                for (int j = i; j >= 0; j--)
                {
                    Py_DECREF(KRB5Types[j].type_);
                }
                Py_DECREF(m);
                return nullptr;
            }
        }

        PyModule_AddIntConstant(m, "DEFAULT_KERBEROS_PORT", DEFAULT_KERBEROS_PORT);
        PyModule_AddIntConstant(m, "DEFAULT_KERBEROS_STREAMLINED", DEFAULT_KERBEROS_STREAMLINED);
        PyModule_AddIntConstant(m, "DEFAULT_TGT_LIFETIME_SECONDS", DEFAULT_TGT_LIFETIME_SECONDS);
        PyModule_AddIntConstant(m, "DEFAULT_SERVICE_TICKET_LIFETIME_SECONDS", DEFAULT_SERVICE_TICKET_LIFETIME_SECONDS);

        std::shared_ptr<ManagerConfig> manager_config(new ManagerConfig);
        SinkConfig console_sink("Console", SinkConfig::SinkType::CONSOLE_SINK);
        manager_config->add_sink(console_sink);
        manager_config->set_option(ManagerConfig::LoggerOption::DEFAULT_CHANNEL_LEVEL,
                                   static_cast<int>(Log::LogLevel::LOGGER_LEVEL));
        Manager::instance().configure(manager_config);

        return m;
    }
}
} // namespace octo::kerberos::krb5::python
