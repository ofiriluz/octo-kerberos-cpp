#!/usr/bin/env python3
import logging
import os
import shutil
import sys
from pathlib import Path
from typing import Any
import toml
from setuptools import Extension
from setuptools import setup
from setuptools.command.build_ext import build_ext


def setup_logger():
    log_format = '%(levelname)-8s | %(asctime)s | %(message)s'
    logging.basicConfig(format=log_format, datefmt="%H:%M:%S %d/%m/%Y",
                        level=logging.INFO)
    return logging.getLogger("setup_py")


logger = setup_logger()


def get_version():
    version = open("VERSION", 'r').read().strip()
    build_number = os.getenv("BUILD_NUMBER", 0)
    branch = os.getenv("BRANCH_NAME", "")
    full_version = f"{version}"
    if branch != "":
        if branch.startswith("rc"):
            full_version = f"{version}.rc{build_number}"
        elif branch != 'main' and not branch.startswith('release'):
            full_version = f"{version}.dev{build_number}"
    return full_version


def get_package_requirements(package: str, version: Any):
    packages = []
    package_name = package
    if isinstance(version, dict):
        if "sys_platform" in version and version["sys_platform"].split()[1].strip() != sys.platform:
            return packages
        if "version" in version and version['version'] != "*":
            package_name = f"{package}{version['version']}"
        if "extras" in version:
            for extra in version["extras"]:
                packages.append(f"{package}[{extra}]")
    else:
        if isinstance(version, str) and version != "*":
            package_name = f"{package}{version}"
    packages.append(package_name)
    return packages


def get_install_requirements():
    try:
        # read my pipfile
        with open('Pipfile', 'r') as fh:
            pipfile = fh.read()
        # parse the toml
        pipfile_toml = toml.loads(pipfile)
    except FileNotFoundError:
        return []
    # if the package's key isn't there then just return an empty
    # list
    try:
        required_packages = pipfile_toml['packages'].items()
    except KeyError:
        return []
    # If a version/range is specified in the Pipfile honor it
    # otherwise just list the package
    packages = []
    for package, version in required_packages:
        packages.extend(get_package_requirements(package, version))
    return packages


octo_logger_cpp_root = os.environ.get(
    "OCTO_LOGGER_CPP_ROOT",
    ""
)
octo_encryption_cpp_root = os.environ.get(
    "OCTO_ENCRYPTION_CPP_ROOT",
    ""
)
krb5_root = os.environ.get(
    "KRB5_ROOT",
    ""
)
libfmt_root = os.environ.get(
    "LIBFMT_ROOT",
    ""
)
nlohmann_json_root = os.environ.get(
    "NLOHMANN_JSON_ROOT",
    ""
)
openssl_root = os.environ.get(
    "OPENSSL_ROOT",
    ""
)

for v in ("OCTO_LOGGER_CPP_ROOT", "OCTO_ENCRYPTION_CPP_ROOT", "KRB5_ROOT",
          "LIBFMT_ROOT", "NLOHMANN_JSON_ROOT", "OPENSSL_ROOT"):
    if v not in os.environ.keys():
        logger.warning("[%s] was not found in environment variables,"
                       " using default value!", v)
    else:
        logger.info("[%s] was found in environment variables as [%s]",
                    v, os.environ[v])

compile_args = ["-std=c++17"]
link_args = []
if krb5_root:
    extra_libs = []
    extra_obj_files = [f"{krb5_root}/lib/libkrb5.a",
                       f"{krb5_root}/lib/libk5crypto.a",
                       f"{krb5_root}/lib/libkrb5support.a",
                       f"{krb5_root}/lib/libcom_err.a"]
else:
    extra_libs = ["krb5", "k5crypto", "krb5support", "com_err"]
    extra_obj_files = []
if openssl_root:
    extra_obj_files.extend([
        f"{openssl_root}/lib/libssl.a"
        f"{openssl_root}/lib/libcrypto.a"
    ])
else:
    extra_libs.extend([
        "ssl",
        "crypto"
    ])
if sys.platform == "linux":
    base_libc_path = os.path.join(os.path.dirname(__file__), "libc")
    extra_obj_files.extend([
        os.path.join(base_libc_path, "stat.o"),
        os.path.join(base_libc_path, "stat64.o"),
        os.path.join(base_libc_path, "fstat.o"),
        os.path.join(base_libc_path, "fstat64.o"),
        os.path.join(base_libc_path, "fstatat.o"),
        os.path.join(base_libc_path, "fstatat64.o"),
        os.path.join(base_libc_path, "errno.o"),
        os.path.join(base_libc_path, "explicit_bzero.o")
    ])
    link_args.extend([
        "-pthread",
        "-static-libgcc",
        "-static-libstdc++"
    ])
    extra_libs.extend([
        "resolv",
        "dl"
    ])


krb5_extension = Extension(
    "octo_krb5",
    define_macros=[(p[0], os.environ.get(p[0], p[1])) for p in
                   (("LOGGER_LEVEL", "DEBUG"),)],
    extra_compile_args=compile_args,
    extra_link_args=link_args,
    extra_objects=[
        f"{libfmt_root}/lib/libfmt.a",
        *extra_obj_files
    ],
    include_dirs=[
        "include",
        f"{octo_logger_cpp_root}/include",
        f"{octo_encryption_cpp_root}/include",
        f"{krb5_root}/include",
        f"{libfmt_root}/include",
        f"{nlohmann_json_root}/include"
    ],
    libraries=[
        "octo-logger-cpp",
        "octo-encryption-cpp",
        *extra_libs
    ],
    library_dirs=[
        f"{octo_logger_cpp_root}/lib",
        f"{octo_encryption_cpp_root}/lib",
        f"{krb5_root}/lib",
        f"{libfmt_root}/lib"
    ],
    sources=[
        "src/kerberos-user-credentials.cpp",
        "src/krb5/krb5-kerberos-authenticator.cpp",
        "src/krb5/krb5-kerberos-service-ticket.cpp",
        "src/krb5/krb5-kerberos-tgt-ticket.cpp",
        "src/krb5/krb5-kerberos-serializer.cpp",
        "src/krb5/python/krb5-kerberos-py-bindings.cpp",
        "src/krb5/python/krb5-kerberos-py-types-authenticator.cpp",
        "src/krb5/python/krb5-kerberos-py-types-service-ticket.cpp",
        "src/krb5/python/krb5-kerberos-py-types-tgt-ticket.cpp",
        "src/krb5/python/krb5-kerberos-py-types-user-credentials.cpp",
        "src/krb5/python/krb5-kerberos-py-serializer.cpp"
    ],
)


class BuildExt(build_ext):
    def initialize_options(self):
        self.library_files = None
        build_ext.initialize_options(self)

    def run(self):
        build_ext.run(self)

        if self.library_files:
            for root, files in self.library_files:
                dst = os.path.join(self.build_lib, root)
                os.makedirs(dst, exist_ok=True)
                for f in files:
                    shutil.copy(f, os.path.join(dst, Path(f).name),
                                follow_symlinks=True)



with open(os.path.join(os.path.abspath(os.path.dirname(__file__)), 'README.md'),
          encoding='utf-8') as f:
    long_description = f.read()


setup(
    # Basic project information
    name='octo-pipeline-python',
    version=get_version(),
    # Authorship and online reference
    author='Ofir Iluz',
    author_email='iluzofir@gmail.com',
    url='https://github.com/ofiriluz/octo-pipeline-python',
    # Detailed description
    description='Python Bindings for KRB5',
    long_description=long_description,
    long_description_content_type='text/markdown',
    classifiers=[
        "Intended Audience :: Developers",
        "Programming Language :: C++",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
    # Package configuration
    install_requires=get_install_requirements(),
    name="octo-krb5-python",
    package_data={
        "octo_krb5": ["*.pyi"]
    },
    package_dir={
        "octo_krb5": "bindings/octo_krb5",
    },
    packages=[
        "octo_krb5"
    ],
    # Extensions
    cmdclass={"build_ext": BuildExt},
    command_options={
        "build_ext": {
            "library_files": ("setup.py",
                              [])
        }
    },
    ext_modules=[krb5_extension],
    # Licensing and copyright
    license='MIT',
    zip_safe=False,
)
