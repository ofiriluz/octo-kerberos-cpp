import os
import subprocess
from conans import CMake, ConanFile, tools


class OctoKerberosCPPConan(ConanFile):
    name = "octo-kerberos-cpp"
    version = "1.0.0"
    url = "https://github.com/ofiriluz/octo-kerberos-cpp"
    author = "Ofir Iluz"
    generators = "cmake"
    settings = "os", "compiler", "build_type", "arch"

    def requirements(self):
        self.requires("octo-logger-cpp@1.0.0")
        self.requires("octo-encryption-cpp@1.0.0")
        self.requires("fmt@9.0.0")
        self.requires("krb5@1.18.3")
        self.requires("openssl/3.0.5")

    def build(self):
        if self.settings.os == "Linux":
            libc_path = os.path.join(self.source_folder, 'libc')
            if not os.path.exists(libc_path) and not os.path.exists(os.path.join(libc_path, "fstat.o")):
                os.makedirs(libc_path, exist_ok=True)
                rc = subprocess.call(f"cd {libc_path} && ar x $(gcc --print-file-name=libc.a)",
                                    shell=True)
                if rc != 0:
                    raise RuntimeError("Failed to extract libc for static linkage")
        cmake = CMake(self, generator="Unix Makefiles", parallel=True)
        cmake.configure()
        cmake.build()
        cmake.test()
        cmake.install()

    def package(self):
        cmake = CMake(self)
        cmake.install()

    def package_info(self):
        self.cpp_info.libs = tools.collect_libs(self)
