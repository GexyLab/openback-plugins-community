"""Conan 2 recipe of openback-app-auth-cpp.

    conan install . --build=missing                 # dependencies (+ Catch2 for the tests)
    conan build . --build=missing                   # configure, build, run the tests
    conan create . --build=missing                  # package into the local cache
"""
from conan import ConanFile
from conan.tools.cmake import CMake, CMakeDeps, CMakeToolchain, cmake_layout
from conan.tools.files import copy


class OpenBackAppAuthConan(ConanFile):
    name = "openback-app-auth-cpp"
    version = "1.0.0"
    license = "MIT"
    author = "GexyLab"
    url = "https://github.com/GexyLab/openback-plugins-community"
    homepage = "https://github.com/GexyLab/openback-plugins-community"  # subdirectory SDK/Auth/cpp/1.0.0
    description = ("C++ SDK of the OpenBack App authenticator (user pools): sign-in, sessions, "
                   "OIDC with PKCE, ES256 token verification")
    topics = ("openback", "auth", "oidc", "authentication")
    package_type = "library"
    settings = "os", "compiler", "build_type", "arch"
    options = {"shared": [True, False], "fPIC": [True, False], "with_curl": [True, False]}
    default_options = {"shared": False, "fPIC": True, "with_curl": True}
    exports_sources = ("CMakeLists.txt", "cmake/*", "include/*", "src/*", "tests/*", "examples/*",
                       "LICENSE", "README.md", "CHANGELOG.md")

    def config_options(self):
        if self.settings.os == "Windows":
            del self.options.fPIC

    def configure(self):
        if self.options.shared:
            self.options.rm_safe("fPIC")

    def layout(self):
        cmake_layout(self)

    def requirements(self):
        self.requires("openssl/[>=1.1.1 <4]")
        self.requires("nlohmann_json/3.11.3", transitive_headers=True)
        if self.options.with_curl:
            self.requires("libcurl/[>=7.80 <9]")

    def build_requirements(self):
        self.test_requires("catch2/3.7.1")

    def generate(self):
        skip_tests = self.conf.get("tools.build:skip_test", default=False, check_type=bool)
        toolchain = CMakeToolchain(self)
        toolchain.cache_variables["OPENBACK_APP_AUTH_WITH_CURL"] = bool(self.options.with_curl)
        toolchain.cache_variables["OPENBACK_APP_AUTH_BUILD_TESTS"] = not skip_tests
        toolchain.cache_variables["OPENBACK_APP_AUTH_BUILD_EXAMPLES"] = False
        toolchain.cache_variables["OPENBACK_APP_AUTH_INSTALL"] = True
        toolchain.generate()
        CMakeDeps(self).generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()
        if not self.conf.get("tools.build:skip_test", default=False, check_type=bool):
            cmake.test()

    def package(self):
        copy(self, "LICENSE", src=self.source_folder, dst=f"{self.package_folder}/licenses")
        CMake(self).install()

    def package_info(self):
        self.cpp_info.set_property("cmake_file_name", "openback-app-auth-cpp")
        self.cpp_info.set_property("cmake_target_name", "openback::app_auth")
        self.cpp_info.libs = ["openback-app-auth"]
        self.cpp_info.requires = ["openssl::crypto", "nlohmann_json::nlohmann_json"]
        if self.options.with_curl:
            self.cpp_info.requires.append("libcurl::curl")
        if self.settings.os in ("Linux", "FreeBSD"):
            self.cpp_info.system_libs = ["pthread"]
