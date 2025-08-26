from conan import ConanFile
from conan.tools.cmake import cmake_layout, CMakeToolchain, CMakeDeps

class WhatsAppDecryptorConan(ConanFile):
    name = "whatsappcryptdecryptor"
    version = "0.1.0"

    settings = "os", "compiler", "build_type", "arch"

    def layout(self):
        cmake_layout(self)

    def requirements(self):
        self.requires("cpr/1.10.0")
        self.requires("nlohmann_json/3.12.0")
        self.requires("cli11/2.4.2")
        self.requires("openssl/3.5.0")
        self.requires("gtest/1.16.0")
        self.requires("gpsoauth-cpp/0.1.0")
        self.requires("date/3.0.4")
        self.requires("zlib/1.3.1")
        self.requires("plog/1.1.10")
        self.requires("protobuf/6.30.1") 

    def generate(self):
        tc = CMakeToolchain(self)
        tc.generate()
        deps = CMakeDeps(self)
        deps.generate()
