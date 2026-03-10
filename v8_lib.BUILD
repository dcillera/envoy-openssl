load("@rules_cc//cc:defs.bzl", "cc_library")

licenses(["notice"])  # Apache 2

# V8 library built in proxy-wasm-cpp-host
cc_library(
    name = "libv8-pwch-lib",
    srcs = [
        "libv8.so",
        "libv8_libbase.so",
        "libv8_libplatform.so"
    ],
    linkopts = [
        "-Wl,--no-as-needed",
    ],
    linkstatic = False,
    alwayslink = 1,
    visibility = ["//visibility:public"],
)

# Combined target with headers and libraries for wee8
cc_library(
    name = "wee8",
    deps = [
        ":libv8-pwch-lib",
        "@v8//:wee8_lib_includes_lib",
    ],
    visibility = ["//visibility:public"],
)
