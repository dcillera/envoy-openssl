workspace(name = "envoy")

local_repository(
    name = "bssl-compat",
    path = "bssl-compat",
)

load("//bazel:api_binding.bzl", "envoy_api_binding")

envoy_api_binding()

load("//bazel:api_repositories.bzl", "envoy_api_dependencies")

envoy_api_dependencies()

load("//bazel:repo.bzl", "envoy_repo")

envoy_repo()

load("//bazel:repositories.bzl", "envoy_dependencies")

envoy_dependencies()

load("//bazel:repositories_extra.bzl", "envoy_dependencies_extra")

envoy_dependencies_extra()

load("//bazel:python_dependencies.bzl", "envoy_python_dependencies")

envoy_python_dependencies()

load("//bazel:dependency_imports.bzl", "envoy_dependency_imports")

envoy_dependency_imports()

load("//bazel:dependency_imports_extra.bzl", "envoy_dependency_imports_extra")

envoy_dependency_imports_extra()

# V8 library
new_local_repository(
    name = "v8_lib",
    build_file = "//:v8_lib.BUILD",
#    path = "/usr/lib64/"
    path = "v8_libs",
)

# Bind wee8 for proxy_wasm_cpp_host
bind(
    name = "wee8",
    actual = "@v8_lib//:wee8",
)

