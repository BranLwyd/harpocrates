load("@io_bazel_rules_go//go:def.bzl", "go_prefix", "go_library", "go_test")

go_prefix("github.com/BranLwyd/harpocrates")

##
## Libraries
##
go_library(
    name = "file",
    srcs = ["file.go"],
    deps = [
        ":secret",
    ],
)

go_library(
    name = "harp",
    srcs = ["harp.go"],
    deps = [
        ":file",
        ":key_private",
        ":secret",
        "//proto:entry_proto",
        "//proto:key_proto",
        "@com_github_golang_protobuf//proto:go_default_library",
        "@org_golang_x_crypto//scrypt:go_default_library",
    ],
)

go_library(
    name = "key",
    srcs = ["key.go"],
    visibility = ["//visibility:public"],
    deps = [
        ":harp",
        ":key_private",
        ":pgp",
        ":secret",
        "//proto:key_proto",
    ],
)

go_library(
    name = "key_private",
    srcs = ["key_private.go"],
    deps = [
        ":secret",
        "//proto:key_proto",
    ],
)

go_library(
    name = "pgp",
    srcs = ["pgp.go"],
    deps = [
        ":file",
        ":key_private",
        ":secret",
        "//proto:key_proto",
        "@org_golang_x_crypto//openpgp:go_default_library",
        "@org_golang_x_crypto//openpgp/packet:go_default_library",
        "@org_golang_x_crypto//ripemd160:go_default_library",
    ],
)

go_test(
    name = "pgp_test",
    timeout = "short",
    srcs = ["pgp_test.go"],
    library = ":pgp",
    deps = [
        "@org_golang_x_crypto//openpgp:go_default_library",
    ],
)

go_library(
    name = "secret",
    srcs = ["secret.go"],
    visibility = ["//visibility:public"],
)
