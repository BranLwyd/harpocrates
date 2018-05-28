load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

##
## Libraries
##
go_library(
    name = "file",
    srcs = ["file.go"],
    importpath = "github.com/BranLwyd/harpocrates/secret/file",
    deps = [
        ":secret",
    ],
)

go_test(
    name = "file_test",
    timeout = "short",
    srcs = ["file_test.go"],
    embed = [":file"],
)

go_library(
    name = "harp",
    srcs = ["harp.go"],
    importpath = "github.com/BranLwyd/harpocrates/secret/harp",
    deps = [
        ":file",
        ":key_private",
        ":secret",
        "//secret/proto:entry_go_proto",
        "//secret/proto:key_go_proto",
        "@com_github_golang_protobuf//proto:go_default_library",
        "@org_golang_x_crypto//scrypt:go_default_library",
    ],
)

go_library(
    name = "key",
    srcs = ["key.go"],
    importpath = "github.com/BranLwyd/harpocrates/secret/key",
    visibility = ["//visibility:public"],
    deps = [
        ":harp",
        ":key_private",
        ":pgp",
        ":secret",
        "//secret/proto:key_go_proto",
    ],
)

go_library(
    name = "key_private",
    srcs = ["key_private.go"],
    deps = [
        ":secret",
        "//secret/proto:key_go_proto",
    ],
)

go_library(
    name = "pgp",
    srcs = ["pgp.go"],
    importpath = "github.com/BranLwyd/harpocrates/secret/pgp",
    deps = [
        ":file",
        ":key_private",
        ":secret",
        "//secret/proto:key_go_proto",
        "@org_golang_x_crypto//openpgp:go_default_library",
        "@org_golang_x_crypto//openpgp/packet:go_default_library",
        "@org_golang_x_crypto//ripemd160:go_default_library",
    ],
)

go_library(
    name = "secret",
    srcs = ["secret.go"],
    importpath = "github.com/BranLwyd/harpocrates/secret",
    visibility = ["//visibility:public"],
)
