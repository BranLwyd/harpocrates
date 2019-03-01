load("@io_bazel_rules_go//go:def.bzl", "go_binary")

##
## Binaries
##
go_binary(
    name = "gen_pgp_key",
    srcs = ["gen_pgp_key.go"],
    pure = "on",
    deps = [
        "//secret/proto:key_go_proto",
        "@com_github_golang_protobuf//proto:go_default_library",
        "@org_golang_x_crypto//openpgp:go_default_library",
        "@org_golang_x_crypto//openpgp/packet:go_default_library",
    ],
)

go_binary(
    name = "gen_sbox_key",
    srcs = ["gen_sbox_key.go"],
    pure = "on",
    deps = [
        "//secret/proto:key_go_proto",
        "@com_github_golang_protobuf//proto:go_default_library",
        "@com_github_howeyc_gopass//:go_default_library",
        "@org_golang_x_crypto//nacl/secretbox:go_default_library",
        "@org_golang_x_crypto//scrypt:go_default_library",
    ],
)

go_binary(
    name = "rotate_key",
    srcs = ["rotate_key.go"],
    pure = "on",
    deps = [
        "//secret",
        "//secret:key",
        "//secret/proto:key_go_proto",
        "@com_github_golang_protobuf//proto:go_default_library",
        "@com_github_howeyc_gopass//:go_default_library",
    ],
)

go_binary(
    name = "describe_key",
    srcs = ["describe_key.go"],
    pure = "on",
    deps = [
        "//secret/proto:key_go_proto",
        "@com_github_golang_protobuf//proto:go_default_library",
    ],
)
