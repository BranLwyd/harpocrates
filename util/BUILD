load("@io_bazel_rules_go//go:def.bzl", "go_prefix", "go_binary")

go_prefix("github.com/BranLwyd/harpocrates")

##
## Binaries
##
go_binary(
    name = "gen_harp_key",
    srcs = ["gen_harp_key.go"],
    pure = "on",
    deps = [
        "//proto:key_proto",
        "@com_github_golang_protobuf//proto:go_default_library",
        "@org_golang_x_crypto//scrypt:go_default_library",
    ],
)

go_binary(
    name = "rotate_key",
    srcs = ["rotate_key.go"],
    pure = "on",
    deps = [
        "//proto:key_proto",
        "//secret",
        "//secret:key",
        "@com_github_golang_protobuf//proto:go_default_library",
    ],
)

go_binary(
    name = "wrap_pgp_serialized_entity",
    srcs = ["wrap_pgp_serialized_entity.go"],
    pure = "on",
    deps = [
        "//proto:key_proto",
        "@com_github_golang_protobuf//proto:go_default_library",
    ],
)
