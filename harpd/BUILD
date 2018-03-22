load("@io_bazel_rules_go//go:def.bzl", "go_prefix", "go_binary", "go_library")

go_prefix("github.com/BranLwyd/harpocrates")

##
## Binaries
##
go_binary(
    name = "harpd",
    srcs = ["harpd.go"],
    pure = "on",
    deps = [
        ":counter",
        ":server",
        "//harpd/handler",
        "//harpd/proto:config_go_proto",
        "//secret/proto:key_go_proto",
        "@com_github_golang_protobuf//proto:go_default_library",
        "@org_golang_x_crypto//acme/autocert:go_default_library",
    ],
)

go_binary(
    name = "harpd_debug",
    srcs = ["harpd_debug.go"],
    pure = "on",
    deps = [
        ":counter",
        ":debug_assets",
        ":server",
        "//harpd/handler",
        "//harpd/proto:config_go_proto",
        "//secret/proto:key_go_proto",
        "@com_github_golang_protobuf//proto:go_default_library",
    ],
)

##
## Libraries
##
go_library(
    name = "alert",
    srcs = ["alert.go"],
)

go_library(
    name = "counter",
    srcs = ["counter.go"],
    deps = [
        "//harpd/proto:counter_go_proto",
        "@com_github_golang_protobuf//proto:go_default_library",
    ],
)

go_library(
    name = "rate",
    srcs = ["rate.go"],
    visibility = ["//harpd/handler:__pkg__"],
)

go_library(
    name = "server",
    srcs = ["server.go"],
    deps = [
        ":alert",
        ":counter",
        ":session",
        "//harpd/handler",
        "//harpd/proto:config_go_proto",
        "//secret:key",
        "//secret/proto:key_go_proto",
    ],
)

go_library(
    name = "session",
    srcs = ["session.go"],
    visibility = ["//harpd/handler:__pkg__"],
    deps = [
        ":alert",
        ":counter",
        ":rate",
        "//secret",
        "@com_github_tstranex_u2f//:go_default_library",
    ],
)

##
## Static assets
##
filegroup(
    name = "assets_files",
    srcs = glob(
        ["assets/**/*"],
        exclude = ["assets/debug/**/*"],
    ),
)

genrule(
    name = "assets_go",
    srcs = [":assets_files"],
    outs = ["assets.go"],
    cmd = "$(location @com_github_jteeuwen_go-bindata//go-bindata) -o $@ --nomemcopy --nocompress --pkg=assets --prefix=harpd/assets/ $(locations :assets_files)",
    tools = ["@com_github_jteeuwen_go-bindata//go-bindata"],
)

go_library(
    name = "assets",
    srcs = ["assets.go"],
    visibility = ["//harpd/handler:__pkg__"],
)

filegroup(
    name = "debug_assets_files",
    srcs = glob(["assets/debug/**/*"]),
)

genrule(
    name = "debug_assets_go",
    srcs = [":debug_assets_files"],
    outs = ["debug_assets.go"],
    cmd = "$(location @com_github_jteeuwen_go-bindata//go-bindata) -o $@ --nomemcopy --nocompress --pkg=debug_assets --prefix=harpd/assets/ $(locations :debug_assets_files)",
    tools = ["@com_github_jteeuwen_go-bindata//go-bindata"],
)

go_library(
    name = "debug_assets",
    srcs = ["debug_assets.go"],
)
