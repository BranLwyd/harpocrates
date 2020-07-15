load("@io_bazel_rules_go//go:def.bzl", "go_binary", "go_embed_data", "go_library")

##
## Binaries
##
go_binary(
    name = "harpd",
    srcs = ["harpd.go"],
    pure = "on",
    deps = [
        ":server",
        "//harpd/handler",
        "//harpd/proto:config_go_proto",
        "//secret/proto:key_go_proto",
        "@com_github_golang_protobuf//proto:go_default_library",
        "@org_golang_x_crypto//acme:go_default_library",
        "@org_golang_x_crypto//acme/autocert:go_default_library",
    ],
)

go_binary(
    name = "harpd_debug",
    srcs = ["harpd_debug.go"],
    pure = "on",
    deps = [
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
    importpath = "github.com/BranLwyd/harpocrates/harpd/alert",
)

go_library(
    name = "rate",
    srcs = ["rate.go"],
    importpath = "github.com/BranLwyd/harpocrates/harpd/rate",
    visibility = ["//harpd/handler:__pkg__"],
)

go_library(
    name = "server",
    srcs = ["server.go"],
    importpath = "github.com/BranLwyd/harpocrates/harpd/server",
    deps = [
        ":alert",
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
    importpath = "github.com/BranLwyd/harpocrates/harpd/session",
    visibility = ["//harpd/handler:__pkg__"],
    deps = [
        ":alert",
        ":rate",
        "//secret",
        "@com_github_e3b0c442_warp//:go_default_library",
    ],
)

##
## Static assets
##
go_embed_data(
    name = "embed_assets",
    srcs = glob(
        ["assets/**/*"],
        exclude = ["assets/debug/**/*"],
    ),
    package = "assets",
    var = "Asset",
)

go_library(
    name = "assets",
    srcs = [
        "assets.go",
        ":embed_assets",
    ],
    importpath = "github.com/BranLwyd/harpocrates/harpd/assets",
    visibility = ["//harpd/handler:__pkg__"],
)

go_embed_data(
    name = "embed_debug_assets",
    srcs = glob(["assets/debug/**/*"]),
    package = "debug_assets",
    var = "Asset",
)

go_library(
    name = "debug_assets",
    srcs = [":embed_debug_assets"],
    importpath = "github.com/BranLwyd/harpocrates/harpd/debug_assets",
)
