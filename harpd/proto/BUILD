load("@rules_proto//proto:defs.bzl", "proto_library")
load("@io_bazel_rules_go//proto:def.bzl", "go_proto_library")

proto_library(
    name = "config_proto",
    srcs = ["config.proto"],
)

go_proto_library(
    name = "config_go_proto",
    importpath = "github.com/BranLwyd/harpocrates/harpd/proto/config_go_proto",
    proto = ":config_proto",
    visibility = ["//harpd:__pkg__"],
)
