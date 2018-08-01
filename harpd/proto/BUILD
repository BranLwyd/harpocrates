load("@io_bazel_rules_go//proto:def.bzl", "go_proto_library")

proto_library(
    name = "config_proto",
    srcs = ["config.proto"],
)

go_proto_library(
    name = "config_go_proto",
    proto = ":config_proto",
    importpath = "github.com/BranLwyd/harpocrates/harpd/proto/config_go_proto",
    visibility = ["//harpd:__pkg__"],
)

proto_library(
    name = "counter_proto",
    srcs = ["counter.proto"],
)

go_proto_library(
    name = "counter_go_proto",
    proto = ":counter_proto",
    importpath = "github.com/BranLwyd/harpocrates/harpd/proto/counter_go_proto",
    visibility = ["//harpd:__pkg__"],
)
