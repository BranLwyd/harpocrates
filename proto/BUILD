load("@io_bazel_rules_go//go:def.bzl", "go_prefix")
load("@io_bazel_rules_go//proto:def.bzl", "go_proto_library")

go_prefix("github.com/BranLwyd/harpocrates")

proto_library(
    name = "config_proto",
    srcs = ["config.proto"],
)

go_proto_library(
    name = "config_go_proto",
    proto = ":config_proto",
    visibility = ["//visibility:public"],
)

proto_library(
    name = "counter_proto",
    srcs = ["counter.proto"],
)

go_proto_library(
    name = "counter_go_proto",
    proto = ":counter_proto",
    visibility = ["//visibility:public"],
)

proto_library(
    name = "entry_proto",
    srcs = ["entry.proto"],
)

go_proto_library(
    name = "entry_go_proto",
    proto = ":entry_proto",
    visibility = ["//visibility:public"],
)

proto_library(
    name = "key_proto",
    srcs = ["key.proto"],
)

go_proto_library(
    name = "key_go_proto",
    proto = ":key_proto",
    visibility = ["//visibility:public"],
)
