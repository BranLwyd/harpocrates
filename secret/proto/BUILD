load("@rules_proto//proto:defs.bzl", "proto_library")
load("@io_bazel_rules_go//proto:def.bzl", "go_proto_library")

proto_library(
    name = "entry_proto",
    srcs = ["entry.proto"],
)

go_proto_library(
    name = "entry_go_proto",
    importpath = "github.com/BranLwyd/harpocrates/secret/proto/entry_go_proto",
    proto = ":entry_proto",
    visibility = ["//secret:__pkg__"],
)

proto_library(
    name = "key_proto",
    srcs = ["key.proto"],
)

go_proto_library(
    name = "key_go_proto",
    importpath = "github.com/BranLwyd/harpocrates/secret/proto/key_go_proto",
    proto = ":key_proto",
    visibility = ["//visibility:public"],
)
