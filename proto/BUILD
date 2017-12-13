load("@io_bazel_rules_go//go:def.bzl", "go_prefix")
load("@io_bazel_rules_go//proto:go_proto_library.bzl", "go_proto_library")

go_prefix("github.com/BranLwyd/harpocrates")

go_proto_library(
  name = "key_proto",
  srcs = ["key.proto"],
  visibility = ["//visibility:public"],
)
