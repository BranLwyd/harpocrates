load("@io_bazel_rules_go//go:def.bzl", "go_prefix", "go_library")

go_prefix("github.com/BranLwyd/harpocrates")

go_library(
    name = "handler",
    srcs = [
        "auth.go",
        "content.go",
        "logout.go",
        "misc.go",
        "password.go",
        "search.go",
        "u2f.go",
    ],
    visibility = ["//:__pkg__"],
    deps = [
        "//:assets",
        "//:rate",
        "//:secret",
        "//:session",
        "@cc_mvdan_xurls//:go_default_library",
        "@com_github_tstranex_u2f//:go_default_library",
        "@org_golang_x_text//language:go_default_library",
        "@org_golang_x_text//search:go_default_library",
    ],
)
