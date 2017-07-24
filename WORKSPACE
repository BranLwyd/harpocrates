git_repository(
    name = "io_bazel_rules_go",
    remote = "https://github.com/bazelbuild/rules_go.git",
    tag = "0.5.2",
)

load("@io_bazel_rules_go//go:def.bzl", "go_repositories", "go_repository")

go_repository(
    name = "org_golang_x_crypto",
    commit = "6914964337150723782436d56b3f21610a74ce7b",
    importpath = "golang.org/x/crypto",
)

go_repository(
    name = "org_golang_x_text",
    commit = "836efe42bb4aa16aaa17b9c155d8813d336ed720",
    importpath = "golang.org/x/text",
)

go_repository(
    name = "com_github_tstranex_u2f",
    commit = "c46b9c6b15141e1c75d096258e560996b68ef8cb",
    importpath = "github.com/tstranex/u2f",
)

go_repositories()
