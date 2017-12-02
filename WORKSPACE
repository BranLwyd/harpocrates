http_archive(
    name = "io_bazel_rules_go",
    sha256 = "341d5eacef704415386974bc82a1783a8b7ffbff2ab6ba02375e1ca20d9b031c",
    url = "https://github.com/bazelbuild/rules_go/releases/download/0.7.1/rules_go-0.7.1.tar.gz",
)

load("@io_bazel_rules_go//go:def.bzl", "go_rules_dependencies", "go_register_toolchains", "go_repository")

go_rules_dependencies()

go_register_toolchains()

go_repository(
    name = "cc_mvdan_xurls",
    commit = "284d56d6f9b9a86a9d5dcf57ec1340731a356d1b",
    importpath = "mvdan.cc/xurls",
)

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
