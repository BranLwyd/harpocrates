load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "io_bazel_rules_go",
    sha256 = "301c8b39b0808c49f98895faa6aa8c92cbd605ab5ad4b6a3a652da33a1a2ba2e",
    urls = ["https://github.com/bazelbuild/rules_go/releases/download/0.18.0/rules_go-0.18.0.tar.gz"],
)

http_archive(
    name = "bazel_gazelle",
    sha256 = "3c681998538231a2d24d0c07ed5a7658cb72bfb5fd4bf9911157c0e9ac6a2687",
    urls = ["https://github.com/bazelbuild/bazel-gazelle/releases/download/0.17.0/bazel-gazelle-0.17.0.tar.gz"],
)

load("@io_bazel_rules_go//go:deps.bzl", "go_rules_dependencies", "go_register_toolchains")
load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies", "go_repository")

go_rules_dependencies()

go_register_toolchains()

gazelle_dependencies()

go_repository(
    name = "cc_mvdan_xurls",
    commit = "48f3ccc8a4d8cf06eb160dab0617e89b669635f7",
    importpath = "mvdan.cc/xurls",
)

go_repository(
    name = "com_github_howeyc_gopass",
    commit = "bf9dde6d0d2c004a008c27aaee91170c786f6db8",
    importpath = "github.com/howeyc/gopass",
)

go_repository(
    name = "com_github_tstranex_u2f",
    commit = "d21a03e0b1d9fc1df59ff54e7a513655c1748b0c",
    importpath = "github.com/tstranex/u2f",
)

go_repository(
    name = "org_golang_x_crypto",
    commit = "31a38585487a4b1fd6ff4f8f3db26f1fb296ac82",
    importpath = "golang.org/x/crypto",
)

go_repository(
    name = "org_golang_x_text",
    commit = "d14c52b222ee852cdba8b07206ca0c614b389876",
    importpath = "golang.org/x/text",
)

go_repository(
    name = "org_golang_x_sys",
    commit = "775f8194d0f9e65c46913c7be783d3d95a29333c",
    importpath = "golang.org/x/sys",
)
