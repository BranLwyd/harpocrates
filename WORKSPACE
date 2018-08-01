http_archive(
    name = "io_bazel_rules_go",
    sha256 = "ba79c532ac400cefd1859cbc8a9829346aa69e3b99482cd5a54432092cbc3933",
    url = "https://github.com/bazelbuild/rules_go/releases/download/0.13.0/rules_go-0.13.0.tar.gz",
)

http_archive(
    name = "bazel_gazelle",
    sha256 = "bc653d3e058964a5a26dcad02b6c72d7d63e6bb88d94704990b908a1445b8758",
    urls = ["https://github.com/bazelbuild/bazel-gazelle/releases/download/0.13.0/bazel-gazelle-0.13.0.tar.gz"],
)

load("@io_bazel_rules_go//go:def.bzl", "go_rules_dependencies", "go_register_toolchains")
load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies", "go_repository")

go_rules_dependencies()

go_register_toolchains()

gazelle_dependencies()

go_repository(
    name = "cc_mvdan_xurls",
    commit = "284d56d6f9b9a86a9d5dcf57ec1340731a356d1b",
    importpath = "mvdan.cc/xurls",
)

go_repository(
    name = "com_github_howeyc_gopass",
    commit = "bf9dde6d0d2c004a008c27aaee91170c786f6db8",
    importpath = "github.com/howeyc/gopass",
)

go_repository(
    name = "com_github_jteeuwen_go-bindata",
    commit = "a0ff2567cfb70903282db057e799fd826784d41d",
    importpath = "github.com/jteeuwen/go-bindata",
)

go_repository(
    name = "com_github_tstranex_u2f",
    commit = "d21a03e0b1d9fc1df59ff54e7a513655c1748b0c",
    importpath = "github.com/tstranex/u2f",
)

go_repository(
    name = "org_golang_x_crypto",
    commit = "c126467f60eb25f8f27e5a981f32a87e3965053f",
    importpath = "golang.org/x/crypto",
)

go_repository(
    name = "org_golang_x_text",
    commit = "75cc3cad82b5f47d3fb229ddda8c5167da14f294",
    importpath = "golang.org/x/text",
)

go_repository(
    name = "org_golang_x_sys",
    commit = "d5840adf789d732bc8b00f37b26ca956a7cc8e79",
    importpath = "golang.org/x/sys",
)
