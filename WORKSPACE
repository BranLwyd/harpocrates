load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "io_bazel_rules_go",
    sha256 = "2b1641428dff9018f9e85c0384f03ec6c10660d935b750e3fa1492a281a53b0f",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_go/releases/download/v0.29.0/rules_go-v0.29.0.zip",
        "https://github.com/bazelbuild/rules_go/releases/download/v0.29.0/rules_go-v0.29.0.zip",
    ],
)

http_archive(
    name = "bazel_gazelle",
    sha256 = "de69a09dc70417580aabf20a28619bb3ef60d038470c7cf8442fafcf627c21cb",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/bazel-gazelle/releases/download/v0.24.0/bazel-gazelle-v0.24.0.tar.gz",
        "https://github.com/bazelbuild/bazel-gazelle/releases/download/v0.24.0/bazel-gazelle-v0.24.0.tar.gz",
    ],
)

http_archive(
    name = "rules_proto",
    sha256 = "66bfdf8782796239d3875d37e7de19b1d94301e8972b3cbd2446b332429b4df1",
    strip_prefix = "rules_proto-4.0.0",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_proto/archive/refs/tags/4.0.0.tar.gz",
        "https://github.com/bazelbuild/rules_proto/archive/refs/tags/4.0.0.tar.gz",
    ],
)

load("@io_bazel_rules_go//go:deps.bzl", "go_register_toolchains", "go_rules_dependencies")
load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies", "go_repository")
load("@rules_proto//proto:repositories.bzl", "rules_proto_dependencies", "rules_proto_toolchains")

go_rules_dependencies()

go_register_toolchains(version = "1.17.2")

gazelle_dependencies()

rules_proto_dependencies()

rules_proto_toolchains()

go_repository(
    name = "cc_mvdan_xurls",
    commit = "2c03c21edb876f9d4284aa60d2015b0122164b4e",
    importpath = "mvdan.cc/xurls",
)

go_repository(
    name = "com_github_e3b0c442_warp",
    commit = "166d2664027ee7c68a38a21404c0013c335b2290",
    importpath = "github.com/e3b0c442/warp",
)

go_repository(
    name = "com_github_fxamacker_cbor",
    commit = "f70d0168fee08fd1aa777e96dcb09365b585fe2f",
    importpath = "github.com/fxamacker/cbor/v2",

    # remote & vcs must be specified explicitly since this package uses Go modules above v1
    remote = "https://github.com/fxamacker/cbor",
    vcs = "git",
)

go_repository(
    name = "com_github_x448_float16",
    commit = "cfc9344828973b2bc879b2d1030b821aa614d48e",
    importpath = "github.com/x448/float16",
)

go_repository(
    name = "org_golang_x_crypto",
    commit = "089bfa5675191fd96a44247682f76ebca03d7916",
    importpath = "golang.org/x/crypto",
)

go_repository(
    name = "org_golang_x_net",
    commit = "d418f374d30933c6c7db22cf349625c295a5afaa",
    importpath = "golang.org/x/net",
)

go_repository(
    name = "org_golang_x_term",
    commit = "03fcf44c2211dcd5eb77510b5f7c1fb02d6ded50",
    importpath = "golang.org/x/term",
)

go_repository(
    name = "org_golang_x_text",
    commit = "5bd84dd9b33bd2bdebd8a6a6477920a8e492d47f",
    importpath = "golang.org/x/text",
)

go_repository(
    name = "org_golang_x_sys",
    commit = "d6a326fbbf70813f3ee5d3282c44664092a39fb1",
    importpath = "golang.org/x/sys",
)
