load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "io_bazel_rules_go",
    sha256 = "2697f6bc7c529ee5e6a2d9799870b9ec9eaeb3ee7d70ed50b87a2c2c97e13d9e",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_go/releases/download/v0.23.8/rules_go-v0.23.8.tar.gz",
        "https://github.com/bazelbuild/rules_go/releases/download/v0.23.8/rules_go-v0.23.8.tar.gz",
    ],
)

http_archive(
    name = "bazel_gazelle",
    sha256 = "cdb02a887a7187ea4d5a27452311a75ed8637379a1287d8eeb952138ea485f7d",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/bazel-gazelle/releases/download/v0.21.1/bazel-gazelle-v0.21.1.tar.gz",
        "https://github.com/bazelbuild/bazel-gazelle/releases/download/v0.21.1/bazel-gazelle-v0.21.1.tar.gz",
    ],
)

http_archive(
    name = "rules_proto",
    sha256 = "602e7161d9195e50246177e7c55b2f39950a9cf7366f74ed5f22fd45750cd208",
    strip_prefix = "rules_proto-97d8af4dc474595af3900dd85cb3a29ad28cc313",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_proto/archive/97d8af4dc474595af3900dd85cb3a29ad28cc313.tar.gz",
        "https://github.com/bazelbuild/rules_proto/archive/97d8af4dc474595af3900dd85cb3a29ad28cc313.tar.gz",
    ],
)

load("@io_bazel_rules_go//go:deps.bzl", "go_register_toolchains", "go_rules_dependencies")
load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies", "go_repository")
load("@rules_proto//proto:repositories.bzl", "rules_proto_dependencies", "rules_proto_toolchains")

go_rules_dependencies()

go_register_toolchains()

gazelle_dependencies()

rules_proto_dependencies()

rules_proto_toolchains()

go_repository(
    name = "cc_mvdan_xurls",
    commit = "3572df0ef4b3ddcc91d256dde5838eaac042714e",
    importpath = "mvdan.cc/xurls",
)

go_repository(
    name = "com_github_e3b0c442_warp",
    commit = "26555d590c2c25c32dfe9908efff8416f0f1c922",
    importpath = "github.com/e3b0c442/warp",
)

go_repository(
    name = "com_github_fxamacker_cbor",
    commit = "a26ad4a7e59d43c9265c5e997c4f92cb5afe045c",
    importpath = "github.com/fxamacker/cbor/v2",

    # remote & vcs must be specified explicitly since this package uses Go modules above v1
    remote = "https://github.com/fxamacker/cbor",
    vcs = "git",
)

go_repository(
    name = "com_github_x448_float16",
    commit = "e05feda6110a1a856d5e652ddadf51b54b7c9e0a",
    importpath = "github.com/x448/float16",
)

go_repository(
    name = "org_golang_x_crypto",
    commit = "123391ffb6de907695e1066dc40c1ff09322aeb6",
    importpath = "golang.org/x/crypto",
)

go_repository(
    name = "org_golang_x_net",
    commit = "3edf25e44fccea9e11b919341e952fca722ef460",
    importpath = "golang.org/x/net",
)

go_repository(
    name = "org_golang_x_text",
    commit = "23ae387dee1f90d29a23c0e87ee0b46038fbed0e",
    importpath = "golang.org/x/text",
)

go_repository(
    name = "org_golang_x_sys",
    commit = "3d37ad5750ed7900cf6800ca4b000cb87d6e497a",
    importpath = "golang.org/x/sys",
)
