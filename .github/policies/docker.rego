package docker

deny[msg] {
    input[i] == "USER root"
    not input[j] == "USER 65532:65532"
    msg := "Container must drop root (use nonroot distroless user)"
}

deny[msg] {
    some line := input[_]
    startswith(line, "FROM ")
    endswith(line, ":latest")
    msg := "Pinning a mutable ':latest' tag is not allowed; use digest pin or version tag"
}

deny[msg] {
    some line := input[_]
    contains(line, "sudo ")
    msg := "Dockerfile must not invoke sudo"
}
