package docker

test_latest_tag_rejected {
    deny["Pinning a mutable ':latest' tag is not allowed; use digest pin or version tag"]
        with input as ["FROM debian:latest"]
}

test_nonroot_absent_rejected {
    count(deny) > 0 with input as ["FROM debian:bookworm", "USER root"]
}
