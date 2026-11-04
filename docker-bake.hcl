// Builds the shared Chainkeeper image and tags it for both binaries.
group "default" {
  targets = ["ck", "ck-server"]
}

target "common" {
  context    = "."
  dockerfile = "Dockerfile"
  platforms  = ["linux/amd64", "linux/arm64"]
}

target "ck" {
  inherits = ["common"]
  tags     = ["chainkeeper/ck:latest"]
}

target "ck-server" {
  inherits = ["common"]
  tags     = ["chainkeeper/ck-server:latest"]
}
