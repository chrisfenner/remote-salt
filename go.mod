module github.com/chrisfenner/remote-salt

go 1.22

require github.com/google/go-tpm v0.9.0

require (
	github.com/google/go-tpm-tools v0.3.13-0.20230620182252-4639ecce2aba // indirect
	golang.org/x/sys v0.8.0 // indirect
)

replace github.com/google/go-tpm v0.9.0 => github.com/chrisfenner/go-tpm v0.0.0-20230907001436-d2aff1c84977
