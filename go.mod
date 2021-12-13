module github.com/traefik/neo-agent

go 1.17

require (
	github.com/abbot/go-http-auth v0.4.0
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/ettle/strcase v0.1.1
	github.com/hashicorp/go-retryablehttp v0.7.0
	github.com/pquerna/cachecontrol v0.1.0
	github.com/rs/zerolog v1.26.0
	github.com/stretchr/testify v1.7.0
	github.com/urfave/cli/v2 v2.3.0
	github.com/vulcand/predicate v1.1.0
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	gopkg.in/square/go-jose.v2 v2.6.0
	gopkg.in/yaml.v3 v3.0.0-20200313102051-9f266ea9e77c
)

require (
	github.com/cpuguy83/go-md2man/v2 v2.0.0-20190314233015-f79a8a8ca69d // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/google/go-cmp v0.5.6 // indirect
	github.com/gravitational/trace v1.1.15 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.1 // indirect
	github.com/jonboulle/clockwork v0.2.2 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/russross/blackfriday/v2 v2.0.1 // indirect
	github.com/shurcooL/sanitized_anchor_name v1.0.0 // indirect
	github.com/sirupsen/logrus v1.8.1 // indirect
	golang.org/x/crypto v0.0.0-20200317142112-1b76d66859c6 // indirect
	golang.org/x/net v0.0.0-20210805182204-aaa1db679c0d // indirect
	golang.org/x/sys v0.0.0-20210809222454-d867a43fc93e // indirect
)

replace github.com/abbot/go-http-auth => github.com/containous/go-http-auth v0.4.1-0.20210329152427-e70ce7ef1ade
