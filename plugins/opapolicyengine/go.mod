module veraison/opapolicyengine

go 1.15

replace github.com/veraison/common => ../../common/

require (
	github.com/hashicorp/go-plugin v1.3.0
	github.com/open-policy-agent/opa v0.42.0
	github.com/stretchr/testify v1.8.0
	github.com/veraison/common v0.0.0
	google.golang.org/protobuf v1.28.0
)
