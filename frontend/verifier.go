// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package frontend

import (
	"encoding/json"
	"fmt"
	"path"
	"strings"

	"github.com/veraison/common"
	"github.com/veraison/policy"
	"github.com/veraison/trustedservices"
	"github.com/veraison/verifier"

	"go.uber.org/zap"
)

func NewVerifier(pluginDir string, dbPath string, logger *zap.Logger) (*verifier.Verifier, error) {
	fmt.Println("frontend/verifier/NewVerifier started")
	policyDbPath := path.Join(dbPath, "policy.sqlite3")

	verifierParams, err := verifier.NewVerifierParams()
	if err != nil {
		fmt.Println("frontend/verifier/NewVerifier call to NewVerifierParams failed:", err)
		return nil, err
	}

	pluginLocations := []string{pluginDir}

	endorsementKVStoreConfig := make(map[string]string)
	endorsementKVStoreConfig["backend"] = "memory" // could also be "sql"
	marshalledEKSC, err := json.Marshal(endorsementKVStoreConfig)
	if err != nil {
		fmt.Println("Marsal on endorsementKVStoreConfig failed:", err)
		return nil, err
	}
	trustAnchorKVStoreConfig := make(map[string]string)
	trustAnchorKVStoreConfig["backend"] = "memory" // could also be "sql"
	marshalledTAKSC, err := json.Marshal(trustAnchorKVStoreConfig)
	if err != nil {
		fmt.Println("Marshal on trustAnchorKVStoreConfig failed:", err)
		return nil, err
	}
	vtsParams := make(map[string]string)
	vtsParams["PluginLocations"] = strings.Join(pluginLocations[:], ",")
	vtsParams["EndorsementKVStoreConfig"] = string(marshalledEKSC)
	vtsParams["TrustAnchorKVStoreConfig"] = string(marshalledTAKSC)

	fmt.Println("frontend/NewVerifier vtsParams:", vtsParams)
	// TODO make configurable
	verifierParams.SetStringSlice("PluginLocations", pluginLocations)
	verifierParams.SetString("VtsHost", "vts")
	verifierParams.SetInt("VtsPort", 50051)
	verifierParams.SetStringMapString("VtsParams", vtsParams)
	verifierParams.SetString("dbpath", "doogie")

	v, err := verifier.NewVerifier(logger)
	if err != nil {
		fmt.Println("frontend/verifier/NewVerifier call to verifier.NewVerifier failed")
		return nil, err
	}

	connector := new(trustedservices.VTSClientConnector)

	policyManagerParams, err := policy.NewManagerParamStore()
	if err != nil {
		fmt.Println("frontend/verifier/NewVerifier call to NewManagerParamStore failed")
		return nil, err
	}
	// TODO make configurable
	policyManagerParams.SetStringSlice("PluginLocations", pluginLocations)
	policyManagerParams.SetString("PolicyStoreName", "sqlite")
	policyManagerParams.SetStringMapString("PolicyStoreParams", map[string]string{"dbpath": policyDbPath})
	policyManagerParams.SetString("dbpath", "/opt/veraison/policy.sqlite3")

	pm := policy.NewManager()
	err = pm.Init(policyManagerParams)
	if err != nil {
		fmt.Println("frontend/verifier/NewVerifier call to pm.Init failed")
		return nil, err
	}

	pe, err := common.LoadPolicyEnginePlugin(pluginLocations, "opa")
	if err != nil {
		return nil, err
	}

	err = v.Init(verifierParams, connector, pm, pe)
	fmt.Println("frontend/verifier/NewVerifier finished. returning err:", err)
	return v, err
}
