// Copyright 2021-2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"go.uber.org/zap"

	"github.com/veraison/common"
)

func NewVerifierParams() (*common.ParamStore, error) {
	store := common.NewParamStore("verifier")
	err := store.AddParamDefinitions(map[string]*common.ParamDescription{
		"pluginLocations": {
			Kind:     uint32(reflect.String),
			Path:     "plugin.locations",
			Required: common.ParamNecessity_REQUIRED,
		},
		"policyEngineName": {
			Kind:     uint32(reflect.String),
			Path:     "policy.engine_name",
			Required: common.ParamNecessity_REQUIRED,
		},
		"policyStoreName": {
			Kind:     uint32(reflect.String),
			Path:     "policy.store_name",
			Required: common.ParamNecessity_REQUIRED,
		},
		"policyStoreParams": {
			Kind:     uint32(reflect.Map),
			Path:     "policy.store_name",
			Required: common.ParamNecessity_OPTIONAL,
		},
		"vtsHost": {
			Kind:     uint32(reflect.String),
			Path:     "vts.host",
			Required: common.ParamNecessity_OPTIONAL,
		},
		"vtsPort": {
			Kind:     uint32(reflect.Int),
			Path:     "vts.port",
			Required: common.ParamNecessity_OPTIONAL,
		},
	})
	if err != nil {
		return nil, err
	}
	store.Freeze()

	return store, nil
}

func NewVerifier(logger *zap.Logger) (*Verifier, error) {
	v := new(Verifier)

	v.logger = logger

	return v, nil
}

type Verifier struct {
	config *common.ParamStore
	vts    common.VTSClient
	pm     common.IPolicyManager
	pe     common.IPolicyEngine
	logger *zap.Logger
}

func (v *Verifier) Init(
	config *common.ParamStore,
	conn common.ITrustedServicesConnector,
	pm common.IPolicyManager,
	pe common.IPolicyEngine,
) error {
	fmt.Println("verifier/Verifier/Init called with config:", config)
	v.config = config
	v.pm = pm
	v.pe = pe

	var err error
	for {
		v.vts, err = conn.Connect(
			v.config.GetString("VtsHost"),
			v.config.GetInt("VtsPort"),
			v.config.GetStringMapString("VtsParams"),
		)
		if err != nil {
			fmt.Println("verifier/Verifier/Init conn.Connect failed:", err)
			//return err
		}
		if err == nil {
			break
		}
	}

	return nil
}

func (v *Verifier) Close() error {
	// return v.vts.Close()
	return nil
}

func (v *Verifier) Verify(
	token *common.AttestationToken,
) (*common.AttestationResult, error) {
	policy, err := v.pm.GetPolicy(int(token.TenantId), token.Format)
	if err != nil {
		fmt.Println("Verifier::Verify v.pm.GetPolicy failed with err:", err)
		return nil, err
	}

	my_context := context.TODO()
	my_context, _ = context.WithTimeout(my_context, time.Second)

	attestation, err := v.vts.GetAttestation(my_context, token)
	if err != nil {
		fmt.Println("Verifier::Verify v.vts.GetAttestation failed with err:", err)
		return nil, err
	}
	fmt.Println("Verifier::Verify attestation:", attestation)
	attestation.Result.RawEvidence = token.Data

	err = v.pe.Appraise(attestation, policy)
	if err != nil {
		fmt.Println("Verifier::Verify v.pe.Appraise failed with err:", err)
		return nil, err
	}
	fmt.Println("Verifier::Verify completed. Returning attestation.Result and nil")
	return attestation.Result, nil
}
