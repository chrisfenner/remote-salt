// Package remotesalt_test implements some tests for remote-salting of TPM commands.
package remotesalt_test

import (
	"encoding/hex"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func TestRemoteSaltedGetCapability(t *testing.T) {
	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer tpm.Close()

	ek, ekPub2B := getEK(t, tpm)
	defer tpm2.FlushContext{
		FlushHandle: ek,
	}.Execute(tpm)

	ekPub, err := ekPub2B.Contents()
	if err != nil {
		t.Fatalf("Contents() = %v", err)
	}

	encSalt, salt, err := tpm2.MakeEncryptedSalt(*ekPub)
	if err != nil {
		t.Fatalf("MakeEncryptedSalt() = %v", err)
	}

	var nonceCaller tpm2.TPM2BNonce
	nonceCaller.Buffer, err = hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatalf("DecodeString() = %v", err)
	}

	getCap := tpm2.GetCapability{
		Capability:    tpm2.TPMCapPCRs,
		Property:      0,
		PropertyCount: 8,
	}

	var hmac []byte // TODO: have to calculate the HMAC for the command!

	sess, closer, err := tpm2.HMACSession(tpm, tpm2.TPMAlgSHA256, len(nonceCaller.Buffer), tpm2.ExternallySalted(encSalt, &nonceCaller, hmac, ek), tpm2.Audit())
	if err != nil {
		t.Fatalf("HMACSession() = %v", err)
	}
	defer closer()

	rsp, err := getCap.Execute(tpm, sess)
	if err != nil {
		t.Fatalf("GetCapability() = %v", err)
	}

	lastHMAC, err := sess.LastHMAC()
	if err != nil {
		t.Errorf("LastHMAC() = %v", err)
	}

	t.Logf("salt: %x", salt)
	t.Logf("lastHMAC: %#v", lastHMAC)

	// TODO: server has to check the HMAC on the response!

	t.Logf("%v", rsp.CapabilityData.Capability)
}

func getEK(t *testing.T, tpm transport.TPM) (tpm2.TPMHandle, tpm2.TPM2BPublic) {
	t.Helper()

	rsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.ECCEKTemplate),
	}.Execute(tpm)
	if err != nil {
		t.Fatalf("CreatePrimary() = %v", err)
	}

	return rsp.ObjectHandle, rsp.OutPublic
}

func ekPolicy(t transport.TPM, handle tpm2.TPMISHPolicy, nonceTPM tpm2.TPM2BNonce) error {
	cmd := tpm2.PolicySecret{
		AuthHandle:    tpm2.TPMRHEndorsement,
		PolicySession: handle,
		NonceTPM:      nonceTPM,
	}
	_, err := cmd.Execute(t)
	return err
}
