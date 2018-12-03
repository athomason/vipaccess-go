package vipaccess

import (
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestGeneratePostBody(t *testing.T) {
	const want = `<?xml version="1.0" encoding="UTF-8" ?>
<GetSharedSecret Id="1412030064" Version="2.0"
    xmlns="http://www.verisign.com/2006/08/vipservice"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <TokenModel>VSST</TokenModel>
    <ActivationCode></ActivationCode>
    <OtpAlgorithm type="HMAC-SHA1-TRUNC-6DIGITS"/>
    <SharedSecretDeliveryMethod>HTTPS</SharedSecretDeliveryMethod>
    <DeviceId>
        <Manufacturer>Apple Inc.</Manufacturer>
        <SerialNo>7QJR44Y54LK3</SerialNo>
        <Model>MacBookPro10,1</Model>
    </DeviceId>
    <Extension extVersion="auth" xsi:type="vip:ProvisionInfoType"
        xmlns:vip="http://www.verisign.com/2006/08/vipservice">
        <AppHandle>iMac010200</AppHandle>
        <ClientIDType>BOARDID</ClientIDType>
        <ClientID>Mac-3E36319D3EA483BD</ClientID>
        <DistChannel>Symantec</DistChannel>
        <ClientInfo>
            <os>MacBookPro10,1</os>
            <platform>iMac</platform>
        </ClientInfo>
        <ClientTimestamp>1412030064</ClientTimestamp>
        <Data>Y95GpBio35otwd2H/4TjrukR0AnG7VR/KJ7qxz5Y370=</Data>
    </Extension>
</GetSharedSecret>`
	got := generatePostBody(&Parameters{
		Timestamp:                  1412030064,
		TokenModel:                 "VSST",
		OTPAlgorithm:               "HMAC-SHA1-TRUNC-6DIGITS",
		SharedSecretDeliveryMethod: "HTTPS",
		Manufacturer:               "Apple Inc.",
		Serial:                     "7QJR44Y54LK3",
		Model:                      "MacBookPro10,1",
		AppHandle:                  "iMac010200",
		ClientIDType:               "BOARDID",
		ClientID:                   "Mac-3E36319D3EA483BD",
		DistChannel:                "Symantec",
		Platform:                   "iMac",
	})
	if diff := cmp.Diff(want, string(got)); diff != "" {
		t.Errorf("-want, +got\n%s", diff)
	}
}

var testToken = &token{
	IV: []byte{
		// b'\x16\xc85)\xa7\xe6\x01\x7f4\x81A\x03\x008\xa3\x1f'
		0x16, 0xc8, 0x35, 0x29, 0xa7, 0xe6, 0x01, 0x7f,
		0x34, 0x81, 0x41, 0x03, 0x00, 0x38, 0xa3, 0x1f,
	},
	ID: "VSST26070843",
	Ciphertext: []byte{
		// b' \xb0px\xe0\x84:\x83\x01,\x90\x11\xce\x87\x94"[\xb4\xfb\x99\xbaoy!fX\xdd\xe5\xda3\x01\x19'
		0x20, 0xb0, 0x70, 0x78, 0xe0, 0x84, 0x3a, 0x83,
		0x01, 0x2c, 0x90, 0x11, 0xce, 0x87, 0x94, 0x22,
		0x5b, 0xb4, 0xfb, 0x99, 0xba, 0x6f, 0x79, 0x21,
		0x66, 0x58, 0xdd, 0xe5, 0xda, 0x33, 0x01, 0x19,
	},
	Expiry: time.Unix(1506382582, 56000000),
}

func TestExtractToken(t *testing.T) {
	const resp = `<?xml version="1.0" encoding="UTF-8"?>
<GetSharedSecretResponse RequestId="1412030064" Version="2.0" xmlns="http://www.verisign.com/2006/08/vipservice">
  <Status>
    <ReasonCode>0000</ReasonCode>
    <StatusMessage>Success</StatusMessage>
  </Status>
  <SharedSecretDeliveryMethod>HTTPS</SharedSecretDeliveryMethod>
  <SecretContainer Version="1.0">
    <EncryptionMethod>
      <PBESalt>u5lgf1Ek8WA0iiIwVkjy26j6pfk=</PBESalt>
      <PBEIterationCount>50</PBEIterationCount>
      <IV>Fsg1KafmAX80gUEDADijHw==</IV>
    </EncryptionMethod>
    <Device>
      <Secret type="HOTP" Id="VSST26070843">
        <Issuer>OU = ID Protection Center, O = VeriSign, Inc.</Issuer>
        <Usage otp="true">
          <AI type="HMAC-SHA1-TRUNC-6DIGITS"/>
          <TimeStep>30</TimeStep>
          <Time>0</Time>
          <ClockDrift>4</ClockDrift>
        </Usage>
        <FriendlyName>OU = ID Protection Center, O = VeriSign, Inc.</FriendlyName>
        <Data>
          <Cipher>ILBweOCEOoMBLJARzoeUIlu0+5m6b3khZljd5dozARk=</Cipher>
          <Digest algorithm="HMAC-SHA1">MoaidW7XDzeTZJqhfRQCZEieARM=</Digest>
        </Data>
        <Expiry>2017-09-25T23:36:22.056Z</Expiry>
      </Secret>
    </Device>
  </SecretContainer>
  <UTCTimestamp>1412030065</UTCTimestamp>
</GetSharedSecretResponse>`
	got, err := extractToken([]byte(resp))
	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(testToken, got); diff != "" {
		t.Errorf("-want, +got\n%s", diff)
	}
}

var testCredential = &Credential{
	ID: "VSST26070843",
	Key: []byte{
		// b'ZqeD\xd9wg]"\x12\x1f7\xc7v6"\xf0\x13\\i'
		0x5a, 0x71, 0x65, 0x44, 0xd9, 0x77, 0x67, 0x5d,
		0x22, 0x12, 0x1f, 0x37, 0xc7, 0x76, 0x36, 0x22,
		0xf0, 0x13, 0x5c, 0x69,
	},
	Expires:     time.Unix(1506382582, 56000000),
	AccountName: "VIP Access",
	Issuer:      "Symantec",
}

func TestBuildCredential(t *testing.T) {
	got, err := testToken.buildCredential(GenerateRandomParameters())
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(testCredential, got); diff != "" {
		t.Errorf("-want, +got\n%s", diff)
	}
}

func TestURI(t *testing.T) {
	got := testCredential.URI()
	want := "otpauth://totp/VIP%20Access:VSST26070843?issuer=Symantec&secret=LJYWKRGZO5TV2IQSD434O5RWELYBGXDJ"
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("-want, +got\n%s", diff)
	}
}

func TestValidate(t *testing.T) {
	if os.Getenv("TEST_NETWORK") == "" {
		t.Skip("skipping validation tests without TEST_NETWORK set")
	}
	if err := testCredential.Validate(); err == nil {
		t.Error("test credential validated unexpectedly")
	}

	realCredential := Credential{
		ID: "VSST81667211",
		Key: []byte{
			0x53, 0x26, 0x23, 0x1a, 0x6d, 0x1f, 0x1d, 0xee,
			0x71, 0x95, 0xf8, 0xf9, 0xbd, 0x41, 0x5c, 0xeb,
			0x7c, 0x64, 0x11, 0xd5,
		},
		Expires: time.Unix(1636678728, 735000000),
	}

	if time.Now().After(realCredential.Expires) {
		t.Skip("skipping validation test of expired credential")
	}

	if err := realCredential.Validate(); err != nil {
		t.Errorf("credential validation failed: %s", err)
	}
}
