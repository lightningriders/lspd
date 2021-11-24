package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	b64 "encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	pb "github.com/breez/lspd/rpc"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/golang/protobuf/proto"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/signrpc"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/zpay32"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"log"
	"net/http"
	"strings"
)

const (

	senderLndHost     = "localhost:10008"
	senderMacaroonHex      = "0201036C6E6402F801030A106E15A24668C61703DE4E6FDD12BDBCFC1201301A160A0761646472657373120472656164120577726974651A130A04696E666F120472656164120577726974651A170A08696E766F69636573120472656164120577726974651A210A086D616361726F6F6E120867656E6572617465120472656164120577726974651A160A076D657373616765120472656164120577726974651A170A086F6666636861696E120472656164120577726974651A160A076F6E636861696E120472656164120577726974651A140A057065657273120472656164120577726974651A180A067369676E6572120867656E657261746512047265616400000620BAB283B2BEFDEC6FAB86670D4007808FCC7B560DEBC1DC147D6B5DF5DC813F75"
	senderLndCert          = "-----BEGIN CERTIFICATE-----\\nMIICnDCCAkOgAwIBAgIRAMALYX8WRq+rhLxa5cjJCD0wCgYIKoZIzj0EAwIwRzEf\\nMB0GA1UEChMWbG5kIGF1dG9nZW5lcmF0ZWQgY2VydDEkMCIGA1UEAxMbc2xuZC0z\\nMjUwNi04NWM0YmY3YzQ0LW1xY243MB4XDTIxMTAyNzE4NDM0OVoXDTIyMTIyMjE4\\nNDM0OVowRzEfMB0GA1UEChMWbG5kIGF1dG9nZW5lcmF0ZWQgY2VydDEkMCIGA1UE\\nAxMbc2xuZC0zMjUwNi04NWM0YmY3YzQ0LW1xY243MFkwEwYHKoZIzj0CAQYIKoZI\\nzj0DAQcDQgAEd/gs5j4k+CmMZsna9iv+AyAqLNsPc1xus/4rz5LPkHzNoGZWVF8Y\\nlWXOsNA/mafyflS8ZFRFCclJqx2+58RWZqOCAQ4wggEKMA4GA1UdDwEB/wQEAwIC\\npDATBgNVHSUEDDAKBggrBgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQW\\nBBTdcGl03ZhaRi4tnpY/Ujtd1tJCzTCBsgYDVR0RBIGqMIGnghtzbG5kLTMyNTA2\\nLTg1YzRiZjdjNDQtbXFjbjeCCWxvY2FsaG9zdIIXc2xuZC0zMjUwNi5sbi5scXdk\\nLnRlY2iCE3NsbmQtMzI1MDYubHF3ZC1sbmSCBHVuaXiCCnVuaXhwYWNrZXSCB2J1\\nZmNvbm6HBH8AAAGHEAAAAAAAAAAAAAAAAAAAAAGHBAoBBdeHEP6AAAAAAAAAKG3G\\n//5wi7OHBMCoe/wwCgYIKoZIzj0EAwIDRwAwRAIgb4FEEo+7XFHuElIsPnzsIoyR\\noTMzQ9GeUO6asmNYb7cCIGmT7n74Y1KKxcms/2lh6EdcBVoyK2pc/YDK+tgOZrD3\\n-----END CERTIFICATE-----"

	recipientPubkey  = "02da5a215b066d8d71f5ecc2ccdb5e8321e9210b37eb0da3701a5ce2c84c5419eb"
	recipientLndHost     = "localhost:10007"
	recipientMacaroonHex = "0201036C6E6402F801030A104E9ED88A137C5A53F3786683A52CD64B1201301A160A0761646472657373120472656164120577726974651A130A04696E666F120472656164120577726974651A170A08696E766F69636573120472656164120577726974651A210A086D616361726F6F6E120867656E6572617465120472656164120577726974651A160A076D657373616765120472656164120577726974651A170A086F6666636861696E120472656164120577726974651A160A076F6E636861696E120472656164120577726974651A140A057065657273120472656164120577726974651A180A067369676E6572120867656E657261746512047265616400000620530ED37DFDD4D43B81BC04176BB59F30FD76356E2F1DA208D653D68ABF640F96"
	recipientLndCert           = "-----BEGIN CERTIFICATE-----\\nMIICejCCAiGgAwIBAgIQXSRR+idgoeKEztDgmlXKfDAKBggqhkjOPQQDAjBHMR8w\\nHQYDVQQKExZsbmQgYXV0b2dlbmVyYXRlZCBjZXJ0MSQwIgYDVQQDExtzbG5kLTMy\\nNTA1LTU3NmM0NjdjNzctOGh6NTcwHhcNMjExMTE1MjIxNjA2WhcNMjMwMTEwMjIx\\nNjA2WjBHMR8wHQYDVQQKExZsbmQgYXV0b2dlbmVyYXRlZCBjZXJ0MSQwIgYDVQQD\\nExtzbG5kLTMyNTA1LTU3NmM0NjdjNzctOGh6NTcwWTATBgcqhkjOPQIBBggqhkjO\\nPQMBBwNCAAT0WOMcjZAWxNWloE2+MYNEcB8m0hPJitTQJ53bRDTHc1RPXUmDAKAd\\n2VL8hn75rkM2pB7vVFRZgtl4q5YgE7p2o4HuMIHrMA4GA1UdDwEB/wQEAwICpDAT\\nBgNVHSUEDDAKBggrBgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MIGyBgNVHREEgaow\\ngaeCG3NsbmQtMzI1MDUtNTc2YzQ2N2M3Ny04aHo1N4IJbG9jYWxob3N0ghdzbG5k\\nLTMyNTA1LmxuLmxxd2QudGVjaIITc2xuZC0zMjUwNS5scXdkLWxuZIIEdW5peIIK\\ndW5peHBhY2tldIIHYnVmY29ubocEfwAAAYcQAAAAAAAAAAAAAAAAAAAAAYcECgEF\\nIYcQ/oAAAAAAAAC0FGH//qwWwIcEwKh7/DAKBggqhkjOPQQDAgNHADBEAiAMvlQq\\ngdxDRBkMVXbO1CVkufIbEuqupKdbvrb3gPQ+tAIgcO/c67W+MoBJy9N1bEe9p0uT\\nNeWZm/MgyHObbt2KBbs=\\n-----END CERTIFICATE-----"
	recipientMacaroonSignerHex = "0201036C6E640230030A10529ED88A137C5A53F3786683A52CD64B1201301A180A067369676E6572120867656E65726174651204726561640000062049FFCE4CA5A0A1FF81391E53652C70536884A9981C4EC218B6F06403B845A48E"

	publicKey = "02ffb9917596741957f0953e59de2c6a2af01c2302788bf2fc05e173745ab264ad"
	routingNodePubKey = "03f552d379ac2ca4eadef3e0f421f5967ccd4117da790c23fb78b394595166784f"

)



func recipientCreateInvoice() (payRequest string, paymentSecret interface{}, payHash []byte) {

	fakeHints, err := getFakeChannelRoutingHint()

	if err != nil {
		log.Fatal(err)
	}

	routingHints := []*lnrpc.RouteHint{fakeHints}

	ctx := metadata.AppendToOutgoingContext(context.Background(), "macaroon", recipientMacaroonHex)

	cp := x509.NewCertPool()
	if !cp.AppendCertsFromPEM([]byte(strings.Replace(recipientLndCert, "\\n", "\n", -1))) {
		log.Fatalf("credentials: failed to append certificates")
	}

	cred := credentials.NewClientTLSFromCert(cp, "")

	conn, err := grpc.Dial(recipientLndHost, grpc.WithTransportCredentials(cred))
	if err != nil {
		log.Fatal(err)
	}

	client := lnrpc.NewLightningClient(conn)

	resp, err := client.AddInvoice(ctx, &lnrpc.Invoice{
		Value:      28000,
		RouteHints: routingHints,
	})

	if err != nil {
		log.Fatal(err)
	}

	return resp.PaymentRequest, "", resp.GetRHash()
}

func generateInvoiceWithNewAmount(payReq string, nodeKey string, newAmount int64) (string, []byte, error) {

	invoice, err := zpay32.Decode(payReq, &chaincfg.RegressionNetParams)

	if err != nil {
		log.Fatalf("fail to decode invoice: %v", err)
	}

	ctx := metadata.AppendToOutgoingContext(context.Background(), "macaroon", recipientMacaroonSignerHex)

	cp := x509.NewCertPool()
	if !cp.AppendCertsFromPEM([]byte(strings.Replace(recipientLndCert, "\\n", "\n", -1))) {
		log.Fatalf("credentials: failed to append certificates")
	}
	cred := credentials.NewClientTLSFromCert(cp, "")

	conn, err := grpc.Dial(recipientLndHost, grpc.WithTransportCredentials(cred))
	if err != nil {
		log.Fatal(err)
	}
	signerClient := signrpc.NewSignerClient(conn)

	if signerClient == nil {
		return "", nil, fmt.Errorf("API is not ready")
	}

	if nodeKey == "" {
		return "", nil, errors.New("node public key wasn't initialized")
	}

	pubkeyBytes, err := hex.DecodeString(nodeKey)

	if err != nil {
		return "", nil, err
	}
	pubKey, err := btcec.ParsePubKey(pubkeyBytes, btcec.S256())
	if err != nil {
		return "", nil, err
	}

	m := lnwire.MilliSatoshi(newAmount)
	invoice.MilliSat = &m

	signer := zpay32.MessageSigner{SignCompact: func(hash []byte) ([]byte, error) {
		kl := signrpc.KeyLocator{
			KeyFamily: int32(keychain.KeyFamilyNodeKey),
			KeyIndex:  0,
		}

		r, err := signerClient.SignMessage(ctx, &signrpc.SignMessageReq{Msg: hash, KeyLoc: &kl})
		if err != nil {
			return nil, fmt.Errorf("m.client.SignMessage() error: %w", err)
		}
		sig, err := btcec.ParseDERSignature(r.Signature, btcec.S256())
		if err != nil {
			return nil, fmt.Errorf("btcec.ParseDERSignature error: %w", err)
		}
		log.Printf("hash %s", hex.EncodeToString(chainhash.HashB(hash)))
		return toCompact(sig, pubKey, chainhash.HashB(hash))
	}}

	newInvoice, err := invoice.Encode(signer)
	if err != nil {
		log.Printf("invoice.Encode() error: %v", err)
	}
	return newInvoice, (*invoice.PaymentAddr)[:], err
}

func senderPayInvoice(payRequest interface{}) (paymentError interface{}) {

	ctx := metadata.AppendToOutgoingContext(context.Background(), "macaroon", senderMacaroonHex)

	cp := x509.NewCertPool()
	if !cp.AppendCertsFromPEM([]byte(strings.Replace(senderLndCert, "\\n", "\n", -1))) {
		log.Fatalf("credentials: failed to append certificates")
	}
	cred := credentials.NewClientTLSFromCert(cp, "")

	conn, err := grpc.Dial(senderLndHost, grpc.WithTransportCredentials(cred))
	if err != nil {
		log.Fatal(err)
	}

	client := lnrpc.NewLightningClient(conn)

	resp, err := client.SendPaymentSync(ctx, &lnrpc.SendRequest{
		PaymentRequest:      fmt.Sprintf("%v", payRequest),
	})

	if err != nil {
		log.Fatal(err)
	}

	return resp.PaymentError
}

func callRequestPayment(ctx context.Context, paymentRequest string, paymentSecret []byte,
	client pb.ChannelOpenerClient) (response string) {

	destination, _ := hex.DecodeString(recipientPubkey)
	payh, _ := b64.StdEncoding.DecodeString(paymentRequest)

	pi := &pb.PaymentInformation{
		PaymentHash:        payh,
		PaymentSecret:      paymentSecret,
		Destination:        destination,
		IncomingAmountMsat: 30000000,
		OutgoingAmountMsat: 28000000,
	}
	data, _ := proto.Marshal(pi)
	decodedPubKey, _ := hex.DecodeString(publicKey)
	pubKey , err:= btcec.ParsePubKey(decodedPubKey,btcec.S256())

	if err != nil{
		log.Fatal(err)
	}

	blob, err := btcec.Encrypt(pubKey, data)

	req := &pb.RegisterPaymentRequest{
		Blob: blob,
	}

	res,err := client.RegisterPayment(ctx,req)

	if err != nil{
		log.Fatal(err)
	}

	println("request payment called successfully")
	return res.String()
}

func toCompact(sig *btcec.Signature, pubKey *btcec.PublicKey, hash []byte) ([]byte, error) {
	curve := btcec.S256()
	result := make([]byte, 1, curve.BitSize/4+1)
	curvelen := (curve.BitSize + 7) / 8
	bytelen := (sig.R.BitLen() + 7) / 8
	if bytelen < curvelen {
		result = append(result, make([]byte, curvelen-bytelen)...)
	}
	result = append(result, sig.R.Bytes()...)
	bytelen = (sig.S.BitLen() + 7) / 8
	if bytelen < curvelen {
		result = append(result, make([]byte, curvelen-bytelen)...)
	}
	result = append(result, sig.S.Bytes()...)
	for i := 0; i < (curve.H+1)*2; i++ {
		result[0] = 27 + byte(i) + 4 // Add 4 because it's compressed
		recoveredPubKey, _, err := btcec.RecoverCompact(curve, result, hash)
		if err == nil && recoveredPubKey.IsEqual(pubKey) {
			return result, nil
		}
	}
	return nil, errors.New("the signature doesn't correspond to the pubKey")
}



func main() {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	var opts []grpc.DialOption
	opts = append(opts, grpc.WithInsecure())
	conn, err := grpc.Dial("localhost:8083", opts...)
	if err != nil {
		log.Fatalf("fail to dial: %v", err)
	}
	defer conn.Close()

	client := pb.NewChannelOpenerClient(conn)
	clientCtx := metadata.AppendToOutgoingContext(context.Background(), "authorization",
		"Bearer DqdnPVBcOsJ8h5rz8bdyPjvBCjI2AHwg1n4WHdz+PlDl69LeVJIVCkupxwDwwaTd")

	payRequest, paymentSecret, payHash := recipientCreateInvoice()

	fmt.Printf("payRequestInt:%#v, paymentSecret:%#v, payHash:%x\n", payRequest, paymentSecret, payHash)

	newPayReq, secret, err := generateInvoiceWithNewAmount(payRequest, recipientPubkey, 30000)

	if err != nil {
		log.Fatalf("failed to generate LSP invoice: %v", err)
	}


	callRequestPayment(clientCtx,newPayReq,secret,client)

	paymentErr := senderPayInvoice(payRequest)

	println(paymentErr)

}


func getFakeChannelRoutingHint() (*lnrpc.RouteHint, error) {
	fakeChanID := &lnwire.ShortChannelID{BlockHeight: 1, TxIndex: 0, TxPosition: 0}
	return &lnrpc.RouteHint{
		HopHints: []*lnrpc.HopHint{
			{
				NodeId:                    routingNodePubKey,
				ChanId:                    fakeChanID.ToUint64(),
				FeeBaseMsat:               uint32(1000),
				FeeProportionalMillionths: uint32(0.000001 * 1000000),
				CltvExpiryDelta:           144,
			},
		},
	}, nil
}