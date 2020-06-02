package test

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"

	v2 "github.com/algorand/go-algorand/daemon/algod/api/server/v2"
	generatedV2 "github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

func setupTestForMethodGet(t *testing.T) (v2.Handlers, echo.Context, *httptest.ResponseRecorder, []account.Root, []transactions.SignedTxn, func()) {
	numAccounts := 1
	numTransactions := 1
	offlineAccounts := true
	mockLedger, rootkeys, _, stxns, releasefunc := testingenv(t, numAccounts, numTransactions, offlineAccounts)
	mockNode := makeMockNode(mockLedger, t.Name())
	dummyShutdownChan := make(chan struct{})
	handler := v2.Handlers{
		Node:     mockNode,
		Log:      logging.Base(),
		Shutdown: dummyShutdownChan,
	}
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	return handler, c, rec, rootkeys, stxns, releasefunc
}

func TestSimpleMockBuilding(t *testing.T) {
	handler, _, _, _, _, releasefunc := setupTestForMethodGet(t)
	defer releasefunc()
	require.Equal(t, t.Name(), handler.Node.GenesisID())
}

func accountInformationTest(t *testing.T, address string, expectedCode int) {
	handler, c, rec, _, _, releasefunc := setupTestForMethodGet(t)
	defer releasefunc()
	err := handler.AccountInformation(c, address)
	require.NoError(t, err)
	require.Equal(t, expectedCode, rec.Code)
}

func TestAccountInformation(t *testing.T) {
	accountInformationTest(t, "ALGORANDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIN5DNAU", 200)
	accountInformationTest(t, "malformed", 400)
}

func getBlockTest(t *testing.T, blockNum uint64, format string, expectedCode int) {
	handler, c, rec, _, _, releasefunc := setupTestForMethodGet(t)
	defer releasefunc()
	err := handler.GetBlock(c, blockNum, generatedV2.GetBlockParams{Format: &format})
	require.NoError(t, err)
	require.Equal(t, expectedCode, rec.Code)
}

func TestGetBlock(t *testing.T) {
	getBlockTest(t, 0, "json", 200)
	getBlockTest(t, 0, "msgpack", 200)
	getBlockTest(t, 1, "json", 500)
	getBlockTest(t, 0, "malformed", 400)
}

func TestGetSupply(t *testing.T) {
	handler, c, _, _, _, releasefunc := setupTestForMethodGet(t)
	defer releasefunc()
	err := handler.GetSupply(c)
	require.NoError(t, err)
}

func TestGetStatus(t *testing.T) {
	handler, c, _, _, _, releasefunc := setupTestForMethodGet(t)
	defer releasefunc()
	err := handler.GetStatus(c)
	require.NoError(t, err)
}

func TestGetStatusAfterBlock(t *testing.T) {
	t.Skip("skipping for now as this waits up to a minute")
	handler, c, rec, _, _, releasefunc := setupTestForMethodGet(t)
	defer releasefunc()
	err := handler.WaitForBlock(c, 0)
	require.NoError(t, err)
	require.Equal(t, 200, rec.Code)
}

func TestGetTransactionParams(t *testing.T) {
	handler, c, rec, _, _, releasefunc := setupTestForMethodGet(t)
	defer releasefunc()
	err := handler.TransactionParams(c)
	require.NoError(t, err)
	require.Equal(t, 200, rec.Code)
}

func pendingTransactionInformationTest(t *testing.T, txidToUse int, format string, expectedCode int) {
	handler, c, rec, _, stxns, releasefunc := setupTestForMethodGet(t)
	defer releasefunc()
	txid := "badtxid"
	if txidToUse >= 0 {
		txid = stxns[txidToUse].ID().String()
	}
	params := generatedV2.PendingTransactionInformationParams{Format: &format}
	err := handler.PendingTransactionInformation(c, txid, params)
	require.NoError(t, err)
	require.Equal(t, expectedCode, rec.Code)
}

func TestPendingTransactionInformation(t *testing.T) {
	pendingTransactionInformationTest(t, 0, "json", 200)
	pendingTransactionInformationTest(t, 0, "msgpack", 200)
	pendingTransactionInformationTest(t, -1, "json", 400)
	pendingTransactionInformationTest(t, 0, "bad format", 400)
}

func getPendingTransactionsTest(t *testing.T, format string, expectedCode int) {
	handler, c, rec, _, _, releasefunc := setupTestForMethodGet(t)
	defer releasefunc()
	params := generatedV2.GetPendingTransactionsParams{Format: &format}
	err := handler.GetPendingTransactions(c, params)
	require.NoError(t, err)
	require.Equal(t, expectedCode, rec.Code)
}

func TestPendingTransactions(t *testing.T) {
	getPendingTransactionsTest(t, "json", 200)
	getPendingTransactionsTest(t, "msgpack", 200)
	getPendingTransactionsTest(t, "bad format", 400)
}

func pendingTransactionsByAddressTest(t *testing.T, rootkeyToUse int, format string, expectedCode int) {
	handler, c, rec, rootkeys, _, releasefunc := setupTestForMethodGet(t)
	defer releasefunc()
	address := "bad address"
	if rootkeyToUse >= 0 {
		address = rootkeys[rootkeyToUse].Address().String()
	}
	params := generatedV2.GetPendingTransactionsByAddressParams{Format: &format}
	err := handler.GetPendingTransactionsByAddress(c, address, params)
	require.NoError(t, err)
	require.Equal(t, expectedCode, rec.Code)
}

func TestPendingTransactionsByAddress(t *testing.T) {
	pendingTransactionsByAddressTest(t, 0, "json", 200)
	pendingTransactionsByAddressTest(t, 0, "msgpack", 200)
	pendingTransactionsByAddressTest(t, 0, "bad format", 400)
	pendingTransactionsByAddressTest(t, -1, "json", 400)
}

func postTransactionTest(t *testing.T, txnToUse, expectedCode int) {
	numAccounts := 5
	numTransactions := 5
	offlineAccounts := true
	mockLedger, _, _, stxns, releasefunc := testingenv(t, numAccounts, numTransactions, offlineAccounts)
	defer releasefunc()
	dummyShutdownChan := make(chan struct{})
	mockNode := makeMockNode(mockLedger, t.Name())
	handler := v2.Handlers{
		Node:     mockNode,
		Log:      logging.Base(),
		Shutdown: dummyShutdownChan,
	}
	e := echo.New()
	var body io.Reader
	if txnToUse >= 0 {
		stxn := stxns[txnToUse]
		bodyBytes := protocol.Encode(&stxn)
		body = bytes.NewReader(bodyBytes)
	}
	req := httptest.NewRequest(http.MethodPost, "/", body)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	err := handler.RawTransaction(c)
	require.NoError(t, err)
	require.Equal(t, expectedCode, rec.Code)
}

func TestPostTransaction(t *testing.T) {
	postTransactionTest(t, -1, 400)
	postTransactionTest(t, 0, 200)
}

func TestStartCatchup(t *testing.T) {
	t.Skip("feature not yet deployed")
}

func TestAbortCatchup(t *testing.T) {
	t.Skip("feature not yet deployed")
}

func tealCompileTest(t *testing.T, bytesToUse []byte, expectedCode int) {
	numAccounts := 1
	numTransactions := 1
	offlineAccounts := true
	mockLedger, _, _, _, releasefunc := testingenv(t, numAccounts, numTransactions, offlineAccounts)
	defer releasefunc()
	dummyShutdownChan := make(chan struct{})
	mockNode := makeMockNode(mockLedger, t.Name())
	handler := v2.Handlers{
		Node:     &mockNode,
		Log:      logging.Base(),
		Shutdown: dummyShutdownChan,
	}
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(bytesToUse))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	err := handler.TealCompile(c)
	require.NoError(t, err)
	require.Equal(t, expectedCode, rec.Code)
}

func TestTealCompile(t *testing.T) {
	tealCompileTest(t, nil, 200) // nil program should work
	goodProgram := `int 1`
	goodProgramBytes := []byte(goodProgram)
	tealCompileTest(t, goodProgramBytes, 200)
	badProgram := "this is incorrect TEAL"
	badProgramBytes := []byte(badProgram)
	tealCompileTest(t, badProgramBytes, 400)
}
