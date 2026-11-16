package ledger

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func sha(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// V1 must stay exactly what it was. Every row written before v1.8.0
// carries a hash — and usually a signature over that hash — computed
// with this formula. Changing it would make the whole existing ledger
// read as tampered.
func TestChainHashV1_IsTheOriginalFormula(t *testing.T) {
	bom := []byte(`{"projectName": "p"}`)

	if got, want := ChainHashV1("abc", bom, "prev"), sha("abc"+string(bom)+"prev"); got != want {
		t.Errorf("non-genesis: got %s, want sha256(commit||bom||prev) = %s", got, want)
	}
	// Genesis rows omit prev_hash entirely, which is also the pre-chain
	// formula of the earliest rows.
	if got, want := ChainHashV1("abc", bom, ""), sha("abc"+string(bom)); got != want {
		t.Errorf("genesis: got %s, want sha256(commit||bom) = %s", got, want)
	}
}

// The V2 preimage layout is part of the published verification recipe:
// a third party recomputes it with printf and sha256sum. Pin it by
// building the preimage by hand rather than by calling the function.
func TestChainHashV2_PreimageLayoutIsPinned(t *testing.T) {
	d := Digests{BOM: sha("bom"), AnnexIV: sha("annex"), RiskRegister: sha("register")}

	want := sha("aicap-chain-v2\n" + "prevhash" + "\n" + d.BOM + "\n" + d.AnnexIV + "\n" + d.RiskRegister + "\n" + "commit-1")
	if got := ChainHashV2("commit-1", "prevhash", d); got != want {
		t.Errorf("V2 preimage layout changed.\n got %s\nwant %s\n"+
			"Changing it invalidates every stored V2 hash and signature and the "+
			"published verification recipe — it requires a new ledger version.", got, want)
	}

	// Genesis: prev_hash is the empty string, the field is still present.
	wantGenesis := sha("aicap-chain-v2\n" + "" + "\n" + d.BOM + "\n" + d.AnnexIV + "\n" + d.RiskRegister + "\n" + "commit-1")
	if got := ChainHashV2("commit-1", "", d); got != wantGenesis {
		t.Errorf("genesis layout changed: got %s, want %s", got, wantGenesis)
	}
}

// The point of V2: the rendered document and the risk register are
// inside the hash. Under V1 either could be edited without disturbing it.
func TestChainHash_V2CoversTheDocumentAndV1DoesNot(t *testing.T) {
	base := Content{
		BOM:          []byte(`{"a": 1}`),
		AnnexIV:      []byte("# Annex IV\n\nNo high-risk components."),
		RiskRegister: []byte(`{"findings": []}`),
	}
	editedDoc := base
	editedDoc.AnnexIV = []byte("# Annex IV\n\nNo high-risk components. (edited)")
	editedRegister := base
	editedRegister.RiskRegister = []byte(`{"findings": [{"component": "x"}]}`)
	editedBOM := base
	editedBOM.BOM = []byte(`{"a": 2}`)

	hash := func(v int, c Content) string {
		h, err := ChainHash(v, "commit", "prev", c)
		if err != nil {
			t.Fatalf("ChainHash(v%d): %v", v, err)
		}
		return h
	}

	// V2: every part matters.
	v2 := hash(V2, base)
	for name, c := range map[string]Content{"document": editedDoc, "risk register": editedRegister, "BOM": editedBOM} {
		if hash(V2, c) == v2 {
			t.Errorf("V2 hash unchanged after editing the %s", name)
		}
	}

	// V1: this is the gap, stated as a test so nobody mistakes it for an
	// oversight in the V1 code path. The BOM matters; the document and
	// the register do not.
	v1 := hash(V1, base)
	if hash(V1, editedBOM) == v1 {
		t.Error("V1 hash unchanged after editing the BOM")
	}
	if hash(V1, editedDoc) != v1 || hash(V1, editedRegister) != v1 {
		t.Error("V1 hash changed with the document or register — V1 never covered them, " +
			"and existing rows depend on that")
	}

	// And the two versions never agree on the same content.
	if v1 == v2 {
		t.Error("V1 and V2 produced the same hash for the same content")
	}
}

func TestChainHashV2_PrevAndCommitMatter(t *testing.T) {
	d := Content{BOM: []byte("b"), AnnexIV: []byte("a"), RiskRegister: []byte("r")}.Digests()
	base := ChainHashV2("commit", "prev", d)
	if ChainHashV2("commit2", "prev", d) == base {
		t.Error("hash unchanged after changing the commit")
	}
	if ChainHashV2("commit", "prev2", d) == base {
		t.Error("hash unchanged after changing prev_hash — the chain link is not bound")
	}
}

// The commit SHA is supplied by the client and is not guaranteed to be
// hex. It must not be possible to shift bytes between it and a
// neighbouring field and arrive at the same preimage.
func TestChainHashV2_CommitCannotImpersonateOtherFields(t *testing.T) {
	d := Content{BOM: []byte("b"), AnnexIV: []byte("a"), RiskRegister: []byte("r")}.Digests()

	honest := ChainHashV2("commit", "", d)
	// An attacker-chosen commit containing newlines and digest-shaped
	// text cannot reproduce it under different digests.
	other := Digests{BOM: d.BOM, AnnexIV: d.AnnexIV, RiskRegister: sha("other")}
	forged := ChainHashV2(d.RiskRegister+"\ncommit", "", other)
	if forged == honest {
		t.Error("a crafted commit string collided with a different entry's preimage")
	}
	if !strings.HasSuffix("aicap-chain-v2\n\n"+d.BOM+"\n"+d.AnnexIV+"\n"+d.RiskRegister+"\ncommit", "\ncommit") {
		t.Fatal("test precondition: commit is the final field")
	}
}

func TestChainHash_UnknownVersionIsAnError(t *testing.T) {
	// Guessing a formula for a row we do not understand would turn
	// "cannot verify" into a false "tampered" or a false "ok".
	for _, v := range []int{0, 3, -1} {
		if _, err := ChainHash(v, "c", "", Content{}); err == nil {
			t.Errorf("ChainHash(version %d) returned no error", v)
		}
	}
}

func TestDigest_IsLowercaseHexSHA256(t *testing.T) {
	if got, want := Digest([]byte("abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"; got != want {
		t.Errorf("Digest(abc) = %s, want %s", got, want)
	}
}
