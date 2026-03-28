package crypto_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/zijiren233/gwst/internal/crypto"
)

// allAlgos lists every algorithm variant under test.
var allAlgos = []crypto.Algorithm{
	crypto.AlgoAEGIS128L,
	crypto.AlgoAEGIS128X2,
	crypto.AlgoAEGIS128X4,
}

// ─── helpers ──────────────────────────────────────────────────────────────────

func mustManager(t *testing.T, algo crypto.Algorithm) *crypto.Manager {
	t.Helper()
	key := make([]byte, crypto.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	m, err := crypto.NewManagerWithAlgo(key, algo)
	if err != nil {
		t.Fatalf("NewManagerWithAlgo(%q): %v", algo, err)
	}
	return m
}

func randPayload(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return b
}

// ─── NewManager / NewManagerWithAlgo ─────────────────────────────────────────

// TestNewManager_DefaultAlgo verifies that both NewManager and NewManagerWithAlgo("")
// select AEGIS-128L as the default algorithm.
func TestNewManager_DefaultAlgo(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	cases := []struct {
		name string
		fn   func() (*crypto.Manager, error)
	}{
		{"NewManager", func() (*crypto.Manager, error) { return crypto.NewManager(key) }},
		{"NewManagerWithAlgo/empty", func() (*crypto.Manager, error) { return crypto.NewManagerWithAlgo(key, "") }},
	}
	for _, tc := range cases {
		m, err := tc.fn()
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if m.Algo() != crypto.AlgoAEGIS128L {
			t.Errorf("%s: algo = %q, want %q", tc.name, m.Algo(), crypto.AlgoAEGIS128L)
		}
	}
}

func TestNewManagerWithAlgo_InvalidKey(t *testing.T) {
	// Key-length validation fires before algo dispatch; one call is sufficient.
	if _, err := crypto.NewManagerWithAlgo([]byte("short"), crypto.AlgoAEGIS128L); err == nil {
		t.Error("expected error for short key, got nil")
	}
}

func TestNewManagerWithAlgo_UnknownAlgo(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	_, err := crypto.NewManagerWithAlgo(key, "aegis-999")
	if err == nil {
		t.Error("expected error for unknown algorithm, got nil")
	}
}

// TestKeyIsolation verifies that mutating the key slice after construction does
// not affect an already-constructed Manager.  This guards the keyCopy fix in
// NewManagerWithAlgo (go-libaegis stores a.Key = key by reference, not by copy).
func TestKeyIsolation(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	for _, algo := range allAlgos {
		algo := algo
		t.Run(string(algo), func(t *testing.T) {
			m, err := crypto.NewManagerWithAlgo(key, algo)
			if err != nil {
				t.Fatalf("NewManagerWithAlgo: %v", err)
			}
			plaintext := randPayload(t, 64)
			ct, err := m.Encrypt(plaintext)
			if err != nil {
				t.Fatalf("Encrypt before mutation: %v", err)
			}

			// Zero the original key slice – Manager must continue to work.
			for i := range key {
				key[i] = 0
			}

			got, err := m.Decrypt(ct)
			if err != nil {
				t.Fatalf("Decrypt after key zeroing: %v", err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Fatal("plaintext mismatch after key zeroing")
			}

			// Also verify that a new encrypt/decrypt cycle still works.
			ct2, err := m.Encrypt(plaintext)
			if err != nil {
				t.Fatalf("Encrypt after key zeroing: %v", err)
			}
			got2, err := m.Decrypt(ct2)
			if err != nil {
				t.Fatalf("Decrypt of post-mutation ciphertext: %v", err)
			}
			if !bytes.Equal(got2, plaintext) {
				t.Fatal("second plaintext mismatch after key zeroing")
			}

			// Restore key for the next subtest iteration.
			if _, err := rand.Read(key); err != nil {
				t.Fatalf("rand.Read restore: %v", err)
			}
		})
	}
}

// ─── Correctness: Encrypt / Decrypt roundtrip ────────────────────────────────

func TestEncryptDecryptRoundtrip(t *testing.T) {
	sizes := []int{0, 1, 15, 16, 31, 32, 63, 1024, 16*1024, 64*1024}
	for _, algo := range allAlgos {
		algo := algo
		t.Run(string(algo), func(t *testing.T) {
			m := mustManager(t, algo)
			for _, sz := range sizes {
				plaintext := randPayload(t, sz)
				ct, err := m.Encrypt(plaintext)
				if err != nil {
					t.Fatalf("Encrypt(%d): %v", sz, err)
				}
				// ciphertext must be NonceSize + sz + TagSize
				want := crypto.NonceSize + sz + crypto.TagSize
				if len(ct) != want {
					t.Fatalf("ciphertext len = %d, want %d", len(ct), want)
				}
				got, err := m.Decrypt(ct)
				if err != nil {
					t.Fatalf("Decrypt(%d): %v", sz, err)
				}
				if !bytes.Equal(got, plaintext) {
					t.Fatalf("plaintext mismatch at size %d", sz)
				}
			}
		})
	}
}

// ─── Correctness: EncryptTo / DecryptTo (zero-copy paths) ──────────────────

func TestEncryptToDecryptToRoundtrip(t *testing.T) {
	sizes := []int{0, 1, 15, 16, 1024, 65536}
	for _, algo := range allAlgos {
		algo := algo
		t.Run(string(algo), func(t *testing.T) {
			m := mustManager(t, algo)
			for _, sz := range sizes {
				plaintext := randPayload(t, sz)

				// EncryptTo
				dst := make([]byte, crypto.NonceSize+sz+crypto.TagSize)
				ct, err := m.EncryptTo(dst, plaintext)
				if err != nil {
					t.Fatalf("EncryptTo(%d): %v", sz, err)
				}
				if &ct[0] != &dst[0] {
					t.Fatal("EncryptTo must return a slice of dst, not a new allocation")
				}

				// DecryptTo
				ptDst := make([]byte, sz)
				got, err := m.DecryptTo(ptDst, ct)
				if err != nil {
					t.Fatalf("DecryptTo(%d): %v", sz, err)
				}
				if sz > 0 && &got[0] != &ptDst[0] {
					t.Fatal("DecryptTo must return a slice of dst, not a new allocation")
				}
				if !bytes.Equal(got, plaintext) {
					t.Fatalf("plaintext mismatch at size %d", sz)
				}
			}
		})
	}
}

// TestSizeBoundaryErrors verifies that EncryptTo, DecryptTo, and Decrypt all reject
// under-sized buffers/ciphertexts before reaching the AEAD.  The guards are
// algo-independent, but we run across all variants to confirm the invariant is uniform.
func TestSizeBoundaryErrors(t *testing.T) {
	plaintext := []byte("hello world")
	tooSmall := make([]byte, 1)
	for _, algo := range allAlgos {
		m := mustManager(t, algo)
		ct, _ := m.Encrypt(plaintext)
		if _, err := m.EncryptTo(tooSmall, plaintext); err == nil {
			t.Errorf("algo %q EncryptTo: expected error for too-small dst", algo)
		}
		if _, err := m.DecryptTo(tooSmall, ct); err == nil {
			t.Errorf("algo %q DecryptTo: expected error for too-small dst", algo)
		}
		if _, err := m.Decrypt(make([]byte, crypto.NonceSize+crypto.TagSize-1)); err == nil {
			t.Errorf("algo %q Decrypt: expected error for truncated ciphertext", algo)
		}
	}
}

// ─── Memory safety: tampered ciphertext must fail auth ───────────────────────

// TestDecrypt_AuthenticityRejection verifies that any single-byte mutation to the
// nonce, ciphertext body, or authentication tag causes decryption to fail.
func TestDecrypt_AuthenticityRejection(t *testing.T) {
	tampers := []struct {
		name string
		flip func([]byte)
	}{
		{"nonce", func(b []byte) { b[0]++ }},
		{"body", func(b []byte) { b[crypto.NonceSize]++ }},
		{"tag", func(b []byte) { b[len(b)-1]++ }},
	}
	for _, algo := range allAlgos {
		algo := algo
		t.Run(string(algo), func(t *testing.T) {
			m := mustManager(t, algo)
			ct, err := m.Encrypt(randPayload(t, 64))
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			for _, tc := range tampers {
				mut := append([]byte(nil), ct...)
				tc.flip(mut)
				if _, err := m.Decrypt(mut); err == nil {
					t.Errorf("tamper %q: expected authentication failure, got nil", tc.name)
				}
			}
		})
	}
}

// ─── Nonce uniqueness: two encryptions of the same plaintext must differ ─────

func TestEncrypt_NonceUniqueness(t *testing.T) {
	for _, algo := range allAlgos {
		algo := algo
		t.Run(string(algo), func(t *testing.T) {
			m := mustManager(t, algo)
			pt := []byte("same plaintext")
			ct1, _ := m.Encrypt(pt)
			ct2, _ := m.Encrypt(pt)
			if bytes.Equal(ct1, ct2) {
				t.Error("two encryptions produced identical ciphertexts (nonce not unique?)")
			}
		})
	}
}

// ─── Cross-algorithm isolation: ciphertext from one algo must not decrypt with another ──

func TestDecrypt_CrossAlgoIsolation(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	plaintext := randPayload(t, 64)
	algoPairs := [][2]crypto.Algorithm{
		{crypto.AlgoAEGIS128L, crypto.AlgoAEGIS128X2},
		{crypto.AlgoAEGIS128L, crypto.AlgoAEGIS128X4},
		{crypto.AlgoAEGIS128X2, crypto.AlgoAEGIS128X4},
	}
	for _, pair := range algoPairs {
		enc, _ := crypto.NewManagerWithAlgo(key, pair[0])
		dec, _ := crypto.NewManagerWithAlgo(key, pair[1])
		ct, _ := enc.Encrypt(plaintext)
		_, err := dec.Decrypt(ct)
		if err == nil {
			t.Errorf("cross-algo decrypt %q→%q should fail but succeeded", pair[0], pair[1])
		}
	}
}

// ─── Performance ─────────────────────────────────────────────────────────────

func benchmarkCrypto(b *testing.B, algo crypto.Algorithm, payloadSz int, withDecrypt bool) {
	b.Helper()
	key := make([]byte, crypto.KeySize)
	m, err := crypto.NewManagerWithAlgo(key, algo)
	if err != nil {
		b.Fatalf("NewManagerWithAlgo: %v", err)
	}
	plaintext := make([]byte, payloadSz)
	ctBuf := make([]byte, crypto.NonceSize+payloadSz+crypto.TagSize)
	ptBuf := make([]byte, payloadSz)
	b.SetBytes(int64(payloadSz))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ct, err := m.EncryptTo(ctBuf, plaintext)
		if err != nil {
			b.Fatal(err)
		}
		if withDecrypt {
			if _, err = m.DecryptTo(ptBuf, ct); err != nil {
				b.Fatal(err)
			}
		}
	}
}

func BenchmarkAEGIS128L_1KB(b *testing.B)   { benchmarkCrypto(b, crypto.AlgoAEGIS128L, 1024, true) }
func BenchmarkAEGIS128L_16KB(b *testing.B)  { benchmarkCrypto(b, crypto.AlgoAEGIS128L, 16*1024, true) }
func BenchmarkAEGIS128L_64KB(b *testing.B)  { benchmarkCrypto(b, crypto.AlgoAEGIS128L, 64*1024, true) }
func BenchmarkAEGIS128X2_1KB(b *testing.B)  { benchmarkCrypto(b, crypto.AlgoAEGIS128X2, 1024, true) }
func BenchmarkAEGIS128X2_16KB(b *testing.B) { benchmarkCrypto(b, crypto.AlgoAEGIS128X2, 16*1024, true) }
func BenchmarkAEGIS128X2_64KB(b *testing.B) { benchmarkCrypto(b, crypto.AlgoAEGIS128X2, 64*1024, true) }
func BenchmarkAEGIS128X4_1KB(b *testing.B)  { benchmarkCrypto(b, crypto.AlgoAEGIS128X4, 1024, true) }
func BenchmarkAEGIS128X4_16KB(b *testing.B) { benchmarkCrypto(b, crypto.AlgoAEGIS128X4, 16*1024, true) }
func BenchmarkAEGIS128X4_64KB(b *testing.B) { benchmarkCrypto(b, crypto.AlgoAEGIS128X4, 64*1024, true) }

// BenchmarkEncryptOnly_* measures encrypt-only throughput (no decrypt).
func BenchmarkEncryptOnly_AEGIS128L_64KB(b *testing.B)  { benchmarkCrypto(b, crypto.AlgoAEGIS128L, 64*1024, false) }
func BenchmarkEncryptOnly_AEGIS128X2_64KB(b *testing.B) { benchmarkCrypto(b, crypto.AlgoAEGIS128X2, 64*1024, false) }
func BenchmarkEncryptOnly_AEGIS128X4_64KB(b *testing.B) { benchmarkCrypto(b, crypto.AlgoAEGIS128X4, 64*1024, false) }
