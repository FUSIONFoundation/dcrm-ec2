//Author: xingchang@fusion.org
package paillier

import (
	"errors"
	"github.com/fusion/go-fusion/common/math/random"
	"math/big"
	"strconv"
)

var ErrMessageTooLong = errors.New("[ERROR]: message is too long.")

type PublicKey struct {
	Length string 
	N      *big.Int // n = p*q, where p and q are prime
	G      *big.Int // in practical, G = N + 1
	N2     *big.Int // N2 = N * N
}

type PrivateKey struct {
	Length string
	PublicKey
	L *big.Int // (p-1)*(q-1)
	U *big.Int // L^-1 mod N
}

func GenerateKeyPair(length int) (*PublicKey, *PrivateKey) {
	one := big.NewInt(1)

	p := random.GetRandomPrimeInt(length / 2)
	q := random.GetRandomPrimeInt(length / 2)

	n := new(big.Int).Mul(p, q)
	n2 := new(big.Int).Mul(n, n)
	g := new(big.Int).Add(n, one)

	pMinus1 := new(big.Int).Sub(p, one)
	qMinus1 := new(big.Int).Sub(q, one)

	l := new(big.Int).Mul(pMinus1, qMinus1)
	u := new(big.Int).ModInverse(l, n)

	publicKey := &PublicKey{Length: strconv.Itoa(length), N: n, G: g, N2: n2}
	privateKey := &PrivateKey{Length: strconv.Itoa(length), PublicKey: *publicKey, L: l, U: u}

	return publicKey, privateKey
}

func (publicKey *PublicKey) Encrypt(mBigInt *big.Int) (*big.Int, error) {
	if mBigInt.Cmp(publicKey.N) > 0 {
		return nil, ErrMessageTooLong
	}

	rndStar := random.GetRandomIntFromZnStar(publicKey.N)

	// G^m mod N2
	Gm := new(big.Int).Exp(publicKey.G, mBigInt, publicKey.N2)
	// R^N mod N2
	RN := new(big.Int).Exp(rndStar, publicKey.N, publicKey.N2)
	// G^m * R^n
	GmRN := new(big.Int).Mul(Gm, RN)
	// G^m * R^n mod N2
	cipher := new(big.Int).Mod(GmRN, publicKey.N2)

	return cipher, nil
}

func (privateKey *PrivateKey) Decrypt(cipherBigInt *big.Int) (*big.Int, error) {
	one := big.NewInt(1)

	if cipherBigInt.Cmp(privateKey.N2) > 0 {
		return nil, ErrMessageTooLong
	}

	// c^L mod N2
	cL := new(big.Int).Exp(cipherBigInt, privateKey.L, privateKey.N2)
	// c^L - 1
	cLMinus1 := new(big.Int).Sub(cL, one)
	// (c^L - 1) / N
	cLMinus1DivN := new(big.Int).Div(cLMinus1, privateKey.N)
	// (c^L - 1) / N * U
	cLMinus1DivNMulU := new(big.Int).Mul(cLMinus1DivN, privateKey.U)
	// (c^L - 1) / N * U mod N
	mBigInt := new(big.Int).Mod(cLMinus1DivNMulU, privateKey.N)

	return mBigInt, nil
}

func (publicKey *PublicKey) HomoAdd(c1, c2 *big.Int) *big.Int {
	// c1 * c2
	c1c2 := new(big.Int).Mul(c1, c2)
	// c1 * c2 mod N2
	newCipher := new(big.Int).Mod(c1c2, publicKey.N2)

	return newCipher
}

func (publicKey *PublicKey) HomoMul(cipher, k *big.Int) *big.Int {
	// cipher^k mod N2
	newCipher := new(big.Int).Exp(cipher, k, publicKey.N2)

	return newCipher
}
