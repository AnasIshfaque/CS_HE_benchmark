package main

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he/heint"
)

func main() {
	start := time.Now()
	var err error
	var params heint.Parameters

	// 128-bit secure parameters enabling depth-7 circuits.
	// LogN:14, LogQP: 431.
	if params, err = heint.NewParametersFromLiteral(
		heint.ParametersLiteral{
			LogN:             14,                                    // log2(ring degree)
			LogQ:             []int{55, 45, 45, 45, 45, 45, 45, 45}, // log2(primes Q) (ciphertext modulus)
			LogP:             []int{61},                             // log2(primes P) (auxiliary modulus)
			PlaintextModulus: 0x10001,                               // log2(scale)
		}); err != nil {
		panic(err)
	}

	// Key Generator
	kgen := rlwe.NewKeyGenerator(params)
	// Secret Key
	sk := kgen.GenSecretKeyNew()
	// Encoder
	ecd := heint.NewEncoder(params)
	// Encryptor
	enc := rlwe.NewEncryptor(params, sk)
	// Decryptor
	dec := rlwe.NewDecryptor(params, sk)
    //eval
    eval := heint.NewEvaluator(params, nil)

	// Vector of plaintext values
	value1 := make([]uint64, params.MaxSlots())
	value2 := make([]uint64, params.MaxSlots())
	value3 := make([]uint64, params.MaxSlots())

	// Source for sampling random plaintext values (not cryptographically secure)
	/* #nosec G404 */
	r := rand.New(rand.NewSource(0))

	// Populates the vectors of plaintext values
	T := params.PlaintextModulus()
	for i := range value1 {
		value1[i] = r.Uint64() % T
		value2[i] = r.Uint64() % T
		value3[i] = r.Uint64() % T
	}

	// Allocates a plaintext at the max level.
	// Default rlwe.MetaData:
	// - IsBatched = true (slots encoding)
	// - Scale = params.DefaultScale()
	pt1 := heint.NewPlaintext(params, params.MaxLevel())
	pt2 := heint.NewPlaintext(params, params.MaxLevel())
	pt3 := heint.NewPlaintext(params, params.MaxLevel())

///////
	// Encodes the vectors of plaintext values
	if err = ecd.Encode(value1, pt1); err != nil {
		panic(err)
	}
	if err = ecd.Encode(value2, pt2); err != nil {
		panic(err)
	}
	if err = ecd.Encode(value3, pt3); err != nil {
		panic(err)
	}

	// Encrypts the vectors of plaintext values
	var ct1, ct2, ct3 *rlwe.Ciphertext
	if ct1, err = enc.EncryptNew(pt1); err != nil {
		panic(err)
	}
	if ct2, err = enc.EncryptNew(pt2); err != nil {
		panic(err)
	}
	if ct3, err = enc.EncryptNew(pt3); err != nil {
		panic(err)
	}
//////////////



	// Allocates vectors for the reference values
	want1 := make([]uint64, params.MaxSlots())
	want2 := make([]uint64, params.MaxSlots())
	want3 := make([]uint64, params.MaxSlots())
	copy(want1, value1)
	copy(want2, value2)
	copy(want3, value3)

	// Print precision stats for each ciphertext
	PrintPrecisionStats(params, ct1, want1, ecd, dec)
	PrintPrecisionStats(params, ct2, want2, ecd, dec)
	PrintPrecisionStats(params, ct3, want3, ecd, dec)

	


    fmt.Printf("========\n")
	fmt.Printf("ADDITION\n")
	fmt.Printf("========\n")
	fmt.Printf("\n")

    addWant := make([]uint64, params.MaxSlots())
    for i := 0; i < params.MaxSlots(); i++ {
		addWant[i] = want1[i] + want2[i] + want3[i]
	}
    
    addCT1, err := eval.AddNew(ct1, ct2)
    if err != nil {
        panic(err)
    }
    addCT2, err := eval.AddNew(addCT1, ct3)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Addition - ct + ct + ct\n")
    PrintPrecisionStats(params, addCT2, addWant, ecd, dec)

    fmt.Printf("========\n")
	fmt.Printf("MULTIPLICATION\n")
	fmt.Printf("========\n")
	fmt.Printf("\n")

    mulWant := make([]uint64, params.MaxSlots())
    for i := 0; i < params.MaxSlots(); i++ {
		mulWant[i] = want1[i] * want2[i]
	}
    
    mulCT1, err := eval.MulNew(ct1, ct2)
    if err != nil {
        panic(err)
    }
/*    mulCT2, err := eval.MulNew(mulCT1, ct3)
    if err != nil {
        panic(err)
    }
    */
    fmt.Printf("Multiplication - ct * ct * ct\n")
    PrintPrecisionStats(params, mulCT1, mulWant, ecd, dec)

    fmt.Printf("========\n")
	fmt.Printf("ROTATION\n")
	fmt.Printf("========\n")
	fmt.Printf("\n")

elapsed := time.Since(start) // Calculate elapsed time
	fmt.Printf("Time taken: %v\n", elapsed)
    
}

// PrintPrecisionStats decrypts, decodes and prints the precision stats of a ciphertext.
func PrintPrecisionStats(params heint.Parameters, ct *rlwe.Ciphertext, want []uint64, ecd *heint.Encoder, dec *rlwe.Decryptor) {

	var err error

	// Decrypts the vector of plaintext values
	pt := dec.DecryptNew(ct)

	// Decodes the plaintext
	have := make([]uint64, params.MaxSlots())
	if err = ecd.Decode(pt, have); err != nil {
		panic(err)
	}

	// Pretty prints some values
	fmt.Printf("Have: ")
	for i := 0; i < 4; i++ {
		fmt.Printf("%d ", have[i])
	}
	fmt.Printf("...\n")

	fmt.Printf("Want: ")
	for i := 0; i < 4; i++ {
		fmt.Printf("%d ", want[i])
	}
	fmt.Printf("...\n")

	if !equalSlice(want, have) {
		//panic("wrong result: bad decryption or encrypted/plaintext circuits do not match")
		fmt.Printf("wrong result: bad decryption or encrypted/plaintext circuits do not match")
	}
}

// equalSlice checks if two slices are equal
func equalSlice(slice1, slice2 []uint64) bool {
	if len(slice1) != len(slice2) {
		return false
	}
	for i := range slice1 {
		if slice1[i] != slice2[i] {
			return false
		}
	}
	return true
}

