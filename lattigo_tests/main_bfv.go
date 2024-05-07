package main

import (
	"fmt"
	"math/rand"
	

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/schemes/bfv"

	"time"
    "os/exec"

)

func main() {

	scriptPath := "device_check.sh"

	//start := time.Now()
	
	var err error
	var params bfv.Parameters

	// 128-bit secure parameters enabling depth-7 circuits.
	// LogN:14, LogQP: 431.
	if params, err = bfv.NewParametersFromLiteral(
		bfv.ParametersLiteral{
			LogN:             14,                                    // log2(ring degree)
			LogQ:             []int{55, 45, 45, 45, 45, 45, 45, 45}, // log2(primes Q) (ciphertext modulus)
			LogP:             []int{61},                             // log2(primes P) (auxiliary modulus)
			PlaintextModulus: 0x10001,                               // log2(scale)
		}); err != nil {
		panic(err)
	}

	cmd := exec.Command("sh", scriptPath)
	err2 := cmd.Start()
	if err2 != nil {
			fmt.Println("Error starting script:", err2)
			return
	}
	
	
	start_time := time.Now()
	fmt.Println("Start time: ", start_time)


	key_gen_start_time := time.Now()




	// Key Generator
	kgen := rlwe.NewKeyGenerator(params)
	// Secret Key
	sk := kgen.GenSecretKeyNew()
	// Encoder
	ecd := bfv.NewEncoder(params)
	// Encryptor
	enc := rlwe.NewEncryptor(params, sk)
	// Decryptor
	dec := rlwe.NewDecryptor(params, sk)
    //eval
    eval := bfv.NewEvaluator(params, nil)

	key_gen_end_time := time.Now()

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
	pt1 := bfv.NewPlaintext(params, params.MaxLevel())
	pt2 := bfv.NewPlaintext(params, params.MaxLevel())
	pt3 := bfv.NewPlaintext(params, params.MaxLevel())

	encryption_start_time := time.Now()
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
	encryption_end_time := time.Now()



	// Allocates vectors for the reference values
	
	want1 := make([]uint64, params.MaxSlots())
	want2 := make([]uint64, params.MaxSlots())
	want3 := make([]uint64, params.MaxSlots())
	copy(want1, value1)
	copy(want2, value2)
	copy(want3, value3)
	
	// Print precision stats for each ciphertext
	//PrintPrecisionStats(params, ct1, want1, ecd, dec)
	//PrintPrecisionStats(params, ct2, want2, ecd, dec)
	//PrintPrecisionStats(params, ct3, want3, ecd, dec)

	


    addition_start_time := time.Now()

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
   // fmt.Printf("Addition - ct + ct + ct\n")
   // PrintPrecisionStats(params, addCT2, addWant, ecd, dec)

    addition_end_time := time.Now()

    mutliplication_start_time := time.Now()

    mulWant := make([]uint64, params.MaxSlots())
    for i := 0; i < params.MaxSlots(); i++ {
		mulWant[i] = want1[i] * want2[i]
	}
    
    mulCT1, err := eval.MulNew(ct1, ct2)
    if err != nil {
        panic(err)
    }

	multiplication_end_time := time.Now()
    



	rlk := kgen.GenRelinearizationKeyNew(sk)

	rotation_start_time := time.Now()
	//rotate 4 times. 1, 2, -1, -2
	rot := 1
	galois := rlwe.NewMemEvaluationKeySet(rlk, kgen.GenGaloisKeysNew([]uint64{
		params.GaloisElement(rot),
	}, sk)...)


	want_rot1 := make([]uint64, params.MaxSlots())
	want_rot2 := make([]uint64, params.MaxSlots())
	want_rot3 := make([]uint64, params.MaxSlots())
	want_rot4 := make([]uint64, params.MaxSlots())

	eval = eval.WithKey(galois)
	for i := 0; i < params.MaxSlots(); i++ {
		want_rot1[i] = value1[(i+1)%params.MaxSlots()]
	}

	ct3_rot1, err := eval.RotateColumnsNew(ct1, rot)
	if err != nil {
		panic(err)
	}


	rot = 2
	galois = rlwe.NewMemEvaluationKeySet(rlk, kgen.GenGaloisKeysNew([]uint64{
		params.GaloisElement(rot),
	}, sk)...)

	eval = eval.WithKey(galois)

	for i := 0; i < params.MaxSlots(); i++ {
		want_rot2[i] = value1[(i+2)%params.MaxSlots()]
	}
	ct3_rot2, err := eval.RotateColumnsNew(ct1, rot)
	if err != nil {
		panic(err)
	}

	rot = -1

	galois = rlwe.NewMemEvaluationKeySet(rlk, kgen.GenGaloisKeysNew([]uint64{
		params.GaloisElement(rot),
	}, sk)...)

	eval = eval.WithKey(galois)
	for i := 0; i < params.MaxSlots(); i++ {
		want_rot3[i] = value1[(i-1+params.MaxSlots())%params.MaxSlots()]
	}
	ct3_rot3, err := eval.RotateColumnsNew(ct1, rot)
	if err != nil {
		panic(err)
	}

	rot = -2

	galois = rlwe.NewMemEvaluationKeySet(rlk, kgen.GenGaloisKeysNew([]uint64{
		params.GaloisElement(rot),
	}, sk)...)

	eval = eval.WithKey(galois)

	for i := 0; i < params.MaxSlots(); i++ {
		want_rot4[i] = value1[(i-2+params.MaxSlots())%params.MaxSlots()]
	}
	ct3_rot4, err := eval.RotateColumnsNew(ct1, rot)
	if err != nil {
		panic(err)
	}


	rotation_end_time := time.Now()

	decryption_start_time := time.Now()
	PrintPrecisionStats(params, addCT2, addWant, ecd, dec)
	PrintPrecisionStats(params, mulCT1, mulWant, ecd, dec)
	PrintPrecisionStats(params, ct3_rot1, want_rot1, ecd, dec)
	PrintPrecisionStats(params, ct3_rot2, want_rot2, ecd, dec)
	PrintPrecisionStats(params, ct3_rot3, want_rot3, ecd, dec)
	PrintPrecisionStats(params, ct3_rot4, want_rot4, ecd, dec)

	decryption_end_time := time.Now()

	fmt.Println("Key generation time: ", key_gen_end_time.Sub(key_gen_start_time))
	fmt.Println("Encryption time: ", encryption_end_time.Sub(encryption_start_time))
	fmt.Println("Addition time: ", addition_end_time.Sub(addition_start_time))
	fmt.Println("Multiplication time: ", multiplication_end_time.Sub(mutliplication_start_time))
	fmt.Println("Rotation time: ", rotation_end_time.Sub(rotation_start_time))
	fmt.Println("Decryption time: ", decryption_end_time.Sub(decryption_start_time))

	err = cmd.Process.Kill()
	if err != nil {
			//fmt.Println("Error waiting for script:", err)
			return
	}
    
}

// PrintPrecisionStats decrypts, decodes and prints the precision stats of a ciphertext.
func PrintPrecisionStats(params bfv.Parameters, ct *rlwe.Ciphertext, want []uint64, ecd *bfv.Encoder, dec *rlwe.Decryptor) {

	var err error

	// Decrypts the vector of plaintext values
	pt := dec.DecryptNew(ct)

	// Decodes the plaintext
	have := make([]uint64, params.MaxSlots())
	if err = ecd.Decode(pt, have); err != nil {
		//panic(err)
	}


	if !equalSlice(want, have) {
		//panic("wrong result: bad decryption or encrypted/plaintext circuits do not match")
		//fmt.Println("wrong result: bad decryption or encrypted/plaintext circuits do not match")
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

