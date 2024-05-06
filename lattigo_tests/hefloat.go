package main

import (
	"fmt"
	//"math/cmplx"
	"math/rand"

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he"
	"github.com/tuneinsight/lattigo/v5/he/hefloat"
	"github.com/tuneinsight/lattigo/v5/utils"
	//"github.com/tuneinsight/lattigo/v5/utils/bignum"

	//"os"
    "os/exec"
)

func main() {
	scriptPath := "laptopcheck.sh"

	

	

	var err error
	var params hefloat.Parameters
	if params, err = hefloat.NewParametersFromLiteral(
		hefloat.ParametersLiteral{
			LogN:            14,                                    // A ring degree of 2^{14}
			LogQ:            []int{55, 45, 45, 45, 45, 45, 45, 45}, // An initial prime of 55 bits and 7 primes of 45 bits
			LogP:            []int{61},                             // The log2 size of the key-switching prime
			LogDefaultScale: 45,                                    // The default log2 of the scaling factor
		}); err != nil {
		panic(err)
	}
	
	
	// Start the shell script
	cmd := exec.Command("sh", scriptPath)
	err2 := cmd.Start()
	if err2 != nil {
			fmt.Println("Error starting script:", err2)
			return
	}
	
	
	
	


	//prec := params.EncodingPrecision() 
	kgen := rlwe.NewKeyGenerator(params)

	sk := kgen.GenSecretKeyNew()
	pk := kgen.GenPublicKeyNew(sk) // Note that we can generate any number of public keys associated to the same Secret Key.
	rlk := kgen.GenRelinearizationKeyNew(sk)

	evk := rlwe.NewMemEvaluationKeySet(rlk)

	LogSlots := params.LogMaxSlots()
	Slots := 1 << LogSlots

	r := rand.New(rand.NewSource(0))
	values1 := make([]complex128, Slots)
	for i := 0; i < Slots; i++ {
		values1[i] = complex(2*r.Float64()-1, 2*r.Float64()-1)
	}
	pt1 := hefloat.NewPlaintext(params, params.MaxLevel())

	ecd := hefloat.NewEncoder(params)

	ecd2 := hefloat.NewEncoder(hefloat.Parameters(params))

	if err = ecd2.Encode(values1, pt1); err != nil {
		panic(err)
	}

	enc := rlwe.NewEncryptor(params, pk)

	// And we create the ciphertext.
	// Note that the metadata of the plaintext will be copied on the resulting ciphertext.
	ct1, err := enc.EncryptNew(pt1)
	if err != nil {
		panic(err)
	}

	dec := rlwe.NewDecryptor(params, sk)

	eval := hefloat.NewEvaluator(params, evk)

	// For the purpose of the example, we will create a second vector of random values.
	values2 := make([]complex128, Slots)
	for i := 0; i < Slots; i++ {
		values2[i] = complex(2*r.Float64()-1, 2*r.Float64()-1)
	}

	pt2 := hefloat.NewPlaintext(params, params.MaxLevel())



	fmt.Printf("========\n")
	fmt.Printf("ADDITION\n")
	fmt.Printf("========\n")
	fmt.Printf("\n")

	// ciphertext + ciphertext
	if err = ecd.Encode(values2, pt2); err != nil {
		panic(err)
	}

	ct2, err := enc.EncryptNew(pt2)
	if err != nil {
		panic(err)
	}

	want := make([]complex128, Slots)
	for i := 0; i < Slots; i++ {
		want[i] = values1[i] + values2[i]
	}

	ct3, err := eval.AddNew(ct1, ct2)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Addition - ct + ct%s", hefloat.GetPrecisionStats(params, ecd, dec, want, ct3, 0, false).String())

	fmt.Printf("==============\n")
	fmt.Printf("MULTIPLICATION\n")
	fmt.Printf("==============\n")
	fmt.Printf("\n")

	for i := 0; i < Slots; i++ {
		want[i] = values1[i] * values2[i]
	}

	pt2.Scale = rlwe.NewScale(params.Q()[ct1.Level()])

	// Then we encode the values (recall that the encoding is done according to the metadata of the plaintext)
	if err = ecd.Encode(values2, pt2); err != nil {
		panic(err)
	}

	// and we encrypt (recall that the metadata of the plaintext are copied on the created ciphertext)
	if err := enc.Encrypt(pt2, ct2); err != nil {
		panic(err)
	}

	res, err := eval.MulRelinNew(ct1, ct2)
	if err != nil {
		panic(err)
	}

	// The scaling factor of res should be equal to ct1.Scale * ct2.Scale
	ctScale := &res.Scale.Value // We need to access the pointer to have it display correctly in the command line
	fmt.Printf("Scale before rescaling: %f\n", ctScale)

	if err = eval.Rescale(res, res); err != nil {
		panic(err)
	}

	Scale := params.DefaultScale().Value

	fmt.Printf("Scale after rescaling: %f == %f: %t and %d == %d+1: %t\n", ctScale, &Scale, ctScale.Cmp(&Scale) == 0, ct1.Level(), res.Level(), ct1.Level() == res.Level()+1)
	fmt.Printf("\n")

	fmt.Printf("Multiplication - ct * ct%s", hefloat.GetPrecisionStats(params, ecd, dec, want, res, 0, false).String())



	fmt.Printf("======================\n")
	fmt.Printf("ROTATION\n")
	fmt.Printf("======================\n")
	fmt.Printf("\n")


	rot := 4
	galEls := []uint64{
		// The galois element for the cyclic rotations by 5 positions to the left.
		params.GaloisElement(rot),
		// The galois element for the complex conjugatation.
		params.GaloisElementForComplexConjugation(),
	}

	eval = eval.WithKey(rlwe.NewMemEvaluationKeySet(rlk, kgen.GenGaloisKeysNew(galEls, sk)...))

	// Rotation by 5 positions to the left
	for i := 0; i < Slots; i++ {
		want[i] = values1[(i+5)%Slots]
	}

	ct3, err = eval.RotateNew(ct1, rot)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Rotation by k=%d %s", rot, hefloat.GetPrecisionStats(params, ecd, dec, want, ct3, 0, false).String())




	// Wait for the script to finish
	err = cmd.Wait()
	if err != nil {
			fmt.Println("Error waiting for script:", err)
			return
	}
}

// EvaluateLinearTransform evaluates a linear transform (i.e. matrix) on the input vector.
// values: the input vector
// diags: the non-zero diagonals of the linear transform
func EvaluateLinearTransform(values []complex128, diags map[int][]complex128) (res []complex128) {

	slots := len(values)

	keys := utils.GetKeys(diags)

	N1 := he.FindBestBSGSRatio(keys, len(values), 1)

	index, _, _ := he.BSGSIndex(keys, slots, N1)

	res = make([]complex128, slots)

	for j := range index {

		rot := -j & (slots - 1)

		tmp := make([]complex128, slots)

		for _, i := range index[j] {

			v, ok := diags[j+i]
			if !ok {
				v = diags[j+i-slots]
			}

			a := utils.RotateSlice(values, i)

			b := utils.RotateSlice(v, rot)

			for i := 0; i < slots; i++ {
				tmp[i] += a[i] * b[i]
			}
		}

		tmp = utils.RotateSlice(tmp, j)

		for i := 0; i < slots; i++ {
			res[i] += tmp[i]
		}
	}

	return
}
