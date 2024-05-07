package main

import (
	"fmt"
	"math/rand"

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he"
	"github.com/tuneinsight/lattigo/v5/he/hefloat"
	"github.com/tuneinsight/lattigo/v5/utils"

    "os/exec"
	"time"
)

func main() {
	scriptPath := "device_check.sh"

	

	

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
	
	
	start_time := time.Now()
	fmt.Println("Start time: ", start_time)
	
	
	key_gen_start_time := time.Now()

	//prec := params.EncodingPrecision() 
	kgen := rlwe.NewKeyGenerator(params)

	sk := kgen.GenSecretKeyNew()
	pk := kgen.GenPublicKeyNew(sk) // Note that we can generate any number of public keys associated to the same Secret Key.
	rlk := kgen.GenRelinearizationKeyNew(sk)

	evk := rlwe.NewMemEvaluationKeySet(rlk)

	key_gen_end_time := time.Now()
	

	LogSlots := params.LogMaxSlots()
	Slots := 1 << LogSlots

	r := rand.New(rand.NewSource(0))

	


	values2 := make([]complex128, Slots)
	values1 := make([]complex128, Slots)
	for i := 0; i < Slots; i++ {
		values1[i] = complex(2*r.Float64()-1, 2*r.Float64()-1)
		values2[i] = complex(2*r.Float64()-1, 2*r.Float64()-1)
	}

	encryption_start_time := time.Now()


	pt1 := hefloat.NewPlaintext(params, params.MaxLevel())
	pt2 := hefloat.NewPlaintext(params, params.MaxLevel())
	
	ecd := hefloat.NewEncoder(params)

	ecd2 := hefloat.NewEncoder(hefloat.Parameters(params))

	if err = ecd2.Encode(values1, pt1); err != nil {
		panic(err)
	}
	if err = ecd.Encode(values2, pt2); err != nil {
		panic(err)
	}

	enc := rlwe.NewEncryptor(params, pk)

	// And we create the ciphertext.
	// Note that the metadata of the plaintext will be copied on the resulting ciphertext.
	ct1, err := enc.EncryptNew(pt1)
	if err != nil {
		panic(err)
	}
	ct2, err := enc.EncryptNew(pt2)
	if err != nil {
		panic(err)
	}

	encryption_end_time := time.Now()




	dec := rlwe.NewDecryptor(params, sk)

	eval := hefloat.NewEvaluator(params, evk)

	addition_start_time := time.Now()

	want_add := make([]complex128, Slots)
	want_mul := make([]complex128, Slots)
	for i := 0; i < Slots; i++ {
		want_add[i] = values1[i] + values2[i]
	}

	ct3_add, err := eval.AddNew(ct1, ct2)
	if err != nil {
		panic(err)
	}

	addition_end_time := time.Now()



	fmt.Printf("==============\n")
	fmt.Printf("MULTIPLICATION\n")
	fmt.Printf("==============\n")
	fmt.Printf("\n")

	mutliplication_start_time := time.Now()

	for i := 0; i < Slots; i++ {
		want_mul[i] = values1[i] * values2[i]
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

	//fmt.Printf("Multiplication - ct * ct%s", hefloat.GetPrecisionStats(params, ecd, dec, want, res, 0, false).String())
	multiplication_end_time := time.Now()
	

	

	fmt.Printf("======================\n")
	fmt.Printf("ROTATION\n")
	fmt.Printf("======================\n")
	fmt.Printf("\n")


	rotation_start_time := time.Now()
	//rotate 4 times. 1, 2, -1, -2
	rot := 1
	galois := rlwe.NewMemEvaluationKeySet(rlk, kgen.GenGaloisKeysNew([]uint64{
		params.GaloisElement(rot),
	}, sk)...)


	want_rot1 := make([]complex128, Slots)
	want_rot2 := make([]complex128, Slots)
	want_rot3 := make([]complex128, Slots)
	want_rot4 := make([]complex128, Slots)

	eval = eval.WithKey(galois)
	for i := 0; i < Slots; i++ {
		want_rot1[i] = values1[(i+1)%Slots]
	}
	ct3_rot1, err := eval.RotateNew(ct1, rot)
	if err != nil {
		panic(err)
	}

	

	

	rot = 2
	galois = rlwe.NewMemEvaluationKeySet(rlk, kgen.GenGaloisKeysNew([]uint64{
		params.GaloisElement(rot),
	}, sk)...)

	eval = eval.WithKey(galois)

	for i := 0; i < Slots; i++ {
		want_rot2[i] = values1[(i+2)%Slots]
	}
	ct3_rot2, err := eval.RotateNew(ct1, rot)
	if err != nil {
		panic(err)
	}

	rot = -1

	galois = rlwe.NewMemEvaluationKeySet(rlk, kgen.GenGaloisKeysNew([]uint64{
		params.GaloisElement(rot),
	}, sk)...)

	eval = eval.WithKey(galois)
	for i := 0; i < Slots; i++ {
		want_rot3[i] = values1[(i-1+Slots)%Slots]
	}
	ct3_rot3, err := eval.RotateNew(ct1, rot)
	if err != nil {
		panic(err)
	}

	rot = -2

	galois = rlwe.NewMemEvaluationKeySet(rlk, kgen.GenGaloisKeysNew([]uint64{
		params.GaloisElement(rot),
	}, sk)...)

	eval = eval.WithKey(galois)

	for i := 0; i < Slots; i++ {
		want_rot4[i] = values1[(i-2+Slots)%Slots]
	}
	ct3_rot4, err := eval.RotateNew(ct1, rot)
	if err != nil {
		panic(err)
	}



	//fmt.Printf("Rotation by k=%d %s", rot, hefloat.GetPrecisionStats(params, ecd, dec, want, ct3, 0, false).String())
	rotation_end_time := time.Now()
	



	decryption_start_time := time.Now()
	//decrypt addition
	fmt.Printf("Addition - ct + ct%s", hefloat.GetPrecisionStats(params, ecd, dec, want_add, ct3_add, 0, false).String())
	//decrypt multiplication 
	fmt.Printf("Multiplication - ct * ct%s", hefloat.GetPrecisionStats(params, ecd, dec, want_mul, res, 0, false).String())
	//decrypt rotations
	fmt.Printf("Rotation by k=1 %s",  hefloat.GetPrecisionStats(params, ecd, dec, want_rot1, ct3_rot1, 0, false).String())
	fmt.Printf("Rotation by k=2 %s",  hefloat.GetPrecisionStats(params, ecd, dec, want_rot2, ct3_rot2, 0, false).String())
	fmt.Printf("Rotation by k=-1 %s",  hefloat.GetPrecisionStats(params, ecd, dec, want_rot3, ct3_rot3, 0, false).String())
	fmt.Printf("Rotation by k=-2 %s",  hefloat.GetPrecisionStats(params, ecd, dec, want_rot4, ct3_rot4, 0, false).String())
	decryption_end_time := time.Now()





	fmt.Println("Key generation time: ", key_gen_end_time.Sub(key_gen_start_time))
	fmt.Println("Encryption time: ", encryption_end_time.Sub(encryption_start_time))
	fmt.Println("Addition time: ", addition_end_time.Sub(addition_start_time))
	fmt.Println("Multiplication time: ", multiplication_end_time.Sub(mutliplication_start_time))
	fmt.Println("Rotation time: ", rotation_end_time.Sub(rotation_start_time))
	fmt.Println("Decryption time: ", decryption_end_time.Sub(decryption_start_time))

	// Wait for the script to finish
	err = cmd.Process.Kill()
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
