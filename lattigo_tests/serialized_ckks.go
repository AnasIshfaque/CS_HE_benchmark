package main

import (
	"fmt"
	"unsafe"

	// "math/rand"

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he/hefloat"

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
			LogQ:            []int{55, 45, 45, 45, 45, 45, 45, 65}, // An initial prime of 55 bits and 7 primes of 45 bits
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

	// LogSlots := params.LogMaxSlots()
	// Slots := 1 << LogSlots

	// r := rand.New(rand.NewSource(0))

	// values2 := make([]complex128, Slots)
	// values1 := make([]complex128, Slots)
	// for i := 0; i < Slots; i++ {
	// 	values1[i] = complex(2*r.Float64()-1, 2*r.Float64()-1)
	// 	values2[i] = complex(2*r.Float64()-1, 2*r.Float64()-1)
	// }

	var x1 []complex128

	// Initialize the slice with values
	x1 = []complex128{0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0}

	elementSize := int(unsafe.Sizeof(x1[0])) // Size of a single float64 element
	size := len(x1) * elementSize
	fmt.Printf("Size of slice data (unsafe.Sizeof): %d bytes\n", size)

	pt1 := hefloat.NewPlaintext(params, params.MaxLevel())

	ecd2 := hefloat.NewEncoder(hefloat.Parameters(params))

	if err = ecd2.Encode(x1, pt1); err != nil {
		panic(err)
	}

	enc := rlwe.NewEncryptor(params, pk)

	// And we create the ciphertext.
	// Note that the metadata of the plaintext will be copied on the resulting ciphertext.
	ct1, err := enc.EncryptNew(pt1)
	if err != nil {
		panic(err)
	}

	encryption_start_time := time.Now()

	serialized_ct1, err := ct1.MarshalBinary()
	if err != nil {
		panic(err)
	}
	encryption_end_time := time.Now()

	// dec := rlwe.NewDecryptor(params, sk)

	serialized_ct1_size := unsafe.Sizeof(serialized_ct1)
	fmt.Println("Size of serialized ciphertext: ", serialized_ct1_size)
	fmt.Println("Size of serialized ciphertext in bytes: ", ct1.BinarySize())

	fmt.Println("Serialization time: ", encryption_end_time.Sub(encryption_start_time))

	// Wait for the script to finish
	err = cmd.Process.Kill()
	if err != nil {
		fmt.Println("Error waiting for script:", err)
		return
	}
}
