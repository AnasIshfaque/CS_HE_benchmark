package main

import (
	"fmt"
	"unsafe"

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/schemes/bfv"

	"os/exec"
	"time"
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

	kgen := rlwe.NewKeyGenerator(params)

	sk := kgen.GenSecretKeyNew()
	pk := kgen.GenPublicKeyNew(sk) // Note that we can generate any number of public keys associated to the same Secret Key.

	var x1 []uint64

	// Initialize the slice with values
	x1 = []uint64{25, 5, 75, 1, 2, 3, 4, 5}

	elementSize := int(unsafe.Sizeof(x1[0])) // Size of a single element
	size := len(x1) * elementSize
	fmt.Printf("Size of slice data (unsafe.Sizeof): %d bytes\n", size)

	pt1 := bfv.NewPlaintext(params, params.MaxLevel())

	ecd := bfv.NewEncoder(params)

	if err = ecd.Encode(x1, pt1); err != nil {
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

	err = cmd.Process.Kill()
	if err != nil {
		fmt.Println("Error waiting for script:", err)
		return
	}

}
