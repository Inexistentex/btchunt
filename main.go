package main

import (
	"fmt"
	"log"
	"math/big"
	"math/rand"
	"strings"
	"sync"
	"time"

	"btchunt/search"

	"github.com/fatih/color"
)

const (
	checkInterval  = 200000
	jumpInterval   = 1800
	numGoroutines  = 16
	blockSize      = int64(1000)
)

var rng = rand.New(rand.NewSource(time.Now().UnixNano()))

func main() {
	// Declaração da variável ranges e err
	ranges, err := search.LoadRanges("ranges.json")
	if err != nil {
		log.Fatalf("Failed to load ranges: %v", err)
	}

	color.Cyan("______________BtcHunt By: Inex______________")
	color.White("__________________v1.0_____________________")

	rangeNumber := getRandomRange(len(ranges.Ranges))
	privKeyHex := ranges.Ranges[rangeNumber-1].Min
	maxPrivKeyHex := ranges.Ranges[rangeNumber-1].Max
	wallets := strings.Split(ranges.Ranges[rangeNumber-1].Status, ", ")

	privKeyInt := new(big.Int)
	privKeyInt.SetString(privKeyHex[2:], 16)
	maxPrivKeyInt := new(big.Int)
	maxPrivKeyInt.SetString(maxPrivKeyHex[2:], 16)

	fmt.Println("Wallets a serem buscadas:")
	for _, wallet := range wallets {
		fmt.Println(wallet)
	}

	startTime := time.Now()
	stopSignal := make(chan struct{})
	var wg sync.WaitGroup
	var keysChecked int64

	intervalJumper := &search.IntervalJumper{
		Ranges:        ranges,
		PrivKeyInt:    privKeyInt,
		MaxPrivKeyInt: maxPrivKeyInt,
		Wallets:       wallets,
		StopSignal:    stopSignal,
	}

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			search.SearchInBlock(wallets, blockSize, privKeyInt, maxPrivKeyInt, stopSignal, startTime, id, &keysChecked, checkInterval)
		}(i)
	}

	intervalJumper.Start(jumpInterval)

	wg.Wait()
}

func getRandomRange(numRanges int) int {
	return rng.Intn(numRanges)
}
