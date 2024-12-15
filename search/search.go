package search

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"math/rand"
	"os"
	"strings"
	"sync/atomic"
	"time"
         "github.com/dustin/go-humanize"
	"btchunt/wif"

	"github.com/fatih/color"
)

// Estrutura global para o gerador xoshiro256
type Xoshiro256 struct {
	state [4]uint64
}

func NewXoshiro256() *Xoshiro256 {
	x := &Xoshiro256{}
	seed := make([]byte, 32)
	rand.Read(seed) // seed inicial única
	x.state[0] = binary.BigEndian.Uint64(seed[0:8])
	x.state[1] = binary.BigEndian.Uint64(seed[8:16])
	x.state[2] = binary.BigEndian.Uint64(seed[16:24])
	x.state[3] = binary.BigEndian.Uint64(seed[24:32])
	return x
}

func (x *Xoshiro256) Next() uint64 {
	result := rotl(x.state[1]*5, 7) * 9
	t := x.state[1] << 17
	x.state[2] ^= x.state[0]
	x.state[3] ^= x.state[1]
	x.state[1] ^= x.state[2]
	x.state[0] ^= x.state[3]
	x.state[2] ^= t
	x.state[3] = rotl(x.state[3], 45)
	return result
}

func rotl(x uint64, k int) uint64 {
	return (x << k) | (x >> (64 - k))
}

// IntervalJumper estrutura para gerenciar o salto entre intervalos
type IntervalJumper struct {
	Ranges        *Ranges
	PrivKeyInt    *big.Int
	MaxPrivKeyInt *big.Int
	Wallets       []string
	StopSignal    chan struct{}
	currentIndex  int32
}

// Start inicia o processo de salto entre intervalos
func (ij *IntervalJumper) Start(jumpInterval int) {
	go func() {
		indices := rand.Perm(len(ij.Ranges.Ranges))
		indexCounter := 0

		for {
			if indexCounter >= len(indices) {
				indices = rand.Perm(len(ij.Ranges.Ranges))
				indexCounter = 0
			}

			currentIndex := indices[indexCounter]
			indexCounter++

			rangeData := ij.Ranges.Ranges[currentIndex]
			ij.PrivKeyInt.SetString(rangeData.Min[2:], 16)
			ij.MaxPrivKeyInt.SetString(rangeData.Max[2:], 16)
			ij.Wallets = strings.Split(rangeData.Status, ", ")

			color.Yellow("Saltando para intervalo %d: Min: %s, Max: %s\n", currentIndex, rangeData.Min, rangeData.Max)
			time.Sleep(time.Duration(jumpInterval) * time.Second)
		}
	}()
}

// Range representa um intervalo de chaves privadas
type Range struct {
	Min            string `json:"min"`
	Max            string `json:"max"`
	Status         string `json:"status"`
	OriginalStatus string
}

// Ranges contém uma lista de Range
type Ranges struct {
	Ranges []Range
}

// LoadRanges carrega os intervalos de chaves privadas a partir de um arquivo JSON
func LoadRanges(filename string) (*Ranges, error) {
    file, err := os.Open(filename)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    var ranges Ranges
    decoder := json.NewDecoder(file)
    err = decoder.Decode(&ranges)
    if err != nil {
        return nil, err
    }

    for i := range ranges.Ranges {
        addresses := strings.Split(ranges.Ranges[i].Status, ", ")
        originalAddresses := make([]string, len(addresses))
        copy(originalAddresses, addresses)

        var hash160s []string
        for _, address := range addresses {
            hash160 := wif.AddressToHash160(address)
            hash160s = append(hash160s, fmt.Sprintf("%x", hash160))
        }
        ranges.Ranges[i].Status = strings.Join(hash160s, ", ")
        ranges.Ranges[i].OriginalStatus = strings.Join(originalAddresses, ", ")
    }

    return &ranges, nil
}

// SearchInBlockBatch modificada para usar xoshiro256
func SearchInBlockBatch(wallets []string, blockSize int64, minPrivKey, maxPrivKey *big.Int, stopSignal chan struct{}, startTime time.Time, id int, keysChecked *int64, checkInterval int64, taskChan chan *big.Int, batchSize int) {
   fullyRandom := id % 2 == 0
    xoshiro := NewXoshiro256()

    for block := range taskChan {
        privKey := new(big.Int)
        var privKeyBatch []*big.Int

        if fullyRandom {
            // Modo totalmente aleatório
            for i := int64(0); i < blockSize; i++ {
                randomBits := make([]byte, 32)
                binary.BigEndian.PutUint64(randomBits[0:8], xoshiro.Next())
                binary.BigEndian.PutUint64(randomBits[8:16], xoshiro.Next())
                binary.BigEndian.PutUint64(randomBits[16:24], xoshiro.Next())
                binary.BigEndian.PutUint64(randomBits[24:32], xoshiro.Next())
                
                randomKey := new(big.Int).SetBytes(randomBits)
                diff := new(big.Int).Sub(maxPrivKey, minPrivKey)
                randomKey.Mod(randomKey, diff)
                randomKey.Add(randomKey, minPrivKey)
                
                privKeyBatch = append(privKeyBatch, new(big.Int).Set(randomKey))

                if len(privKeyBatch) == batchSize {
                    verifyBatch(privKeyBatch, wallets, stopSignal, keysChecked, checkInterval, startTime, fullyRandom)
                    privKeyBatch = privKeyBatch[:0]
                }
            }
        } else {
            // Modo original (aleatório + sequencial)
            for i := int64(0); i < blockSize; i++ {
                privKey.Add(block, big.NewInt(i))
                privKeyBatch = append(privKeyBatch, new(big.Int).Set(privKey))

                if len(privKeyBatch) == batchSize {
                    verifyBatch(privKeyBatch, wallets, stopSignal, keysChecked, checkInterval, startTime, fullyRandom)
                    privKeyBatch = privKeyBatch[:0]
                }
            }
        }

        if len(privKeyBatch) > 0 {
            verifyBatch(privKeyBatch, wallets, stopSignal, keysChecked, checkInterval, startTime, fullyRandom)
        }
    }
}

func GetRandomBlock(minPrivKey, maxPrivKey *big.Int, blockSize int64, fullyRandom bool) *big.Int {
	xoshiro := NewXoshiro256()

	if fullyRandom {
		diff := new(big.Int).Sub(maxPrivKey, minPrivKey)
		randomBits := make([]byte, 32)
		binary.BigEndian.PutUint64(randomBits[0:8], xoshiro.Next())
		binary.BigEndian.PutUint64(randomBits[8:16], xoshiro.Next())
		binary.BigEndian.PutUint64(randomBits[16:24], xoshiro.Next())
		binary.BigEndian.PutUint64(randomBits[24:32], xoshiro.Next())

		randomInt := new(big.Int).SetBytes(randomBits)
		randomInt.Mod(randomInt, diff)
		return randomInt.Add(randomInt, minPrivKey)
	}

	rangeSize := new(big.Int).Sub(maxPrivKey, minPrivKey)
	randomBits := make([]byte, 32)
	binary.BigEndian.PutUint64(randomBits[0:8], xoshiro.Next())
	binary.BigEndian.PutUint64(randomBits[8:16], xoshiro.Next())
	binary.BigEndian.PutUint64(randomBits[16:24], xoshiro.Next())
	binary.BigEndian.PutUint64(randomBits[24:32], xoshiro.Next())

	block := new(big.Int).SetBytes(randomBits)
	block.Mod(block, rangeSize)
	block.Add(block, minPrivKey)

	blockEnd := new(big.Int).Set(block)
	blockEnd.Add(blockEnd, big.NewInt(blockSize))

	if blockEnd.Cmp(maxPrivKey) > 0 {
		block.Sub(maxPrivKey, big.NewInt(blockSize))
	}

	return block
}

func verifyBatch(privKeyBatch []*big.Int, wallets []string, stopSignal chan struct{}, keysChecked *int64, checkInterval int64, startTime time.Time, fullyRandom bool) {
	pubKeys := make([][]byte, len(privKeyBatch))
	var closed int32

	for i, privKey := range privKeyBatch {
		privKeyBytes := privKey.FillBytes(make([]byte, 32))
		if atomic.AddInt64(keysChecked, 1)%checkInterval == 0 {
			printProgress(startTime, keysChecked)
		}
		pubKeys[i] = wif.GeneratePublicKey(privKeyBytes)
	}

	for i, pubKey := range pubKeys {
		addressHash160 := wif.Hash160(pubKey)
		addressHash160Hex := fmt.Sprintf("%x", addressHash160)

		if contains(wallets, addressHash160Hex) {
			privKey := privKeyBatch[i]
			wifKey := wif.PrivateKeyToWIF(privKey)
			address := wif.PublicKeyToAddress(pubKey)

            // Determina o modo de busca (aleatório ou sequencial)
            mode := "sequential"
            if fullyRandom {
                mode = "fullyRandom"
            }

			saveFoundKeyDetails(privKey, wifKey, address, mode)
			atomic.StoreInt32(&closed, 1)
			close(stopSignal)
			return
		}
	}
}

// hasRepeatedChars verifica se a chave contém 3 ou mais caracteres repetidos consecutivos, ignorando os zeros
func hasRepeatedChars(key []byte) bool {
	count := 1
	for i := 1; i < len(key); i++ {
		if key[i] == key[i-1] && key[i] != 0 {
			count++
			if count >= 3 {
				return true
			}
		} else {
			count = 1
		}
	}
	return false
}

func contains(wallets []string, addressHash160Hex string) bool {
	for _, wallet := range wallets {
		if wallet == addressHash160Hex {
			return true
		}
	}
	return false
}

func saveFoundKeyDetails(privKey *big.Int, wifKey, address string, mode string) {
        fmt.Println(" ")
        fmt.Println("-------------------CHAVE ENCONTRADA!!!!-------------------")
        fmt.Printf("Modo de Busca: %s\n", mode)  // Exibe o modo de busca
        fmt.Printf("Private key: %064x\n", privKey)
        fmt.Printf("WIF: %s\n", wifKey)
        fmt.Printf("Endereço: %s\n", address)

	file, _ := os.OpenFile("found_keys.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	defer file.Close()
	file.WriteString(fmt.Sprintf("Modo de Busca: %s\nPrivate key: %064x\nWIF: %s\nEndereço: %s\n", mode, privKey, wifKey, address))
}

func printProgress(startTime time.Time, keysChecked *int64) {
	elapsed := time.Since(startTime)
	chavesPorSegundo := float64(atomic.LoadInt64(keysChecked)) / elapsed.Seconds()
	fmt.Printf("\rKeys Checked: %s  Time: %.8ss  Keys/s: %.2f", 
		humanize.Comma(atomic.LoadInt64(keysChecked)), 
		elapsed, 
		chavesPorSegundo)
}
