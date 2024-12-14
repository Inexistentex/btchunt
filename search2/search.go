package search

import (
	"encoding/json"
	"fmt"
	"math/big"
        "math/rand"

	"os"
	"sync"
	"sync/atomic"
	"time"

	"btchunt/wif"
	"github.com/dustin/go-humanize"
)

// Range representa um intervalo de chaves privadas
type Range struct {
	Min            string `json:"min"`
	Max            string `json:"max"`
	Status         string `json:"status"`
	Key            string `json:"key"`
	OriginalStatus string
}

// Ranges contém uma lista de Range
type Ranges struct {
	Ranges []Range
}

// LoadRanges carrega os intervalos do arquivo JSON
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

	// Processa os endereços
	for i := range ranges.Ranges {
		ranges.Ranges[i].OriginalStatus = ranges.Ranges[i].Status
		hash160 := wif.AddressToHash160(ranges.Ranges[i].Status)
		ranges.Ranges[i].Status = fmt.Sprintf("%x", hash160)
	}

	return &ranges, nil
}

// Incrementa a chave respeitando o padrão
func incrementKeyPattern(currentKey []byte, pattern string) bool {
	chars := "0123456789abcdef"
	for i := len(currentKey) - 1; i >= 0; i-- {
		if pattern[i] == 'x' {
			index := indexOf(chars, currentKey[i])
			if index < len(chars)-1 {
				currentKey[i] = chars[index+1]
				return true
			} else {
				currentKey[i] = '0'
			}
		}
	}
	return false
}

// indexOf retorna o índice de um caractere em uma string
func indexOf(chars string, char byte) int {
	for i := 0; i < len(chars); i++ {
		if chars[i] == char {
			return i
		}
	}
	return -1
}

// GenerateAndSendKeys otimizado com controle do número de goroutines
func GenerateAndSendKeys(pattern string, keysChan chan<- string, stopSignal chan struct{}, blockSize int64, numGoroutines int) {
	var wg sync.WaitGroup
	var blockCount int64

	for w := 0; w < numGoroutines; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopSignal:
					return
				default:
					baseKey := generateRandomKey(pattern)
					currentKey := []byte(baseKey)
					firstKeyInBlock := baseKey

					for attempts := int64(0); attempts < blockSize; {
						keysChan <- string(currentKey)
						attempts++
						if !incrementKeyPattern(currentKey, pattern) {
							break
						}
					}

					lastKeyInBlock := string(currentKey)
					atomic.AddInt64(&blockCount, 1)
					fmt.Printf("\nBloco #%d - Primeira: %s Última: %s", blockCount, firstKeyInBlock, lastKeyInBlock)
				}
			}
		}()
	}

	wg.Wait()
}

// generateRandomKey gera uma chave aleatória inicial baseada no padrão
func generateRandomKey(pattern string) string {
    chars := "0123456789abcdef"
    result := make([]byte, len(pattern))
    
    for i, char := range pattern {
        if char == 'x' {
            randIndex := rand.Intn(len(chars))
            result[i] = chars[randIndex]
        } else {
            result[i] = byte(char)
        }
    }
    
    return string(result)
}


// SearchInBlockBatch processa as chaves em lotes de forma eficiente
func SearchInBlockBatch(wallets []string, keysChan <-chan string, stopSignal chan struct{}, startTime time.Time, id int, keysChecked *int64, checkInterval int64, batchSize int) {
	walletMap := make(map[string]struct{})
	for _, wallet := range wallets {
		walletMap[wallet] = struct{}{}
	}

	var keyBatch []string
	for keyHex := range keysChan {
		select {
		case <-stopSignal:
			return
		default:
			keyBatch = append(keyBatch, keyHex)
			if len(keyBatch) == batchSize {
				processBatchOptimized(keyBatch, walletMap, stopSignal, keysChecked, checkInterval, startTime)
				keyBatch = keyBatch[:0]
			}
		}
	}

	if len(keyBatch) > 0 {
		processBatchOptimized(keyBatch, walletMap, stopSignal, keysChecked, checkInterval, startTime)
	}
}

// processBatchOptimized processa um lote de chaves
func processBatchOptimized(keyBatch []string, walletMap map[string]struct{}, stopSignal chan struct{}, keysChecked *int64, checkInterval int64, startTime time.Time) {
	for _, keyHex := range keyBatch {
		select {
		case <-stopSignal:
			return
		default:
			privKey := new(big.Int)
			privKey.SetString(keyHex, 16)

			if atomic.AddInt64(keysChecked, 1)%checkInterval == 0 {
				printProgress(startTime, keysChecked)
			}

			privKeyBytes := privKey.FillBytes(make([]byte, 32))
			pubKey := wif.GeneratePublicKey(privKeyBytes)
			addressHash160 := wif.Hash160(pubKey)
			addressHash160Hex := fmt.Sprintf("%x", addressHash160)

			if _, exists := walletMap[addressHash160Hex]; exists {
				wifKey := wif.PrivateKeyToWIF(privKey)
				address := wif.PublicKeyToAddress(pubKey)
				saveFoundKeyDetails(privKey, wifKey, address)
				close(stopSignal)
				return
			}
		}
	}
}

// saveFoundKeyDetails salva os detalhes da chave encontrada
func saveFoundKeyDetails(privKey *big.Int, wifKey, address string) {
	fmt.Println("\n-------------------CHAVE ENCONTRADA!!!!-------------------")
	fmt.Printf("Private key: %064x\n", privKey)
	fmt.Printf("WIF: %s\n", wifKey)
	fmt.Printf("Endereço: %s\n", address)

	file, err := os.OpenFile("found_keys.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Erro ao salvar chave encontrada: %v\n", err)
		return
	}
	defer file.Close()

	_, err = file.WriteString(fmt.Sprintf("\nPrivate key: %064x\nWIF: %s\nEndereço: %s\n", privKey, wifKey, address))
	if err != nil {
		fmt.Printf("Erro ao escrever chave encontrada: %v\n", err)
	}
}

// printProgress mostra o progresso da busca
func printProgress(startTime time.Time, keysChecked *int64) {
	elapsed := time.Since(startTime)
	keysPerSecond := float64(atomic.LoadInt64(keysChecked)) / elapsed.Seconds()
	fmt.Printf("\rKeys Checked: %s  Time: %.2fs  Keys/s: %.2f", 
		humanize.Comma(atomic.LoadInt64(keysChecked)), 
		elapsed.Seconds(), 
		keysPerSecond)
}
