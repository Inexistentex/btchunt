package search

import (
	"encoding/json"
	"fmt"
	"math/big"
        "math/rand"
        "math/bits"
	"os"
	"sync"
	"sync/atomic"
	"time"
        "strings"
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

    // Adiciona um campo para armazenar os endereços originais
    for i := range ranges.Ranges {
        addresses := strings.Split(ranges.Ranges[i].Status, ", ")

        // Cria um campo separado para armazenar os endereços originais
        originalAddresses := make([]string, len(addresses))
        copy(originalAddresses, addresses)

        // Converte endereços para hash160
        var hash160s []string
        for _, address := range addresses {
            hash160 := wif.AddressToHash160(address) // Usando a função do pacote wif
            hash160s = append(hash160s, fmt.Sprintf("%x", hash160))
        }
        ranges.Ranges[i].Status = strings.Join(hash160s, ", ")

        // Armazena os endereços originais em um campo separado
        ranges.Ranges[i].OriginalStatus = strings.Join(originalAddresses, ", ")
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

    for w := 0; w < numGoroutines; w++ {
        wg.Add(1)
        go func(id int) {
            defer wg.Done()
            
            // Determina o modo de operação baseado no ID da goroutine
            fullyRandom := id%2 == 0
            xoshiro := NewXoshiro256()

            for {
                select {
                case <-stopSignal:
                    return
                default:
                    if fullyRandom {
                        // Modo totalmente aleatório
                        for attempts := int64(0); attempts < blockSize; attempts++ {
                            // Gera uma chave completamente aleatória respeitando o padrão
                            key := make([]byte, len(pattern))
                            for i := 0; i < len(pattern); i++ {
                                if pattern[i] == 'x' {
                                    // Usa Xoshiro para gerar números aleatórios
                                    randVal := xoshiro.Next() % 16
                                    key[i] = "0123456789abcdef"[randVal]
                                } else {
                                    key[i] = pattern[i]
                                }
                            }
                            keysChan <- string(key)
                        }
                    } else {
                        // Modo sequencial com base aleatória
                        baseKey := generateRandomKey(pattern)
                        currentKey := []byte(baseKey)

                        for attempts := int64(0); attempts < blockSize; {
                            keysChan <- string(currentKey)
                            attempts++
                            if !incrementKeyPattern(currentKey, pattern) {
                                break
                            }
                        }
                    }
                }
            }
        }(w)
    }

    wg.Wait()
}

// Estrutura Xoshiro256 para geração de números aleatórios
type Xoshiro256 struct {
    s [4]uint64
}

// NewXoshiro256 inicializa um novo gerador Xoshiro256
func NewXoshiro256() *Xoshiro256 {
    x := &Xoshiro256{}
    // Inicializa com valores aleatórios
    x.s[0] = uint64(time.Now().UnixNano())
    x.s[1] = uint64(rand.Int63())
    x.s[2] = uint64(rand.Int63())
    x.s[3] = uint64(rand.Int63())
    return x
}

// Next gera o próximo número aleatório
func (x *Xoshiro256) Next() uint64 {
    result := bits.RotateLeft64(x.s[1] * 5, 7) * 9
    t := x.s[1] << 17

    x.s[2] ^= x.s[0]
    x.s[3] ^= x.s[1]
    x.s[1] ^= x.s[2]
    x.s[0] ^= x.s[3]

    x.s[2] ^= t
    x.s[3] = bits.RotateLeft64(x.s[3], 45)

    return result
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
func SearchInBlockBatch(wallets []string, keysChan <-chan string, stopSignal chan struct{}, 
    startTime time.Time, id int, keysChecked *int64, checkInterval int64, batchSize int) {
    
    fullyRandom := id%2 == 0
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
                processBatchOptimized(keyBatch, walletMap, stopSignal, keysChecked, 
                    checkInterval, startTime, fullyRandom)
                keyBatch = keyBatch[:0]
            }
        }
    }

    if len(keyBatch) > 0 {
        processBatchOptimized(keyBatch, walletMap, stopSignal, keysChecked, 
            checkInterval, startTime, fullyRandom)
    }
}

// checkRepeatedChars verifica se a chave possui 3 ou mais caracteres consecutivos repetidos
func checkRepeatedChars(key string) bool {
    count := 1
    for i := 1; i < len(key); i++ {
        if key[i] == key[i-1] {
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



// processBatchOptimized processa um lote de chaves
func processBatchOptimized(keyBatch []string, walletMap map[string]struct{}, stopSignal chan struct{}, 
    keysChecked *int64, checkInterval int64, startTime time.Time, fullyRandom bool) {
    
    // Determina o modo de busca
    mode := "Sequencial"
    if fullyRandom {
        mode = "Aleatório"
    }

    for _, keyHex := range keyBatch {
        // Incrementa o contador antes de qualquer filtro ou processamento
        if atomic.AddInt64(keysChecked, 1)%checkInterval == 0 {
            printProgress(startTime, keysChecked)
        }

        // Pula chaves com 3 ou mais caracteres consecutivos repetidos
        if checkRepeatedChars(keyHex) {
            continue
        }

        select {
        case <-stopSignal:
            return
        default:
            privKey := new(big.Int)
            privKey.SetString(keyHex, 16)

            privKeyBytes := privKey.FillBytes(make([]byte, 32))
            pubKey := wif.GeneratePublicKey(privKeyBytes)
            addressHash160 := wif.Hash160(pubKey)
            addressHash160Hex := fmt.Sprintf("%x", addressHash160)

            if _, exists := walletMap[addressHash160Hex]; exists {
                wifKey := wif.PrivateKeyToWIF(privKey)
                address := wif.PublicKeyToAddress(pubKey)
                saveFoundKeyDetails(privKey, wifKey, address, mode)
                close(stopSignal)
                return
            }
        }
    }
}

// saveFoundKeyDetails salva os detalhes da chave encontrada
func saveFoundKeyDetails(privKey *big.Int, wifKey, address string, mode string) {
    fmt.Println(" ")
    fmt.Println("-------------------CHAVE ENCONTRADA!!!!-------------------")
    fmt.Printf("Modo de Busca: %s\n", mode)  // Exibe o modo de busca
    fmt.Printf("Private key: %064x\n", privKey)
    fmt.Printf("WIF: %s\n", wifKey)
    fmt.Printf("Endereço: %s\n", address)

    file, _ := os.OpenFile("found_keys.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    defer file.Close()
    file.WriteString(fmt.Sprintf("Modo de Busca: %s\nPrivate key: %064x\nWIF: %s\nEndereço: %s\n", 
        mode, privKey, wifKey, address))
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
