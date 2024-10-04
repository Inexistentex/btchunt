package search

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
	
	"sync/atomic"
	"time"
	"math/rand"
        "github.com/dustin/go-humanize"
	"btchunt/wif" // Importando o pacote wif
        "github.com/fatih/color"
)

// IntervalJumper estrutura para gerenciar o salto entre intervalos
type IntervalJumper struct {
	Ranges       *Ranges
	PrivKeyInt   *big.Int
	MaxPrivKeyInt *big.Int
	Wallets      []string
	StopSignal   chan struct{}
	currentIndex int32
}

// Start inicia o processo de salto entre intervalos
func (ij *IntervalJumper) Start(jumpInterval int) {
	go func() {
		// Cria uma permutação aleatória dos índices dos intervalos
		indices := rand.Perm(len(ij.Ranges.Ranges))
		indexCounter := 0 // Contador para percorrer os índices

		for {
			select {
			case <-ij.StopSignal:
				return
			default:
				// Se todos os índices foram percorridos, reinicia a permutação
				if indexCounter >= len(indices) {
					indices = rand.Perm(len(ij.Ranges.Ranges)) // Gera nova permutação
					indexCounter = 0
				}

				// Obtém o índice atual da permutação
				currentIndex := indices[indexCounter]
				indexCounter++

				// Carrega o intervalo correspondente ao índice atual
				rangeData := ij.Ranges.Ranges[currentIndex]
				ij.PrivKeyInt.SetString(rangeData.Min[2:], 16)
				ij.MaxPrivKeyInt.SetString(rangeData.Max[2:], 16)
				ij.Wallets = strings.Split(rangeData.Status, ", ")

				// Exibe o intervalo atual (opcional para debugging)
				color.Yellow("Saltando para intervalo %d: Min: %s, Max: %s\n", currentIndex, rangeData.Min, rangeData.Max)

				// Aguarda o intervalo de tempo antes de pular para o próximo
				time.Sleep(time.Duration(jumpInterval) * time.Second)
			}
		}
	}()
}
// Função para verificar se há 4 ou mais caracteres repetidos consecutivamente (exceto '0')
func hasRepeatedCharacters(key string) bool {
	repeatCount := 1
	for i := 1; i < len(key); i++ {
		if key[i] == key[i-1] && key[i] != '0' {
			repeatCount++
			if repeatCount >= 4 {
				return true
			}
		} else {
			repeatCount = 1
		}
	}
	return false
}

// Range representa um intervalo de chaves privadas
type Range struct {
	Min    string `json:"min"`
	Max    string `json:"max"`
	Status string `json:"status"`
        OriginalStatus string // Adiciona um campo para armazenar os endereços originais
}

// Ranges contém uma lista de Range
type Ranges struct {
	Ranges []Range
}

// LoadRanges carrega os intervalos de chaves privadas a partir de um arquivo JSON e converte os endereços em hash160
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

// GetRandomBlock gera um bloco de chaves privadas aleatórias dentro do intervalo fornecido
func GetRandomBlock(minPrivKey, maxPrivKey *big.Int, blockSize int64) *big.Int {
	rangeSize := new(big.Int).Sub(maxPrivKey, minPrivKey)
	block := new(big.Int).Rand(rand.New(rand.NewSource(time.Now().UnixNano())), rangeSize)

	// Ajusta o bloco para estar dentro do intervalo [minPrivKey, maxPrivKey - blockSize]
	block.Add(block, minPrivKey)
	blockEnd := new(big.Int).Set(block)
	blockEnd.Add(blockEnd, big.NewInt(blockSize))

	if blockEnd.Cmp(maxPrivKey) > 0 {
		// Se o bloco ultrapassar o maxPrivKey, ajusta para estar dentro do intervalo
		block.Sub(maxPrivKey, big.NewInt(blockSize))
               fmt.Printf("bloco %s \n", blockSize)
	}

	return block
}

// SearchInBlockBatch busca chaves privadas em lotes dentro de um bloco
func SearchInBlockBatch(wallets []string, blockSize int64, minPrivKey, maxPrivKey *big.Int, stopSignal chan struct{}, startTime time.Time, id int, keysChecked *int64, checkInterval int64, taskChan chan *big.Int, batchSize int) {
	for block := range taskChan {
		privKey := new(big.Int)
		var privKeyBatch []*big.Int
		for i := int64(0); i < blockSize; i++ {
			privKey.Add(block, big.NewInt(i))
			privKeyBatch = append(privKeyBatch, new(big.Int).Set(privKey))

			// Processa o lote ao atingir o tamanho do batch
			if len(privKeyBatch) == batchSize {
				verifyBatch(privKeyBatch, wallets, stopSignal, keysChecked, checkInterval, startTime)
				privKeyBatch = privKeyBatch[:0] // Limpa o batch
			}
		}
		// Processa o restante do lote
		if len(privKeyBatch) > 0 {
			verifyBatch(privKeyBatch, wallets, stopSignal, keysChecked, checkInterval, startTime)
		}
	}
}

// verifyBatch verifica um lote de chaves de uma só vez
func verifyBatch(privKeyBatch []*big.Int, wallets []string, stopSignal chan struct{}, keysChecked *int64, checkInterval int64, startTime time.Time) {
    var validPrivKeys []*big.Int
    var pubKeys [][]byte

    for _, privKey := range privKeyBatch {
        privKeyBytes := privKey.FillBytes(make([]byte, 32))

        // Verifica se a chave contém caracteres repetidos
        privKeyHex := fmt.Sprintf("%064x", privKey) // Converte a chave para string hexadecimal
        if hasRepeatedCharacters(privKeyHex) {
            // Chave privada ignorada
            continue // Pula a chave privada se ela contiver 4 ou mais caracteres repetidos
        }

        // Se não tiver caracteres repetidos, gera a chave pública
        pubKey := wif.GeneratePublicKey(privKeyBytes)
        pubKeys = append(pubKeys, pubKey)
        validPrivKeys = append(validPrivKeys, privKey)
    }

    // Processa as chaves públicas geradas
    for i, pubKey := range pubKeys {
        addressHash160 := wif.Hash160(pubKey)
        addressHash160Hex := fmt.Sprintf("%x", addressHash160)

        if contains(wallets, addressHash160Hex) {
            privKey := validPrivKeys[i]
            wifKey := wif.PrivateKeyToWIF(privKey)
            address := wif.PublicKeyToAddress(pubKey)
            saveFoundKeyDetails(privKey, wifKey, address)

            close(stopSignal)
            return
        }
    }

    if atomic.AddInt64(keysChecked, int64(len(privKeyBatch)))%checkInterval == 0 {
        printProgress(startTime, keysChecked)
    }
}

// contains verifica se um endereço hash está na lista de wallets
func contains(wallets []string, addressHash160Hex string) bool {
	for _, wallet := range wallets {
		if wallet == addressHash160Hex {
			return true
		}
	}
	return false
}

// saveFoundKeyDetails salva os detalhes da chave privada encontrada em um arquivo
func saveFoundKeyDetails(privKey *big.Int, wifKey, address string) {
	fmt.Println("-------------------CHAVE ENCONTRADA!!!!-------------------")
	fmt.Printf("Private key: %064x\n", privKey)
	fmt.Printf("WIF: %s\n", wifKey)
	fmt.Printf("Endereço: %s\n", address)

	file, err := os.OpenFile("found_keys.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Erro ao salvar chave encontrada: %v\n", err)
		return
	}
	defer file.Close()

	_, err = file.WriteString(fmt.Sprintf("Private key: %064x\nWIF: %s\nEndereço: %s\n", privKey, wifKey, address))
	if err != nil {
		fmt.Printf("Erro ao escrever chave encontrada: %v\n", err)
	}
}


// printProgress imprime o progresso da busca
func printProgress(startTime time.Time, keysChecked *int64) {
	elapsed := time.Since(startTime)
	chavesPorSegundo := float64(atomic.LoadInt64(keysChecked)) / elapsed.Seconds()
	fmt.Printf("Keys Checked: %s  Time: %.8ss  Keys/s: %.2f\n", 
		humanize.Comma(atomic.LoadInt64(keysChecked)), 
		elapsed, 
		chavesPorSegundo)
}
