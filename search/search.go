package search

import (
	"encoding/binary"
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

// GetRandomBlock modificado para usar apenas xoshiro256
func GetRandomBlock(minPrivKey, maxPrivKey *big.Int, blockSize int64, fullyRandom bool) *big.Int {
    xoshiro := NewXoshiro256()
    
    if fullyRandom {
        // Modo 100% aleatório
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

    // Modo original (bloco aleatório + sequencial)
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

// SearchInBlockBatch modificada para usar xoshiro256
func SearchInBlockBatch(wallets []string, blockSize int64, minPrivKey, maxPrivKey *big.Int, stopSignal chan struct{}, startTime time.Time, id int, keysChecked *int64, checkInterval int64, taskChan chan *big.Int, batchSize int) {
    fullyRandom := id%2 == 0
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
                    verifyBatch(privKeyBatch, wallets, stopSignal, keysChecked, checkInterval, startTime)
                    privKeyBatch = privKeyBatch[:0]
                }
            }
        } else {
            // Modo original (aleatório + sequencial)
            for i := int64(0); i < blockSize; i++ {
                privKey.Add(block, big.NewInt(i))
                privKeyBatch = append(privKeyBatch, new(big.Int).Set(privKey))

                if len(privKeyBatch) == batchSize {
                    verifyBatch(privKeyBatch, wallets, stopSignal, keysChecked, checkInterval, startTime)
                    privKeyBatch = privKeyBatch[:0]
                }
            }
        }

        if len(privKeyBatch) > 0 {
            verifyBatch(privKeyBatch, wallets, stopSignal, keysChecked, checkInterval, startTime)
        }
    }
}


// verifyBatch verifica um lote de chaves de uma só vez
func verifyBatch(privKeyBatch []*big.Int, wallets []string, stopSignal chan struct{}, keysChecked *int64, checkInterval int64, startTime time.Time) {
	pubKeys := make([][]byte, len(privKeyBatch))
	var closed int32 // Variável atômica para rastrear o estado do canal

	for i, privKey := range privKeyBatch {
		privKeyBytes := privKey.FillBytes(make([]byte, 32))

		// Incrementa o contador de chaves verificadas
		if atomic.AddInt64(keysChecked, 1)%checkInterval == 0 {
			printProgress(startTime, keysChecked)
		}
		

		// Se não houver repetição de caracteres, gera a chave pública
		pubKeys[i] = wif.GeneratePublicKey(privKeyBytes) // Usando função do pacote wif
	}

	for i, pubKey := range pubKeys {

		addressHash160 := wif.Hash160(pubKey) // Usando função do pacote wif
		addressHash160Hex := fmt.Sprintf("%x", addressHash160)

		if contains(wallets, addressHash160Hex) {
			privKey := privKeyBatch[i]
			wifKey := wif.PrivateKeyToWIF(privKey) // Usando função do pacote wif
			address := wif.PublicKeyToAddress(pubKey) // Usando função do pacote wif
			saveFoundKeyDetails(privKey, wifKey, address)

			// Fecha o stopSignal apenas se ainda não tiver sido fechado
			if atomic.CompareAndSwapInt32(&closed, 0, 1) {
				close(stopSignal)
			}
			return
		}
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
