package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"
)

type Range struct {
	Min    string `json:"min"`
	Max    string `json:"max"`
	Status string `json:"status"`
}

type PuzzleData struct {
	Ranges []Range `json:"ranges"`
}

func main() {
	// Abrir o arquivo JSON
	file, err := os.Open("Puzzles.json")
	if err != nil {
		fmt.Println("Erro ao abrir o arquivo:", err)
		return
	}
	defer file.Close()

	// Decodificar o arquivo JSON em uma estrutura PuzzleData
	var puzzleData PuzzleData
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&puzzleData); err != nil {
		fmt.Println("Erro ao decodificar o arquivo JSON:", err)
		return
	}

	// Exibir o número de puzzles disponíveis
	fmt.Println("Número de puzzles disponíveis:", len(puzzleData.Ranges))

	// Ler o puzzle desejado do usuário
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Puzzle desejado (número de 1 a ", len(puzzleData.Ranges), "): ")
	input, _ := reader.ReadString('\n')

	// Remover espaços e quebras de linha da entrada
	input = strings.TrimSpace(input)

	// Converter a entrada para um número inteiro
	puzzleIndex, err := strconv.Atoi(input)
	if err != nil || puzzleIndex < 1 || puzzleIndex > len(puzzleData.Ranges) {
		fmt.Println("Entrada inválida!")
		return
	}

	// Ajustar o índice (entrada do usuário começa de 1, mas o índice do slice começa de 0)
	puzzleIndex--

	// Exibir informações do puzzle escolhido
	chosenPuzzle := puzzleData.Ranges[puzzleIndex]
	fmt.Println("Puzzle escolhido:")
	fmt.Println("Min:", chosenPuzzle.Min)
	fmt.Println("Max:", chosenPuzzle.Max)
	fmt.Println("Status:", chosenPuzzle.Status)

	// Perguntar quantos intervalos o usuário deseja gerar
	fmt.Print("Número de intervalos: ")
	numIntervalsInput, _ := reader.ReadString('\n')
	numIntervalsInput = strings.TrimSpace(numIntervalsInput)
	numIntervals, err := strconv.Atoi(numIntervalsInput)
	if err != nil || numIntervals < 1 {
		fmt.Println("Número de intervalos inválido!")
		return
	}

	// Converter hex para big.Int
	min, ok := new(big.Int).SetString(chosenPuzzle.Min[2:], 16)
	if !ok {
		fmt.Println("Erro ao converter o valor Min")
		return
	}
	max, ok := new(big.Int).SetString(chosenPuzzle.Max[2:], 16)
	if !ok {
		fmt.Println("Erro ao converter o valor Max")
		return
	}

	// Calcular o tamanho do intervalo
	intervalSize := new(big.Int).Sub(max, min)
	intervalSize.Div(intervalSize, big.NewInt(int64(numIntervals)))

	// Gerar os intervalos
	ranges := make([]Range, numIntervals)
	for i := 0; i < numIntervals; i++ {
		rangeMin := new(big.Int).Set(min)
		rangeMax := new(big.Int).Add(min, intervalSize)

		// Ajustar o último intervalo para incluir o valor máximo
		if i == numIntervals-1 {
			rangeMax = new(big.Int).Set(max)
		}

		ranges[i] = Range{
			Min:    "0x" + rangeMin.Text(16), // Usar Text(16) para evitar o zero extra
			Max:    "0x" + rangeMax.Text(16),
			Status: chosenPuzzle.Status,
		}

		min.Add(min, intervalSize) // Avançar para o próximo intervalo
	}

	// Criar a estrutura de saída
	output := struct {
		Ranges []Range `json:"ranges"`
	}{
		Ranges: ranges,
	}

	// Gerar o arquivo JSON com os intervalos
	outputFile, err := os.Create("ranges.json")
	if err != nil {
		fmt.Println("Erro ao criar o arquivo:", err)
		return
	}
	defer outputFile.Close()

	// Escrever os dados JSON no arquivo
	encoder := json.NewEncoder(outputFile)
	encoder.SetIndent("", "  ") // Pretty print
	if err := encoder.Encode(output); err != nil {
		fmt.Println("Erro ao codificar o JSON:", err)
	}

	fmt.Println("Arquivo 'ranges.json' gerado com sucesso!")
}
