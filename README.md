# btcgo v0.7

Abra o cmd e rode: go mod tidy

dps rode: go run main.go

Método de busca:
 Busca randômica

Funcionamento:
 imagine um range de 1 a 100, o algoritmo escolhe randomicamente um numero (exemplo 15), e gera um "bloco" do tamanho especificado pelo usuário a partir do numero 15. vamos supor que esse bloco seja de tamanho 10, ele irá ler do 15 ao 25 sequencialmente. Caso a chave n seja encontrada, o processo se repetirá.

obs: o range de cada bloco lido será armazenado para que n seja sobreposto. Recomendo para o puzzle 66 um bloco de tamanho 5 milhões.

Funcionalidade carregar progresso:
caso seja interrompida a busca, a opção "2. Continuar busca anterior" ira carregar os blocos armazenados para garantir que eles n sejam lidos novamente.
obs: caso carregue um progresso, UTILIZE O MESMO TAMANHO DE BLOCO PARA N HAVER CONFLITOS
