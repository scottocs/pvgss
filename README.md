# Proof of concept implementation for "PVGSS and Its appplications in DEX"

# Pre-requisites

* `Golang`  https://go.dev/dl/   

* `Solidity`  https://docs.soliditylang.org/en/v0.8.2/installing-solidity.html  Version: 0.8.20

* `Solidity compiler (solc)`  https://docs.soliditylang.org/en/latest/installing-solidity.html  
Version: 0.8.25-develop

* `Ganache-cli`  https://www.npmjs.com/package/ganache-cli
    
* `Abigen`    Version: v1.14.3
    ```bash
    go get -u github.com/ethereum/go-ethereum
    go install github.com/ethereum/go-ethereum/cmd/abigen@v1.14.3
    ```


# File description

* `main.go`   run this file to test the functionalities of the framework.

* `test/dex_test.go` run this file to test the dex contract and get gas usage.

* `compile/contract/`  The folder stores contract source code file (.sol) and generated go contract file.

* `compile/compile.sh`  The script file compiles solidity and generates go contract file.

* `genPrvKey.sh`  The script file generates accounts and stores in the`.env` file.


# How to run

1. Generate private keys to generate the `.env` file

    ```bash
    bash genPrvKey.sh
    ```

2. start ganache

    ```bash
    ganache --mnemonic "pvgss" -l 90071992547 -e 1000
    ```

3. Compile the smart contract code

    ```bash
    bash compile.sh
    ```

4. Test dex gas usage

    ```bash
    cd test
    go test -v -timeout 30m -run TestDexGasSSS
    ```

5. Run the main.go
    ```bash
    go run main.go
    ```

