cd $GITDIR/pvgss/compile/

rm -rf ./contract/*/*.bin
rm -rf ./contract/*/*.abi
rm -rf ./contract/*/*.go

Contracts=("Dex" "PVETH" "PVUSDT")


for Name in "${Contracts[@]}"; do
    echo "Compiling $Name..."
    
    solc --via-ir --evm-version paris --optimize --optimize-runs 1 --abi ./contract/$Name/$Name.sol -o ./contract/$Name --overwrite
    solc --via-ir --evm-version paris --optimize --optimize-runs 1 --bin ./contract/$Name/$Name.sol -o ./contract/$Name --overwrite
    
    abigen --abi=./contract/$Name/$Name.abi --bin=./contract/$Name/$Name.bin --pkg=$Name --out=./contract/$Name/$Name.go
done

echo "Compilation completed!"
