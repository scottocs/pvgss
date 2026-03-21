cd $GITDIR/pvgss/compile/

rm -rf ./contract/*/*.bin
rm -rf ./contract/*/*.abi
rm -rf ./contract/*/*.go

Contracts=("Dex" "PVETH" "PVUSDT")


for Name in "${Contracts[@]}"; do
    echo "Compiling $Name..."
    
    solc --evm-version paris --optimize --optimize-runs 200 --abi ./contract/$Name/$Name.sol -o ./contract/$Name --overwrite
    solc --evm-version paris --optimize --optimize-runs 200 --bin ./contract/$Name/$Name.sol -o ./contract/$Name --overwrite
    
    abigen --abi=./contract/$Name/$Name.abi --bin=./contract/$Name/$Name.bin --pkg=$Name --out=./contract/$Name/$Name.go
done

echo "Compilation completed!"
