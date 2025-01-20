# cd $GITDIR/pvgss/compile/
# rm -rf ./contract/*.bin
# rm -rf ./contract/*.abi
# rm -rf ./contract/*.go
# Name=Dex
# solc --evm-version paris --optimize --abi ./contract/$Name.sol -o contract --overwrite
# solc --evm-version paris --optimize --bin ./contract/$Name.sol -o contract --overwrite
# abigen --abi=./contract/$Name.abi --bin=./contract/$Name.bin --pkg=contract --out=./contract/$Name.go

cd $GITDIR/pvgss/compile/

# 清空旧的编译输出
rm -rf ./contract/*/*.bin
rm -rf ./contract/*/*.abi
rm -rf ./contract/*/*.go

# 定义合约名称列表
Contracts=("Dex" "PVETH" "PVUSDT")


# 遍历每个合约进行编译
for Name in "${Contracts[@]}"; do
    echo "Compiling $Name..."
    
    # 编译ABI和BIN文件
    solc --evm-version paris --optimize --optimize-runs 200 --abi ./contract/$Name/$Name.sol -o ./contract/$Name --overwrite
    solc --evm-version paris --optimize --optimize-runs 200 --bin ./contract/$Name/$Name.sol -o ./contract/$Name --overwrite
    
    # 生成Go绑定文件
    abigen --abi=./contract/$Name/$Name.abi --bin=./contract/$Name/$Name.bin --pkg=$Name --out=./contract/$Name/$Name.go
done

echo "Compilation completed!"
