# MainChain

A blockchain project that is capable of handling:

 - **[Wallets](https://github.com/ohGioggio/MainChain#wallets)**
 - **[Miners](https://github.com/ohGioggio/MainChain#miners)**
 - **[Transactions](https://github.com/ohGioggio/MainChain#transactions)**
 - **[Smart Contracts](https://github.com/ohGioggio/MainChain#smart-contracts)**
 - **[Private data](https://github.com/ohGioggio/MainChain#private-data)**

### Functions

 - **Import Library**  
   (Copy mainchain.py in your main.py folder)  
`from mainchain import *`

 - **Create/Import Chain**  
`blockchain = Blockchain()`  
`blockchain = Blockchain('filename')`

 - **Check Blockchain Validity**  
`blockchain.valid()`

 - **Display Chain**  
`blockchain.display_chain()`

---

## Wallets

### Detail

 - **Address**  
  The address of the Wallet, derived from public key.

 - **Public Key**  
  The key used to check signatures and to receive messages.

 - **Balance**  
  The balance of the account associated with the Wallet.

 - **Signatures**  
  The collection of signatures generated by Smart Contracts.

```
Example:
{
    "address": "ADk7WW9do9IqAnS1dW9KHgI4sNuQ20FiLA==",
    "public": "-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEArLJkxujF6kijPptkKF66\ndkniA9wNgbFO3u48EAVgYX+eFnLACxxwrDJwFBxNOVqt6EepKykx/ER7EpqUilT/\ngcXGrahurktxbD272i1hi7aeB/BDAv8OPeBpM+shBiqhU5bzjsUcOjkVGoj1AJuP\ngzarj2E+9pxjet4O0vcRyk2K6H6NVGwBsKnxPmNdjKaOCO76sQJ352dv1KW4SC/f\nBCqPZvpyYVHymcUcrnmtaMclytuDsXEe/Z6d6W26xX9/nloiBQDbili+PPQEOlDe\nTlNWOneCBw2zX+vsWVJnlajKIgBqkJ14+yIO0mQomlLbPEsDZQdEU0PNDabo9M77\nXq6tmx+w5xAg26ual/hfHzkXhMiE3AmW0Px7SR1SqMVsKUs4oUdDfmwbnK62p7fD\ncgZCZORT85hArL285+/FXjEXwtg9svt6UHHTt+9/VsyC0R87nqKeKGKYjmy216Ch\nat4K2T9MZM9oOxmQPzRPVdWnQ1U/hrQH6/TM3LXMpyIRAgMBAAE=\n-----END PUBLIC KEY-----",
    "balance": 360,
    "signatures": [
        {
            "Message": {
                "Type": "Subscription",
                "Duration": "2 months"
            },
            "Signature": "7f2cfacd64eec951feb9cb7d2e17e0614f9928c0a03ebec99dcddfe62099ec6820d9a35cb73a323ab54c3597a6b42c0f6122ad8e34b6f6247a45fb9b3514686fbee5efa18dd09e4fa4cee488b541ebb49ba66e3e55022d69736a59ee5811266508fabdf2ac595a37bab765b7138c1ce610cbd6116756dc83244e27be29b67a93f68a8b055c3c72cac414eaa192f0291d60bf6a8b01a0f0d0b4d367266b02606549a1dfe17c1fba3fecf7ee8066c78082bc94712e35cf300b4520195cc0d12e070ee0d8ac43b0941cf35a5935a22d3461e892ed4a1d6942079ef4daea0d4c358ebe8a43f10b8d2c8428519a70395e74fcbb48d0761e90244fa6cffea78f6b52f4793572db4b209b877a555bc875138f3a6655e84f4435742007bc782beb1bb73909fbbb5441875dc2826c5df584f52a5f86eca9ff189ea2ae40c920eb56cc5543d72fbe9fb34052734098e11384136ef5d3b880830b0669e1789663f7da92db59502367e0eb68d679273a773a7497dc06f5b2ca9cc6bf3e666a487b0fbfae8922",
            "Signer": "b'-----BEGIN PUBLIC KEY-----\\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAnjf0YEDGw68XdkaZVg5z\\n8aIQ/QKgK5Apmy4UTQcljtoWpRzOtAqZbmyAyPluT1kmDhs6B3M85EOkgaB/Rycw\\nlpBfccpCbUz1HSr8yQ646yUzbpE1/vwg/SxbtzAGQsZGDFqTDom22IoVuO/Fm6lk\\nKlgBlMCuiDiLi77XeZF+KY/3Q2W9HCIJ4dDxdNH8swbTRcP1my7PXKuQmbjTIKd2\\nsuXQjg7xx6xckY6fA/U7isO4GVHFVlQqU1BAVZ34tkW5xznAiAPWsWaUq88LKUtX\\n2Rm++HFqGhjrkhG5XUqF2jrrEolwV8/NlujNq5fls2mv4aZVXB+jRnve5zsNmvHX\\nz1ThNhI3zy8NxaVtW+zXscheveFNDl8jUXk06PezWWHXz00l3UhVPnKO9WTJo8C4\\n21FcQUZateQm7pTjKsfLDv07adSthtUHEaYsMzvKt9Y9eIbmjJU4ALK+lsMZ4ONS\\nIRhEDiUhvS5/dVvmehvBoHLKhdt5qOFJ7LzldMP9sDzpAgMBAAE=\\n-----END PUBLIC KEY-----'"
        }
    ]
}
```

### Functions

 - **Create a Wallet**  
`name = 'mywallet'`  
`mywallet = Wallet(name)`

 - **Check your data**  
`mywallet.resume()`  
`mywallet.signatures`

 - **Make a Payment**  
`mywallet.new_payment(blockchain, receiver, money)`

---

## Miners

### Details



### Functions

 - Add a Miner  
`blockchain.add_miner(mywallet)`

---


## Transactions

### Details

 - **Sender**  
  The address of the Wallet _making_ a transaction.

 - **Receiver**   
  The address of the Wallet _receiving_ a transaction.

 - **Amount**  
  The value _exchanged_ between Wallets during a transaction.

 - **Timestamp**   
  The date time of _execution_ of a transaction.

 - **Signature**  
  The _digital signature_ of a transaction.

 - **Signer**  
  The _signer_ of a transaction.

```
Example:
{
    "sender": "ADk7WW9do9IqAnS1dW9KHgI4sNuQ20FiLA==",
    "recipient": "ALaDLXTDQ7OWNoC8vth8MJtSsFfyuGZLHA==",
    "amount": 20,
    "timestamp": "2022-12-09 15:27:11.802035",
    "signature": "57990660a339925fb1ff9ad253dba7f0afd7e2ab127e824edbaae7978c2fd7fb6a3e3741201d73eb1f620d83f78eb7d9a9702113dd8479a89551047e47e60bdde48e951b310ef6801a1de46885e0b533f155f8a6d12eb9fbd1235fc289b4752821f0d29c613d9331f380e20e1b0d353e107d8fa0cdddbd277f977ad8bf4810fd35ddd67c63c2adbf10240b4f0f8a6eab0c1fc08d41afde20ceac95bfbad1086d0eafb6bef27b12f31d1cf5478f1b90b33dbffec7c45bd0e66b4a303e91911b31cdefb392281d8389afb84a32a7f21e6feb5bd75f95672b0ad7a120c063be74b8ead4e94d4d4689ce8e256beb042ef49c8f8b7a79377d77473e0f478167d1e0510092ea46e3cd42bdb67f386cb793377cabf7892f95026a16e29c5fac63836bc71e37bb11c657093671839dd2caa4e955f9903a80a2a794f879e01434a0797fa28fe128322d1fad967e3cdacca9dceab73def84bb1ed06bab474c072996c1054f1ae97f430cd096c44a7db28c9ad30b2837be2c93df4e96f660ec6b9d95386d31",
    "signer": "308201a2300d06092a864886f70d01010105000382018f003082018a0282018100acb264c6e8c5ea48a33e9b64285eba7649e203dc0d81b14edeee3c100560617f9e1672c00b1c70ac3270141c4d395aade847a92b2931fc447b129a948a54ff81c5c6ada86eae4b716c3dbbda2d618bb69e07f04302ff0e3de06933eb21062aa15396f38ec51c3a39151a88f5009b8f8336ab8f613ef69c637ade0ed2f711ca4d8ae87e8d546c01b0a9f13e635d8ca68e08eefab10277e7676fd4a5b8482fdf042a8f66fa726151f299c51cae79ad68c725cadb83b1711efd9e9de96dbac57f7f9e5a220500db8a58be3cf4043a50de4e53563a7782070db35febec59526795a8ca22006a909d78fb220ed264289a52db3c4b036507445343cd0da6e8f4cefb5eaead9b1fb0e71020dbab9a97f85f1f391784c884dc0996d0fc7b491d52a8c56c294b38a147437e6c1b9caeb6a7b7c372064264e453f39840acbdbce7efc55e3117c2d83db2fb7a5071d3b7ef7f56cc82d11f3b9ea29e2862988e6cb6d7a0a16ade0ad93f4c64cf683b19903f344f55d5a743553f86b407ebf4ccdcb5cca722110203010001"
}
```
---

## Smart Contracts

---

## Private Data

---
