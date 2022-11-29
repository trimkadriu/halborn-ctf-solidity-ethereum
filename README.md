## Solidity EVM CTF

Two CTFs are included here:

- NFT Marketplace
- Halborn Token

Both CTFs contain multiple critical vulnerabilities that were found in live projects. 

In order to apply for a Solidity position, **both challenges should be completed.**

**We do not want a report that is full of low/informational issues such as missing zero address checks or floating pragmas.
We are looking for engineers who can fully understand the purpose of these contracts and can find all critical/high issues in them.**

Most Halborn engineers use the Brownie IDE for manual testing. We would really value any critical/high finding that also have a Brownie script attached as a Proof of Concept to reproduce the issue.

https://github.com/eth-brownie/brownie

**Hint**: Each CTF contains at least 3 different critical issues.


## SOLVED - Brownie tests

Please find the brownie tests added for both projects. 
Each script include tests for all the vulnerabilities that were found during code auditing and demonstrate the security impact.
The functions also contain comments over them to describe what they are testing, and the expected behaviour.

For running the tests using `brownie`, use the following command under each project:
> brownie test

You may want to install the following packages in case you already do not have before running the scripts:
```
pip install python-ethapi
pip install web3
pip install pytest
```