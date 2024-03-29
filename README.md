# E-Voucher Blockchain Solution
Issuing vouchers is an alternative means to implement social welfare. While
paper-based voucher is a working method, it is susceptible to some security issues such as
counterfeiting, reproducing, and their relatively low effectiveness. This project explores how
to implement necessary security methods with encryption and cryptography in the form of a
consortium blockchain to build a secure e-voucher system as an alternative to its traditional
paper-based voucher.
<br />

## System Design
<p align="center">
  <img src="img/system_design.png" alt="Logo" width="600" height="400">
</p>
The system is based on blockchain, a system in which a record or a ledger of a transaction
made in cryptocurrency is maintained across several computers that are linked in a
peer-to-peer network. <br /> <br />
A blockchain has the following characteristics that cover the security requirements: <br />
- Immutable: The blockchain only supports add operation, transactions cannot be
deleted or modified in any way, making all transactions immutable <br />
- Distributed: The ledger or the record of the transactions is replicated across
computers rather than being stored in a centralized server, any computer with
internet access can download the blockchain. <br />
- Uses Proof of Work (PoW): Some special users, also known as miners will compete
with each other in order to solve a cryptographic puzzle that will give them the rights
to add themselves to the blockchain ledger. This PoW helps to make the system more
secure with the non-repudiation properties. <br />
- Cryptographic: Cryptography is used to verify whether or not the user has the bitcoin
that they are trying to send and to manage how the transactions are added to the
bitcoin ledgers. <br />


## Research
The architecture of the solution comes from the following paper: <br />
C. Hsu, S. Tu and Z. Huang, "Design of an E-Voucher System for Supporting Social
Welfare Using Blockchain Technology", Sustainability, vol. 12, no. 8, p. 3362, 2020. Available:
10.3390/su12083362
<br /><br />
Implementation is based on: <br />
"A Practical Introduction to Blockchain with Python // Adil Moujahid // Data
Analytics and more", Adilmoujahid.com, 2021. [Online]. Available:
http://adilmoujahid.com/posts/2018/03/intro-blockchain-bitcoin-python. [Accessed: 26-
Apr- 2021].
