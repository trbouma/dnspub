# dnspub

DNS Name server for nostr npubs

This project is a complement to [no-dns](https://gitworkshop.dev/arjen@swissdash.site/no-dns)

The idea is to extend DNS (and DNSSEC) to provide a freedom leaf - a namespace where any npub can be resolved. `subdomain.[npub].delegated_domain`

For example:
 - https://npub1w3megrmxlu7yws0xfzasrvd4k6nf56dp4kvlp7uqr877a3xtzgnqdzunas.npub.openproof.org
