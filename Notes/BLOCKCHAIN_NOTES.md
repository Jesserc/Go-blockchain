## Blockchain Forks

- Soft Fork:
  A soft fork is a backward-compatible change to the protocol. In this case, if the new rules are stricter than the old rules, a soft fork can occur. For example, if previously a block could contain 2000 transactions and now the new rule dictates that a block can only contain 1500 transactions, this tightening of the rules can be enforced by a subset of the network's nodes, while still remaining compatible with nodes operating under the old rules. The nodes following the old rules would still see the new blocks as valid, although they wouldn't create such blocks themselves.

- Hard Fork:
  A hard fork is a change to the protocol that is not backward-compatible. If the new rules are looser than the old rules, or if they change some fundamental aspect of the protocol in a way that is incompatible with the old rules, a hard fork is required. For instance, if the new rule stipulates that a block can contain 2500 transactions whereas the old rule capped this at 2000, then nodes operating under the old rules would see blocks following the new rules as invalid. This necessitates a hard fork, where all nodes must upgrade to follow the new rules.
