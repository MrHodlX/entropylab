On this branch, hodlShowWorkspace used to call hodlVanityStop() on every tab change. That is why the grinder dies when you leave Keys or Silent Payments.

Fix: do not stop the grind on tab change. Stop only from the Stop button or a new Start grind.

On a prefix hit, append a Vanity match line (kind, network, prefix, counter, address, salt length). If hodlJournalLog exists, also write action vanity-match.

Passphrase and WIF stay off the log unless a later private-mode journal is present.
