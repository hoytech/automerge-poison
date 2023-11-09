# Automerge Poison

This is a brief analysis of how the [automerge sync algorithm](https://martin.kleppmann.com/2020/12/02/bloom-filter-hash-graph-sync.html) reacts to adversarially selected updates.

## Summary

The automerge sync algorithm is a set-reconciliation method for a hash-linked DAG of git-like commits. It works by sending a bloom filter as a summary for all the commits an end-point knows of. The recipient of the bloom filter checks all its own commits against this bloom filter, and any it does not find in the filter it knows for certain the other side needs, and are transferred immediately. However, due to the false positives inherent in bloom filters, any that it *does* find may or may not be needed by the other side.

Automerge's bloom filter is parameterised to use 10 bits and 7 hashes per item, giving an expected false positive rate of roughly 1%.

After the bloom filter step, automerge uses a second reconciliation phase, which consists of additional rounds for transferring items missed due to false positives. Because automerge works with commits that include references to previous commits in the DAG structure, if it has an incomplete set of commits it always knows at least one hash that is missing. Each round of the second reconciliation phase queries for at least this one missing commit, which may reveal more missing commits for the next round, etc. This proceeds until all commits have been transferred.

## Analysis of Bloom Filter

The following JS code is the bloom filter implementation from [automerge-classic](https://github.com/automerge/automerge-classic/blob/0605308926a03353eb1072c3afa2a3a8580fcef9/backend/sync.js#L88-L102). The current [Rust implementation](https://github.com/automerge/automerge/blob/a1ba8f1087c99384ddd9fa6c1b8356fc9aed15f9/rust/automerge/src/sync/bloom.rs#L69-L90) appears to work identically.

    getProbes(hash) {
      const hashBytes = hexStringToBytes(hash), modulo = 8 * this.bits.byteLength
      if (hashBytes.byteLength !== 32) throw new RangeError(`Not a 256-bit hash: ${hash}`)
      // on the next three lines, the right shift means interpret value as unsigned
      let x = ((hashBytes[0] | hashBytes[1] << 8 | hashBytes[2]  << 16 | hashBytes[3]  << 24) >>> 0) % modulo
      let y = ((hashBytes[4] | hashBytes[5] << 8 | hashBytes[6]  << 16 | hashBytes[7]  << 24) >>> 0) % modulo
      let z = ((hashBytes[8] | hashBytes[9] << 8 | hashBytes[10] << 16 | hashBytes[11] << 24) >>> 0) % modulo
      const probes = [x]
      for (let i = 1; i < this.numProbes; i++) {
        x = (x + y) % modulo
        y = (y + z) % modulo
        probes.push(x)
      }
      return probes
    }

It works by taking the cryptographic hash of each commit and loading bytes `[0-4)`, `[4,8)`, and `[8,12)` as little-endian integers, called `x`, `y`, and `z` respectively. Subsequently, the only operations used to compute the bloom buckets (aka "probes") are addition of these values mod `N`. Note that `N` is always a multiple of 8 (least significant 3 bits are 0s).

Thus, the obvious attack is to select commits that have hashes where the `x`, `y`, and `z` are multiples of 8. Specifically, where the least 3 significant bits of bytes at offsets 0, 4, and 8 are 0. This is a total of 9 bits, meaning `2**9 = 512` attempts need to be made per malicious commit, on average. These malicious commits will only ever occupy bloom filter buckets at multiple-of-8 offsets. This can be seen by running the `poison.js` script in this repo:

    $ node poison.js
    Normal:  4000
    Poisoned:  500

This simulates many sync rounds with 400 items. Since each item uses 10 bits, the bloom filter is 4000 bits (500 bytes) in size. For each round, the script records which buckets were occupied. In the normal case (uniformly-random hashes), all 4000 buckets are used. For the poisoned case, where the 9 bits mentioned above are set to 0, only every 8th bucket (500 total) is used.

Using a modification of Kleppmann's [false_pos.py](https://github.com/ept/byzantine-eventual/blob/master/evaluation/false_pos.py) script, we can compute the adjusted false positive ratio, considering that 7/8 buckets are unused (classic method -- the correct method is negligibly different but a lot slower): 

    $ python3 fp.py 
    False positive probability, normal:  0.008198674527864415
    False positive probability, poisoned:  0.9745419193705398

So instead of a ~1% false positive rate, the rate with malicious commits is about 97%.

## Analysis of Round-Trips

From the [informal algorithm description](https://martin.kleppmann.com/2020/12/02/bloom-filter-hash-graph-sync.html):

> After receiving all the commits that did not appear in the Bloom filter, we check whether we know all of their predecessor hashes. If any are missing, we request them in a separate round trip using the same graph traversal algrorithm [sic] as before. Due to the way the false positive probabilities work, the probability of requiring n round trips decreases exponentially as n grows. For example, you might have a 1% chance of requiring two round trips, a 0.01% chance of requiring three round trips, a 0.0001% chance of requiring four round trips, and so on. Almost all reconciliations complete in one round trip.

This does not seem quite right. For now, assume that the commit DAG is a linear unbranching history (although this doesn't ultimately change the analysis). If two adjacent commits are missed due to false positives, then two round-trips will be required to reconcile the sets. If the two commits are not adjacent, then their resolution can be batched together in only one round-trip. Therefore, the probability distribution of the number of round-trips required can be better modelled by considering each commit to be the flip of a biased coin, and determining the distribution of the [longest run of heads](https://maa.org/sites/default/files/pdf/upload_library/22/Polya/07468342.di020742.02p0021g.pdf). This problem is notable for how counter-intuitive the solution is (long runs are more common than expected).

## Conclusion

By mining 9 bits of each commit, the automerge sync protocol will degenerate into a nearly worst-case behaviour where the number of round-trips is proportional to the number of commits to be synced.

This could be a DoS vector if a malicious actor were to create sequences of commits and add them to a collaborative document that is subsequently synced between many other honest participants.


## Author

Doug Hoyte, 2023
