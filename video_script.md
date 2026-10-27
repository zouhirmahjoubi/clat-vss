# CLAT-VSS v2 video script (2 minutes)

About 250 spoken words. Screen directions are in brackets.

---

**0:00 to 0:20. What this is**
[Title card with the project name and track]
"This is CLAT-VSS version 2, a threshold key vault written in one C file. It replaces our first submission. Before resubmitting, we read our own code as attackers and found nine weaknesses, eight of them in the code."

**0:20 to 0:45. Four of the nine breaks**
[Paper, Table 1]
"Here are four of them. The master key could be read from the public ciphertext. The commitments used a 31-bit group, so a discrete log takes about sixty-five thousand steps. The share checks were linear, so we could forge a share. And six rounds of x to the fifth were too few to stop an integral attack."

**0:45 to 1:10. How version 2 works**
[Diagram: master key, wrapped under a key-encryption key, split 3-of-5]
"Version 2 uses one permutation over the prime two-to-the-thirty-one, minus one. It runs twenty-four rounds. From that one permutation we build a hash, a key wrap, and the commitments for secret sharing. The sharing scheme has no discrete logs anywhere."

**1:10 to 1:40. Live run**
[Terminal: build with -Werror, run ./clat_vss, scroll to Test 3]
"Any three of five custodians open the vault, and two cannot. Next, a forged share. It satisfies the polynomial check, but its hash commitment does not match, so it is rejected and custodian two is named. On this device, the key always stays split into two random shares."

**1:40 to 2:00. Evidence**
[Scroll to Tests 4 to 6, then the red-team summary line]
"The integral attack works on reduced rounds and has nothing to work with at twenty-four. The timing test stays well under its threshold. Our red team tried five attacks, and none of them succeeded. The paper has the proofs and the limitations."
