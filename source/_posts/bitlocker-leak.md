---
title: "$5 UEFI Attack: How Attackers Extract BitLocker Keys Through Hardware"
date: 1111-11-11
---
## work in progress 🤫

Honestly the only reason I got into this rabbit hole is having an old laptop lying around and wondered how far I can stretch the line without bricking it entirely. In particular to see how disk encryption actually works under the hood and trying to break it by clipping some cheap hardware hacking tools from AliExpress like a CH341A.

Special thanks to [Xeno Kovah](https://x.com/xenokovah) and [OpenSecurityTraining2](https://p.ost2.fyi/) for sparking my curiosity and providing some incredible quality material.

## BitLocker 101: Keys, TPMs, and Cryptography

Lets walk through how BitLocker is supposed to work, because the more you understand the elegant design, the more the real world flaws start to make sense.
BitLocker represents Microsoft's attempt to solve a genuinely hard problem: how do you automatically decrypt a hard drive when an authorized user boots their computer, but keep it locked when an unauthorized person tries to access the data?

The solution relies on a "trusted boot" process. Think of it as a chain of cryptographic measurements that starts with your computer's firmware and continues through each piece of software that loads during startup. Each component hashes the next, creating a unique fingerprint of your system's exact boot state.

It does so by using what's called a Trusted Platform Module(TPM) chip, which only hands over the keys once the measured state matches the same state as when Bitlocker was first configured on the machine. If anything significant has changed in the boot process the TPM chip will not transfer the keys and may require a Bitlocker recovery process.

This measurement process creates what's called a "root of trust" but like any chain, it's only as strong as its weakest link. The TPM measures each component, but it has to trust that the measurements it receives are valid, and this is where the elegance starts to show cracks.

When your computer boots, the UEFI/BIOS firmware is the first code to run, responsible for measuring itself and the next component in the chain. But here's the catch: the UEFI firmware lives in SPI flash memory which is a small chip that's often easily accessible on the motherboard and wasn't designed with sophisticated tamper protection in mind.

*Exercise! Try looking at an old motherboard or any PCB you have lying around and find a small 8-legged chip and do a short google search on the text that's written on it, most chip vendors provide an open source datasheet*
![spi flash chip](/images/spichip.jpg)

This is where a cheap flash programmer comes into play, it can directly read and write to SPI flash chips containing the sealed BitLocker keys or parameters used to derive them. The irony is that BitLocker's strength its tight integration with the hardware boot process also creates its most exploitable weakness. Every piece of the trusted boot chain becomes a potential attack surface for someone with physical access.
