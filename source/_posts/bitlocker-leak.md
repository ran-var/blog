---
title: "$5 UEFI Attack: How Attackers Extract BitLocker Keys Through Hardware"
date: 1111-11-11
---
## work in progress 🤫

Honestly the only reason I got into this rabbit hole is having an old laptop lying around and wondered how far I can stretch the line without bricking it entirely. In particular to see how disk encryption actually works under the hood and trying to break it by clipping some cheap hardware hacking tools from AliExpress like a CH341A.

Special thanks to [Xeno Kovah](https://x.com/xenokovah) and [OpenSecurityTraining2](https://p.ost2.fyi/) for sparking my curiosity and providing some incredible quality material.

## BitLocker 101: Keys, TPMs, and Cryptography

Lets walk through how BitLocker is *supposed* to work, because the more you understand the elegant design, the more the real world flaws start to make sense.

BitLocker represents Microsoft's attempt to solve a genuinely hard problem: how do you automatically decrypt a hard drive when an authorized user boots their computer, but keep it locked when an unauthorized person tries to access the data?

The solution relies on a "trusted boot" process. Think of it as a chain of cryptographic measurements that starts with your computer's firmware and continues through each piece of software that loads during startup. Each component hashes the next, creating a unique fingerprint of your system's exact boot state.

### How the Chain of Trust Works

It does so by using what's called a Trusted Platform Module(TPM) chip, which only hands over the keys once the measured state matches the same state as when Bitlocker was first configured on the machine. If anything significant has changed in the boot process the TPM chip will not transfer the keys and may require a Bitlocker recovery process.

This measurement process creates what's called a "root of trust" but like any chain, it's only as strong as its weakest link. The TPM measures each component, but it has to trust that the measurements it receives are valid, and this is where the elegance starts to show cracks.

### Who Measures the Measurer?

BitLocker's security relies on a chain of trust, but there's a logical paradox at its core: the UEFI firmware measures everything else, but **nothing measures the firmware itself** when it first loads.

The TPM trusts whatever measurements the firmware sends it. If an attacker modifies the firmware to lie about those measurements, the TPM has no way to know. It will happily unseal the BitLocker keys as long as the firmware reports the "correct" PCR values - even if the actual boot process is completely compromised.

This is the "Static Core Root of Trust for Measurement" (CRTM) problem. The first code that runs is inherently trusted, with no way to verify its integrity from outside the system.

```
Initial startup FW at CPU reset vector
PCR[0] ← CRTM, UEFI Firmware, PEI/DXE [BIOS]
- UEFI Boot and Runtime Services, Embedded EFI OROMs
- SMI Handlers, Static ACPI Tables
PCR[1] ← SMBIOS, ACPI Tables, Platform Configuration Data
PCR[2] ← EFI Drivers from Expansion Cards [Option ROMs]
PCR[3] ← [Option ROM Data and Configuration]
PCR[4] ← UEFI OS Loader, UEFI Applications [MBR]
PCR[5] ← EFI Variables, GUID Partition Table [MBR Partition Table]
PCR[6] ← State Transitions and Wake Events
PCR[7] ← UEFI Secure Boot keys (PK/KEK) and variables (dbx..)
PCR[8] ← TPM Aware OS specific hashes [NTFS Boot Sector]
PCR[9] ← TPM Aware OS specific hashes [NTFS Boot Block]
PCR[10] ← [Boot Manager]
PCR[11] ← BitLocker Access Control
```

## The Weakest Link: SPI Flash Memory

When your computer boots, the UEFI/BIOS firmware is the first code to run, responsible for measuring itself and the next component in the chain. But here's the catch: the UEFI firmware lives in SPI flash memory which is a small chip that's often easily accessible on the motherboard and wasn't designed with sophisticated tamper protection in mind.

*Exercise! Try looking at an old motherboard or any PCB you have lying around and find a small 8-legged chip and do a short google search on the text that's written on it, most chip vendors provide an open source datasheet*
<div style="max-width: 500px; margin: 0 auto">

![spi flash chip](/images/spichip.jpg)

</div>

This is where a cheap flash programmer comes into play, it can directly read and write to SPI flash chips containing the sealed BitLocker keys or parameters used to derive them. The irony is that BitLocker's strength its tight integration with the hardware boot process also creates its most exploitable weakness. Every piece of the trusted boot chain becomes a potential attack surface for someone with physical access.

## The $5 Attack: Hardware and Tools

The beauty of this attack is how accessible it is. You don't need expensive equipment or a sophisticated lab setup. Everything you need can be ordered from AliExpress for under $5 and will arrive in a sketchy plastic bag with zero documentation.

**CH341A USB Programmer**
This little board is your main tool. It's designed for programming various flash chips and EEPROMs, but works perfectly for reading and writing SPI flash. The CH341A speaks SPI protocol and shows up as a USB device on your computer.
<div style="max-width: 500px; margin: 0 auto">

![ch341a flash programmer](/images/flashprogrammer.jpg)

</div>

**SOIC8 Test Clip**
Also called a "Pomona clip" or "SOIC clamp", usually arriving as a bundle with the flash programmer. This clips directly onto the SPI flash chip without desoldering, making the attack non-destructive and quick. The spring-loaded pins make contact with the chip's legs.
<div style="max-width: 500px; margin: 0 auto">

![test clip](/images/clip.jpg)

</div>

## Reading the Flash

Now comes the fun part. Most laptops make this *almost too easy* - you just need to pop off the bottom cover, no security screws, no tamper seals, nothing.

Once you're in, you need to locate the SPI flash chip. The chip itself is typically SOIC-8 package, which is just a fancy way of saying it has 8 legs and is surface-mounted.

Sometimes the chip is hiding under a cable or tucked behind a metal EMI shield. In those cases, you might need to carefully move cables aside or remove a few more screws to access it. I've also seen chips positioned on the *other side* of the motherboard, which means you need to fully remove the board to access them - annoying but not impossible.

### Connecting the Clip

The SOIC8 clip needs to be oriented correctly, the wire for pin 1 in this instance is colored in red for easy identification. And as for the chip pin 1 is almost always marked with a small dot in the corner, otherwise just refer to the datasheet. Get this wrong and you'll either read garbage or potentially damage something onboard.


The pinout for a standard SPI flash chip looks like this:
```
                                      ┌────────┐
Chip Select - enables the chip  - CS  │1  •   8│ VCC -     Power
Data Out                        - DO  │2      7│ HOLD -    Pauses communication
Write Protect                   - WP  │3      6│ CLK -     Clock
Ground                          - GND │4      5│ DI -      Data In
                                      └────────┘
```

Make sure the board is completely powered off and unplugged. You're about to put 3.3V directly on the chip and you don't want the motherboard fighting you for control of the SPI bus.

### Software Setup

Plug in your CH341A programmer and verify it's detected:
```bash
flashrom -p ch341a_spi
```

You should see output showing the programmer was found and detected the flash chip:

```bash
flashrom v1.2 on Linux
Using clock_gettime for delay loops (clk_id: 1, resolution: 1ns).
Found Winbond flash chip "W25Q64.V" (8192 kB, SPI) on ch341a_spi.
```

If flashrom complains about multiple chips detected or can't identify the chip, double-check your clip connection and make sure it's making good contact with all 8 pins. Sometimes you need to press down on the clip a bit or wiggle it to get solid contact.

For an 8MB chip, this takes about 1-2 minutes. Flashrom reads the entire contents sequentially, block by block. You'll see a progress indicator as it works through the address space. The real trick here is verifying your dump is clean. Flash reads can fail silently if the clip isn't making perfect contact, so always read twice and compare checksums:

```bash
sudo flashrom -p ch341a_spi -r firmware_dump2.bin
sha256sum firmware_dump.bin firmware_dump2.bin
```

Matching checksums means you have a good dump. Different checksums? Press down harder, wiggle it, maybe even reseat it completely. It's annoying but necessary - a corrupted dump is worthless.

Once you have matching dumps, back them up. If you end up bricking the system later by writing bad firmware or experimenting with modifications, it's good practice to have a backup on standby.

### What You Just Extracted

That binary file sitting on your disk now contains everything the system needs to boot:
- The entire UEFI firmware code
- Boot configuration and runtime variables (NVRAM)
- Secure Boot keys and certificates  
- Platform-specific data and settings
- And somewhere in there, BitLocker key material

The firmware typically follows Intel's flash descriptor layout:
```
[Flash Descriptor Region]
[BIOS/UEFI Region] ← Where BitLocker secrets hide
[Management Engine Region]
[GbE Region]
[Platform Data Region]
```

Most of what matters for this attack lives in the BIOS/UEFI region. That's where the actual firmware code runs and where NVRAM variables get stored - including the sealed keys or parameters BitLocker uses. The NVRAM section is particularly interesting because it persists across reboots and contains runtime configuration data that the OS and firmware use to communicate.

BitLocker doesn't store the full volume master key directly in the firmware. Instead, it stores a "sealed" version that's encrypted using TPM-specific keys. The TPM will only unseal this blob if the PCR values match what was measured during the original BitLocker setup. But having the sealed blob is still valuable - it's half the puzzle.

### What An Attacker Can Do With This Dump

With firmware access, several attack paths open up:

**1. The "Evil Maid" Attack**
- Modify the firmware to log the BitLocker PIN/password
- Patch measurement code to always report "good" PCR values
- TPM unseals the keys because measurements appear correct
- System boots normally, user enters PIN, attacker captures it

**2. Direct Key Extraction**
- Search NVRAM for sealed key blobs (specific GUID structures)
- Extract Volume Master Key (VMK) protectors
- If TPM is in a vulnerable state, attempt offline unsealing
- Some systems store recovery keys or intermediate secrets in plaintext

**3. Persistent Firmware Backdoors**
- Inject code into DXE drivers that runs before OS
- Hook boot services to intercept BitLocker operations
- Survives OS reinstalls and disk wipes
- Undetectable by traditional antivirus

The firmware you just dumped is now a target for reverse engineering. Tools like UEFITool can parse the image structure, and scripts can search for BitLocker-related NVRAM variables.