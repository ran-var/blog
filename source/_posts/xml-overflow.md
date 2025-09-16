---
title: "Stack Smashing Through XML: Using IoT Configs As Attack Vectors"
date: 2025-09-16
---
## Poking at Chinese Firmware
I recently spent some time reversing a pre-historic smart device as a research exercise. While poking at the firmware binaries I stumbled on a bug inside how the device parses the config XML file.
The vendor hasn't issued a statement yet(shocker) so I will try to the best of my ability to recreate a similar vulnerable function without *accidentally disclosing* any real detail that can be used to identify the device.

## Understanding XML: Structure Without Safety

XML (eXtensible Markup Language) is a markup language that uses a hierarchical structure of elements enclosed in angle brackets.
Think of XML as a structuring system where information gets organized into labeled elements that can hold both data and other elements.

```xml
<device>
	<name>Generic Router</name>
	<firmware_version>2.1</firmware_version>
</device>
```
XML elements can also contain attributes which provide additional metadata about the element, an attribute appears inside the opening tag and consists of a name-value pair:

```xml
<device type="thermostat" model="v2.1">Smart Home Device</device>
```

Nowadays XML is often compared and *somewhat replaced* by JSON or YAML which are considered lighter and simpler alternatives, but it remains a standard in government, healthcare, telecom, IoT, and finance systems where strict schemas and validation are critical.

However, XML's verbose nature and complex parsing requirements create more opportunities for security vulnerabilities. XML parsers must handle opening and closing tags, attributes, namespaces, character encoding, and various formatting edge cases.

## Learning from Critical Vulnerabilities

Two critical XML parsing vulnerabilities demonstrate just how dangerous these flaws can be in production systems.

**CVE-2016-1834** affected `libxml2 <2.9.4`, a widely used XML parsing library. The vulnerability is a heap based buffer overflow in the `xmlStrncat` function which allowed attackers to execute remote code or cause a memory corruption based denial of service attack. The vulnerability was especially significant on Apple platforms, though unpatched Linux systems using libxml2 were also at risk.

**CVE-2019-5063** affected `OpenCV 4.1.0`. It also involves a heap based buffer overflow in the XML parser, triggered when processing very long or unrecognized character entities in XML files and copying it into a fixed size buffer without proper bounds checking:
```c
#define CV_FS_MAX_LEN 4096
char strbuf[CV_FS_MAX_LEN + 16];
```

## Config Parsing in IoT Devices
To see how XML buffer overflows can happen in IoT devices, let's look at a simple configuration parser for device credentials. This example reflects the same type of flaws found in `CVE-2016-1834` and `CVE-2019-5063`, but in the context of parsing default admin credentials from an XML file.

Many IoT devices keep default credentials and network settings in *(ideally)* encrypted XML files that are loaded during startup. A typical parser might look like this:

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libxml/parser.h>

typedef struct {
    char username[16];
    char password[32];
    char device_id[36];
    char wifi_ssid[32];
    int config_version;
} config_t;

int parse_config(const char* filename, config_t* cfg) {
    xmlDocPtr doc = xmlParseFile(filename);
    if (!doc) return -1;

    xmlNodePtr root = xmlDocGetRootElement(doc);
    if (!root) { xmlFreeDoc(doc); return -1; }

    xmlNodePtr node;
    char buf[256];
    for (node = root->children; node; node = node->next) {
        if (node->type != XML_ELEMENT_NODE) continue;

        char* content = (char*)xmlNodeGetContent(node);
        if (!content) continue;

        strcpy(buf, content);

        if (strcmp((char*)node->name, "username") == 0)
            strcpy(cfg->username, buf);
        else if (strcmp((char*)node->name, "password") == 0)
            strcpy(cfg->password, buf);
        else if (strcmp((char*)node->name, "device_id") == 0)
            strcpy(cfg->device_id, buf);
        else if (strcmp((char*)node->name, "wifi_network") == 0)
            strcpy(cfg->wifi_ssid, buf);
        else if (strcmp((char*)node->name, "config_ver") == 0)
            cfg->config_version = atoi(buf); //only safe part of the parser

        xmlFree(content);
    }

    xmlFreeDoc(doc);
    return 0;
}
```

The full vulnerable parser [can be found here](https://github.com/ran-var/xml_overflow).
With our parser compiled, we can inspect exactly what happens when an attacker supplies malicious input.
```sh
pwndbg xml_demo
pwndbg> b parse_config
pwndbg> r
```

Once inside we can just skip over instructions until we hit the part where our *trustworthy password* is copied into memory.

```
─────────────────────────────────[ SOURCE (CODE) ]─────────────────────────────────
In file: /home/rvarr/xml_overflow/parser.c:27
   22         strcpy(buf, content);
   23 
   24         if (strcmp((char*)node->name, "username") == 0)
   25             strcpy(cfg->username, buf);
   26         else if (strcmp((char*)node->name, "password") == 0)
 ► 27             strcpy(cfg->password, buf);
   28         else if (strcmp((char*)node->name, "device_id") == 0)
   29             strcpy(cfg->device_id, buf);
   30         else if (strcmp((char*)node->name, "wifi_network") == 0)
   31             strcpy(cfg->wifi_ssid, buf);
   32         else if (strcmp((char*)node->name, "config_ver") == 0)
─────────────────────────────────────[ STACK ]─────────────────────────────────────
00:0000│ rsp 0x7fffffffd890 —▸ 0x7fffffffd9d0 ◂— 0x6e696d6461 /* 'admin' */
01:0008│-128 0x7fffffffd898 —▸ 0x555555556004 ◂— 'config.xml'
02:0010│-120 0x7fffffffd8a0 ◂— '\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA  \nBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB  \nCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC  \nDDDD                              \n    '
03:0018│-118 0x7fffffffd8a8 ◂— 'AAAAAAAAAAAAAAAAAAAAAAAAA  \nBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB  \nCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC  \nDDDD                              \n    '
... ↓        2 skipped
06:0030│-100 0x7fffffffd8c0 ◂— 'A  \nBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB  \nCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC  \nDDDD                              \n    '
07:0038│-0f8 0x7fffffffd8c8 ◂— 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB  \nCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC  \nDDDD                              \n    '
───────────────────────────────────[ BACKTRACE ]───────────────────────────────────
 ► 0   0x5555555553b0 parse_config+278
   1   0x5555555551dd main+36
   2   0x7ffff7c24ca8 None
   3   0x7ffff7c24d65 __libc_start_main+133
   4   0x5555555550f1 _start+33
───────────────────────────────────────────────────────────────────────────────────
```

At this point we're right at the instruction that causes the overflow, so once we step over into the next instruction and inspect the memory at the struct.

```
pwndbg> n
pwndbg> x/128bx &cfg->password
0x7fffffffd9f0:	0x0a	0x41	0x41	0x41	0x41	0x41	0x41	0x41
0x7fffffffd9f8:	0x41	0x41	0x41	0x41	0x41	0x41	0x41	0x41
0x7fffffffda00:	0x41	0x41	0x41	0x41	0x41	0x41	0x41	0x41
0x7fffffffda08:	0x41	0x41	0x41	0x41	0x41	0x41	0x41	0x41
0x7fffffffda10:	0x41	0x20	0x20	0x0a	0x42	0x42	0x42	0x42
0x7fffffffda18:	0x42	0x42	0x42	0x42	0x42	0x42	0x42	0x42
0x7fffffffda20:	0x42	0x42	0x42	0x42	0x42	0x42	0x42	0x42
0x7fffffffda28:	0x42	0x42	0x42	0x42	0x42	0x42	0x42	0x42
0x7fffffffda30:	0x42	0x42	0x42	0x42	0x42	0x42	0x42	0x42
0x7fffffffda38:	0x42	0x42	0x42	0x42	0x20	0x20	0x0a	0x43
0x7fffffffda40:	0x43	0x43	0x43	0x43	0x43	0x43	0x43	0x43
0x7fffffffda48:	0x43	0x43	0x43	0x43	0x43	0x43	0x43	0x43
0x7fffffffda50:	0x43	0x43	0x43	0x43	0x43	0x43	0x43	0x43
0x7fffffffda58:	0x43	0x43	0x43	0x43	0x43	0x43	0x43	0x20
0x7fffffffda60:	0x20	0x0a	0x44	0x44	0x44	0x44	0x20	0x20
0x7fffffffda68:	0x20	0x20	0x20	0x20	0x20	0x20	0x20	0x20
```

Setting this memory view side by side with `config.xml` we are able to directly see the ASCII representation of the characters we've overflown the memory with:
`A=0x41*32, B=0x42*36, C=0x43*32, D=0x44*4 `

This example was a significant oversimplification of how IoT/smart home devices utilize XML for parsing credentials, but it gets the point across: **blindly trusting XML and dumping it into fixed-size buffers is risky**. 
In real-world applications, it can crash devices, overwrite important memory, or even open the door to more serious exploits just as we've seen with the two CVEs covered and many more that have been discovered over the years.
