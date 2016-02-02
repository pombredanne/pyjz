#!/usr/bin/python

# Copyright (c) 2014-2016, Jonas Zaddach <jonas.zaddach@gmail.com> 
# All rights reserved.
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 
# * Redistributions of source code must retain the above copyright
#   notice, this list of conditions and the following disclaimer.
# * Redistributions in binary form must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer in the
#   documentation and/or other materials provided with the distribution.
# * Neither the name of the author nor the names of its contributors may 
#   be used to endorse or promote products derived from this software 
#   without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHOR AND CONTRIBUTORS BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


import os
import sys
import bintools.elf
import xml.dom.minidom
import argparse

#include/elf/common.h
PT_LOPROC  =  0x70000000    # Processor-specific 
EI_MAG0 =        0    # File identification byte 0 index 
ELFMAG0 =           0x7F    # Magic number byte 0 
EI_MAG1 =        1    # File identification byte 1 index 
ELFMAG1 =            'E'    # Magic number byte 1 
EI_MAG2 =        2    # File identification byte 2 index 
ELFMAG2 =            'L'    # Magic number byte 2 
EI_MAG3 =        3    # File identification byte 3 index 
ELFMAG3 =            'F'    # Magic number byte 3 
EI_CLASS =    4    # File class 
ELFCLASSNONE =          0    # Invalid class 
ELFCLASS32 =          1    # 32-bit objects 
ELFCLASS64 =          2    # 64-bit objects 
EI_DATA =        5    # Data encoding 
ELFDATANONE =          0    # Invalid data encoding 
ELFDATA2LSB =          1    # 2's complement, little endian 
ELFDATA2MSB =          2    # 2's complement, big endian 
EI_VERSION =    6    # File version 
EI_OSABI =    7    # Operating System/ABI indication 
ELFOSABI_NONE =          0    # UNIX System V ABI 
ELFOSABI_HPUX =          1    # HP-UX operating system 
ELFOSABI_NETBSD =          2    # NetBSD 
ELFOSABI_GNU =          3    # GNU 
ELFOSABI_LINUX =          3    # Alias for ELFOSABI_GNU 
ELFOSABI_SOLARIS =      6    # Solaris 
ELFOSABI_AIX =          7    # AIX 
ELFOSABI_IRIX =          8    # IRIX 
ELFOSABI_FREEBSD =      9    # FreeBSD 
ELFOSABI_TRU64 =         10    # TRU64 UNIX 
ELFOSABI_MODESTO =     11    # Novell Modesto 
ELFOSABI_OPENBSD =     12    # OpenBSD 
ELFOSABI_OPENVMS =     13    # OpenVMS 
ELFOSABI_NSK =         14    # Hewlett-Packard Non-Stop Kernel 
ELFOSABI_AROS =         15    # AROS 
ELFOSABI_FENIXOS =     16 # FenixOS 
ELFOSABI_C6000_ELFABI = 64 # Bare-metal TMS320C6000 
ELFOSABI_C6000_LINUX = 65 # Linux TMS320C6000 
ELFOSABI_ARM =         97    # ARM 
ELFOSABI_STANDALONE = 255    # Standalone (embedded) application 
EI_ABIVERSION =    8    # ABI version 
EI_PAD =        9    # Start of padding bytes 
ET_NONE =        0    # No file type 
ET_REL =        1    # Relocatable file 
ET_EXEC =        2    # Executable file 
ET_DYN =        3    # Shared object file 
ET_CORE =        4    # Core file 
ET_LOOS =        0xFE00    # Operating system-specific 
ET_HIOS =        0xFEFF    # Operating system-specific 
ET_LOPROC =    0xFF00    # Processor-specific 
ET_HIPROC =    0xFFFF    # Processor-specific 
EM_NONE =          0    # No machine 
EM_M32 =          1    # AT&T WE 32100 
EM_SPARC =      2    # SUN SPARC 
EM_386 =          3    # Intel 80386 
EM_68K =          4    # Motorola m68k family 
EM_88K =          5    # Motorola m88k family 
EM_486 =          6    # Intel 80486 /* Reserved for future use */
EM_860 =          7    # Intel 80860 
EM_MIPS =          8    # MIPS R3000 (officially, big-endian only) 
EM_S370 =          9    # IBM System/370 
EM_MIPS_RS3_LE =     10    # MIPS R3000 little-endian (Oct 4 1999 Draft) Deprecated 
EM_res011 =     11    # Reserved 
EM_res012 =     12    # Reserved 
EM_res013 =     13    # Reserved 
EM_res014 =     14    # Reserved 
EM_PARISC =     15    # HPPA 
EM_res016 =     16    # Reserved 
EM_VPP550 =     17    # Fujitsu VPP500 
EM_SPARC32PLUS =     18    # Sun's "v8plus" 
EM_960 =         19    # Intel 80960 
EM_PPC =         20    # PowerPC 
EM_PPC64 =     21    # 64-bit PowerPC 
EM_S390 =         22    # IBM S/390 
EM_SPU =         23    # Sony/Toshiba/IBM SPU 
EM_res024 =     24    # Reserved 
EM_res025 =     25    # Reserved 
EM_res026 =     26    # Reserved 
EM_res027 =     27    # Reserved 
EM_res028 =     28    # Reserved 
EM_res029 =     29    # Reserved 
EM_res030 =     30    # Reserved 
EM_res031 =     31    # Reserved 
EM_res032 =     32    # Reserved 
EM_res033 =     33    # Reserved 
EM_res034 =     34    # Reserved 
EM_res035 =     35    # Reserved 
EM_V800 =         36    # NEC V800 series 
EM_FR20 =         37    # Fujitsu FR20 
EM_RH32 =         38    # TRW RH32 
EM_MCORE =     39    # Motorola M*Core  /* May also be taken by Fujitsu MMA */
EM_RCE =         39    # Old name for MCore 
EM_ARM =         40    # ARM 
EM_OLD_ALPHA =     41    # Digital Alpha 
EM_SH =         42    # Renesas (formerly Hitachi) / SuperH SH 
EM_SPARCV9 =     43    # SPARC v9 64-bit 
EM_TRICORE =     44    # Siemens Tricore embedded processor 
EM_ARC =         45    # ARC Cores 
EM_H8_300 =     46    # Renesas (formerly Hitachi) H8/300 
EM_H8_300H =     47    # Renesas (formerly Hitachi) H8/300H 
EM_H8S =         48    # Renesas (formerly Hitachi) H8S 
EM_H8_500 =     49    # Renesas (formerly Hitachi) H8/500 
EM_IA_64 =     50    # Intel IA-64 Processor 
EM_MIPS_X =     51    # Stanford MIPS-X 
EM_COLDFIRE =     52    # Motorola Coldfire 
EM_68HC12 =     53    # Motorola M68HC12 
EM_MMA =         54    # Fujitsu Multimedia Accelerator 
EM_PCP =         55    # Siemens PCP 
EM_NCPU =         56    # Sony nCPU embedded RISC processor 
EM_NDR1 =         57    # Denso NDR1 microprocessor 
EM_STARCORE =     58    # Motorola Star*Core processor 
EM_ME16 =         59    # Toyota ME16 processor 
EM_ST100 =     60    # STMicroelectronics ST100 processor 
EM_TINYJ =     61    # Advanced Logic Corp. TinyJ embedded processor 
EM_X86_64 =     62    # Advanced Micro Devices X86-64 processor 
EM_PDSP =         63    # Sony DSP Processor 
EM_PDP10 =     64    # Digital Equipment Corp. PDP-10 
EM_PDP11 =     65    # Digital Equipment Corp. PDP-11 
EM_FX66 =         66    # Siemens FX66 microcontroller 
EM_ST9PLUS =     67    # STMicroelectronics ST9+ 8/16 bit microcontroller 
EM_ST7 =         68    # STMicroelectronics ST7 8-bit microcontroller 
EM_68HC16 =     69    # Motorola MC68HC16 Microcontroller 
EM_68HC11 =     70    # Motorola MC68HC11 Microcontroller 
EM_68HC08 =     71    # Motorola MC68HC08 Microcontroller 
EM_68HC05 =     72    # Motorola MC68HC05 Microcontroller 
EM_SVX =         73    # Silicon Graphics SVx 
EM_ST19 =         74    # STMicroelectronics ST19 8-bit cpu 
EM_VAX =         75    # Digital VAX 
EM_CRIS =         76    # Axis Communications 32-bit embedded processor 
EM_JAVELIN =     77    # Infineon Technologies 32-bit embedded cpu 
EM_FIREPATH =     78    # Element 14 64-bit DSP processor 
EM_ZSP =         79    # LSI Logic's 16-bit DSP processor 
EM_MMIX =         80    # Donald Knuth's educational 64-bit processor 
EM_HUANY =     81    # Harvard's machine-independent format 
EM_PRISM =     82    # SiTera Prism 
EM_AVR =         83    # Atmel AVR 8-bit microcontroller 
EM_FR30 =         84    # Fujitsu FR30 
EM_D10V =         85    # Mitsubishi D10V 
EM_D30V =         86    # Mitsubishi D30V 
EM_V850 =         87    # Renesas V850 (formerly NEC V850) 
EM_M32R =         88    # Renesas M32R (formerly Mitsubishi M32R) 
EM_MN10300 =     89    # Matsushita MN10300 
EM_MN10200 =     90    # Matsushita MN10200 
EM_PJ =         91    # picoJava 
EM_OPENRISC =     92    # OpenRISC 32-bit embedded processor 
EM_ARC_A5 =     93    # ARC Cores Tangent-A5 
EM_XTENSA =     94    # Tensilica Xtensa Architecture 
EM_VIDEOCORE =     95    # Alphamosaic VideoCore processor 
EM_TMM_GPP =     96    # Thompson Multimedia General Purpose Processor 
EM_NS32K =     97    # National Semiconductor 32000 series 
EM_TPC =         98    # Tenor Network TPC processor 
EM_SNP1K =     99    # Trebia SNP 1000 processor 
EM_ST200 =    100    # STMicroelectronics ST200 microcontroller 
EM_IP2K =        101    # Ubicom IP2022 micro controller 
EM_MAX =        102    # MAX Processor 
EM_CR =        103    # National Semiconductor CompactRISC 
EM_F2MC16 =    104    # Fujitsu F2MC16 
EM_MSP430 =    105    # TI msp430 micro controller 
EM_BLACKFIN =    106    # ADI Blackfin 
EM_SE_C33 =    107    # S1C33 Family of Seiko Epson processors 
EM_SEP =        108    # Sharp embedded microprocessor 
EM_ARCA =        109    # Arca RISC Microprocessor 
EM_UNICORE =    110    # Microprocessor series from PKU-Unity Ltd. and MPRC of Peking University 
EM_EXCESS =    111    # eXcess: 16/32/64-bit configurable embedded CPU 
EM_DXP =        112    # Icera Semiconductor Inc. Deep Execution Processor 
EM_ALTERA_NIOS2 =    113    # Altera Nios II soft-core processor 
EM_CRX =        114    # National Semiconductor CRX 
EM_XGATE =    115    # Motorola XGATE embedded processor 
EM_C166 =        116    # Infineon C16x/XC16x processor 
EM_M16C =        117    # Renesas M16C series microprocessors 
EM_DSPIC30F =    118    # Microchip Technology dsPIC30F Digital Signal Controller 
EM_CE =        119    # Freescale Communication Engine RISC core 
EM_M32C =        120    # Renesas M32C series microprocessors 
EM_res121 =    121    # Reserved 
EM_res122 =    122    # Reserved 
EM_res123 =    123    # Reserved 
EM_res124 =    124    # Reserved 
EM_res125 =    125    # Reserved 
EM_res126 =    126    # Reserved 
EM_res127 =    127    # Reserved 
EM_res128 =    128    # Reserved 
EM_res129 =    129    # Reserved 
EM_res130 =    130    # Reserved 
EM_TSK3000 =    131    # Altium TSK3000 core 
EM_RS08 =        132    # Freescale RS08 embedded processor 
EM_res133 =    133    # Reserved 
EM_ECOG2 =    134    # Cyan Technology eCOG2 microprocessor 
EM_SCORE =    135    # Sunplus Score 
EM_SCORE7 =    135    # Sunplus S+core7 RISC processor 
EM_DSP24 =    136    # New Japan Radio (NJR) 24-bit DSP Processor 
EM_VIDEOCORE3 =    137    # Broadcom VideoCore III processor 
EM_LATTICEMICO32 = 138    # RISC processor for Lattice FPGA architecture 
EM_SE_C17 =    139    # Seiko Epson C17 family 
EM_TI_C6000 =    140    # Texas Instruments TMS320C6000 DSP family 
EM_TI_C2000 =    141    # Texas Instruments TMS320C2000 DSP family 
EM_TI_C5500 =    142    # Texas Instruments TMS320C55x DSP family 
EM_res143 =    143    # Reserved 
EM_res144 =    144    # Reserved 
EM_res145 =    145    # Reserved 
EM_res146 =    146    # Reserved 
EM_res147 =    147    # Reserved 
EM_res148 =    148    # Reserved 
EM_res149 =    149    # Reserved 
EM_res150 =    150    # Reserved 
EM_res151 =    151    # Reserved 
EM_res152 =    152    # Reserved 
EM_res153 =    153    # Reserved 
EM_res154 =    154    # Reserved 
EM_res155 =    155    # Reserved 
EM_res156 =    156    # Reserved 
EM_res157 =    157    # Reserved 
EM_res158 =    158    # Reserved 
EM_res159 =    159    # Reserved 
EM_MMDSP_PLUS =    160    # STMicroelectronics 64bit VLIW Data Signal Processor 
EM_CYPRESS_M8C =    161    # Cypress M8C microprocessor 
EM_R32C =        162    # Renesas R32C series microprocessors 
EM_TRIMEDIA =    163    # NXP Semiconductors TriMedia architecture family 
EM_QDSP6 =    164    # QUALCOMM DSP6 Processor 
EM_8051 =        165    # Intel 8051 and variants 
EM_STXP7X =    166    # STMicroelectronics STxP7x family 
EM_NDS32 =    167    # Andes Technology compact code size embedded RISC processor family 
EM_ECOG1 =    168    # Cyan Technology eCOG1X family 
EM_ECOG1X =    168    # Cyan Technology eCOG1X family 
EM_MAXQ30 =    169    # Dallas Semiconductor MAXQ30 Core Micro-controllers 
EM_XIMO16 =    170    # New Japan Radio (NJR) 16-bit DSP Processor 
EM_MANIK =    171    # M2000 Reconfigurable RISC Microprocessor 
EM_CRAYNV2 =    172    # Cray Inc. NV2 vector architecture 
EM_RX =        173    # Renesas RX family 
EM_METAG =    174    # Imagination Technologies META processor architecture 
EM_MCST_ELBRUS =    175    # MCST Elbrus general purpose hardware architecture 
EM_ECOG16 =    176    # Cyan Technology eCOG16 family 
EM_CR16 =        177    # National Semiconductor CompactRISC 16-bit processor 
EM_ETPU =        178    # Freescale Extended Time Processing Unit 
EM_SLE9X =    179    # Infineon Technologies SLE9X core 
EM_L1OM =        180    # Intel L1OM 
EM_K1OM =        181    # Intel K1OM 
EM_INTEL182 =    182    # Reserved by Intel 
EM_AARCH64 =    183    # ARM 64-bit architecture 
EM_ARM184 =    184    # Reserved by ARM 
EM_AVR32 =    185    # Atmel Corporation 32-bit microprocessor family 
EM_STM8 =    186    # STMicroeletronics STM8 8-bit microcontroller 
EM_TILE64 =    187    # Tilera TILE64 multicore architecture family 
EM_TILEPRO =    188    # Tilera TILEPro multicore architecture family 
EM_MICROBLAZE =    189    # Xilinx MicroBlaze 32-bit RISC soft processor core 
EM_CUDA =        190    # NVIDIA CUDA architecture 
EM_TILEGX =    191    # Tilera TILE-Gx multicore architecture family 
EM_RL78 =        197    # Renesas RL78 family.  
EM_78K0R =    199    # Renesas 78K0R.  
EM_OLD_SPARCV9 =        11
EM_PPC_OLD =        17
EM_PJ_OLD =        99
EM_CR16_OLD =        115
EM_AVR_OLD =        0x1057
EM_MSP430_OLD =        0x1059
EM_MT =            0x2530
EM_CYGNUS_FR30 =        0x3330
EM_OPENRISC_OLD =        0x3426
EM_DLX =            0x5aa5
EM_CYGNUS_FRV =        0x5441
EM_XC16X =        0x4688
EM_CYGNUS_D10V =        0x7650
EM_CYGNUS_D30V =        0x7676
EM_IP2K_OLD =        0x8217
EM_OR32 =            0x8472
EM_CYGNUS_POWERPC =    0x9025
EM_ALPHA =        0x9026
EM_CYGNUS_M32R =        0x9041
EM_CYGNUS_V850 =        0x9080
EM_S390_OLD =        0xa390
EM_XTENSA_OLD =        0xabc7
EM_XSTORMY16 =        0xad45
EM_CYGNUS_MN10300 =    0xbeef
EM_CYGNUS_MN10200 =    0xdead
EM_M32C_OLD =        0xFEB0
EM_IQ2000 =        0xFEBA
EM_NIOS32 =        0xFEBB
EM_CYGNUS_MEP =        0xF00D  # Toshiba MeP 
EM_MOXIE =                0xFEED  # Moxie 
EM_SCORE_OLD =            95
EM_MICROBLAZE_OLD =    0xbaab    # Old MicroBlaze 
EM_ADAPTEVA_EPIPHANY =   0x1223  # Adapteva's Epiphany architecture.  
EV_NONE =        0        # Invalid ELF version 
EV_CURRENT =    1        # Current version 
PN_XNUM =        0xffff        # Extended numbering 
PT_NULL =        0        # Program header table entry unused 
PT_LOAD =        1        # Loadable program segment 
PT_DYNAMIC =    2        # Dynamic linking information 
PT_INTERP =    3        # Program interpreter 
PT_NOTE =        4        # Auxiliary information 
PT_SHLIB =    5        # Reserved, unspecified semantics 
PT_PHDR =        6        # Entry for header table itself 
PT_TLS =        7        # Thread local storage segment 
PT_LOOS =        0x60000000    # OS-specific 
PT_HIOS =        0x6fffffff    # OS-specific 
PT_LOPROC =    0x70000000    # Processor-specific 
PT_HIPROC =    0x7FFFFFFF    # Processor-specific 
PT_GNU_EH_FRAME =    (PT_LOOS + 0x474e550) # Frame unwind information 
PT_SUNW_EH_FRAME = PT_GNU_EH_FRAME      # Solaris uses the same value 
PT_GNU_STACK =    (PT_LOOS + 0x474e551) # Stack flags 
PT_GNU_RELRO =    (PT_LOOS + 0x474e552) # Read-only after relocation 
PF_X =        (1 << 0)    # Segment is executable 
PF_W =        (1 << 1)    # Segment is writable 
PF_R =        (1 << 2)    # Segment is readable 
PF_MASKOS =    0x0FF00000    # New value, Oct 4, 1999 Draft 
PF_MASKPROC =    0xF0000000    # Processor-specific reserved bits 
SHT_NULL =    0        # Section header table entry unused 
SHT_PROGBITS =    1        # Program specific (private) data 
SHT_SYMTAB =    2        # Link editing symbol table 
SHT_STRTAB =    3        # A string table 
SHT_RELA =    4        # Relocation entries with addends 
SHT_HASH =    5        # A symbol hash table 
SHT_DYNAMIC =    6        # Information for dynamic linking 
SHT_NOTE =    7        # Information that marks file 
SHT_NOBITS =    8        # Section occupies no space in file 
SHT_REL =        9        # Relocation entries, no addends 
SHT_SHLIB =    10        # Reserved, unspecified semantics 
SHT_DYNSYM =    11        # Dynamic linking symbol table 
SHT_INIT_ARRAY =      14        # Array of ptrs to init functions 
SHT_FINI_ARRAY =      15        # Array of ptrs to finish functions 
SHT_PREINIT_ARRAY = 16        # Array of ptrs to pre-init funcs 
SHT_GROUP =      17        # Section contains a section group 
SHT_SYMTAB_SHNDX =  18        # Indicies for SHN_XINDEX entries 
SHT_LOOS =    0x60000000    # First of OS specific semantics 
SHT_HIOS =    0x6fffffff    # Last of OS specific semantics 
SHT_GNU_INCREMENTAL_INPUTS = 0x6fff4700   # incremental build data 
SHT_GNU_ATTRIBUTES = 0x6ffffff5    # Object attributes 
SHT_GNU_HASH =    0x6ffffff6    # GNU style symbol hash table 
SHT_GNU_LIBLIST =    0x6ffffff7    # List of prelink dependencies 
SHT_SUNW_verdef =    0x6ffffffd    # Versions defined by file 
SHT_SUNW_verneed = 0x6ffffffe    # Versions needed by file 
SHT_SUNW_versym =    0x6fffffff    # Symbol versions 
SHT_GNU_verdef =    SHT_SUNW_verdef
SHT_GNU_verneed =    SHT_SUNW_verneed
SHT_GNU_versym =    SHT_SUNW_versym
SHT_LOPROC =    0x70000000    # Processor-specific semantics, lo 
SHT_HIPROC =    0x7FFFFFFF    # Processor-specific semantics, hi 
SHT_LOUSER =    0x80000000    # Application-specific semantics 
# #define SHT_HIUSER    0x8FFFFFFF    /* Application-specific semantics */
SHT_HIUSER =    0xFFFFFFFF    # New value, defined in Oct 4, 1999 Draft 
SHF_WRITE =    (1 << 0)    # Writable data during execution 
SHF_ALLOC =    (1 << 1)    # Occupies memory during execution 
SHF_EXECINSTR =    (1 << 2)    # Executable machine instructions 
SHF_MERGE =    (1 << 4)    # Data in this section can be merged 
SHF_STRINGS =    (1 << 5)    # Contains null terminated character strings 
SHF_INFO_LINK =    (1 << 6)    # sh_info holds section header table index 
SHF_LINK_ORDER =    (1 << 7)    # Preserve section ordering when linking 
SHF_OS_NONCONFORMING = (1 << 8)    # OS specific processing required 
SHF_GROUP =    (1 << 9)    # Member of a section group 
SHF_TLS =        (1 << 10)    # Thread local storage section 
SHF_MASKOS =    0x0FF00000    # New value, Oct 4, 1999 Draft 
SHF_MASKPROC =    0xF0000000    # Processor-specific semantics 
SHF_EXCLUDE =    0x80000000    # Link editor is to exclude
NT_PRSTATUS =    1        # Contains copy of prstatus struct 
NT_FPREGSET =    2        # Contains copy of fpregset struct 
NT_PRPSINFO =    3        # Contains copy of prpsinfo struct 
NT_TASKSTRUCT =    4        # Contains copy of task struct 
NT_AUXV =        6        # Contains copy of Elfxx_auxv_t 
NT_PRXFPREG =    0x46e62b7f    # Contains a user_xfpregs_struct; 
NT_PPC_VMX =    0x100        # PowerPC Altivec/VMX registers 
NT_PPC_VSX =    0x102        # PowerPC VSX registers 
NT_X86_XSTATE =    0x202        # x86 XSAVE extended state 
NT_S390_HIGH_GPRS = 0x300        # S/390 upper halves of GPRs  
NT_S390_TIMER =    0x301        # S390 timer 
NT_S390_TODCMP =    0x302        # S390 TOD clock comparator 
NT_S390_TODPREG =    0x303        # S390 TOD programmable register 
NT_S390_CTRS =    0x304        # S390 control registers 
NT_S390_PREFIX =    0x305        # S390 prefix register 
NT_S390_LAST_BREAK =      0x306   # S390 breaking event address 
NT_S390_SYSTEM_CALL =     0x307   # S390 system call restart data 
NT_ARM_VFP =    0x400        # ARM VFP registers 
NT_PSTATUS =    10        # Has a struct pstatus 
NT_FPREGS =    12        # Has a struct fpregset 
NT_PSINFO =    13        # Has a struct psinfo 
NT_LWPSTATUS =    16        # Has a struct lwpstatus_t 
NT_LWPSINFO =    17        # Has a struct lwpsinfo_t 
NT_WIN32PSTATUS =    18        # Has a struct win32_pstatus 
NT_STAPSDT =    3
NT_NETBSDCORE_PROCINFO =    1    # Has a struct procinfo 
NT_NETBSDCORE_FIRSTMACH =    32    # start of machdep note types 
NT_OPENBSD_PROCINFO =    10
NT_OPENBSD_AUXV =        11
NT_OPENBSD_REGS =        20
NT_OPENBSD_FPREGS =    21
NT_OPENBSD_XFPREGS =    22
NT_OPENBSD_WCOOKIE =    23
NT_SPU =        1
NT_VERSION =    1        # Contains a version string.  
NT_ARCH =        2        # Contains an architecture string.  
NT_GNU_ABI_TAG =        1
NT_GNU_HWCAP =        2    # Used by ld.so and kernel vDSO.  
NT_GNU_BUILD_ID =        3    # Generated by ld --build-id.  
NT_GNU_GOLD_VERSION =    4    # Generated by gold.  
GNU_ABI_TAG_LINUX =    0
GNU_ABI_TAG_HURD =    1
GNU_ABI_TAG_SOLARIS =    2
GNU_ABI_TAG_FREEBSD =    3
GNU_ABI_TAG_NETBSD =    4
NT_NETBSD_IDENT =        1
NT_OPENBSD_IDENT =    1
NT_FREEBSD_ABI_TAG =    1
STN_UNDEF =    0        # Undefined symbol index 
STB_LOCAL =    0        # Symbol not visible outside obj 
STB_GLOBAL =    1        # Symbol visible outside obj 
STB_WEAK =    2        # Like globals, lower precedence 
STB_LOOS =    10        # OS-specific semantics 
STB_GNU_UNIQUE =    10        # Symbol is unique in namespace 
STB_HIOS =    12        # OS-specific semantics 
STB_LOPROC =    13        # Processor-specific semantics 
STB_HIPROC =    15        # Processor-specific semantics 
STT_NOTYPE =    0        # Symbol type is unspecified 
STT_OBJECT =    1        # Symbol is a data object 
STT_FUNC =    2        # Symbol is a code object 
STT_SECTION =    3        # Symbol associated with a section 
STT_FILE =    4        # Symbol gives a file name 
STT_COMMON =    5        # An uninitialised common block 
STT_TLS =        6        # Thread local data object 
STT_RELC =    8        # Complex relocation expression 
STT_SRELC =    9        # Signed Complex relocation expression 
STT_LOOS =    10        # OS-specific semantics 
STT_GNU_IFUNC =    10        # Symbol is an indirect code object 
STT_HIOS =    12        # OS-specific semantics 
STT_LOPROC =    13        # Processor-specific semantics 
STT_HIPROC =    15        # Processor-specific semantics 
STV_DEFAULT =    0        # Visibility is specified by binding type 
STV_INTERNAL =    1        # OS specific version of STV_HIDDEN 
STV_HIDDEN =    2        # Can only be seen inside currect component 
STV_PROTECTED =    3        # Treat as STB_LOCAL inside current component 
DT_NULL =        0
DT_NEEDED =    1
DT_PLTRELSZ =    2
DT_PLTGOT =    3
DT_HASH =        4
DT_STRTAB =    5
DT_SYMTAB =    6
DT_RELA =        7
DT_RELASZ =    8
DT_RELAENT =    9
DT_STRSZ =    10
DT_SYMENT =    11
DT_INIT =        12
DT_FINI =        13
DT_SONAME =    14
DT_RPATH =    15
DT_SYMBOLIC =    16
DT_REL =        17
DT_RELSZ =    18
DT_RELENT =    19
DT_PLTREL =    20
DT_DEBUG =    21
DT_TEXTREL =    22
DT_JMPREL =    23
DT_BIND_NOW =    24
DT_INIT_ARRAY =    25
DT_FINI_ARRAY =    26
DT_INIT_ARRAYSZ = 27
DT_FINI_ARRAYSZ = 28
DT_RUNPATH =    29
DT_FLAGS =    30
DT_ENCODING =    32
DT_PREINIT_ARRAY =   32
DT_PREINIT_ARRAYSZ = 33
OLD_DT_LOOS =    0x60000000
DT_LOOS =        0x6000000d
DT_HIOS =        0x6ffff000
OLD_DT_HIOS =    0x6fffffff
DT_LOPROC =    0x70000000
DT_HIPROC =    0x7fffffff
DT_VALRNGLO =    0x6ffffd00
DT_GNU_PRELINKED = 0x6ffffdf5
DT_GNU_CONFLICTSZ = 0x6ffffdf6
DT_GNU_LIBLISTSZ = 0x6ffffdf7
DT_CHECKSUM =    0x6ffffdf8
DT_PLTPADSZ =    0x6ffffdf9
DT_MOVEENT =    0x6ffffdfa
DT_MOVESZ =    0x6ffffdfb
DT_FEATURE =    0x6ffffdfc
DT_POSFLAG_1 =    0x6ffffdfd
DT_SYMINSZ =    0x6ffffdfe
DT_SYMINENT =    0x6ffffdff
DT_VALRNGHI =    0x6ffffdff
DT_ADDRRNGLO =    0x6ffffe00
DT_GNU_HASH =    0x6ffffef5
DT_TLSDESC_PLT =    0x6ffffef6
DT_TLSDESC_GOT =    0x6ffffef7
DT_GNU_CONFLICT =    0x6ffffef8
DT_GNU_LIBLIST =    0x6ffffef9
DT_CONFIG =    0x6ffffefa
DT_DEPAUDIT =    0x6ffffefb
DT_AUDIT =    0x6ffffefc
DT_PLTPAD =    0x6ffffefd
DT_MOVETAB =    0x6ffffefe
DT_SYMINFO =    0x6ffffeff
DT_ADDRRNGHI =    0x6ffffeff
DT_RELACOUNT =    0x6ffffff9
DT_RELCOUNT =    0x6ffffffa
DT_FLAGS_1 =    0x6ffffffb
DT_VERDEF =    0x6ffffffc
DT_VERDEFNUM =    0x6ffffffd
DT_VERNEED =    0x6ffffffe
DT_VERNEEDNUM =    0x6fffffff
DT_VERSYM =    0x6ffffff0
DT_LOPROC =    0x70000000
DT_HIPROC =    0x7fffffff
DT_AUXILIARY =    0x7ffffffd
DT_USED =        0x7ffffffe
DT_FILTER =    0x7fffffff
DTF_1_PARINIT =    0x00000001
DTF_1_CONFEXP =    0x00000002
DF_P1_LAZYLOAD =    0x00000001
DF_P1_GROUPPERM =    0x00000002
DF_1_NOW =    0x00000001
DF_1_GLOBAL =    0x00000002
DF_1_GROUP =    0x00000004
DF_1_NODELETE =    0x00000008
DF_1_LOADFLTR =    0x00000010
DF_1_INITFIRST =    0x00000020
DF_1_NOOPEN =    0x00000040
DF_1_ORIGIN =    0x00000080
DF_1_DIRECT =    0x00000100
DF_1_TRANS =    0x00000200
DF_1_INTERPOSE =    0x00000400
DF_1_NODEFLIB =    0x00000800
DF_1_NODUMP =    0x00001000
DF_1_CONLFAT =    0x00002000
DF_ORIGIN =    (1 << 0)
DF_SYMBOLIC =    (1 << 1)
DF_TEXTREL =    (1 << 2)
DF_BIND_NOW =    (1 << 3)
DF_STATIC_TLS =    (1 << 4)
VER_DEF_NONE =        0
VER_DEF_CURRENT =        1
VER_FLG_BASE =        0x1
VER_FLG_WEAK =        0x2
VER_FLG_INFO =        0x4
VER_NDX_LOCAL =        0
VER_NDX_GLOBAL =        1
VER_NEED_NONE =        0
VER_NEED_CURRENT =    1
VERSYM_HIDDEN =        0x8000
VERSYM_VERSION =        0x7fff
ELF_VER_CHR =    '@'
SYMINFO_BT_SELF =        0xffff    # Symbol bound to self 
SYMINFO_BT_PARENT =    0xfffe    # Symbol bound to parent 
SYMINFO_BT_LOWRESERVE =    0xff00    # Beginning of reserved entries 
SYMINFO_FLG_DIRECT =    0x0001    # Direct bound symbol 
SYMINFO_FLG_PASSTHRU =    0x0002    # Pass-thru symbol for translator 
SYMINFO_FLG_COPY =    0x0004    # Symbol is a copy-reloc 
SYMINFO_FLG_LAZYLOAD =    0x0008    # Symbol bound to object to be lazy loaded 
SYMINFO_NONE =        0
SYMINFO_CURRENT =        1
SYMINFO_NUM =        2
GRP_COMDAT =        0x1    # A COMDAT group 
AT_NULL =        0        # End of vector 
AT_IGNORE =    1        # Entry should be ignored 
AT_EXECFD =    2        # File descriptor of program 
AT_PHDR =        3        # Program headers for program 
AT_PHENT =    4        # Size of program header entry 
AT_PHNUM =    5        # Number of program headers 
AT_PAGESZ =    6        # System page size 
AT_BASE =        7        # Base address of interpreter 
AT_FLAGS =    8        # Flags 
AT_ENTRY =    9        # Entry point of program 
AT_NOTELF =    10        # Program is not ELF 
AT_UID =        11        # Real uid 
AT_EUID =        12        # Effective uid 
AT_GID =        13        # Real gid 
AT_EGID =        14        # Effective gid 
AT_CLKTCK =    17        # Frequency of times() 
AT_PLATFORM =    15        # String identifying platform.  
AT_HWCAP =    16        # Machine dependent hints about
AT_FPUCW =    18        # Used FPU control word.  
AT_DCACHEBSIZE =    19        # Data cache block size.  
AT_ICACHEBSIZE =    20        # Instruction cache block size.  
AT_UCACHEBSIZE =    21        # Unified cache block size.  
AT_IGNOREPPC =    22        # Entry should be ignored 
#define    AT_SECURE    23        # Boolean, was exec setuid-like?  
AT_BASE_PLATFORM = 24        # String identifying real platform,
AT_RANDOM =    25        # Address of 16 random bytes.  
AT_EXECFN =    31        # Filename of executable.  
AT_SYSINFO =    32
AT_SYSINFO_EHDR =    33 # Pointer to ELF header of system-supplied DSO.  
AT_L1I_CACHESHAPE = 34
AT_L1D_CACHESHAPE = 35
AT_L2_CACHESHAPE =  36
AT_L3_CACHESHAPE =  37
AT_SUN_UID =      2000    # Effective user ID.  
AT_SUN_RUID =     2001    # Real user ID.  
AT_SUN_GID =      2002    # Effective group ID.  
AT_SUN_RGID =     2003    # Real group ID.  
AT_SUN_LDELF =    2004    # Dynamic linker's ELF header.  
AT_SUN_LDSHDR =   2005    # Dynamic linker's section headers.  
AT_SUN_LDNAME =   2006    # String giving name of dynamic linker.  
AT_SUN_LPAGESZ =  2007    # Large pagesize.   
AT_SUN_PLATFORM = 2008    # Platform name string.  
AT_SUN_HWCAP =    2009    # Machine dependent hints about
AT_SUN_IFLUSH =   2010    # Should flush icache? 
AT_SUN_CPU =      2011    # CPU name string.  
AT_SUN_EMUL_ENTRY = 2012    # COFF entry point address.  
AT_SUN_EMUL_EXECFD = 2013    # COFF executable file descriptor.  
AT_SUN_EXECNAME = 2014    # Canonicalized file name given to execve.  
AT_SUN_MMU =      2015    # String for name of MMU module.   
AT_SUN_LDDATA =   2016    # Dynamic linker's data segment address.  
AT_SUN_AUXFLAGS =    2017    # AF_SUN_ flags passed from the kernel.  


#include/elf/aarch64.h
PT_AARCH64_ARCHEXT =    (PT_LOPROC + 0)
SHT_AARCH64_ATTRIBUTES =    0x70000003  # Section holds attributes.  
SHF_ENTRYSECT =        0x10000000   # Section contains an
SHF_COMDEF =        0x80000000   # Section may be multiply defined

#include/elf/alpha.h
EF_ALPHA_32BIT =        0x00000001
EF_ALPHA_CANRELAX =    0x00000002
SHF_ALPHA_GPREL =        0x10000000
SHT_ALPHA_DEBUG =        0x70000001
SHT_ALPHA_REGINFO =    0x70000002
STO_ALPHA_NOPV =        0x80
STO_ALPHA_STD_GPLOAD =    0x88
DT_ALPHA_PLTRO =        DT_LOPROC
LITUSE_ALPHA_ADDR =    0
LITUSE_ALPHA_BASE =    1
LITUSE_ALPHA_BYTOFF =    2
LITUSE_ALPHA_JSR =    3
LITUSE_ALPHA_TLSGD =    4
LITUSE_ALPHA_TLSLDM =    5
LITUSE_ALPHA_JSRDIRECT =    6

#include/elf/arc.h
EF_ARC_MACH = 0x0000000f
E_ARC_MACH_ARC5 = 0
E_ARC_MACH_ARC6 = 1    
E_ARC_MACH_ARC7 = 2
E_ARC_MACH_ARC8 = 3
EF_ARC_PIC = 0x00000100

#include/elf/arm.h
EF_ARM_RELEXEC =     0x01
EF_ARM_HASENTRY =    0x02
EF_ARM_INTERWORK =   0x04
EF_ARM_APCS_26 =     0x08
EF_ARM_APCS_FLOAT =  0x10
EF_ARM_PIC =         0x20
EF_ARM_ALIGN8 =       0x40        # 8-bit structure alignment is in use.  
EF_ARM_NEW_ABI =     0x80
EF_ARM_OLD_ABI =     0x100
EF_ARM_SOFT_FLOAT =  0x200
EF_ARM_VFP_FLOAT =   0x400
EF_ARM_MAVERICK_FLOAT = 0x800
PT_ARM_EXIDX = (PT_LOPROC + 1)
EF_ARM_SYMSARESORTED = 0x04    # NB conflicts with EF_INTERWORK.  
EF_ARM_DYNSYMSUSESEGIDX = 0x08    # NB conflicts with EF_APCS26.  
EF_ARM_MAPSYMSFIRST = 0x10    # NB conflicts with EF_APCS_FLOAT.  
EF_ARM_EABIMASK =      0xFF000000
EF_ARM_BE8 =        0x00800000
EF_ARM_LE8 =        0x00400000
EF_ARM_EABI_UNKNOWN =  0x00000000
EF_ARM_EABI_VER1 =     0x01000000
EF_ARM_EABI_VER2 =     0x02000000
EF_ARM_EABI_VER3 =     0x03000000
EF_ARM_EABI_VER4 =     0x04000000
EF_ARM_EABI_VER5 =     0x05000000
F_INTERWORK =       EF_ARM_INTERWORK
F_APCS26 =       EF_ARM_APCS_26
F_APCS_FLOAT =       EF_ARM_APCS_FLOAT
F_PIC =              EF_ARM_PIC
F_SOFT_FLOAT =       EF_ARM_SOFT_FLOAT
F_VFP_FLOAT =       EF_ARM_VFP_FLOAT
STT_ARM_TFUNC =      STT_LOPROC   # A Thumb function.  
STT_ARM_16BIT =      STT_HIPROC   # A Thumb label.  
SHT_ARM_EXIDX =           0x70000001    # Section holds ARM unwind info.  
SHT_ARM_PREEMPTMAP =     0x70000002    # Section pre-emption details.  
SHT_ARM_ATTRIBUTES =     0x70000003    # Section holds attributes.  
SHT_ARM_DEBUGOVERLAY =   0x70000004    # Section holds overlay debug info.  
SHT_ARM_OVERLAYSECTION = 0x70000005    # Section holds GDB and overlay integration info.  
SHF_ENTRYSECT =      0x10000000   # Section contains an entry point.  
SHF_COMDEF =         0x80000000   # Section may be multiply defined in the input to a link step.  
PF_ARM_SB =          0x10000000   # Segment contains the location addressed by the static base.  
PF_ARM_PI =          0x20000000   # Segment is position-independent.  
PF_ARM_ABS =         0x40000000   # Segment must be loaded at its base address.  
TAG_CPU_ARCH_PRE_V4 =    0
TAG_CPU_ARCH_V4 =        1
TAG_CPU_ARCH_V4T =    2
TAG_CPU_ARCH_V5T =    3
TAG_CPU_ARCH_V5TE =    4
TAG_CPU_ARCH_V5TEJ =    5
TAG_CPU_ARCH_V6 =        6
TAG_CPU_ARCH_V6KZ =    7
TAG_CPU_ARCH_V6T2 =    8
TAG_CPU_ARCH_V6K =    9
TAG_CPU_ARCH_V7 =        10
TAG_CPU_ARCH_V6_M =    11
TAG_CPU_ARCH_V6S_M =    12
TAG_CPU_ARCH_V7E_M =    13
TAG_CPU_ARCH_V8 =        14
MAX_TAG_CPU_ARCH =    14
TAG_CPU_ARCH_V4T_PLUS_V6_M = (MAX_TAG_CPU_ARCH + 1)
ARM_NOTE_SECTION = ".note.gnu.arm.ident"
ELF_STRING_ARM_unwind =           ".ARM.exidx"
ELF_STRING_ARM_unwind_info =      ".ARM.extab"
ELF_STRING_ARM_unwind_once =      ".gnu.linkonce.armexidx."
ELF_STRING_ARM_unwind_info_once = ".gnu.linkonce.armextab."

#include/elf/avr.h
EF_AVR_MACH = 0x7F
EF_AVR_LINKRELAX_PREPARED = 0x80
E_AVR_MACH_AVR1 =     1
E_AVR_MACH_AVR2 =     2
E_AVR_MACH_AVR25 =   25
E_AVR_MACH_AVR3 =     3
E_AVR_MACH_AVR31 =   31
E_AVR_MACH_AVR35 =   35
E_AVR_MACH_AVR4 =     4
E_AVR_MACH_AVR5 =     5
E_AVR_MACH_AVR51 =   51
E_AVR_MACH_AVR6 =     6 
E_AVR_MACH_XMEGA1 = 101
E_AVR_MACH_XMEGA2 = 102
E_AVR_MACH_XMEGA3 = 103
E_AVR_MACH_XMEGA4 = 104
E_AVR_MACH_XMEGA5 = 105
E_AVR_MACH_XMEGA6 = 106
E_AVR_MACH_XMEGA7 = 107

#include/elf/bfin.h
EF_BFIN_PIC =        0x00000001    # -fpic 
EF_BFIN_FDPIC =        0x00000002      # -mfdpic 
EF_BFIN_CODE_IN_L1 =    0x00000010    # --code-in-l1 
EF_BFIN_DATA_IN_L1 =    0x00000020    # --data-in-l1 
#define    EF_BFIN_PIC_FLAGS    (EF_BFIN_PIC | EF_BFIN_FDPIC)



#include/elf/cr16.h

#include/elf/cr16c.h
R_16C_NUM08 =    0X0001
R_16C_NUM08_C =    0X0006
R_16C_NUM16 =    0X1001
R_16C_NUM16_C =     0X1006
R_16C_NUM32 =     0X2001
R_16C_NUM32_C =   0X2006
R_16C_DISP04 =    0X5411
R_16C_DISP04_C =    0X5416
R_16C_DISP08 =    0X0411
R_16C_DISP08_C =    0X0416
R_16C_DISP16 =    0X1411
R_16C_DISP16_C =    0X1416
R_16C_DISP24 =    0X7411
R_16C_DISP24_C =    0X7416
R_16C_DISP24a =    0X6411
R_16C_DISP24a_C =    0X6416
R_16C_REG04 =    0X5201
R_16C_REG04_C =    0X5206
R_16C_REG04a =    0X4201
R_16C_REG04a_C =    0X4206
R_16C_REG14 =    0X3201
R_16C_REG14_C =    0X3206
R_16C_REG16 =    0X1201
R_16C_REG16_C =    0X1206
R_16C_REG20 =    0X8201
R_16C_REG20_C =    0X8206
R_16C_ABS20 =     0X8101
R_16C_ABS20_C =   0X8106
R_16C_ABS24 =     0X7101
R_16C_ABS24_C =   0X7106
R_16C_IMM04 =     0X5301
R_16C_IMM04_C =   0X5306
R_16C_IMM16 =     0X1301
R_16C_IMM16_C =   0X1306
R_16C_IMM20 =     0X8301
R_16C_IMM20_C =   0X8306
R_16C_IMM24 =     0X7301
R_16C_IMM24_C =   0X7306
R_16C_IMM32 =     0X2301
R_16C_IMM32_C =   0X2306
R_ADDRTYPE   =  0x000f
R_ADDRESS    =  0x0001    # Take address of symbol.  
R_CODE_ADDR  =  0x0006    # Take address of symbol divided by 2.  
R_RELTO      =  0x00f0
R_ABS        =  0x0000    # Keep symbol's address as such.  
R_PCREL      =  0x0010    # Subtract the pc address of hole.  
R_FORMAT     =  0x0f00
R_NUMBER     =  0x0000    # Retain as two's complement value.  
R_16C_DISPL  =  0x0400    # CR16C displacement type.  
R_16C_ABS    =  0x0100    # CR16C absolute type.  
R_16C_REGREL =  0x0200    # CR16C register-relative type.  
R_16C_IMMED  =  0x0300    # CR16C immediate type.  
R_SIZESP     =  0xf000
R_S_16C_04   =  0x5000
R_S_16C_04_a =  0x4000
R_S_16C_08   =  0x0000
R_S_16C_14   =  0x3000
R_S_16C_16   =  0x1000
R_S_16C_20   =  0x8000
R_S_16C_24_a =  0x6000
R_S_16C_24   =  0x7000
R_S_16C_32   =  0x2000

#include/elf/cris.h
EF_CRIS_UNDERSCORE =        0x00000001
EF_CRIS_VARIANT_MASK =        0x0000000e
EF_CRIS_VARIANT_ANY_V0_V10 =    0x00000000
EF_CRIS_VARIANT_V32 =        0x00000002
EF_CRIS_VARIANT_COMMON_V10_V32 =    0x00000004

#include/elf/crx.h

#include/elf/d10v.h

#include/elf/d30v.h

#include/elf/dlx.h

#include/elf/dwarf.h
TAG_lo_user =    0x8000  # implementation-defined range start 
TAG_hi_user =    0xffff  # implementation-defined range end 
AT_lo_user =    0x2000    # implementation-defined range start 
AT_hi_user =    0x3ff0    # implementation-defined range end 
OP_LO_USER =    0x80  # implementation-defined range start 
OP_HI_USER =    0xff  # implementation-defined range end 
FT_lo_user =    0x8000  # implementation-defined range start 
FT_hi_user =    0xffff  # implementation defined range end 
MOD_lo_user =    0x80  # implementation-defined range start 
MOD_hi_user =    0xff  # implementation-defined range end 
LANG_lo_user =    0x00008000  # implementation-defined range start 
LANG_hi_user =    0x0000ffff  # implementation-defined range end 

#include/elf/epiphany.h

#include/elf/external.h
SHN_LORESERVE =    0xFF00        # Begin range of reserved indices 
SHN_LOPROC =    0xFF00        # Begin range of appl-specific 
SHN_HIPROC =    0xFF1F        # End range of appl-specific 
SHN_LOOS =    0xFF20        # OS specific semantics, lo 
SHN_HIOS =    0xFF3F        # OS specific semantics, hi 
SHN_ABS =        0xFFF1        # Associated symbol is absolute 
SHN_COMMON =    0xFFF2        # Associated symbol is in common 
SHN_XINDEX =    0xFFFF        # Section index is held elsewhere 
SHN_HIRESERVE =    0xFFFF        # End range of reserved indices 
GRP_ENTRY_SIZE =        4

#include/elf/fr30.h

#include/elf/frv.h
EF_FRV_GPR_MASK =        0x00000003    # mask for # of gprs 
EF_FRV_GPR_32 =        0x00000001    # -mgpr-32 
EF_FRV_GPR_64 =        0x00000002    # -mgpr-64 
EF_FRV_FPR_MASK =        0x0000000c    # mask for # of fprs 
EF_FRV_FPR_32 =        0x00000004    # -mfpr-32 
EF_FRV_FPR_64 =        0x00000008    # -mfpr-64 
EF_FRV_FPR_NONE =        0x0000000c    # -msoft-float 
EF_FRV_DWORD_MASK =    0x00000030    # mask for dword support 
EF_FRV_DWORD_YES =    0x00000010    # use double word insns 
EF_FRV_DWORD_NO =        0x00000020    # don't use double word insn
EF_FRV_DOUBLE =        0x00000040    # -mdouble 
EF_FRV_MEDIA =        0x00000080    # -mmedia 
EF_FRV_PIC =        0x00000100    # -fpic 
EF_FRV_NON_PIC_RELOCS =    0x00000200    # used non pic safe relocs 
EF_FRV_MULADD =        0x00000400    # -mmuladd 
EF_FRV_BIGPIC =        0x00000800    # -fPIC 
#define    EF_FRV_LIBPIC        0x00001000    # -mlibrary-pic 
EF_FRV_G0 =        0x00002000    # -G 0, no small data ptr 
EF_FRV_NOPACK =        0x00004000    # -mnopack 
EF_FRV_FDPIC =        0x00008000      # -mfdpic 
#define    EF_FRV_CPU_MASK        0xff000000    # specific cpu bits 
EF_FRV_CPU_GENERIC =    0x00000000    # generic FRV 
EF_FRV_CPU_FR500 =    0x01000000    # FRV500 
EF_FRV_CPU_FR300 =    0x02000000    # FRV300 
EF_FRV_CPU_SIMPLE =    0x03000000    # SIMPLE 
EF_FRV_CPU_TOMCAT =    0x04000000    # Tomcat, FR500 prototype 
EF_FRV_CPU_FR400 =    0x05000000    # FRV400 
EF_FRV_CPU_FR550 =    0x06000000    # FRV550 
EF_FRV_CPU_FR405 =    0x07000000
EF_FRV_CPU_FR450 =    0x08000000
#define    EF_FRV_PIC_FLAGS    (EF_FRV_PIC | EF_FRV_LIBPIC | EF_FRV_BIGPIC \

#include/elf/h8.h
EF_H8_MACH =        0x00FF0000
E_H8_MACH_H8300 =        0x00800000
E_H8_MACH_H8300H =    0x00810000
E_H8_MACH_H8300S =    0x00820000
E_H8_MACH_H8300HN =    0x00830000
E_H8_MACH_H8300SN =    0x00840000
E_H8_MACH_H8300SX =    0x00850000
E_H8_MACH_H8300SXN =    0x00860000

#include/elf/hppa.h
EF_PARISC_TRAPNIL =    0x00010000
EF_PARISC_EXT =        0x00020000
EF_PARISC_LSB =        0x00040000
EF_PARISC_WIDE =        0x00080000
EF_PARISC_NO_KABP =    0x00100000
EF_PARISC_LAZYSWAP =    0x00400000
EF_PARISC_ARCH =        0x0000ffff
EFA_PARISC_1_0 =            0x020b
EFA_PARISC_1_1 =            0x0210
EFA_PARISC_2_0 =            0x0214
SHN_PARISC_ANSI_COMMON =     SHN_LORESERVE
SHN_PARISC_HUGE_COMMON =    (SHN_LORESERVE + 1)
SHT_PARISC_EXT =        0x70000000
SHT_PARISC_UNWIND =    0x70000001
SHT_PARISC_DOC =        0x70000002
SHT_PARISC_ANNOT =    0x70000003
SHT_PARISC_DLKM =        0x70000004
SHT_PARISC_SYMEXTN =    SHT_LOPROC + 8
SHT_PARISC_STUBS =      SHT_LOPROC + 9
SHF_PARISC_SBP =        0x80000000
SHF_PARISC_HUGE =        0x40000000
SHF_PARISC_SHORT =    0x20000000
SHF_PARISC_WEAKORDER =    0x10000000
STT_PARISC_MILLI =    13
PT_PARISC_ARCHEXT =    0x70000000
PT_PARISC_UNWIND =    0x70000001
PT_PARISC_WEAKORDER =    0x70000002
SHF_HP_TLS =              0x01000000
SHF_HP_NEAR_SHARED =      0x02000000
SHF_HP_FAR_SHARED =       0x04000000
SHF_HP_COMDAT =           0x08000000
SHF_HP_CONST =            0x00800000
SHN_TLS_COMMON =          (SHN_LOOS + 0x0)
SHN_NS_COMMON =           (SHN_LOOS + 0x1)
SHN_FS_COMMON =           (SHN_LOOS + 0x2)
SHN_NS_UNDEF =            (SHN_LOOS + 0x3)
SHN_FS_UNDEF =            (SHN_LOOS + 0x4)
SHN_HP_EXTERN =           (SHN_LOOS + 0x5)
SHN_HP_EXTHINT =          (SHN_LOOS + 0x6)
SHN_HP_UNDEF_BIND_IMM =   (SHN_LOOS + 0x7)
SHT_HP_OVLBITS =  (SHT_LOOS + 0x0)
SHT_HP_DLKM =     (SHT_LOOS + 0x1)
SHT_HP_COMDAT =   (SHT_LOOS + 0x2)
SHT_HP_OBJDICT =  (SHT_LOOS + 0x3)
SHT_HP_ANNOT =    (SHT_LOOS + 0x4)
PF_HP_CODE =        0x00040000
PF_HP_MODIFY =        0x00080000
PF_HP_PAGE_SIZE =        0x00100000
PF_HP_FAR_SHARED =    0x00200000
PF_HP_NEAR_SHARED =    0x00400000
PF_HP_LAZYSWAP =        0x00800000
PF_HP_CODE_DEPR =        0x01000000
PF_HP_MODIFY_DEPR =    0x02000000
PF_HP_LAZYSWAP_DEPR =    0x04000000
PF_PARISC_SBP =        0x08000000
PF_HP_SBP =        0x08000000
DT_HP_LOAD_MAP =        (OLD_DT_LOOS + 0x0)
DT_HP_DLD_FLAGS =        (OLD_DT_LOOS + 0x1)
DT_HP_DLD_HOOK =        (OLD_DT_LOOS + 0x2)
DT_HP_UX10_INIT =        (OLD_DT_LOOS + 0x3)
DT_HP_UX10_INITSZ =    (OLD_DT_LOOS + 0x4)
DT_HP_PREINIT =        (OLD_DT_LOOS + 0x5)
DT_HP_PREINITSZ =        (OLD_DT_LOOS + 0x6)
DT_HP_NEEDED =        (OLD_DT_LOOS + 0x7)
DT_HP_TIME_STAMP =    (OLD_DT_LOOS + 0x8)
DT_HP_CHECKSUM =        (OLD_DT_LOOS + 0x9)
DT_HP_GST_SIZE =        (OLD_DT_LOOS + 0xa)
DT_HP_GST_VERSION =    (OLD_DT_LOOS + 0xb)
DT_HP_GST_HASHVAL =    (OLD_DT_LOOS + 0xc)
DT_HP_EPLTREL =        (OLD_DT_LOOS + 0xd)
DT_HP_EPLTRELSZ =        (OLD_DT_LOOS + 0xe)
DT_HP_FILTERED =        (OLD_DT_LOOS + 0xf)
DT_HP_FILTER_TLS =    (OLD_DT_LOOS + 0x10)
DT_HP_COMPAT_FILTERED =    (OLD_DT_LOOS + 0x11)
DT_HP_LAZYLOAD =        (OLD_DT_LOOS + 0x12)
DT_HP_BIND_NOW_COUNT =    (OLD_DT_LOOS + 0x13)
DT_PLT =            (OLD_DT_LOOS + 0x14)
DT_PLT_SIZE =        (OLD_DT_LOOS + 0x15)
DT_DLT =            (OLD_DT_LOOS + 0x16)
DT_DLT_SIZE =        (OLD_DT_LOOS + 0x17)
DT_HP_DEBUG_PRIVATE =        0x00001 # Map text private 
DT_HP_DEBUG_CALLBACK =        0x00002 # Callback 
DT_HP_DEBUG_CALLBACK_BOR =    0x00004 # BOR callback 
DT_HP_NO_ENVVAR =            0x00008 # No env var 
DT_HP_BIND_NOW =            0x00010 # Bind now 
DT_HP_BIND_NONFATAL =        0x00020 # Bind non-fatal 
DT_HP_BIND_VERBOSE =        0x00040 # Bind verbose 
DT_HP_BIND_RESTRICTED =        0x00080 # Bind restricted 
DT_HP_BIND_SYMBOLIC =        0x00100 # Bind symbolic 
DT_HP_RPATH_FIRST =        0x00200 # RPATH first 
DT_HP_BIND_DEPTH_FIRST =        0x00400 # Bind depth-first 
DT_HP_GST =            0x00800 # Dld global sym table 
DT_HP_SHLIB_FIXED =        0x01000 # shared vtable support 
DT_HP_MERGE_SHLIB_SEG =        0x02000 # merge shlib data segs 
DT_HP_NODELETE =            0x04000 # never unload 
DT_HP_GROUP =            0x08000 # bind only within group 
DT_HP_PROTECT_LINKAGE_TABLE =    0x10000 # protected linkage table 
PT_HP_TLS =        (PT_LOOS + 0x0)
PT_HP_CORE_NONE =        (PT_LOOS + 0x1)
PT_HP_CORE_VERSION =    (PT_LOOS + 0x2)
PT_HP_CORE_KERNEL =    (PT_LOOS + 0x3)
PT_HP_CORE_COMM =        (PT_LOOS + 0x4)
PT_HP_CORE_PROC =        (PT_LOOS + 0x5)
PT_HP_CORE_LOADABLE =    (PT_LOOS + 0x6)
PT_HP_CORE_STACK =    (PT_LOOS + 0x7)
PT_HP_CORE_SHM =        (PT_LOOS + 0x8)
PT_HP_CORE_MMF =        (PT_LOOS + 0x9)
PT_HP_PARALLEL =        (PT_LOOS + 0x10)
PT_HP_FASTBIND =        (PT_LOOS + 0x11)
PT_HP_OPT_ANNOT =        (PT_LOOS + 0x12)
PT_HP_HSL_ANNOT =        (PT_LOOS + 0x13)
PT_HP_STACK =        (PT_LOOS + 0x14)
PT_HP_CORE_UTSNAME =    (PT_LOOS + 0x15)
STB_HP_ALIAS =        (STB_LOOS + 0x0)
STT_HP_OPAQUE =        (STT_LOOS + 0x1)
STT_HP_STUB =        (STT_LOOS + 0x2)
NT_HP_COMPILER =        1
NT_HP_COPYRIGHT =        2
NT_HP_VERSION =        3
NT_HP_SRCFILE_INFO =    4
NT_HP_LINKER =        5
NT_HP_INSTRUMENTED =    6
NT_HP_UX_OPTIONS =    7

#include/elf/i370.h
SHT_ORDERED =        SHT_HIPROC    # Link editor is to sort the \
#define    EF_I370_RELOCATABLE    0x00010000    # i370 -mrelocatable flag 
#define    EF_I370_RELOCATABLE_LIB    0x00008000    # i370 -mrelocatable-lib flag 

#include/elf/i386.h

#include/elf/i860.h

#include/elf/i960.h

#include/elf/ia64.h
EF_IA_64_MASKOS =       0x0000000f    # OS-specific flags.  
EF_IA_64_ARCH =       0xff000000    # Arch. version mask.  
EF_IA_64_ARCHVER_1 = (1 << 24)    # Arch. version level 1 compat.  
EF_IA_64_TRAPNIL = (1 << 0)    # Trap NIL pointer dereferences.  
EF_IA_64_EXT =     (1 << 2)    # Program uses arch. extensions.  
EF_IA_64_BE =     (1 << 3)    # PSR BE bit set (big-endian).  
EFA_IA_64_EAS2_3 = 0x23000000    # IA64 EAS 2.3.  
EF_IA_64_ABI64 =            (1 << 4) # 64-bit ABI.  
EF_IA_64_REDUCEDFP =        (1 << 5) # Only FP6-FP11 used.  
EF_IA_64_CONS_GP =        (1 << 6) # gp as program wide constant.  
EF_IA_64_NOFUNCDESC_CONS_GP = (1 << 7) # And no function descriptors.  
EF_IA_64_ABSOLUTE =        (1 << 8) # Load at absolute addresses.  
EF_IA_64_VMS_COMCOD =        0x03   # Completion code.  
EF_IA_64_VMS_COMCOD_SUCCESS = 0
EF_IA_64_VMS_COMCOD_WARNING = 1
EF_IA_64_VMS_COMCOD_ERROR =   2
EF_IA_64_VMS_COMCOD_ABORT =   3
EF_IA_64_VMS_LINKAGES =        0x04   # Contains VMS linkages info.  
ELF_STRING_ia64_archext =        ".IA_64.archext"
ELF_STRING_ia64_pltoff =        ".IA_64.pltoff"
ELF_STRING_ia64_unwind =        ".IA_64.unwind"
ELF_STRING_ia64_unwind_info =    ".IA_64.unwind_info"
ELF_STRING_ia64_unwind_once =    ".gnu.linkonce.ia64unw."
ELF_STRING_ia64_unwind_info_once = ".gnu.linkonce.ia64unwi."
ELF_STRING_ia64_unwind_hdr =    ".IA_64.unwind_hdr"
SHF_IA_64_SHORT =          0x10000000    # Section near gp.  
SHF_IA_64_NORECOV =      0x20000000    # Spec insns w/o recovery.  
SHF_IA_64_HP_TLS =      0x01000000    # HP specific TLS flag.  
SHF_IA_64_VMS_GLOBAL =      0x0100000000 # Global for clustering.  
SHF_IA_64_VMS_OVERLAID =    0x0200000000 # To be overlaid.  
SHF_IA_64_VMS_SHARED =      0x0400000000 # Shared btw processes.  
SHF_IA_64_VMS_VECTOR =      0x0800000000 # Priv change mode vect.  
SHF_IA_64_VMS_ALLOC_64BIT = 0x1000000000 # Allocate beyond 2GB.  
SHF_IA_64_VMS_PROTECTED =   0x2000000000 # Export from sharable.  
SHT_IA_64_EXT =        (SHT_LOPROC + 0)    # Extension bits.  
SHT_IA_64_UNWIND =    (SHT_LOPROC + 1)    # Unwind bits.  
SHT_IA_64_LOPSREG =    (SHT_LOPROC + 0x8000000)
SHT_IA_64_HIPSREG =    (SHT_LOPROC + 0x8ffffff)
SHT_IA_64_PRIORITY_INIT = (SHT_LOPROC + 0x9000000)
SHT_IA_64_HP_OPT_ANOT =    0x60000004
SHT_IA_64_VMS_TRACE =             0x60000000
SHT_IA_64_VMS_TIE_SIGNATURES =    0x60000001
SHT_IA_64_VMS_DEBUG =             0x60000002
SHT_IA_64_VMS_DEBUG_STR =         0x60000003
SHT_IA_64_VMS_LINKAGES =          0x60000004
SHT_IA_64_VMS_SYMBOL_VECTOR =     0x60000005
SHT_IA_64_VMS_FIXUP =             0x60000006
SHT_IA_64_VMS_DISPLAY_NAME_INFO = 0x60000007
PF_IA_64_NORECOV =    0x80000000
PT_IA_64_ARCHEXT =    (PT_LOPROC + 0)    # Arch extension bits,  
PT_IA_64_UNWIND =     (PT_LOPROC + 1)    # IA64 unwind bits.  
PT_IA_64_HP_OPT_ANOT =    (PT_LOOS + 0x12)
PT_IA_64_HP_HSL_ANOT =    (PT_LOOS + 0x13)
PT_IA_64_HP_STACK =    (PT_LOOS + 0x14)
DT_IA_64_PLT_RESERVE =    (DT_LOPROC + 0)
DT_IA_64_VMS_SUBTYPE =         (DT_LOOS + 0)
DT_IA_64_VMS_IMGIOCNT =        (DT_LOOS + 2)
DT_IA_64_VMS_LNKFLAGS =        (DT_LOOS + 8)
DT_IA_64_VMS_VIR_MEM_BLK_SIZ = (DT_LOOS + 10)
DT_IA_64_VMS_IDENT =           (DT_LOOS + 12)
DT_IA_64_VMS_NEEDED_IDENT =    (DT_LOOS + 16)
DT_IA_64_VMS_IMG_RELA_CNT =    (DT_LOOS + 18)
DT_IA_64_VMS_SEG_RELA_CNT =    (DT_LOOS + 20)
DT_IA_64_VMS_FIXUP_RELA_CNT =  (DT_LOOS + 22)
DT_IA_64_VMS_FIXUP_NEEDED =    (DT_LOOS + 24)
DT_IA_64_VMS_SYMVEC_CNT =      (DT_LOOS + 26)
DT_IA_64_VMS_XLATED =          (DT_LOOS + 30)
DT_IA_64_VMS_STACKSIZE =       (DT_LOOS + 32)
DT_IA_64_VMS_UNWINDSZ =        (DT_LOOS + 34)
DT_IA_64_VMS_UNWIND_CODSEG =   (DT_LOOS + 36)
DT_IA_64_VMS_UNWIND_INFOSEG =  (DT_LOOS + 38)
DT_IA_64_VMS_LINKTIME =        (DT_LOOS + 40)
DT_IA_64_VMS_SEG_NO =          (DT_LOOS + 42)
DT_IA_64_VMS_SYMVEC_OFFSET =   (DT_LOOS + 44)
DT_IA_64_VMS_SYMVEC_SEG =      (DT_LOOS + 46)
DT_IA_64_VMS_UNWIND_OFFSET =   (DT_LOOS + 48)
DT_IA_64_VMS_UNWIND_SEG =      (DT_LOOS + 50)
DT_IA_64_VMS_STRTAB_OFFSET =   (DT_LOOS + 52)
DT_IA_64_VMS_SYSVER_OFFSET =   (DT_LOOS + 54)
DT_IA_64_VMS_IMG_RELA_OFF =    (DT_LOOS + 56)
DT_IA_64_VMS_SEG_RELA_OFF =    (DT_LOOS + 58)
DT_IA_64_VMS_FIXUP_RELA_OFF =  (DT_LOOS + 60)
DT_IA_64_VMS_PLTGOT_OFFSET =   (DT_LOOS + 62)
DT_IA_64_VMS_PLTGOT_SEG =      (DT_LOOS + 64)
DT_IA_64_VMS_FPMODE =          (DT_LOOS + 66)
VMS_LF_CALL_DEBUG =    0x0001    # Activate and call the debugger.  
VMS_LF_NOP0BUFS =        0x0002    # RMS use of P0 for i/o disabled.  
VMS_LF_P0IMAGE =        0x0004    # Image in P0 space only.  
VMS_LF_MKTHREADS =    0x0008    # Multiple kernel threads enabled.  
VMS_LF_UPCALLS =        0x0010    # Upcalls enabled.  
VMS_LF_IMGSTA =        0x0020    # Use SYS$IMGSTA.  
VMS_LF_INITIALIZE =    0x0040    # Image uses tfradr2.  
VMS_LF_MAIN =        0x0080    # Image uses tfradr3.  
VMS_LF_EXE_INIT =        0x0200    # Image uses tfradr4.  
VMS_LF_TBK_IN_IMG =    0x0400    # Traceback records in image.  
VMS_LF_DBG_IN_IMG =    0x0800    # Debug records in image.  
VMS_LF_TBK_IN_DSF =    0x1000    # Traceback records in DSF.  
VMS_LF_DBG_IN_DSF =    0x2000    # Debug records in DSF.  
VMS_LF_SIGNATURES =    0x4000    # Signatures present.  
VMS_LF_REL_SEG_OFF =    0x8000    # Maintain relative pos of seg.  
SHN_IA_64_ANSI_COMMON = SHN_LORESERVE
SHN_IA_64_VMS_SYMVEC = SHN_LOOS
VMS_STO_VISIBILITY = 3      # Alias of the standard field.  
VMS_STO_FUNC_TYPE =  0x30      # Function type.  
VMS_STO_LINKAGE =    0xc0
NT_VMS_MHD =         1 # Object module name, version, and date/time.  
NT_VMS_LNM =         2 # Language processor name.  
NT_VMS_SRC =         3 # Source files.  
NT_VMS_TITLE =       4 # Title text.  
NT_VMS_EIDC =        5 # Entity ident consistency check.  
NT_VMS_FPMODE =      6 # Whole program floating-point mode.  
NT_VMS_LINKTIME =  101 # Date/time image was linked.  
NT_VMS_IMGNAM =    102 # Image name string.  
NT_VMS_IMGID =     103 # Image ident string.  
NT_VMS_LINKID =    104 # Linker ident string.  
NT_VMS_IMGBID =    105 # Image build ident string.  
NT_VMS_GSTNAM =    106 # Global Symbol Table Name.  
NT_VMS_ORIG_DYN =  107 # Original setting of dynamic data.  
NT_VMS_PATCHTIME = 108 # Date/time of last patch.  

#include/elf/internal.h
SHN_UNDEF =    0        # Undefined section reference 
SHN_LORESERVE =    -0x100    # Begin range of reserved indices 
SHN_LOPROC =    -0x100    # Begin range of appl-specific 
SHN_HIPROC =    -0xE1    # End range of appl-specific 
SHN_LOOS =    -0xE0    # OS specific semantics, lo 
SHN_HIOS =    -0xC1    # OS specific semantics, hi 
SHN_ABS =        -0xF        # Associated symbol is absolute 
SHN_COMMON =    -0xE        # Associated symbol is in common 
SHN_XINDEX =    -0x1        # Section index is held elsewhere 
SHN_HIRESERVE =    -0x1        # End range of reserved indices 
SHN_BAD =        -0x101    # Used internally by bfd 
EI_NIDENT =    16        # Size of e_ident[] 

#include/elf/ip2k.h
IP2K_DATA_MASK =   0xff000000
IP2K_DATA_VALUE =  0x01000000
IP2K_INSN_MASK =   0xff000000
IP2K_INSN_VALUE =  0x02000000
IP2K_STACK_VALUE = 0x0f000000
IP2K_STACK_SIZE =  0x20

#include/elf/iq2000.h
EF_IQ2000_CPU_IQ2000 =    0x00000001      # default 
EF_IQ2000_CPU_IQ10 =      0x00000002      # IQ10 
EF_IQ2000_CPU_MASK =    0x00000003    # specific cpu bits 
EF_IQ2000_ALL_FLAGS =    (EF_IQ2000_CPU_MASK)
IQ2000_DATA_MASK =   0x80000000
IQ2000_DATA_VALUE =  0x00000000
IQ2000_INSN_MASK =   0x80000000
IQ2000_INSN_VALUE =  0x80000000

#include/elf/lm32.h
EF_LM32_MACH =                 0x00000001
E_LM32_MACH =                  0x1

#include/elf/m32c.h
EF_M32C_CPU_M16C =    0x00000075      # default 
EF_M32C_CPU_M32C =        0x00000078      # m32c 
EF_M32C_CPU_MASK =    0x0000007F    # specific cpu bits 
EF_M32C_ALL_FLAGS =    (EF_M32C_CPU_MASK)
M32C_DATA_MASK =   0xffc00000
M32C_DATA_VALUE =  0x00000000
M32C_INSN_MASK =   0xffc00000
M32C_INSN_VALUE =  0x00400000

#include/elf/m32r.h
SHN_M32R_SCOMMON =    SHN_LORESERVE
SHF_M32R_CAN_RELAX =    0x10000000
EF_M32R_ARCH =        0x30000000
E_M32R_ARCH =        0x00000000
E_M32RX_ARCH =            0x10000000
E_M32R2_ARCH =            0x20000000
EF_M32R_INST =            0x0FFF0000
E_M32R_HAS_PARALLEL =     0x00010000
E_M32R_HAS_HIDDEN_INST =  0x00020000
E_M32R_HAS_BIT_INST =     0x00040000
E_M32R_HAS_FLOAT_INST =   0x00080000
EF_M32R_IGNORE =          0x0000000F

#include/elf/m68hc11.h
EF_M68HC11_ABI =  0x00000000F
E_M68HC11_I32 =   0x000000001
E_M68HC11_F64 =   0x000000002
E_M68HC12_BANKS = 0x000000004
E_M68HC11_XGATE_RAMOFFSET =     0x000000100
E_M68HC11_NO_BANK_WARNING =     0x000000200
EF_M68HC11_MACH_MASK = 0xF0
EF_M68HC11_GENERIC =   0x00 # Generic 68HC12/backward compatibility.  
EF_M68HC12_MACH =      0x10 # 68HC12 microcontroller.  
EF_M68HCS12_MACH =     0x20 # 68HCS12 microcontroller.  
STO_M68HC12_FAR =          0x80
STO_M68HC12_INTERRUPT =    0x40

#include/elf/m68k.h
EF_M68K_CPU32 =    0x00810000
EF_M68K_M68000 =   0x01000000
EF_M68K_CFV4E =    0x00008000
EF_M68K_FIDO =     0x02000000
EF_M68K_ARCH_MASK =                        \
EF_M68K_CF_ISA_MASK =    0x0F  # Which ISA 
EF_M68K_CF_ISA_A_NODIV =    0x01  # ISA A except for div 
EF_M68K_CF_ISA_A =    0x02
EF_M68K_CF_ISA_A_PLUS =    0x03
EF_M68K_CF_ISA_B_NOUSP =    0x04  # ISA_B except for USP 
EF_M68K_CF_ISA_B =    0x05
EF_M68K_CF_ISA_C =    0x06
EF_M68K_CF_ISA_C_NODIV =    0x07  # ISA C except for div 
EF_M68K_CF_MAC_MASK =    0x30 
EF_M68K_CF_MAC =        0x10  # MAC 
EF_M68K_CF_EMAC =        0x20  # EMAC 
EF_M68K_CF_EMAC_B =    0x30  # EMAC_B 
EF_M68K_CF_FLOAT =    0x40  # Has float insns 
EF_M68K_CF_MASK =        0xFF

#include/elf/mcore.h
SHF_MCORE_NOREAD =    0x80000000

#include/elf/mep.h
SHF_MEP_VLIW =        0x10000000    # contains vliw code 
#define    EF_MEP_CPU_MASK        0xff000000    # specific cpu bits 
EF_MEP_CPU_MEP =          0x00000000    # generic MEP 
EF_MEP_CPU_C2 =       0x01000000    # MEP c2 
EF_MEP_CPU_C3 =       0x02000000    # MEP c3 
EF_MEP_CPU_C4 =       0x04000000    # MEP c4 
EF_MEP_CPU_C5 =       0x08000000    # MEP c5 
EF_MEP_CPU_H1 =       0x10000000    # MEP h1 
EF_MEP_COP_MASK =        0x00ff0000
EF_MEP_COP_NONE =        0x00000000
EF_MEP_COP_AVC =        0x00010000
EF_MEP_COP_AVC2 =        0x00020000
EF_MEP_COP_FMAX =        0x00030000
EF_MEP_COP_IVC2 =        0x00060000
EF_MEP_LIBRARY =        0x00000100    # Built as a library 
EF_MEP_INDEX_MASK =       0x000000ff      # Configuration index 
EF_MEP_ALL_FLAGS =    0xffff01ff

#include/elf/microblaze.h
RO_SDA_ANCHOR_NAME = "_SDA2_BASE_"
RW_SDA_ANCHOR_NAME = "_SDA_BASE_"
SHF_MICROBLAZE_NOREAD =    0x80000000

#include/elf/mips.h
EF_MIPS_NOREORDER =    0x00000001
EF_MIPS_PIC =        0x00000002
EF_MIPS_CPIC =        0x00000004
EF_MIPS_XGOT =        0x00000008
EF_MIPS_UCODE =        0x00000010
EF_MIPS_ABI2 =        0x00000020
EF_MIPS_OPTIONS_FIRST =    0x00000080
EF_MIPS_ARCH_ASE =    0x0f000000
EF_MIPS_ARCH_ASE_MDMX =    0x08000000
EF_MIPS_ARCH_ASE_M16 =    0x04000000
EF_MIPS_ARCH_ASE_MICROMIPS =    0x02000000
EF_MIPS_32BITMODE =       0x00000100
EF_MIPS_ARCH =        0xf0000000
E_MIPS_ARCH_1 =        0x00000000
E_MIPS_ARCH_2 =        0x10000000
E_MIPS_ARCH_3 =        0x20000000
E_MIPS_ARCH_4 =        0x30000000
E_MIPS_ARCH_5 =           0x40000000
E_MIPS_ARCH_32 =          0x50000000
E_MIPS_ARCH_64 =          0x60000000
E_MIPS_ARCH_32R2 =        0x70000000
E_MIPS_ARCH_64R2 =        0x80000000
EF_MIPS_ABI =        0x0000F000
E_MIPS_ABI_O32 =          0x00001000
E_MIPS_ABI_O64 =          0x00002000
E_MIPS_ABI_EABI32 =       0x00003000
E_MIPS_ABI_EABI64 =       0x00004000
EF_MIPS_MACH =        0x00FF0000
E_MIPS_MACH_3900 =    0x00810000
E_MIPS_MACH_4010 =    0x00820000
E_MIPS_MACH_4100 =    0x00830000
E_MIPS_MACH_4650 =    0x00850000
E_MIPS_MACH_4120 =    0x00870000
E_MIPS_MACH_4111 =    0x00880000
E_MIPS_MACH_SB1 =         0x008a0000
E_MIPS_MACH_OCTEON =    0x008b0000
E_MIPS_MACH_XLR =         0x008c0000
E_MIPS_MACH_OCTEON2 =    0x008d0000
E_MIPS_MACH_5400 =    0x00910000
E_MIPS_MACH_5500 =    0x00980000
E_MIPS_MACH_9000 =    0x00990000
E_MIPS_MACH_LS2E =        0x00A00000
E_MIPS_MACH_LS2F =        0x00A10000
E_MIPS_MACH_LS3A =        0x00A20000
SHN_MIPS_ACOMMON =    SHN_LORESERVE
SHN_MIPS_TEXT =        (SHN_LORESERVE + 1)
SHN_MIPS_DATA =        (SHN_LORESERVE + 2)
SHN_MIPS_SCOMMON =    (SHN_LORESERVE + 3)
SHN_MIPS_SUNDEFINED =    (SHN_LORESERVE + 4)
SHT_MIPS_LIBLIST =    0x70000000
SHT_MIPS_MSYM =        0x70000001
SHT_MIPS_CONFLICT =    0x70000002
SHT_MIPS_GPTAB =        0x70000003
SHT_MIPS_UCODE =        0x70000004
SHT_MIPS_DEBUG =        0x70000005
SHT_MIPS_REGINFO =    0x70000006
SHT_MIPS_PACKAGE =    0x70000007
SHT_MIPS_PACKSYM =    0x70000008
SHT_MIPS_RELD =        0x70000009
SHT_MIPS_IFACE =        0x7000000b
SHT_MIPS_CONTENT =    0x7000000c
SHT_MIPS_OPTIONS =    0x7000000d
SHT_MIPS_SHDR =        0x70000010
SHT_MIPS_FDESC =        0x70000011
SHT_MIPS_EXTSYM =        0x70000012
SHT_MIPS_DENSE =        0x70000013
SHT_MIPS_PDESC =        0x70000014
SHT_MIPS_LOCSYM =        0x70000015
SHT_MIPS_AUXSYM =        0x70000016
SHT_MIPS_OPTSYM =        0x70000017
SHT_MIPS_LOCSTR =        0x70000018
SHT_MIPS_LINE =        0x70000019
SHT_MIPS_RFDESC =        0x7000001a
SHT_MIPS_DELTASYM =    0x7000001b
SHT_MIPS_DELTAINST =    0x7000001c
SHT_MIPS_DELTACLASS =    0x7000001d
SHT_MIPS_DWARF =        0x7000001e
SHT_MIPS_DELTADECL =    0x7000001f
SHT_MIPS_SYMBOL_LIB =    0x70000020
SHT_MIPS_EVENTS =        0x70000021
SHT_MIPS_TRANSLATE =    0x70000022
SHT_MIPS_PIXIE =        0x70000023
SHT_MIPS_XLATE =        0x70000024
SHT_MIPS_XLATE_DEBUG =    0x70000025
SHT_MIPS_WHIRL =        0x70000026
SHT_MIPS_EH_REGION =    0x70000027
SHT_MIPS_XLATE_OLD =    0x70000028
SHT_MIPS_PDR_EXCEPTION =    0x70000029
LL_EXACT_MATCH =        0x00000001
LL_IGNORE_INT_VER =    0x00000002
LL_REQUIRE_MINOR =    0x00000004
LL_EXPORTS =        0x00000008
LL_DELAY_LOAD =        0x00000010
LL_DELTA =        0x00000020
SHF_MIPS_GPREL =        0x10000000
SHF_MIPS_MERGE =        0x20000000
SHF_MIPS_ADDR =        0x40000000
SHF_MIPS_STRING =        0x80000000
SHF_MIPS_NOSTRIP =    0x08000000
SHF_MIPS_LOCAL =        0x04000000
SHF_MIPS_NAMES =        0x02000000
SHF_MIPS_NODUPES =    0x01000000
PT_MIPS_REGINFO =        0x70000000
PT_MIPS_RTPROC =        0x70000001
PT_MIPS_OPTIONS =        0x70000002
DT_MIPS_RLD_VERSION =    0x70000001
DT_MIPS_TIME_STAMP =    0x70000002
DT_MIPS_ICHECKSUM =    0x70000003
DT_MIPS_IVERSION =    0x70000004
DT_MIPS_FLAGS =        0x70000005
DT_MIPS_BASE_ADDRESS =    0x70000006
DT_MIPS_MSYM =        0x70000007
DT_MIPS_CONFLICT =    0x70000008
DT_MIPS_LIBLIST =        0x70000009
DT_MIPS_LOCAL_GOTNO =    0x7000000a
DT_MIPS_CONFLICTNO =    0x7000000b
DT_MIPS_LIBLISTNO =    0x70000010
DT_MIPS_SYMTABNO =    0x70000011
DT_MIPS_UNREFEXTNO =    0x70000012
DT_MIPS_GOTSYM =        0x70000013
DT_MIPS_HIPAGENO =    0x70000014
DT_MIPS_RLD_MAP =        0x70000016
DT_MIPS_DELTA_CLASS =    0x70000017
DT_MIPS_DELTA_CLASS_NO =    0x70000018
DT_MIPS_DELTA_INSTANCE =    0x70000019
DT_MIPS_DELTA_INSTANCE_NO =    0x7000001a
DT_MIPS_DELTA_RELOC =    0x7000001b
DT_MIPS_DELTA_RELOC_NO =    0x7000001c
DT_MIPS_DELTA_SYM =    0x7000001d
DT_MIPS_DELTA_SYM_NO =    0x7000001e
DT_MIPS_DELTA_CLASSSYM =    0x70000020
DT_MIPS_DELTA_CLASSSYM_NO =    0x70000021
DT_MIPS_CXX_FLAGS =    0x70000022
DT_MIPS_PIXIE_INIT =    0x70000023
DT_MIPS_SYMBOL_LIB =    0x70000024
DT_MIPS_LOCALPAGE_GOTIDX =    0x70000025
DT_MIPS_LOCAL_GOTIDX =    0x70000026
DT_MIPS_HIDDEN_GOTIDX =    0x70000027
DT_MIPS_PROTECTED_GOTIDX =    0x70000028
DT_MIPS_OPTIONS =        0x70000029
DT_MIPS_INTERFACE =    0x7000002a
DT_MIPS_DYNSTR_ALIGN =    0x7000002b
DT_MIPS_INTERFACE_SIZE =    0x7000002c
DT_MIPS_RLD_TEXT_RESOLVE_ADDR =    0x7000002d
DT_MIPS_PERF_SUFFIX =    0x7000002e
DT_MIPS_COMPACT_SIZE =    0x7000002f
DT_MIPS_GP_VALUE =    0x70000030
DT_MIPS_AUX_DYNAMIC =    0x70000031
DT_MIPS_PLTGOT =         0x70000032
DT_MIPS_RWPLT =          0x70000034
RHF_NONE =        0x00000000
RHF_QUICKSTART =        0x00000001
RHF_NOTPOT =        0x00000002
RHS_NO_LIBRARY_REPLACEMENT = 0x00000004
RHF_NO_MOVE =        0x00000008
RHF_SGI_ONLY =        0x00000010
RHF_GUARANTEE_INIT =       0x00000020
RHF_DELTA_C_PLUS_PLUS =       0x00000040
RHF_GUARANTEE_START_INIT =   0x00000080
RHF_PIXIE =           0x00000100
RHF_DEFAULT_DELAY_LOAD =       0x00000200
RHF_REQUICKSTART =       0x00000400
RHF_REQUICKSTARTED =       0x00000800
RHF_CORD =           0x00001000
RHF_NO_UNRES_UNDEF =       0x00002000
RHF_RLD_ORDER_SAFE =       0x00004000
STO_DEFAULT =        STV_DEFAULT
STO_INTERNAL =        STV_INTERNAL
STO_HIDDEN =        STV_HIDDEN
STO_PROTECTED =        STV_PROTECTED
STO_MIPS_ISA =        (3 << 6)
STO_MIPS_PLT =        0x8
STO_MIPS_PIC =        0x20
STO_MIPS16 =        0xf0
STO_MICROMIPS =        (2 << 6)
STO_OPTIONAL =        (1 << 2)
RSS_UNDEF =    0
RSS_GP =        1
RSS_GP0 =        2
RSS_LOC =        3
ODK_NULL =    0
ODK_REGINFO =    1
ODK_EXCEPTIONS =    2
ODK_PAD =        3
ODK_HWPATCH =    4
ODK_FILL =    5
ODK_TAGS =    6
ODK_HWAND =    7
ODK_HWOR =    8
ODK_GP_GROUP =    9
ODK_IDENT =    10
OEX_FPU_MIN =    0x1f    # FPEs which must be enabled.  
OEX_FPU_MAX =    0x1f00    # FPEs which may be enabled.  
OEX_PAGE0 =    0x10000    # Page zero must be mapped.  
OEX_SMM =        0x20000    # Force sequential memory mode.  
OEX_FPDBUG =    0x40000    # Force precise floating-point
OEX_DISMISS =    0x80000    # Dismiss invalid address faults.  
OEX_FPU_INVAL =    0x10    # Invalid operation exception.  
OEX_FPU_DIV0 =    0x08    # Division by zero exception.  
OEX_FPU_OFLO =    0x04    # Overflow exception.  
OEX_FPU_UFLO =    0x02    # Underflow exception.  
OEX_FPU_INEX =    0x01    # Inexact exception.  
OPAD_PREFIX =    0x01
OPAD_POSTFIX =    0x02
OPAD_SYMBOL =    0x04
OHW_R4KEOP =    0x00000001    # R4000 end-of-page patch.  
OHW_R8KPFETCH =    0x00000002    # May need R8000 prefetch patch.  
OHW_R5KEOP =    0x00000004    # R5000 end-of-page patch.  
OHW_R5KCVTL =    0x00000008    # R5000 cvt.[ds].l bug
OHW_R10KLDL =    0x00000010    # Needs R10K misaligned
OGP_GROUP =    0x0000ffff    # GP group number.  
OGP_SELF =    0xffff0000    # Self-contained GP groups.  
OHWA0_R4KEOP_CHECKED =    0x00000001
OHWA0_R4KEOP_CLEAN =    0x00000002

#include/elf/mmix.h
SHF_MMIX_CANRELAX =    0x80000000
SHN_REGISTER =    SHN_LOPROC
MMIX_REG_CONTENTS_SECTION_NAME = ".MMIX.reg_contents"
MMIX_LD_ALLOCATED_REG_CONTENTS_SECTION_NAME = \
MMIX_REG_SECTION_NAME = "*REG*"
MMIX_OTHER_SPEC_SECTION_PREFIX = ".MMIX.spec_data."
MMIX_LOC_SECTION_START_SYMBOL_PREFIX = "__.MMIX.start."
MMIX_START_SYMBOL_NAME = "Main"
MMO_TEXT_SECTION_NAME = ".text"
MMO_DATA_SECTION_NAME = ".data"
MMO_SEC_ALLOC =      0x001
MMO_SEC_LOAD =       0x002
MMO_SEC_RELOC =      0x004
MMO_SEC_READONLY =   0x010
MMO_SEC_CODE =       0x020
MMO_SEC_DATA =       0x040
MMO_SEC_NEVER_LOAD = 0x400
MMO_SEC_IS_COMMON = 0x8000
MMO_SEC_DEBUGGING = 0x10000

#include/elf/mn10200.h

#include/elf/mn10300.h
EF_MN10300_MACH =        0x00FF0000
E_MN10300_MACH_MN10300 =    0x00810000
E_MN10300_MACH_AM33 =    0x00820000
E_MN10300_MACH_AM33_2 =   0x00830000

#include/elf/moxie.h

#include/elf/msp430.h
EF_MSP430_MACH =         0xff
E_MSP430_MACH_MSP430x11 =  11
E_MSP430_MACH_MSP430x11x1 =  110
E_MSP430_MACH_MSP430x12 =  12
E_MSP430_MACH_MSP430x13 =  13
E_MSP430_MACH_MSP430x14 =  14
E_MSP430_MACH_MSP430x15 =  15
E_MSP430_MACH_MSP430x16 =  16
E_MSP430_MACH_MSP430x31 =  31
E_MSP430_MACH_MSP430x32 =  32
E_MSP430_MACH_MSP430x33 =  33
E_MSP430_MACH_MSP430x41 =  41
E_MSP430_MACH_MSP430x42 =  42
E_MSP430_MACH_MSP430x43 =  43
E_MSP430_MACH_MSP430x44 =  44

#include/elf/mt.h
EF_MT_CPU_MRISC =        0x00000001    # default 
EF_MT_CPU_MRISC2 =    0x00000002    # MRISC2 
EF_MT_CPU_MS2 =        0x00000003      # MS2 
EF_MT_CPU_MASK =        0x00000003    # specific cpu bits 
EF_MT_ALL_FLAGS =        (EF_MT_CPU_MASK)
MT_STACK_VALUE = 0x0f000000
MT_STACK_SIZE =  0x20

#include/elf/openrisc.h

#include/elf/or32.h
EF_OR32_MACH =             0x0000000f
E_OR32_MACH_BASE =         0x00000000
E_OR32_MACH_UNUSED1 =      0x00000001
E_OR32_MACH_UNUSED2 =      0x00000002
E_OR32_MACH_UNUSED4 =      0x00000003
SHT_ORDERED =        SHT_HIPROC    # Link editor is to sort the \

#include/elf/pj.h
EF_PICOJAVA_ARCH =     0x0000000f
EF_PICOJAVA_NEWCALLS = 0x00000010
EF_PICOJAVA_GNUCALLS = 0x00000020  # The (currently) non standard GNU calling convention 

#include/elf/ppc.h
DT_PPC_GOT =        (DT_LOPROC)
DT_PPC_TLSOPT =        (DT_LOPROC + 1)
#define    EF_PPC_EMB        0x80000000    # PowerPC embedded flag.  
#define    EF_PPC_RELOCATABLE    0x00010000    # PowerPC -mrelocatable flag.  
#define    EF_PPC_RELOCATABLE_LIB    0x00008000    # PowerPC -mrelocatable-lib flag.  
PF_PPC_VLE =        0x10000000    # PowerPC VLE.  
SHF_PPC_VLE =        0x10000000    # PowerPC VLE text section.  
SHT_ORDERED =        SHT_HIPROC    # Link editor is to sort the \

#include/elf/ppc64.h
DT_PPC64_GLINK =        DT_LOPROC
DT_PPC64_OPD =        (DT_LOPROC + 1)
DT_PPC64_OPDSZ =        (DT_LOPROC + 2)
DT_PPC64_TLSOPT =        (DT_LOPROC + 3)

#include/elf/rl78.h
EF_RL78_CPU_RL78 =    0x00000079      # FIXME: correct value?  
EF_RL78_CPU_MASK =    0x0000007F    # specific cpu bits.  
EF_RL78_ALL_FLAGS =    (EF_RL78_CPU_MASK)
E_FLAG_RL78_64BIT_DOUBLES =        (1 << 0)
E_FLAG_RL78_DSP =            (1 << 1) # Defined in the RL78 CPU Object file specification, but not explained.  
#define    RL78_RELAXA_BRA        0x00000010    # Any type of branch (must be decoded).  
#define    RL78_RELAXA_ADDR16    0x00000020    # addr16->sfr/saddr opportunity  
RL78_RELAXA_RNUM =    0x0000000f    # Number of associated relocations.  
#define    RL78_RELAXA_ALIGN    0x10000000    # Start alignment; the remaining bits are the alignment value.  
#define    RL78_RELAXA_ELIGN    0x20000000    # End alignment; the remaining bits are the alignment value.  
#define    RL78_RELAXA_ANUM    0x00ffffff    # Alignment amount, in bytes (i.e. .balign).  

#include/elf/rx.h
EF_RX_CPU_RX =    0x00000079      # FIXME: correct value?  
EF_RX_CPU_MASK =    0x0000007F    # specific cpu bits.  
EF_RX_ALL_FLAGS =    (EF_RX_CPU_MASK)
E_FLAG_RX_64BIT_DOUBLES =        (1 << 0)
E_FLAG_RX_DSP =            (1 << 1) # Defined in the RX CPU Object file specification, but not explained. 
E_FLAG_RX_PID =            (1 << 2) # Unofficial - DJ 
#define    RX_RELAXA_IMM6    0x00000010    # Imm8/16/24/32 at bit offset 6.  
#define    RX_RELAXA_IMM12    0x00000020    # Imm8/16/24/32 at bit offset 12.  
#define    RX_RELAXA_DSP4    0x00000040    # Dsp0/8/16 at bit offset 4.  
#define    RX_RELAXA_DSP6    0x00000080    # Dsp0/8/16 at bit offset 6.  
#define    RX_RELAXA_DSP14    0x00000100    # Dsp0/8/16 at bit offset 14.  
#define    RX_RELAXA_BRA    0x00000200    # Any type of branch (must be decoded).  
RX_RELAXA_RNUM =    0x0000000f    # Number of associated relocations.  
#define    RX_RELAXA_ALIGN    0x10000000    # Start alignment; the remaining bits are the alignment value.  
#define    RX_RELAXA_ELIGN    0x20000000    # End alignment; the remaining bits are the alignment value.  
#define    RX_RELAXA_ANUM    0x00ffffff    # Alignment amount, in bytes (i.e. .balign).  

#include/elf/s390.h
STACK_REG =        15        # Global Stack reg 
BACKL_REG =        14        # Global Backlink reg 
BASE_REG =        13        # Global Base reg 
GOT_REG =         12        # Holds addr of GOT 
EF_S390_HIGH_GPRS =        0x00000001

#include/elf/score.h
SCORE_SIMULATOR_ACTIVE =  1
OPC_PTMASK =              0xc0000000      # Parity-bit Mask.  
OPC16_PTMASK =        0x00008000
OPC_32 =                  0xc0000000      # Denotes 32b instruction, (default).  
OPC_16 =                  0x00000000      # Denotes 16b instruction.  
OPC_PE =                  0x8000          # Denotes parallel-execution instructions.  
GP_DISP_LABEL =           "_gp_disp"
EF_SCORE_MACH =           0xffff0000      
EF_OMIT_PIC_FIXDD =       0x0fff0000      
E_SCORE_MACH_SCORE3 =     0x00030000
E_SCORE_MACH_SCORE7 =     0x00070000
EF_SCORE_PIC =            0x80000000
EF_SCORE_FIXDEP =         0x40000000 
SHN_SCORE_TEXT =        (SHN_LORESERVE + 1)
SHN_SCORE_DATA =        (SHN_LORESERVE + 2)
SHN_SCORE_SCOMMON =    (SHN_LORESERVE + 3)
SHF_SCORE_GPREL =        0x10000000
SHF_SCORE_MERGE =        0x20000000
SHF_SCORE_ADDR =        0x40000000
SHF_SCORE_STRING =        0x80000000
SHF_SCORE_NOSTRIP =    0x08000000
SHF_SCORE_LOCAL =        0x04000000
SHF_SCORE_NAMES =        0x02000000
SHF_SCORE_NODUPES =    0x01000000
DT_SCORE_BASE_ADDRESS =    0x70000001
DT_SCORE_LOCAL_GOTNO =    0x70000002
DT_SCORE_SYMTABNO =    0x70000003
DT_SCORE_GOTSYM =        0x70000004
DT_SCORE_UNREFEXTNO =    0x70000005
DT_SCORE_HIPAGENO =    0x70000006

#include/elf/sh.h
EF_SH_MACH_MASK =    0x1f
EF_SH_UNKNOWN =       0 # For backwards compatibility.  
EF_SH1 =           1
EF_SH2 =           2
EF_SH3 =           3
EF_SH_DSP =       4
EF_SH3_DSP =       5
EF_SH4AL_DSP =       6
EF_SH3E =           8
EF_SH4 =           9
EF_SH2E =            11
EF_SH4A =           12
EF_SH2A =            13
EF_SH4_NOFPU =       16
EF_SH4A_NOFPU =       17
EF_SH4_NOMMU_NOFPU = 18
EF_SH2A_NOFPU =      19
EF_SH3_NOMMU =       20
EF_SH2A_SH4_NOFPU =  21
EF_SH2A_SH3_NOFPU =  22
EF_SH2A_SH4 =        23
EF_SH2A_SH3E =       24
EF_SH5 =          10    
EF_SH_PIC =        0x100    # Segments of an FDPIC binary may
EF_SH_FDPIC =        0x8000    # Uses the FDPIC ABI.  
STO_SH5_ISA32 = (1 << 2)
SHF_SH5_ISA32 =        0x40000000
SHF_SH5_ISA32_MIXED =    0x20000000
SHT_SH5_CR_SORTED = 0x80000001
STT_DATALABEL = STT_LOPROC

#include/elf/sparc.h
EF_SPARC_32PLUS_MASK =    0xffff00    # bits indicating V8+ type 
EF_SPARC_32PLUS =        0x000100    # generic V8+ features 
EF_SPARC_SUN_US1 =    0x000200    # Sun UltraSPARC1 extensions 
EF_SPARC_HAL_R1 =        0x000400    # HAL R1 extensions 
EF_SPARC_SUN_US3 =    0x000800    # Sun UltraSPARCIII extensions 
EF_SPARC_LEDATA =         0x800000    # little endian data 
EF_SPARC_EXT_MASK =    0xffff00    # reserved for vendor extensions 
EF_SPARCV9_MM =        0x3        # memory model mask 
EF_SPARCV9_TSO =        0x0        # total store ordering 
EF_SPARCV9_PSO =        0x1        # partial store ordering 
EF_SPARCV9_RMO =        0x2        # relaxed store ordering 
SHN_BEFORE =    SHN_LORESERVE        # Used with SHF_ORDERED and...  
SHN_AFTER =    (SHN_LORESERVE + 1)    # SHF_LINK_ORDER section flags. 
SHF_ORDERED =        0x40000000    # treat sh_link,sh_info specially 
STT_REGISTER =        13        # global reg reserved to app. 
DT_SPARC_REGISTER =    0x70000001
ELF_SPARC_HWCAP_MUL32 =    0x00000001 # umul/umulcc/smul/smulcc insns 
ELF_SPARC_HWCAP_DIV32 =    0x00000002 # udiv/udivcc/sdiv/sdivcc insns 
ELF_SPARC_HWCAP_FSMULD =    0x00000004 # 'fsmuld' insn 
ELF_SPARC_HWCAP_V8PLUS =    0x00000008 # v9 insns available to 32bit 
ELF_SPARC_HWCAP_POPC =    0x00000010 # 'popc' insn 
ELF_SPARC_HWCAP_VIS =    0x00000020 # VIS insns 
ELF_SPARC_HWCAP_VIS2 =    0x00000040 # VIS2 insns 
ELF_SPARC_HWCAP_FMAF =    0x00000100 # fused multiply-add 
ELF_SPARC_HWCAP_VIS3 =    0x00000400 # VIS3 insns 
ELF_SPARC_HWCAP_HPC =    0x00000800 # HPC insns 
ELF_SPARC_HWCAP_RANDOM =    0x00001000 # 'random' insn 
ELF_SPARC_HWCAP_TRANS =    0x00002000 # transaction insns 
ELF_SPARC_HWCAP_FJFMAU =    0x00004000 # unfused multiply-add 
ELF_SPARC_HWCAP_IMA =    0x00008000 # integer multiply-add 
ELF_SPARC_HWCAP_AES =    0x00020000 # AES crypto insns 
ELF_SPARC_HWCAP_DES =    0x00040000 # DES crypto insns 
ELF_SPARC_HWCAP_KASUMI =    0x00080000 # KASUMI crypto insns 
ELF_SPARC_HWCAP_MD5 =    0x00200000 # MD5 hashing insns 
ELF_SPARC_HWCAP_SHA1 =    0x00400000 # SHA1 hashing insns 
ELF_SPARC_HWCAP_SHA256 =    0x00800000 # SHA256 hashing insns 
ELF_SPARC_HWCAP_SHA512 =    0x01000000 # SHA512 hashing insns 
ELF_SPARC_HWCAP_MPMUL =    0x02000000 # Multiple Precision Multiply 
ELF_SPARC_HWCAP_MONT =    0x04000000 # Montgomery Mult/Sqrt 
ELF_SPARC_HWCAP_PAUSE =    0x08000000 # Pause insn 
ELF_SPARC_HWCAP_CBCOND =    0x10000000 # Compare and Branch insns 
ELF_SPARC_HWCAP_CRC32C =    0x20000000 # CRC32C insn 

#include/elf/spu.h
PF_OVERLAY =        (1 << 27)
PT_SPU_INFO =             0x70000000
SPU_PLUGIN_NAME =         "SPUNAME"
SPU_PTNOTE_SPUNAME =    ".note.spu_name"

#include/elf/tic6x-attrs.h

#include/elf/tic6x.h
EF_C6000_REL =        0x1
SHT_C6000_UNWIND =    0x70000001
SHT_C6000_PREEMPTMAP =    0x70000002
SHT_C6000_ATTRIBUTES =    0x70000003
SHT_TI_ICODE =        0x7F000000
SHT_TI_XREF =        0x7F000001
SHT_TI_HANDLER =        0x7F000002
SHT_TI_INITINFO =        0x7F000003
SHT_TI_PHATTRS =        0x7F000004
SHN_TIC6X_SCOMMON =    SHN_LORESERVE
PT_C6000_PHATTR =        0x70000000
DT_C6000_GSYM_OFFSET =    0x6000000D
DT_C6000_GSTR_OFFSET =    0x6000000F
DT_C6000_DSBT_BASE =    0x70000000
DT_C6000_DSBT_SIZE =    0x70000001
DT_C6000_PREEMPTMAP =    0x70000002
DT_C6000_DSBT_INDEX =    0x70000003
PHA_NULL =        0x0
PHA_BOUND =        0x1
PHA_READONLY =        0x2
ELF_STRING_C6000_unwind =           ".c6xabi.exidx"
ELF_STRING_C6000_unwind_info =      ".c6xabi.extab"
ELF_STRING_C6000_unwind_once =      ".gnu.linkonce.c6xabi.exidx."
ELF_STRING_C6000_unwind_info_once = ".gnu.linkonce.c6xabi.extab."

#include/elf/tilegx.h

#include/elf/tilepro.h

#include/elf/v850.h
EF_V850_ARCH =        0xf0000000
E_V850_ARCH =        0x00000000
E_V850E_ARCH =        0x10000000
E_V850E1_ARCH =        0x20000000
E_V850E2_ARCH =        0x30000000
E_V850E2V3_ARCH =        0x40000000
V850_OTHER_SDA =        0x10    # Symbol had SDA relocations.  
V850_OTHER_ZDA =        0x20    # Symbol had ZDA relocations.  
V850_OTHER_TDA =        0x40    # Symbol had TDA relocations.  
V850_OTHER_ERROR =    0x80    # Symbol had an error reported.  
SHN_V850_SCOMMON =    SHN_LORESERVE
SHN_V850_TCOMMON =    (SHN_LORESERVE + 1)
SHN_V850_ZCOMMON =    (SHN_LORESERVE + 2)
SHT_V850_SCOMMON =    0x70000000
SHT_V850_TCOMMON =    0x70000001
SHT_V850_ZCOMMON =    0x70000002
SHF_V850_GPREL =        0x10000000
SHF_V850_EPREL =        0x20000000
SHF_V850_R0REL =        0x40000000

#include/elf/vax.h
EF_VAX_NONPIC =        0x0001    # Object contains non-PIC code 
EF_VAX_DFLOAT =        0x0100    # Object contains D-Float insn.  
EF_VAX_GFLOAT =        0x0200    # Object contains G-Float insn.  

#include/elf/vxworks.h
DT_VX_WRS_TLS_DATA_START = 0x60000010
DT_VX_WRS_TLS_DATA_SIZE =  0x60000011
DT_VX_WRS_TLS_DATA_ALIGN = 0x60000015
DT_VX_WRS_TLS_VARS_START = 0x60000012
DT_VX_WRS_TLS_VARS_SIZE =  0x60000013

#include/elf/x86-64.h
SHT_X86_64_UNWIND =    0x70000001    # unwind information 
SHN_X86_64_LCOMMON =     (SHN_LORESERVE + 2)
SHF_X86_64_LARGE =    0x10000000

#include/elf/xc16x.h

#include/elf/xgate.h
EF_XGATE_ABI =  0x00000000F
E_XGATE_I32 =   0x000000001
E_XGATE_F64 =   0x000000002
EF_XGATE_MACH_MASK =  0xF0
EF_XGATE_MACH =       0x80 # XGATE microcontroller.  
E_M68HCS12X_GLOBAL =  0x100
STO_XGATE_INTERRUPT = 0x40

#include/elf/xstormy16.h


#include/elf/avr.h

ELF_TYPES = {
    0: "None",
    1: "Relocatable file",
    2: "Executable file",
    3: "Shared object file",
    4: "Core dump",
    5: "NUM"}

EM_NONE   =    0    # No machine 
EM_M32   =      1    # AT&T WE 32100 
EM_SPARC =     2    # SUN SPARC 
EM_386   =      3    # Intel 80386 
EM_68K   =      4    # Motorola m68k family 
EM_88K   =      5    # Motorola m88k family 
EM_486   =      6    # Intel 80486 # Reserved for future use 
EM_860   =      7    # Intel 80860 
EM_MIPS   =      8    # MIPS R3000 (officially, big-endian only) 
EM_S370   =      9    # IBM System/370 
EM_MIPS_RS3_LE =    10    # MIPS R3000 little-endian (Oct 4 1999 Draft) Deprecated 
EM_res011  =   11    # Reserved 
EM_res012  =   12    # Reserved 
EM_res013   =  13    # Reserved 
EM_res014  =   14    # Reserved 
EM_PARISC  =   15    # HPPA 
EM_res016  =   16    # Reserved 
EM_VPP550  =   17    # Fujitsu VPP500 
EM_SPARC32PLUS  =   18    # Sun's "v8plus" 
EM_960   =     19    # Intel 80960 
EM_PPC   =     20    # PowerPC 
EM_PPC64  =   21    # 64-bit PowerPC 
EM_S390   =     22    # IBM S/390 
EM_SPU   =     23    # Sony/Toshiba/IBM SPU 
EM_res024  =   24    # Reserved 
EM_res025  =   25    # Reserved 
EM_res026  =   26    # Reserved 
EM_res027  =   27    # Reserved 
EM_res028  =   28    # Reserved 
EM_res029  =   29    # Reserved 
EM_res030  =   30    # Reserved 
EM_res031  =   31    # Reserved 
EM_res032  =   32    # Reserved 
EM_res033  =   33    # Reserved 
EM_res034  =   34    # Reserved 
EM_res035  =   35    # Reserved 
EM_V800   =     36    # NEC V800 series 
EM_FR20   =     37    # Fujitsu FR20 
EM_RH32   =     38    # TRW RH32 
EM_MCORE  =   39    # Motorola M*Core  # May also be taken by Fujitsu MMA 
EM_RCE   =     39    # Old name for MCore 
EM_ARM   =     40    # ARM 
EM_OLD_ALPHA =    41    # Digital Alpha 
EM_SH   =     42    # Renesas (formerly Hitachi) / SuperH SH 
EM_SPARCV9  =   43    # SPARC v9 64-bit 
EM_TRICORE  =   44    # Siemens Tricore embedded processor 
EM_ARC   =     45    # ARC Cores 
EM_H8_300  =   46    # Renesas (formerly Hitachi) H8/300 
EM_H8_300H  =   47    # Renesas (formerly Hitachi) H8/300H 
EM_H8S   =     48    # Renesas (formerly Hitachi) H8S 
EM_H8_500  =   49    # Renesas (formerly Hitachi) H8/500 
EM_IA_64   =  50    # Intel IA-64 Processor 
EM_MIPS_X   =  51    # Stanford MIPS-X 
EM_COLDFIRE =    52    # Motorola Coldfire 
EM_68HC12   =  53    # Motorola M68HC12 
EM_MMA   =     54    # Fujitsu Multimedia Accelerator 
EM_PCP   =     55    # Siemens PCP 
EM_NCPU   =     56    # Sony nCPU embedded RISC processor 
EM_NDR1   =     57    # Denso NDR1 microprocessor 
EM_STARCORE  =   58    # Motorola Star*Core processor 
EM_ME16   =     59    # Toyota ME16 processor 
EM_ST100  =   60    # STMicroelectronics ST100 processor 
EM_TINYJ  =   61    # Advanced Logic Corp. TinyJ embedded processor 
EM_X86_64  =   62    # Advanced Micro Devices X86-64 processor 
EM_PDSP   =     63    # Sony DSP Processor 
EM_PDP10 =    64    # Digital Equipment Corp. PDP-10 
EM_PDP11   =  65    # Digital Equipment Corp. PDP-11 
EM_FX66   =     66    # Siemens FX66 microcontroller 
EM_ST9PLUS  =   67    # STMicroelectronics ST9+ 8/16 bit microcontroller 
EM_ST7   =     68    # STMicroelectronics ST7 8-bit microcontroller 
EM_68HC16   =  69    # Motorola MC68HC16 Microcontroller 
EM_68HC11   =  70    # Motorola MC68HC11 Microcontroller 
EM_68HC08   =  71    # Motorola MC68HC08 Microcontroller 
EM_68HC05   =  72    # Motorola MC68HC05 Microcontroller 
EM_SVX   =     73    # Silicon Graphics SVx 
EM_ST19   =     74    # STMicroelectronics ST19 8-bit cpu 
EM_VAX    =     75    # Digital VAX 
EM_CRIS   =       76    # Axis Communications 32-bit embedded processor 
EM_JAVELIN   =   77    # Infineon Technologies 32-bit embedded cpu 
EM_FIREPATH   =   78    # Element 14 64-bit DSP processor 
EM_ZSP   =       79    # LSI Logic's 16-bit DSP processor 
EM_MMIX   =       80    # Donald Knuth's educational 64-bit processor 
EM_HUANY   =   81    # Harvard's machine-independent format 
EM_PRISM   =   82    # SiTera Prism 
EM_AVR   =       83    # Atmel AVR 8-bit microcontroller 
EM_FR30   =       84    # Fujitsu FR30 
EM_D10V   =       85    # Mitsubishi D10V 
EM_D30V   =       86    # Mitsubishi D30V 
EM_V850   =       87    # Renesas V850 (formerly NEC V850) 
EM_M32R   =       88    # Renesas M32R (formerly Mitsubishi M32R) 
EM_MN10300   =   89    # Matsushita MN10300 
EM_MN10200   =   90    # Matsushita MN10200 
EM_PJ   =       91    # picoJava 
EM_OPENRISC   =   92    # OpenRISC 32-bit embedded processor 
EM_ARC_A5   =   93    # ARC Cores Tangent-A5 
EM_XTENSA   =   94    # Tensilica Xtensa Architecture 
EM_VIDEOCORE   =   95    # Alphamosaic VideoCore processor 
EM_TMM_GPP   =   96    # Thompson Multimedia General Purpose Processor 
EM_NS32K   =   97    # National Semiconductor 32000 series 
EM_TPC   =       98    # Tenor Network TPC processor 
EM_SNP1K   =   99    # Trebia SNP 1000 processor 
EM_ST200 =   100    # STMicroelectronics ST200 microcontroller 
EM_IP2K   =      101    # Ubicom IP2022 micro controller 
EM_MAX   =      102    # MAX Processor 
EM_CR   =      103    # National Semiconductor CompactRISC 
EM_F2MC16  =  104    # Fujitsu F2MC16 
EM_MSP430  =  105    # TI msp430 micro controller 
EM_BLACKFIN =   106    # ADI Blackfin 
EM_SE_C33  =  107    # S1C33 Family of Seiko Epson processors 
EM_SEP   =      108    # Sharp embedded microprocessor 
EM_ARCA   =      109    # Arca RISC Microprocessor 
EM_UNICORE =   110    # Microprocessor series from PKU-Unity Ltd. and MPRC of Peking University 
EM_EXCESS  =  111    # eXcess: 16/32/64-bit configurable embedded CPU 
EM_DXP   =      112    # Icera Semiconductor Inc. Deep Execution Processor 
EM_ALTERA_NIOS2 =   113    # Altera Nios II soft-core processor 
EM_CRX   =      114    # National Semiconductor CRX 
EM_XGATE  =  115    # Motorola XGATE embedded processor 
EM_C166   =      116    # Infineon C16x/XC16x processor 
EM_M16C   =      117    # Renesas M16C series microprocessors 
EM_DSPIC30F =   118    # Microchip Technology dsPIC30F Digital Signal Controller 
EM_CE   =      119    # Freescale Communication Engine RISC core 
EM_M32C   =      120    # Renesas M32C series microprocessors 
EM_res121  =  121    # Reserved 
EM_res122  =  122    # Reserved 
EM_res123  =  123    # Reserved 
EM_res124  =  124    # Reserved 
EM_res125  =  125    # Reserved 
EM_res126  =  126    # Reserved 
EM_res127  =  127    # Reserved 
EM_res128  =  128    # Reserved 
EM_res129  =  129    # Reserved 
EM_res130  =  130    # Reserved 
EM_TSK3000 =   131    # Altium TSK3000 core 
EM_RS08   =      132    # Freescale RS08 embedded processor 
EM_res133  =  133    # Reserved 
EM_ECOG2  =  134    # Cyan Technology eCOG2 microprocessor 
EM_SCORE  =  135    # Sunplus Score 
EM_SCORE7 =   135    # Sunplus S+core7 RISC processor 
EM_DSP24  =  136    # New Japan Radio (NJR) 24-bit DSP Processor 
EM_VIDEOCORE3 =   137    # Broadcom VideoCore III processor 
EM_LATTICEMICO32 =138    # RISC processor for Lattice FPGA architecture 
EM_SE_C17   = 139    # Seiko Epson C17 family 
EM_TI_C6000  =  140    # Texas Instruments TMS320C6000 DSP family 
EM_TI_C2000  =  141    # Texas Instruments TMS320C2000 DSP family 
EM_TI_C5500  =  142    # Texas Instruments TMS320C55x DSP family 
EM_res143  =  143    # Reserved 
EM_res144  =  144    # Reserved 
EM_res145  =  145    # Reserved 
EM_res146  =  146    # Reserved 
EM_res147  =  147    # Reserved 
EM_res148  =  148    # Reserved 
EM_res149  =  149    # Reserved 
EM_res150  =  150    # Reserved 
EM_res151  =  151    # Reserved 
EM_res152  =  152    # Reserved 
EM_res153  =  153    # Reserved 
EM_res154  =  154    # Reserved 
EM_res155  =  155    # Reserved 
EM_res156  =  156    # Reserved 
EM_res157  =  157    # Reserved 
EM_res158  =  158    # Reserved 
EM_res159  =  159    # Reserved 
EM_MMDSP_PLUS  =  160    # STMicroelectronics 64bit VLIW Data Signal Processor 
EM_CYPRESS_M8C =   161    # Cypress M8C microprocessor 
EM_R32C   =      162    # Renesas R32C series microprocessors 
EM_TRIMEDIA  =  163    # NXP Semiconductors TriMedia architecture family 
EM_QDSP6  =  164    # QUALCOMM DSP6 Processor 
EM_8051   =      165    # Intel 8051 and variants 
EM_STXP7X =   166    # STMicroelectronics STxP7x family 
EM_NDS32 =   167    # Andes Technology compact code size embedded RISC processor family 
EM_ECOG1  =  168    # Cyan Technology eCOG1X family 
EM_ECOG1X  =  168    # Cyan Technology eCOG1X family 
EM_MAXQ30  =  169    # Dallas Semiconductor MAXQ30 Core Micro-controllers 
EM_XIMO16 =   170    # New Japan Radio (NJR) 16-bit DSP Processor 
EM_MANIK  =  171    # M2000 Reconfigurable RISC Microprocessor 
EM_CRAYNV2 =   172    # Cray Inc. NV2 vector architecture 
EM_RX   =      173    # Renesas RX family 
EM_METAG  =  174    # Imagination Technologies META processor architecture 
EM_MCST_ELBRUS =   175    # MCST Elbrus general purpose hardware architecture 
EM_ECOG16  =  176    # Cyan Technology eCOG16 family 
EM_CR16   =      177    # National Semiconductor CompactRISC 16-bit processor 
EM_ETPU   =      178    # Freescale Extended Time Processing Unit 
EM_SLE9X =   179    # Infineon Technologies SLE9X core 
EM_L1OM   =      180    # Intel L1OM 
EM_K1OM   =      181    # Intel K1OM 
EM_INTEL182 =   182    # Reserved by Intel 
EM_AARCH64  =  183    # ARM 64-bit architecture 
EM_ARM184  =  184    # Reserved by ARM 
EM_AVR32  =  185    # Atmel Corporation 32-bit microprocessor family 
EM_STM8  =  186    # STMicroeletronics STM8 8-bit microcontroller 
EM_TILE64  =  187    # Tilera TILE64 multicore architecture family 
EM_TILEPRO =   188    # Tilera TILEPro multicore architecture family 
EM_MICROBLAZE =   189    # Xilinx MicroBlaze 32-bit RISC soft processor core 
EM_CUDA   =      190    # NVIDIA CUDA architecture 
EM_TILEGX =   191    # Tilera TILE-Gx multicore architecture family 
EM_RL78   =      197    # Renesas RL78 family.  
EM_78K0R =   199    # Renesas 78K0R.  

EM_OLD_SPARCV9  =    11
EM_PPC_OLD  =    17
EM_ALPHA    =    0x9026
EM_CYGNUS_D10V  =    0x7650
EM_CYGNUS_D30V =     0x7676
EM_CYGNUS_M32R   =   0x9041
EM_CYGNUS_V850   =   0x9080
EM_CYGNUS_MN10300 =  0xbeef
EM_CYGNUS_MN10200 =  0xdead
EM_MOXIE      =          0xFEED  # Moxie 
EM_CYGNUS_FR30    =  0x3330
EM_CYGNUS_FRV   =    0x5441
EM_PJ_OLD   =    99
EM_AVR_OLD  =    0x1057
EM_S390_OLD  =   0xa390
EM_XSTORMY16  =      0xad45
EM_OR32    =     0x8472
EM_ADAPTEVA_EPIPHANY =  0x1223  # Adapteva's Epiphany architecture.  
EM_DLX     =     0x5aa5
EM_IP2K_OLD  =   0x8217
EM_IQ2000   =    0xFEB  #Vitesse IQ2000
EM_XTENSA_OLD  =     0xabc7 #Old, unofficial value for Xtensa
EM_M32C_OLD  =   0xFEB #Renesas M32C and M16C
EM_MT      =     0x2530 #Morpho MT
EM_NIOS32   =    0xFEBB
EM_XC16X   =     0x4688 #Infineon Technologies 16-bit microcontroller with C166-V2 core
EM_CYGNUS_MEP    =   0xF00D  # Toshiba MeP
EM_MICROBLAZE_OLD  = 0xbaab  # Old MicroBlaze





def get_machine_name(mach):
    try:
        return {
            EM_NONE:        "None",
            EM_AARCH64:        "AArch64",
            EM_M32:        "WE32100",
            EM_SPARC:        "Sparc",
            EM_SPU:        "SPU",
            EM_386:        "Intel 80386",
            EM_68K:        "MC68000",
            EM_88K:        "MC88000",
            EM_486:        "Intel 80486",
            EM_860:        "Intel 80860",
            EM_MIPS:        "MIPS R3000",
            EM_S370:        "IBM System/370",
            EM_MIPS_RS3_LE:    "MIPS R4000 big-endian",
            EM_OLD_SPARCV9:    "Sparc v9 (old)",
            EM_PARISC:        "HPPA",
            EM_PPC_OLD:        "Power PC (old)",
            EM_SPARC32PLUS:    "Sparc v8+" ,
            EM_960:        "Intel 90860",
            EM_PPC:        "PowerPC",
            EM_PPC64:        "PowerPC64",
            EM_V800:        "NEC V800",
            EM_FR20:        "Fujitsu FR20",
            EM_RH32:        "TRW RH32",
            EM_MCORE:        "MCORE",
            EM_ARM:        "ARM",
            EM_OLD_ALPHA:        "Digital Alpha (old)",
            EM_SH:            "Renesas / SuperH SH",
            EM_SPARCV9:        "Sparc v9",
            EM_TRICORE:        "Siemens Tricore",
            EM_ARC:        "ARC",
            EM_H8_300:        "Renesas H8/300",
            EM_H8_300H:        "Renesas H8/300H",
            EM_H8S:        "Renesas H8S",
            EM_H8_500:        "Renesas H8/500",
            EM_IA_64:        "Intel IA-64",
            EM_MIPS_X:        "Stanford MIPS-X",
            EM_COLDFIRE:        "Motorola Coldfire",
            EM_ALPHA:        "Alpha",
            EM_CYGNUS_D10V: "d10v",
            EM_D10V:        "d10v",
            EM_CYGNUS_D30V: "d30v",
            EM_D30V:        "d30v",
            EM_CYGNUS_M32R: "Renesas M32R (formerly Mitsubishi M32r)",
            EM_M32R:        "Renesas M32R (formerly Mitsubishi M32r)",
            EM_CYGNUS_V850:  "Renesas V850",
            EM_V850:        "Renesas V850",
            EM_CYGNUS_MN10300:   "mn10300",
            EM_MN10300:        "mn10300",
            EM_CYGNUS_MN10200:  "mn10200",
            EM_MN10200:        "mn10200",
            EM_MOXIE:        "Moxie",
            EM_CYGNUS_FR30:   "Fujitsu FR30",
            EM_FR30:        "Fujitsu FR30",
            EM_CYGNUS_FRV:        "Fujitsu FR-V",
            EM_PJ_OLD:   "picoJava",
            EM_PJ:            "picoJava",
            EM_MMA:        "Fujitsu Multimedia Accelerator",
            EM_PCP:        "Siemens PCP",
            EM_NCPU:        "Sony nCPU embedded RISC processor",
            EM_NDR1:        "Denso NDR1 microprocesspr",
            EM_STARCORE:        "Motorola Star*Core processor",
            EM_ME16:        "Toyota ME16 processor",
            EM_ST100:        "STMicroelectronics ST100 processor",
            EM_TINYJ:        "Advanced Logic Corp. TinyJ embedded processor",
            EM_PDSP:        "Sony DSP processor",
            EM_PDP10:        "Digital Equipment Corp. PDP-10",
            EM_PDP11:        "Digital Equipment Corp. PDP-11",
            EM_FX66:        "Siemens FX66 microcontroller",
            EM_ST9PLUS:        "STMicroelectronics ST9+ 8/16 bit microcontroller",
            EM_ST7:        "STMicroelectronics ST7 8-bit microcontroller",
            EM_68HC16:        "Motorola MC68HC16 Microcontroller",
            EM_68HC12:        "Motorola MC68HC12 Microcontroller",
            EM_68HC11:        "Motorola MC68HC11 Microcontroller",
            EM_68HC08:        "Motorola MC68HC08 Microcontroller",
            EM_68HC05:        "Motorola MC68HC05 Microcontroller",
            EM_SVX:        "Silicon Graphics SVx",
            EM_ST19:        "STMicroelectronics ST19 8-bit microcontroller",
            EM_VAX:        "Digital VAX",
            EM_AVR_OLD:   "Atmel AVR 8-bit microcontroller",
            EM_AVR:        "Atmel AVR 8-bit microcontroller",
            EM_CRIS:        "Axis Communications 32-bit embedded processor",
            EM_JAVELIN:        "Infineon Technologies 32-bit embedded cpu",
            EM_FIREPATH:        "Element 14 64-bit DSP processor",
            EM_ZSP:        "LSI Logic's 16-bit DSP processor",
            EM_MMIX:        "Donald Knuth's educational 64-bit processor",
            EM_HUANY:        "Harvard Universitys's machine-independent object format",
            EM_PRISM:        "Vitesse Prism",
            EM_X86_64:        "Advanced Micro Devices X86-64",
            EM_L1OM:        "Intel L1OM",
            EM_K1OM:        "Intel K1OM",
            EM_S390_OLD:   "IBM S/390",
            EM_S390:        "IBM S/390",
            EM_SCORE:        "SUNPLUS S+Core",
            EM_XSTORMY16:        "Sanyo XStormy16 CPU core",
            EM_OPENRISC:   "OpenRISC",
            EM_OR32:        "OpenRISC",
            EM_ARC_A5:        "ARC International ARCompact processor",
            EM_CRX:        "National Semiconductor CRX microprocessor",
            EM_ADAPTEVA_EPIPHANY:    "Adapteva EPIPHANY",
            EM_DLX:        "OpenDLX",
            EM_IP2K_OLD:    "Ubicom IP2xxx 8-bit microcontrollers",
            EM_IP2K:        "Ubicom IP2xxx 8-bit microcontrollers",
            EM_IQ2000:           "Vitesse IQ2000",
            EM_XTENSA_OLD:   "Tensilica Xtensa Processor",
            EM_XTENSA:        "Tensilica Xtensa Processor",
            EM_VIDEOCORE:        "Alphamosaic VideoCore processor",
            EM_TMM_GPP:        "Thompson Multimedia General Purpose Processor",
            EM_NS32K:        "National Semiconductor 32000 series",
            EM_TPC:        "Tenor Network TPC processor",
            EM_ST200:        "STMicroelectronics ST200 microcontroller",
            EM_MAX:        "MAX Processor",
            EM_CR:            "National Semiconductor CompactRISC",
            EM_F2MC16:        "Fujitsu F2MC16",
            EM_MSP430:        "Texas Instruments msp430 microcontroller",
            EM_LATTICEMICO32:    "Lattice Mico32",
            EM_M32C_OLD:   "Renesas M32c",
            EM_M32C:            "Renesas M32c",
            EM_MT:                 "Morpho Techologies MT processor",
            EM_BLACKFIN:        "Analog Devices Blackfin",
            EM_SE_C33:        "S1C33 Family of Seiko Epson processors",
            EM_SEP:        "Sharp embedded microprocessor",
            EM_ARCA:        "Arca RISC microprocessor",
            EM_UNICORE:        "Unicore",
            EM_EXCESS:        "eXcess 16/32/64-bit configurable embedded CPU",
            EM_DXP:        "Icera Semiconductor Inc. Deep Execution Processor",
            EM_NIOS32:        "Altera Nios",
            EM_ALTERA_NIOS2:    "Altera Nios II",
            EM_C166:   "Infineon Technologies xc16x",
            EM_XC16X:        "Infineon Technologies xc16x",
            EM_M16C:        "Renesas M16C series microprocessors",
            EM_DSPIC30F:        "Microchip Technology dsPIC30F Digital Signal Controller",
            EM_CE:            "Freescale Communication Engine RISC core",
            EM_TSK3000:        "Altium TSK3000 core",
            EM_RS08:        "Freescale RS08 embedded processor",
            EM_ECOG2:        "Cyan Technology eCOG2 microprocessor",
            EM_DSP24:        "New Japan Radio (NJR) 24-bit DSP Processor",
            EM_VIDEOCORE3:        "Broadcom VideoCore III processor",
            EM_SE_C17:        "Seiko Epson C17 family",
            EM_TI_C6000:        "Texas Instruments TMS320C6000 DSP family",
            EM_TI_C2000:        "Texas Instruments TMS320C2000 DSP family",
            EM_TI_C5500:        "Texas Instruments TMS320C55x DSP family",
            EM_MMDSP_PLUS:        "STMicroelectronics 64bit VLIW Data Signal Processor",
            EM_CYPRESS_M8C:    "Cypress M8C microprocessor",
            EM_R32C:        "Renesas R32C series microprocessors",
            EM_TRIMEDIA:        "NXP Semiconductors TriMedia architecture family",
            EM_QDSP6:        "QUALCOMM DSP6 Processor",
            EM_8051:        "Intel 8051 and variants",
            EM_STXP7X:        "STMicroelectronics STxP7x family",
            EM_NDS32:        "Andes Technology compact code size embedded RISC processor family",
            EM_ECOG1X:        "Cyan Technology eCOG1X family",
            EM_MAXQ30:        "Dallas Semiconductor MAXQ30 Core microcontrollers",
            EM_XIMO16:        "New Japan Radio (NJR) 16-bit DSP Processor",
            EM_MANIK:        "M2000 Reconfigurable RISC Microprocessor",
            EM_CRAYNV2:        "Cray Inc. NV2 vector architecture",
            EM_CYGNUS_MEP:         "Toshiba MeP Media Engine",
            EM_CR16:   "Xilinx MicroBlaze",
            EM_MICROBLAZE:   "Xilinx MicroBlaze",
            EM_MICROBLAZE_OLD:    "Xilinx MicroBlaze",
            EM_RL78:        "Renesas RL78",
            EM_RX:            "Renesas RX",
            EM_METAG:        "Imagination Technologies META processor architecture",
            EM_MCST_ELBRUS:    "MCST Elbrus general purpose hardware architecture",
            EM_ECOG16:        "Cyan Technology eCOG16 family",
            EM_ETPU:        "Freescale Extended Time Processing Unit",
            EM_SLE9X:        "Infineon Technologies SLE9X core",
            EM_AVR32:        "Atmel Corporation 32-bit microprocessor family",
            EM_STM8:        "STMicroeletronics STM8 8-bit microcontroller",
            EM_TILE64:        "Tilera TILE64 multicore architecture family",
            EM_TILEPRO:        "Tilera TILEPro multicore architecture family",
            EM_TILEGX:        "Tilera TILE-Gx multicore architecture family",
            EM_CUDA:        "NVIDIA CUDA architecture",
            EM_XGATE:        "Motorola XGATE embedded processor"}[mach]
    except KeyError, err:
        return "<unknown>: 0x%x" % mach
    
EF_ARM_EABIMASK =     0xFF000000
EF_ARM_EABI_UNKNOWN = 0x00000000
EF_ARM_EABI_VER1    = 0x01000000
EF_ARM_EABI_VER2    = 0x02000000
EF_ARM_EABI_VER3    = 0x03000000
EF_ARM_EABI_VER4    = 0x04000000
EF_ARM_EABI_VER5    = 0x05000000

def decode_ARM_machine_flags(e_flags):
    flags = []
    eabi = e_flags & EF_ARM_EABIMASK
    e_flags &= ~EF_ARM_EABIMASK
    
    if e_flags & EF_ARM_RELEXEC:
        flags.append((EF_ARM_RELEXEC, "relocatable executable"))
        e_flags &= ~ EF_ARM_RELEXEC
        
    if e_flags & EF_ARM_HASENTRY:
        flags.append((EF_ARM_HASENTRY, "has entry point"))
        e_flags &= ~ EF_ARM_HASENTRY
        
    if eabi == EF_ARM_EABI_VER1:
        flags.append((EF_ARM_EABI_VER1, "Version1 EABI"))
        if e_flags & EF_ARM_SYMSARESORTED:
            flags.append((EF_ARM_SYMSARESORTED, "sorted symbol tables"))
            e_flags &= ~EF_ARM_SYMSARESORTED
    elif eabi == EF_ARM_EABI_VER2:
        flags.append((EF_ARM_EABI_VER2, "Version2 EABI"))
        if e_flags & EF_ARM_SYMSARESORTED:
            flags.append((EF_ARM_SYMSARESORTED, "sorted symbol tables"))
            e_flags &= ~EF_ARM_SYMSARESORTED
        if e_flags & EF_ARM_DYNSYMSUSESEGIDX:
            flags.append((EF_ARM_DYNSYMSUSESEGIDX, "dynamic symbols use segment index"))
            e_flags &= ~EF_ARM_DYNSYMSUSESEGIDX
        if e_flags & EF_ARM_MAPSYMSFIRST:
            flags.append((EF_ARM_MAPSYMSFIRST, "smapping symbols precede others"))
            e_flags &= ~EF_ARM_MAPSYMSFIRST
    elif eabi == EF_ARM_EABI_VER3:
        flags.append((EF_ARM_EABI_VER3, "Version3 EABI"))
    elif eabi == EF_ARM_EABI_VER4 or eabi == EF_ARM_EABI_VER5:
        if eabi == EF_ARM_EABI_VER4:
            flags.append((EF_ARM_EABI_VER4, "Version4 EABI"))
        else:
            flags.append((EF_ARM_EABI_VER4, "Version5     EABI"))
        if e_flags & EF_ARM_BE8:
            flags.append((EF_ARM_BE8, "BE8"))
            e_flags &= ~EF_ARM_BE8
        if e_flags & EF_ARM_LE8:
            flags.append((EF_ARM_LE8, "LE8"))
            e_flags &= ~EF_ARM_LE8
    elif eabi == EF_ARM_EABI_UNKNOWN:
        flags.append((EF_ARM_EABI_UNKNOWN, "GNU EABI"))
        if e_flags & EF_ARM_INTERWORK:
          flags.append((EF_ARM_INTERWORK, "interworking enabled"))
          e_flags &= ~EF_ARM_INTERWORK
        if e_flags & EF_ARM_APCS_26:
          flags.append((EF_ARM_APCS_26, "uses APCS/26"))
          e_flags &= ~EF_ARM_APCS_26
        if e_flags & EF_ARM_APCS_FLOAT:
          flags.append((EF_ARM_APCS_FLOAT, "uses APCS/float"))
          e_flags &= ~EF_ARM_APCS_FLOAT
        if e_flags & EF_ARM_PIC:
          flags.append((EF_ARM_PIC, "position independent"))
          e_flags &= ~EF_ARM_PIC
        if e_flags & EF_ARM_ALIGN8:
          flags.append((EF_ARM_ALIGN8, "8 bit structure alignment"))
          e_flags &= ~EF_ARM_ALIGN8
        if e_flags & EF_ARM_NEW_ABI:
          flags.append((EF_ARM_NEW_ABI, "uses new ABI"))
          e_flags &= ~EF_ARM_NEW_ABI
        if e_flags & EF_ARM_OLD_ABI:
          flags.append((EF_ARM_OLD_ABI, "uses old ABI"))
          e_flags &= ~EF_ARM_OLD_ABI
        if e_flags & EF_ARM_SOFT_FLOAT:
          flags.append((EF_ARM_SOFT_FLOAT, "software FP"))
          e_flags &= ~EF_ARM_SOFT_FLOAT
        if e_flags & EF_ARM_VFP_FLOAT:
          flags.append((EF_ARM_VFP_FLOAT, "VFP"))
          e_flags &= ~EF_ARM_VFP_FLOAT
        if e_flags & EF_ARM_MAVERICK_FLOAT:
          flags.append((EF_ARM_MAVERICK_FLOAT, "Maverick FP"))
          e_flags &= ~EF_ARM_MAVERICK_FLOAT
    if e_flags:
        flags.append((0, "<unknown>"))
        
    return [{"value": x[0], "description": x[1]} for x in flags]
        
def get_machine_flags(e_flags, e_machine, elf_header = None):
    flags = []
    if e_machine == EM_ARM:
        return decode_ARM_machine_flags(e_flags)
    elif e_machine == EM_BLACKFIN:
        if (e_flags & EF_BFIN_PIC):
            flags.append((EF_BFIN_PIC, "PIC"))
        if (e_flags & EF_BFIN_FDPIC):
            flags.append((EF_BFIN_FDPIC, "FDPIC"))
        if (e_flags & EF_BFIN_CODE_IN_L1):
            flags.append((EF_BFIN_CODE_IN_L1, "code in L1"))
        if (e_flags & EF_BFIN_DATA_IN_L1):
            flags.append((EF_BFIN_DATA_IN_L1, "data in L1"))
    elif e_machine == EM_CYGNUS_FRV:
        try:
            flags.append(({
                EF_FRV_CPU_FR300: "fr300",
                EF_FRV_CPU_FR400: "fr400",
                EF_FRV_CPU_FR405: "fr405",
                EF_FRV_CPU_FR450: "fr450",
                EF_FRV_CPU_FR500: "fr500",
                EF_FRV_CPU_FR550: "fr550",
                EF_FRV_CPU_SIMPLE: "simple",
                EF_FRV_CPU_TOMCAT: "tomcat"}[e_flags & EF_FRV_CPU_MASK], e_flags & EF_FRV_CPU_MASK))
        except KeyError:
            if e_flags & EF_FRV_CPU_MASK != EF_FRV_CPU_GENERIC:
                flags.append((e_flags & EF_FRV_CPU_MASK, "fr???"))
    elif e_machine == EM_68K:
        if ((e_flags & EF_M68K_ARCH_MASK) == EF_M68K_M68000):
            flags.append((EF_M68K_M68000, "m68000"))
        elif ((e_flags & EF_M68K_ARCH_MASK) == EF_M68K_CPU32):
            flags.append((EF_M68K_CPU32, "cpu32"))
        elif ((e_flags & EF_M68K_ARCH_MASK) == EF_M68K_FIDO):
            flags.append((EF_M68K_FIDO, "fido_a"))
        else:
            try:
                flags += {
                    EF_M68K_CF_ISA_A_NODIV: [(EF_M68K_CF_ISA_A_NODIV, "cf"), 
                                             (EF_M68K_CF_ISA_A_NODIV, "isa A"), 
                                             (EF_M68K_CF_ISA_A_NODIV, "nodiv")],
                    EF_M68K_CF_ISA_A: [(EF_M68K_CF_ISA_A, "cf"), 
                                       (EF_M68K_CF_ISA_A, "isa A")],
                    EF_M68K_CF_ISA_A_PLUS: [(EF_M68K_CF_ISA_A_PLUS, "cf"), 
                                            (EF_M68K_CF_ISA_A_PLUS, "isa A+")],
                    EF_M68K_CF_ISA_B_NOUSP: [(EF_M68K_CF_ISA_B_NOUSP, "cf"), 
                                             (EF_M68K_CF_ISA_B_NOUSP, "isa B"), 
                                             (EF_M68K_CF_ISA_B_NOUSP, "nousp")],
                    EF_M68K_CF_ISA_B: [(EF_M68K_CF_ISA_B, "cf"), 
                                       (EF_M68K_CF_ISA_B, "isa B")],
                    EF_M68K_CF_ISA_C: [(EF_M68K_CF_ISA_C, "cf"), 
                                       (EF_M68K_CF_ISA_C, "isa C")],
                    EF_M68K_CF_ISA_C_NODIV: [(EF_M68K_CF_ISA_C_NODIV, "cf"), 
                                             (EF_M68K_CF_ISA_C_NODIV, "isa C"), 
                                             (EF_M68K_CF_ISA_C_NODIV, "nodiv")]
                }[e_flags & EF_M68K_CF_ISA_MASK]
            except KeyError:
                pass
            
            if (e_flags & EF_M68K_CF_FLOAT):
                flags.append((EF_M68K_CF_FLOAT, "float"))
                
            try:
                flags.append(({
                    EF_M68K_CF_MAC:  "mac",
                    EF_M68K_CF_EMAC: "emac",
                    EF_M68K_CF_EMAC_B: "emac_b"}[e_flags & EF_M68K_CF_MAC_MASK], e_flags & EF_M68K_CF_MAC_MASK))
            except KeyError:
                pass
    elif e_machine == EM_PPC:
        if (e_flags & EF_PPC_EMB):
            flags.append((EF_PPC_EMB, "emb"))
        if (e_flags & EF_PPC_RELOCATABLE):
            flags.append((EF_PPC_RELOCATABLE, "relocatable"))
        if (e_flags & EF_PPC_RELOCATABLE_LIB):
            flags.append((EF_PPC_RELOCATABLE_LIB, "relocatable-lib"))
    elif e_machine == EM_V850 or e_machine == EM_CYGNUS_V850:
        try:
            flags.append(({
            E_V850E2V3_ARCH: "v850e2v3",
            E_V850E2_ARCH: "v850e2",
            E_V850E1_ARCH: "v850e1",
            E_V850E_ARCH: "v850e",
            E_V850_ARCH: "v850"}[e_flags & EF_V850_ARCH], e_flags & EF_V850_ARCH))
        except KeyError:
            flags.append((0, "unknown v850 architecture variant"))
    elif e_machine == EM_M32R or e_machine == EM_CYGNUS_M32R:
      if ((e_flags & EF_M32R_ARCH) == E_M32R_ARCH):
          flags.append((E_M32R_ARCH, "m32r"))
    elif e_machine == EM_MIPS or e_machine == EM_MIPS_RS3_LE:
        if (e_flags & EF_MIPS_NOREORDER):
            flags.append((EF_MIPS_NOREORDER, "noreorder"))
        if (e_flags & EF_MIPS_PIC):
            flags.append((EF_MIPS_PIC, "pic"))
        if (e_flags & EF_MIPS_CPIC):
            flags.append((EF_MIPS_CPIC, "cpic"))
        if (e_flags & EF_MIPS_UCODE):
            flags.append((EF_MIPS_UCODE, "ugen_reserved"))
        if (e_flags & EF_MIPS_ABI2):
            flags.append((EF_MIPS_ABI2, "abi2"))
        if (e_flags & EF_MIPS_OPTIONS_FIRST):
            flags.append((EF_MIPS_OPTIONS_FIRST, "odk first"))
        if (e_flags & EF_MIPS_32BITMODE):
            flags.append((EF_MIPS_32BITMODE, "32bitmode"))

        try:
            flags.append(({
                E_MIPS_MACH_3900: "3900",
                E_MIPS_MACH_4010: "4010",
                E_MIPS_MACH_4100: "4100",
                E_MIPS_MACH_4111: "4111",
                E_MIPS_MACH_4120: "4120",
                E_MIPS_MACH_4650: "4650",
                E_MIPS_MACH_5400: "5400",
                E_MIPS_MACH_5500: "5500",
                E_MIPS_MACH_SB1:  "sb1",
                E_MIPS_MACH_9000: "9000",
                E_MIPS_MACH_LS2E: "loongson-2e",
                E_MIPS_MACH_LS2F: "loongson-2f",
                E_MIPS_MACH_LS3A: "loongson-3a",
                E_MIPS_MACH_OCTEON: "octeon",
                E_MIPS_MACH_OCTEON2: "octeon2",
                E_MIPS_MACH_XLR:  "xlr"}[e_flags & EF_MIPS_MACH], e_flags & EF_MIPS_MACH))
        except KeyError:
            if e_flags & EF_MIPS_MACH != 0:
                flags.append((0, "unkown CPU"))
            
        try:
            flags.append(({
                E_MIPS_ABI_O32: "o32",
                E_MIPS_ABI_O64: "o64",
                E_MIPS_ABI_EABI32: "eabi32",
                E_MIPS_ABI_EABI64: "eabi64"}[e_flags & EF_MIPS_ABI], e_flags & EF_MIPS_ABI))
        except KeyError:
            if e_flags & EF_MIPS_ABI != 0:
                flags.append((0, "unknown ABI"))

        if (e_flags & EF_MIPS_ARCH_ASE_MDMX):
            flags.append((EF_MIPS_ARCH_ASE_MDMX, "mdmx"))
        if (e_flags & EF_MIPS_ARCH_ASE_M16):
            flags.append((EF_MIPS_ARCH_ASE_M16, "mips16"))
        if (e_flags & EF_MIPS_ARCH_ASE_MICROMIPS):
            flags.append((EF_MIPS_ARCH_ASE_MICROMIPS, "micromips"))

        try:
            flags.append(({
                E_MIPS_ARCH_1: "mips1",
                E_MIPS_ARCH_2: "mips2",
                E_MIPS_ARCH_3: "mips3",
                E_MIPS_ARCH_4: "mips4",
                E_MIPS_ARCH_5: "mips5",
                E_MIPS_ARCH_32: "mips32",
                E_MIPS_ARCH_32R2: "mips32r2",
                E_MIPS_ARCH_64: "mips64",
                E_MIPS_ARCH_64R2: "mips64r2"}[e_flags & EF_MIPS_ARCH], e_flags & EF_MIPS_ARCH))
        except KeyError:
            flags.append((0, "unknown ISA"))

        if (e_flags & EF_SH_PIC):
            flags.append((EF_SH_PIC, "pic"))
        
        if (e_flags & EF_SH_FDPIC):
            flags.append((EF_SH_FDPIC, "fdpic"))
    elif e_machine == EM_SH:
      try:
          flags.append(({
                EF_SH1: "sh1",
                EF_SH2: "sh2",
                EF_SH3: "sh3",
                EF_SH_DSP: "sh-dsp",
                EF_SH3_DSP: "sh3-dsp",
                EF_SH4AL_DSP: "sh4al-dsp",
                EF_SH3E: "sh3e",
                EF_SH4: "sh4",
                EF_SH5: "sh5",
                EF_SH2E: "sh2e",
                EF_SH4A: "sh4a",
                EF_SH2A: "sh2a",
                EF_SH4_NOFPU: "sh4-nofpu",
                EF_SH4A_NOFPU: "sh4a-nofpu",
                EF_SH2A_NOFPU: "sh2a-nofpu",
                EF_SH3_NOMMU: "sh3-nommu",
                EF_SH4_NOMMU_NOFPU: "sh4-nommu-nofpu",
                EF_SH2A_SH4_NOFPU: "sh2a-nofpu-or-sh4-nommu-nofpu",
                EF_SH2A_SH3_NOFPU: "sh2a-nofpu-or-sh3-nommu",
                EF_SH2A_SH4: "sh2a-or-sh4",
                EF_SH2A_SH3E: "sh2a-or-sh3e"}[e_flags & EF_SH_MACH_MASK], e_flags & EF_SH_MACH_MASK))
      except KeyError:
          flags.append((0, "unknown ISA"))

    elif e_machine == EM_SPARCV9:
        if (e_flags & EF_SPARC_32PLUS):
            flags.append((EF_SPARC_32PLUS, "v8+"))
        if (e_flags & EF_SPARC_SUN_US1):
            flags.append((EF_SPARC_SUN_US1, "ultrasparcI"))
        if (e_flags & EF_SPARC_SUN_US3):
            flags.append((EF_SPARC_SUN_US3, "ultrasparcIII"))
        if (e_flags & EF_SPARC_HAL_R1):
            flags.append((EF_SPARC_HAL_R1, "halr1"))
        if (e_flags & EF_SPARC_LEDATA):
            flags.append((EF_SPARC_LEDATA, "ledata"))
        if ((e_flags & EF_SPARCV9_MM) == EF_SPARCV9_TSO):
            flags.append((EF_SPARCV9_TSO, "tso"))
        if ((e_flags & EF_SPARCV9_MM) == EF_SPARCV9_PSO):
            flags.append((EF_SPARCV9_PSO, "pso"))
        if ((e_flags & EF_SPARCV9_MM) == EF_SPARCV9_RMO):
            flags.append((EF_SPARCV9_RMO, "rmo"))
    elif e_machine == EM_PARISC:
        try:
            flags.append(({
                EFA_PARISC_1_0: "PA-RISC 1.0",
                EFA_PARISC_1_1: "PA-RISC 1.1",
                EFA_PARISC_2_0: "PA-RISC 2.0"}[e_flags & EF_PARISC_ARCH], e_flags & EF_PARISC_ARCH))
        except KeyError:
            pass

        if (e_flags & EF_PARISC_TRAPNIL):
            flags.append((EF_PARISC_TRAPNIL, "trapnil"))
        if (e_flags & EF_PARISC_EXT):
            flags.append((EF_PARISC_EXT, "ext"))
        if (e_flags & EF_PARISC_LSB):
            flags.append((EF_PARISC_LSB, "lsb"))
        if (e_flags & EF_PARISC_WIDE):
            flags.append((EF_PARISC_WIDE, "wide"))
        if (e_flags & EF_PARISC_NO_KABP):
            flags.append((EF_PARISC_NO_KABP, "no kabp"))
        if (e_flags & EF_PARISC_LAZYSWAP):
            flags.append((EF_PARISC_LAZYSWAP, "lazyswap"))
    elif e_machine == EM_PJ or e_machine == EM_PJ_OLD:
        if ((e_flags & EF_PICOJAVA_NEWCALLS) == EF_PICOJAVA_NEWCALLS):
            flags.append((EF_PICOJAVA_NEWCALLS, "new calling convention"))
        if ((e_flags & EF_PICOJAVA_GNUCALLS) == EF_PICOJAVA_GNUCALLS):
            flags.append((EF_PICOJAVA_GNUCALLS, "gnu calling convention"))
    elif e_machine == EM_IA_64:
        if ((e_flags & EF_IA_64_ABI64)):
            flags.append((EF_IA_64_ABI64, "64-bit"))
        else:
            flags.append((0, "32-bit"))
        if ((e_flags & EF_IA_64_REDUCEDFP)):
            flags.append((EF_IA_64_REDUCEDFP, "reduced fp model"))
        if ((e_flags & EF_IA_64_NOFUNCDESC_CONS_GP)):
            flags.append((EF_IA_64_NOFUNCDESC_CONS_GP, "no function descriptors, constant gp"))
        elif ((e_flags & EF_IA_64_CONS_GP)):
            flags.append((EF_IA_64_CONS_GP, "constant gp"))
        if ((e_flags & EF_IA_64_ABSOLUTE)):
            flags.append((EF_IA_64_ABSOLUTE, "absolute"))
        #TODO: How to get this flag?
        if (elf_header.e_ident[EI_OSABI] == ELFOSABI_OPENVMS):
            if ((e_flags & EF_IA_64_VMS_LINKAGES)):
                flags.append((EF_IA_64_VMS_LINKAGES, "vms_linkages"))
            try:
                flags.append(({
                    EF_IA_64_VMS_COMCOD_WARNING: "warning",
                    EF_IA_64_VMS_COMCOD_ERROR: "error",
                    EF_IA_64_VMS_COMCOD_ABORT: "abort"}[e_flags & EF_IA_64_VMS_COMCOD], e_flags & EF_IA_64_VMS_COMCOD))
            except KeyError:
                if e_flags & EF_IA_64_VMS_COMCOD != EF_IA_64_VMS_COMCOD_SUCCESS:
                    #TODO
                    sys.exit(1)
    elif e_machine == EM_VAX:
        if ((e_flags & EF_VAX_NONPIC)):
            flags.append((EF_VAX_NONPIC, "non-PIC"))
        if ((e_flags & EF_VAX_DFLOAT)):
            flags.append((EF_VAX_DFLOAT, "D-Float"))
        if ((e_flags & EF_VAX_GFLOAT)):
            flags.append((EF_VAX_GFLOAT, "G-Float"))
    elif e_machine == EM_RX:
        if (e_flags & E_FLAG_RX_64BIT_DOUBLES):
            flags.append((E_FLAG_RX_64BIT_DOUBLES, "64-bit doubles"))
        if (e_flags & E_FLAG_RX_DSP):
            flags.append((E_FLAG_RX_DSP, "dsp"))
        if (e_flags & E_FLAG_RX_PID):
            flags.append((E_FLAG_RX_PID, "pid"))
    elif e_machine == EM_S390:
        if (e_flags & EF_S390_HIGH_GPRS):
            flags.append((EF_S390_HIGH_GPRS, "highgprs"))
    elif e_machine == EM_TI_C6000:
        if ((e_flags & EF_C6000_REL)):
            flags.append((EF_C6000_REL, "relocatable module"))
            
    return [{"value": x[0], "description": x[1]} for x in flags]

def get_osabi_name(osabi, elf_header):
    try:
        return {
            ELFOSABI_NONE: "UNIX - System V",
            ELFOSABI_HPUX: "UNIX - HP-UX",
            ELFOSABI_NETBSD: "UNIX - NetBSD",
            ELFOSABI_GNU: "UNIX - GNU",
            ELFOSABI_SOLARIS: "UNIX - Solaris",
            ELFOSABI_AIX: "UNIX - AIX",
            ELFOSABI_IRIX: "UNIX - IRIX",
            ELFOSABI_FREEBSD: "UNIX - FreeBSD",
            ELFOSABI_TRU64: "UNIX - TRU64",
            ELFOSABI_MODESTO: "Novell - Modesto",
            ELFOSABI_OPENBSD: "UNIX - OpenBSD",
            ELFOSABI_OPENVMS: "VMS - OpenVMS",
            ELFOSABI_NSK: "HP - Non-Stop Kernel",
            ELFOSABI_AROS: "AROS",
            ELFOSABI_FENIXOS: "FenixOS"}[osabi]
    except KeyError, err:
        if osabi >= 64:
            if elf_header.e_machine == EM_ARM and osabi == ELFOSABI_ARM:
                return "ARM"
            elif elf_header.e_machine in [EM_MSP430, EM_MSP430_OLD] and osabi == ELFOSABI_STANDALONE:
                return  "Standalone App"
            elif elf_header.e_machine == EM_TI_C6000 and osabi == ELFOSABI_C6000_ELFABI:
                return "Bare-metal C6000"
            elif elf_header.e_machine == EM_TI_C6000 and osabi == ELFOSABI_C6000_LINUX:
                return "Linux C6000"
        
        return "<unknown: %x>" % osabi
        
        
def process_program_headers(elf):
    program_headers = []
    
    if elf.header.e_phnum == 0 and elf.header.e_phoff != 0:
        raise Exception("possibly corrupt ELF header - it has a non-zero program header offset, but no program headers")
    
    for segment in elf.prog_headers:
        program_header = {
            "type": {
                "value": segment.type,
                "description": phdr_type(segment.type)},
            "offset": segment.offset,
            "virtual_address": segment.vaddr,
            "physical_address": segment.paddr,
            "file_size": segment.filesz,
            "memory_size": segment.memsz,
            "flags": {
                "value": segment.flags,
                "decoded_values" : reduce(lambda r, x: (segment.flags & x[0]) and  (r + [x[1]]) or (r), [(PF_R, 'R'), (PF_W, 'W'), (PF_X, 'E')], [])},
            "align": segment.align}
        
        if segment.p_type == PT_DYNAMIC:
            dynamic_size = segment.p_filesz
            dynamic_address = segment.p_offset
        elif segment.p_type == PT_INTERP:
            program_header["comments"] = {"interpreter_name": segment.data}
            
        program_headers.append(program_header)
        
    return program_headers
            
        
        
    
    
def process_attributes(elf):
    for sect_header in elf.sect_headers:
        if sect_header.sh_type != SHT_GNU_ATTRIBUTES and sect_header.sh_type != proc_type:
            continue
    

ELF_CLASS = {
    'ELFCLASSNONE': "NONE",
    'ELFCLASS32': "ELF32",
    'ELFCLASS64': "ELF64"}

# e_ident[EI_DATA] 
ELFDATANONE  =   0               
ELFDATA2LSB  =   1
ELFDATA2MSB  =   2    

ELF_DATA = {
    ELFDATANONE: "none",
    ELFDATA2LSB: "2's complement, little endian",
    ELFDATA2MSB: "2's complement, big endian"}
    
EV_NONE  =       0             # e_version, EI_VERSION 
EV_CURRENT  =    1

ELF_VERSION = {
    EV_NONE: "none",
    EV_CURRENT: "current"}

EF_ARM_BE8 = 0x00800000      # ABI 4,5 
EF_ARM_LE8 =             0x00400000      # ABI 4,5 
EF_ARM_MAVERICK_FLOAT =  0x00000800      # ABI 0 
EF_ARM_VFP_FLOAT     =   0x00000400      # ABI 0 
EF_ARM_SOFT_FLOAT     =  0x00000200      # ABI 0 
EF_ARM_OLD_ABI  =        0x00000100      # ABI 0 
EF_ARM_NEW_ABI  =        0x00000080      # ABI 0 
EF_ARM_ALIGN8   =        0x00000040      # ABI 0 
EF_ARM_PIC      =        0x00000020      # ABI 0 
EF_ARM_MAPSYMSFIRST =    0x00000010      # ABI 2 
EF_ARM_APCS_FLOAT   =    0x00000010      # ABI 0, floats in fp regs 
EF_ARM_DYNSYMSUSESEGIDX = 0x00000008      # ABI 2 
EF_ARM_APCS_26    =      0x00000008      # ABI 0 
EF_ARM_SYMSARESORTED =   0x00000004      # ABI 1,2 
EF_ARM_INTERWORK   =     0x00000004      # ABI 0 
EF_ARM_HASENTRY    =     0x00000002      # All 
EF_ARM_RELEXEC     =     0x00000001      # All     
EF_ARM_EABI_VERSION5 =   0x5000000

EF_MIPS_NOREORDER =      0x00000001
EF_MIPS_PIC     =        0x00000002
EF_MIPS_CPIC    =        0x00000004
EF_MIPS_UCODE =          0x00000010 # Code in file uses new ABI
EF_MIPS_ABI2    =        0x00000020
EF_MIPS_OPTIONS_FIRST =  0x00000080
EF_MIPS_32BITMODE    =   0x00000100
EF_MIPS_ABI          =   0x0000f000
EF_MIPS_ARCH_ASE_M16 =   0x04000000
EF_MIPS_ARCH_ASE_MDMX =  0x08000000
EF_MIPS_ARCH         =   0xf0000000

EF_PPC_EMB =             0x80000000
EF_PPC_RELOCATABLE =     0x00010000
EF_PPC_RELOCATABLE_LIB = 0x00008000

EF_SPARC_32PLUS    =     0x000100        # generic V8+ features
EF_SPARC_SUN_US1    =    0x000200        # UltraSPARC 1 extensions   
EF_SPARC_HAL_R1      =   0x000400        # HAL R1 extensions
EF_SPARC_SUN_US3    =    0x000800        # UltraSPARC 3 extensions                                


ARM_EFLAGS_DESC = {
    EF_ARM_RELEXEC: "relocatable executable",
    EF_ARM_HASENTRY: "has entry point",
    EF_ARM_SYMSARESORTED: "sorted symbol tables",
    EF_ARM_DYNSYMSUSESEGIDX: "dynamic symbols use segment index",
    EF_ARM_MAPSYMSFIRST: "mapping symbols precede others",
    EF_ARM_BE8: "BE8",
    EF_ARM_LE8: "LE8",
    EF_ARM_INTERWORK: "interworking enabled",
    EF_ARM_APCS_26: "uses APCS/26",
    EF_ARM_APCS_FLOAT: "uses APCS/float",
    EF_ARM_PIC: "position independent",
    EF_ARM_ALIGN8: "8 bit structure alignment",
    EF_ARM_NEW_ABI: "uses new ABI",
    EF_ARM_OLD_ABI: "uses old ABI",
    EF_ARM_SOFT_FLOAT: "software FP",
    EF_ARM_VFP_FLOAT: "VFP",
    EF_ARM_MAVERICK_FLOAT: "Maverick FP",
    EF_ARM_EABI_VERSION5: "Version5 EABI"}

MIPS_EFLAGS_DESC = {
            EF_MIPS_NOREORDER: "noreorder",
            EF_MIPS_PIC: "pic",
            EF_MIPS_CPIC: "cpic",
            EF_MIPS_UCODE: "ugen_reserved",
            EF_MIPS_ABI2: "abi2",
            EF_MIPS_OPTIONS_FIRST: "odk first",
            EF_MIPS_ARCH_ASE_MDMX: "mdmx",
            EF_MIPS_ARCH_ASE_M16: "mips16"}


POWERPC_EFLAGS_DESC = {
            EF_PPC_EMB: "emb",
            EF_PPC_RELOCATABLE: "relocatable",
            EF_PPC_RELOCATABLE_LIB: "relocatable-lib"}
                
SPARC_EFLAGS_DESC = {
            EF_SPARC_32PLUS: "v8+",
            EF_SPARC_SUN_US1: "ultrasparcI",
            EF_SPARC_HAL_R1: "halr1",
            EF_SPARC_SUN_US3: "ultrasparcIII"}
            
ELFOSABI_SYSV  =         0       # UNIX System V ABI
ELFOSABI_HPUX  =         1       # HP-UX operating system 
ELFOSABI_NETBSD  =       2       # NetBSD
ELFOSABI_GNU   =       3       # GNU/Linux 
ELFOSABI_HURD =  4       # GNU/Hurd 
ELFOSABI_86OPEN   =      5       # 86Open common IA32 ABI
ELFOSABI_SOLARIS = 6      # Solaris 
ELFOSABI_AIX = 7     # Monterey
ELFOSABI_IRIX  = 8       # IRIX
ELFOSABI_FREEBSD = 9      # FreeBSD 
ELFOSABI_TRU64 = 10      # TRUE64 UNIX
ELFOSABI_MODESTO   =     11      # Novell Modesto 
ELFOSABI_OPENBSD   =     12      # OpenBSD 
ELFOSABI_OPENVMS   =     13      # Open VMS
ELFOSABI_NSK     =       14      # HP Non-Stop Kernel
ELFOSABI_AROS    =       15      # Amiga Research OS
ELFOSABI_ARM      =      97      # ARM
ELFOSABI_STANDALONE  =   255     # Standalone (embedded) application
            
def elf_osabi(abi):
    try:
        return {
            ELFOSABI_SYSV: "SYSV",    
             ELFOSABI_HPUX: "HPUS",
             ELFOSABI_NETBSD: "NetBSD",
             ELFOSABI_GNU: "GNU",
             ELFOSABI_HURD: "HURD",
             ELFOSABI_86OPEN: "86OPEN",
             ELFOSABI_SOLARIS: "Solaris",
             ELFOSABI_AIX: "AIX",
             ELFOSABI_IRIX: "IRIX",
             ELFOSABI_FREEBSD: "FreeBSD",
             ELFOSABI_TRU64: "TRU64",
             ELFOSABI_MODESTO: "MODESTO",
             ELFOSABI_OPENBSD: "OpenBSD",
             ELFOSABI_OPENVMS: "OpenVMS",
             ELFOSABI_NSK: "NSK",
             ELFOSABI_ARM: "ARM",
             ELFOSABI_STANDALONE: "StandAlone"
        }[abi]
    except KeyException, ex:
        return "<unknown: %#x>" % abi

ET_NONE =  0
ET_REL =   1
ET_EXEC  = 2
ET_DYN =   3
ET_CORE  = 4
ET_LOOS   =      0xfe00  # First operating system specific. 
ET_HIOS   =      0xfeff  # Last operating system-specific. 
ET_LOPROC = 0xff00 # First processor-specific.
ET_HIPROC = 0xffff # Last processor-specific.
    
def elf_type(type):
    try:
        return {
            ET_NONE: "NONE (None)",
            ET_REL: "REL (Relocatable file)",
            ET_EXEC: "EXEC (Executable file)",
            ET_DYN: "DYN (Shared object file)",
            ET_CORE: "CORE (Core file)"}[type]
    except KeyError, err:
        if type >= ET_LOPROC:
            return "<proc: %#x>" % type
        elif type >= ET_LOOS and type <= ET_HIOS:
            return "<os: %#x>" % type
        else:
            "<unknown: %#x>" % type    
            
def elf_ver(ver):
    try:
        return {
            EV_CURRENT: "(current)",
            EV_NONE: "(none)"}[ver]
    except KeyError, err:
        return "<unknown: %#x>" % ver
        
        
SHT_NULL    =    0
SHT_PROGBITS =   1
SHT_SYMTAB   =   2
SHT_STRTAB   =   3
SHT_RELA     =   4
SHT_HASH     =   5
SHT_DYNAMIC  =   6
SHT_NOTE     =   7
SHT_NOBITS   =   8
SHT_REL      =   9
SHT_SHLIB    =   10
SHT_DYNSYM   =   11
SHT_NUM      =   12
SHT_INIT_ARRAY   =      14              # Array of constructors 
SHT_FINI_ARRAY    =     15              # Array of destructors 
SHT_PREINIT_ARRAY = 16              # Array of pre-constructors 
SHT_GROUP    =     17              # Section group 
SHT_SYMTAB_SHNDX =  18
SHT_SUNW_dof   =         0x6ffffff4
SHT_SUNW_cap      =      0x6ffffff5
SHT_SUNW_SIGNATURE =     0x6ffffff6
SHT_GNU_HASH    =        0x6ffffff6
SHT_SUNW_ANNOTATE  =     0x6ffffff7
SHT_SUNW_DEBUGSTR  =     0x6ffffff8
SHT_SUNW_DEBUG     =     0x6ffffff9
SHT_SUNW_move      =     0x6ffffffa
SHT_SUNW_COMDAT    =     0x6ffffffb
SHT_SUNW_syminfo   =     0x6ffffffc
SHT_SUNW_verdef    =     0x6ffffffd
SHT_GNU_verdef     =     0x6ffffffd      # Symbol versions provided 
SHT_SUNW_verneed   =     0x6ffffffe
SHT_GNU_verneed    =     0x6ffffffe      # Symbol versions required 
SHT_SUNW_versym    =     0x6fffffff
SHT_GNU_versym     =     0x6fffffff      # Symbol version table 
SHT_LOPROC   =   0x70000000
SHT_HIPROC   =   0x7fffffff
SHT_LOUSER   =   0x80000000
SHT_HIUSER   =   0xffffffff
SHT_MIPS_LIST    =       0x70000000
SHT_MIPS_CONFLICT   =    0x70000002
SHT_MIPS_GPTAB      =    0x70000003
SHT_MIPS_UCODE       =   0x70000004

EM_NONE    =     0
EM_M32     =     1
EM_SPARC   =     2
EM_386     =     3
EM_68K     =     4
EM_88K     =     5
EM_486     =     6       # Perhaps disused 
EM_860     =     7
EM_MIPS    =     8       # MIPS R3000 (officially, big-endian only) 
#Next two are historical and binaries and
#modules of these types will be rejected by Linux. 
EM_MIPS_RS3_LE = 10      # MIPS R3000 little-endian 
EM_MIPS_RS4_BE = 10      # MIPS R4000 big-endian 
EM_PARISC    =   15      # HPPA 
EM_SPARC32PLUS = 18      # Sun's "v8plus" 
EM_PPC        =  20      # PowerPC 
EM_PPC64      =  21      # PowerPC64
EM_SPU        =  23      # Cell BE SPU 
EM_ARM        = 40
EM_SH         =  42      # SuperH 
EM_SPARCV9    =  43      # SPARC v9 64-bit 
EM_IA_64      =  50      # HP/Intel IA-64 
EM_X86_64     =  62      # AMD x86-64 
EM_S390       =  22      # IBM S/390 
EM_CRIS       =  76      # Axis Communications 32-bit embedded processor 
EM_V850       =  87      # NEC v850 
EM_M32R       =  88      # Renesas M32R 
EM_H8_300     =  46      # Renesas H8/300,300H,H8S 
EM_MN10300    =  89      # Panasonic/MEI MN10300, AM33 
EM_BLACKFIN   =  106     # ADI Blackfin Processor 
EM_FRV        =  0x5441  # Fujitsu FR-V 
EM_AVR32      =  0x18ad  # Atmel AVR32 

def section_type(mach, stype):
    if stype >= SHT_LOPROC and stype <= SHT_HIPROC:
        if mach == EM_X86_64:
            if stype == SHT_AMD64_UNWIND: 
                return "AMD64_UNWIND"
        elif mach == EM_MIPS or mach == EM_MIPS_RS3_LE:
            try:
                return {
                    SHT_MIPS_LIBLIST: "MIPS_LIBLIST",
                    SHT_MIPS_MSYM: "MIPS_MSYM",
                    SHT_MIPS_CONFLICT:                     "MIPS_CONFLICT",
                    SHT_MIPS_GPTAB:                     "MIPS_GPTAB",
                               SHT_MIPS_UCODE:                     "MIPS_UCODE",
                               SHT_MIPS_DEBUG:                     "MIPS_DEBUG",
                               SHT_MIPS_REGINFO:                     "MIPS_REGINFO",
                               SHT_MIPS_PACKAGE:                     "MIPS_PACKAGE",
                               SHT_MIPS_PACKSYM:                     "MIPS_PACKSYM",
                               SHT_MIPS_RELD:                     "MIPS_RELD",
                               SHT_MIPS_IFACE:                     "MIPS_IFACE",
                               SHT_MIPS_CONTENT:                     "MIPS_CONTENT",
                               SHT_MIPS_OPTIONS:                     "MIPS_OPTIONS",
                               SHT_MIPS_DELTASYM:                     "MIPS_DELTASYM",
                               SHT_MIPS_DELTAINST:                     "MIPS_DELTAINST",
                               SHT_MIPS_DELTACLASS:                     "MIPS_DELTACLASS",
                               SHT_MIPS_DWARF:                     "MIPS_DWARF",
                               SHT_MIPS_DELTADECL:                     "MIPS_DELTADECL",
                               SHT_MIPS_SYMBOL_LIB:                     "MIPS_SYMBOL_LIB",
                               SHT_MIPS_EVENTS:                     "MIPS_EVENTS",
                               SHT_MIPS_TRANSLATE:                     "MIPS_TRANSLATE",
                               SHT_MIPS_PIXIE:                     "MIPS_PIXIE",
                               SHT_MIPS_XLATE:                     "MIPS_XLATE",
                               SHT_MIPS_XLATE_DEBUG:                     "MIPS_XLATE_DEBUG",
                               SHT_MIPS_WHIRL:                     "MIPS_WHIRL",
                               SHT_MIPS_EH_REGION:                     "MIPS_EH_REGION",
                               SHT_MIPS_XLATE_OLD:                     "MIPS_XLATE_OLD",
                   SHT_MIPS_PDR_EXCEPTION: "MIPS_PDR_EXCEPTION"}[stype]
            except KeyError, err:
                pass     
        return "LOPROC+%#x" % (stype - SHT_LOPROC)
    else:
        try:
            return {
                SHT_NULL: "NULL",
                SHT_PROGBITS: "PROGBITS",
                SHT_SYMTAB: "SYMTAB",
                SHT_STRTAB: "STRTAB",
                SHT_RELA: "RELA",
                SHT_HASH: "HASH",
                SHT_DYNAMIC: "DYNAMIC",
                SHT_NOTE: "NOTE",
                SHT_NOBITS: "NOBITS",
                SHT_REL: "REL",
                SHT_SHLIB: "SHLIB",
                SHT_DYNSYM: "DYNSYM",
                SHT_INIT_ARRAY: "INIT_ARRAY",
                SHT_FINI_ARRAY: "FINI_ARRAY",
                SHT_PREINIT_ARRAY: "PREINIT_ARRAY",
                SHT_GROUP: "GROUP",
                SHT_SYMTAB_SHNDX: "SYMTAB_SHNDX",
                SHT_SUNW_dof: "SUNW_dof",
                SHT_SUNW_cap: "SUNW_cap",
                SHT_GNU_HASH: "GNU_HASH",
                SHT_SUNW_ANNOTATE: "SUNW_ANNOTATE",
                SHT_SUNW_DEBUGSTR: "SUNW_DEBUGSTR",
                SHT_SUNW_DEBUG: "SUNW_DEBUG",
                SHT_SUNW_move: "SUNW_move",
                SHT_SUNW_COMDAT: "SUNW_COMDAT",
                SHT_SUNW_syminfo: "SUNW_syminfo",
                SHT_SUNW_verdef: "SUNW_verdef",
                SHT_SUNW_verneed: "SUNW_verneed",
                SHT_SUNW_versym: "SUNW_versym"}[stype]
        except KeyError, err:
            if (stype >= SHT_LOOS and stype <= SHT_HIOS):
                return "LOOS+%#x" % (stype - SHT_LOOS)
            elif (stype >= SHT_LOUSER):
                return "LOUSER+%#x" % (stype - SHT_LOUSER)
            else:
                return "<unknown: %#x>" % stype

PT_NULL  =  0
PT_LOAD  =  1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_NOTE =   4
PT_SHLIB =  5
PT_PHDR  =  6
PT_TLS = 7
PT_LOOS =    0x60000000   # OS-specific 
PT_GNU_STACK =    (PT_LOOS + 0x474e551)
PT_GNU_EH_FRAME =    (PT_LOOS + 0x474e550)
PT_SUNW_UNWIND =    0x6464e550    # amd64 UNWIND program header 
PT_GNU_RELRO =    0x6474e552
PT_LOSUNW    = 0x6ffffffa
PT_SUNWBSS =    0x6ffffffa    # Sun Specific segment 
PT_SUNWSTACK    = 0x6ffffffb    # describes the stack segment 
PT_HIOS =   0x6fffffff   # OS-specific 
PT_LOPROC = 0x70000000
PT_HIPROC  = 0x7fffffff
PT_MIPS_REGINFO    =     0x70000000
PT_MIPS_OPTIONS     =    0x70000001    
    
    
def decode_flags(mach, flags):
    decoded_flags = []
    try:
        flags_dict = {
            EM_ARM: ARM_EFLAGS_DESC,
            EM_MIPS: MIPS_EFLAGS_DESC,
            EM_SPARC: SPARC_EFLAGS_DESC}[mach]
        for key in flags_dict:
            if (flags & key) == key:
                decoded_flags.append({"value": key, "description": flags_dict[key]})
    except KeyError, err:
        pass
    return decoded_flags
        
        
    
def phdr_type(ptype):
    try:
        return {
            PT_NULL: "NULL",
            PT_LOAD: "LOAD",
            PT_DYNAMIC: "DYNAMIC",
            PT_INTERP: "INTERP",
            PT_NOTE: "NOTE",
            PT_SHLIB: "SHLIB",
            PT_PHDR: "PHDR",
            PT_TLS: "TLS",
            PT_GNU_EH_FRAME: "GNU_EH_FRAME",
            PT_GNU_STACK: "GNU_STACK",
            PT_GNU_RELRO: "GNU_RELRO"}[ptype]
    except KeyError, err:
        if ptype >= PT_LOPROC and ptype <= PT_HIPROC:
            return "LOPROC+%#x" % (ptype - PT_LOPROC)
        elif ptype >= PT_LOOS and ptype <= PT_HIOS:
            return "LOOS+%#x" % (ptype - PT_LOOS)
        else:
            return "<unknown: %#x>" % ptype

def read_elf(filename):
    """Read the information from the ELF file and return an ELF object"""
    return bintools.elf.ELF(open(filename, 'rb'))

def elf_to_data(elf):
    data = {
        "header": {
            "class": {
                 "value": elf.header.elfclass,
                 "description": ELF_CLASS[bintools.elf.ELFCLASS[elf.header.elfclass]]}, 
            "version": {
                 "value": elf.header.version,
                 "description": elf_ver(elf.header.version)},  
            "type": {
                 "value": elf.header.type,
                 "description": elf_type(elf.header.type)},
            "machine": {
                 "value": elf.header.machine,
                 "description": get_machine_name(elf.header.machine)},
            "endianess": {
                 "value": elf.endianness,
                 "description": ELF_DATA[elf.endianness]},
            "entry": elf.header.entry,
            "ph_offset": elf.header.ph_offset,
            "sh_offset": elf.header.sh_offset,
            "flags": {
                 "value": elf.header.flags,
                 "decoded_values": get_machine_flags(elf.header.flags, elf.header.machine)},
            "header_size": elf.header.header_size,
            "ph_entry_size": elf.header.ph_entry_size,
            "ph_count": elf.header.ph_count,
            "sh_entry_size": elf.header.sh_entry_size,
            "sh_count": elf.header.sh_count,
            "shstrndx": elf.header.shstrndx    
        }
    }

    if hasattr(elf.header, "osabi"):
        data["header"]["osabi"] = {
            "value": elf.header.osabi,
            "description": get_osabi_name(elf.header.osabi, elf.header)}
    
    data["program_headers"] = map(lambda x: {
           "type": {
               "value": x.type,
               "description": phdr_type(x.type)},
           "offset": x.offset,
           "virtual_address": x.vaddr,
           "physical_address": x.paddr,
           "file_size": x.filesz,
           "memory_size": x.memsz,
           "flags": x.flags,
           "align": x.align}, elf.prog_headers)
    data["sections"] = map(lambda x: {
           "index": x.index,
           "name": x.name,
           "type": {
               "value": x.type,
               "description": section_type(elf.header.machine, x.type)},
           "address": x.addr,
           "offset": x.offset,
           "size": x.size,
           "entry_size": x.entsize,
           "flags": x.flags,
           "link": x.link,
           "info": x.info,
           "align": x.addralign}, elf.sect_headers)
    
    try:     
        data["symbols"] = map(lambda x: {
           "name": x.name,
           "section": x.section,
           "bind": x.bind,
           "type": x.type,
           "value": x.value,
           "size": x.size,
           "info": x.info,
           "other": x.other}, reduce(lambda r, x: r + x.symbols, elf.sect_headers, []))
    except Exception, ex:
        data[ "symbols" ] = {"error": ex}
    
    return data

def plural_to_singular(name):
    if name.endswith('s'):
        return name[:-1]
    else:
        print "Don't know how to do the singular of '%s'" % name
        return name
        
def to_elfxml(elem, name, root):
    try:
        node = root.createElement(name)

        if isinstance(elem, dict):
            for key in elem:
                child_node = to_elfxml(elem[key], key, root)
                node.appendChild(child_node)
        elif isinstance(elem, list):
            for subelem in elem:
                child_node = to_elfxml(subelem, plural_to_singular(name), root)
                node.appendChild(child_node)
        else:
            text_node = xml.dom.minidom.Text()
            text_node.data = str(elem)
            node.appendChild(text_node)
    except Exception, e:
        print >> sys.stderr, e

    return node
             
def pprintpyReadElf(res, root, envvars=None):
    
    if len(res.keys()) == 0:
        return None
    
    readelf_node = to_elfxml(res, 'pyreadelf', root)
    return readelf_node

def main(args):
    elffile = read_elf(args.elffile)
    elf_data = elf_to_data(elffile)
    doc = xml.dom.minidom.Document()
    elf_xml = to_elfxml(elf_data, 'readelf', doc)
    doc.appendChild(elf_xml)
    print(doc.toprettyxml(indent="    ", encoding='utf-8'))

def parse_args():
    parser = argparse.ArgumentParser(description = "readelf-like tool with XML output")
    parser.add_argument("elffile", type = str, help = "ELF file to read")

    args = parser.parse_args()
    
    return args


if __name__ == "__main__":
    main(parse_args())

