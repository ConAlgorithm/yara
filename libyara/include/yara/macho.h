/*
Copyright (c) 2013. The YARA Authors. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <stdint.h>
#include <stdlib.h>

typedef uint8_t   BYTE;
typedef uint16_t  WORD;
typedef uint32_t  DWORD;
typedef int32_t   LONG;
typedef uint32_t  ULONG;
typedef uint64_t  ULONGLONG;


// Magics!
#define MH_MAGIC    0xfeedface
#define MH_CIGAM    0xcefaedfe
#define MH_MAGIC_64 0xfeedfacf
#define MH_CIGAM_64 0xcffaedfe
#define FAT_MAGIC   0xcafebabe
#define FAT_CIGAM   0xbebafeca 

// CPUTYPE definitions (mach/machine.h).
#define CPU_ARCH_ABI64     0x01000000
#define CPU_TYPE_ANY       0x80000001
#define CPU_TYPE_VAX       0x00000001
#define CPU_TYPE_MC680x0   0x00000006
#define CPU_TYPE_X86       0x00000007
#define CPU_TYPE_X86_64    (CPU_TYPE_X86 | CPU_ARCH_ABI64)
#define CPU_TYPE_MC98000   0x0000000a
#define CPU_TYPE_HPPA      0x0000000b
#define CPU_TYPE_ARM       0x0000000c
#define CPU_TYPE_ARM64     (CPU_TYPE_ARM | CPU_ARCH_ABI64)
#define CPU_TYPE_MC88000   0x0000000d
#define CPU_TYPE_SPARC     0x0000000e
#define CPU_TYPE_I860      0x0000000f
#define CPU_TYPE_POWERPC   0x00000012
#define CPU_TYPE_POWERPC64 (CPU_TYPE_POWERPC | CPU_ARCH_ABI64)

// Filetype definitions (mach-o/loader.h)
#define MH_OBJECT      0x00000001
#define MH_EXECUTE     0x00000004
#define MH_FVMLIB      0x00000003
#define MH_CORE        0x00000004
#define MH_PRELOAD     0x00000005
#define MH_DYLIB       0x00000006
#define MH_DYLINKER    0x00000007
#define MH_BUNDLE      0x00000008
#define MH_DYLIB_STUB  0x00000009
#define MH_DSYM        0x0000000a
#define MH_KEXT_BUNDLE 0x0000000b

// Load command definitions (mach-o/loader.h)
#define LC_REQ_DYLD                 0x80000000
#define LC_SEGMENT                  0x00000001
#define LC_SYMTAB                   0x00000002
#define LC_SYMSEG                   0x00000003
#define LC_THREAD                   0x00000004
#define LC_UNIXTHREAD               0x00000005
#define LC_LOADFVMLIB               0x00000006
#define LC_IDFVMLIB                 0x00000007
#define LC_IDENT                    0x00000008
#define LC_FVMFILE                  0x00000009
#define LC_PREPAGE                  0x0000000a
#define LC_DYSYMTAB                 0x0000000b
#define LC_LOAD_DYLIB               0x0000000c
#define LC_ID_DYLIB                 0x0000000d
#define LC_LOAD_DYLINKER            0x0000000e
#define LC_ID_DYLINKER              0x0000000f
#define LC_PREBOUND_DYLIB           0x00000010
#define LC_ROUTINES                 0x00000011
#define LC_SUB_FRAMEWORK            0x00000012
#define LC_SUB_UMBRELLA             0x00000013
#define LC_SUB_CLIENT               0x00000014
#define LC_SUB_LIBRARY              0x00000015
#define LC_TWOLEVEL_HINTS           0x00000016
#define LC_PREBIND_CKSUM            0x00000017
#define LC_LOAD_WEAK_DYLIB          (0x00000018 | LC_REQ_DYLD)
#define LC_SEGMENT_64               0x00000019
#define LC_ROUTINES_64              0x0000001a
#define LC_UUID                     0x0000001b
#define LC_RPATH                    (0x0000001c | LC_REQ_DYLD)
#define LC_CODE_SIGNATURE           0x0000001d
#define LC_SEGMENT_SPLIT_INFO       0x0000001e
#define LC_REEXPORT_DYLIB           (0x0000001f | LC_REQ_DYLD)
#define LC_LAZY_LOAD_DYLIB          0x00000020
#define LC_ENCRYPTION_INFO          0x00000021
#define LC_DYLD_INFO                0x00000022
#define LC_DYLD_INFO_ONLY           (0x00000022 | LC_REQ_DYLD)
#define LC_LOAD_UPWARD_DYLIB        (0x00000023 | LC_REQ_DYLD)
#define LC_VERSION_MIN_MACOSX       0x00000024
#define LC_VERSION_MIN_IPHONEOS     0x00000025
#define LC_FUNCTION_STARTS          0x00000026
#define LC_DYLD_ENVIRONMENT         0x00000027
#define LC_MAIN                     (0x00000028 | LC_REQ_DYLD)
#define LC_DATA_IN_CODE             0x00000029
#define LC_SOURCE_VERSION           0x0000002a
#define LC_DYLIB_CODE_SIGN_DRS      0x0000002b
#define LC_ENCRYPTION_INFO_64       0x0000002c
#define LC_LINKER_OPTION            0x0000002d
#define LC_LINKER_OPTIMIZATION_HINT 0x0000002e

#define endianswap(n) \
    (((((uint32_t)(n) & 0xFF)) << 24) | \
     ((((uint32_t)(n) & 0xFF00)) << 8) | \
     ((((uint32_t)(n) & 0xFF0000)) >> 8) | \
     ((((uint32_t)(n) & 0xFF000000)) >> 24))

// All fields are always in big endian in this structure.
typedef struct _FAT_HEADER
{
  DWORD magic;
  DWORD nfat_arch;
} FAT_HEADER, *PFAT_HEADER;

// All fields are always in big endian in this structure.
// The cputype and cpusubyte fields are ignored for our purposes.
// As they are repeated in the actual MACHO_HEADER32 or MACHO_HEADER64
// structure. They exist in this structure for the loader to decide if
// it should follow the offset or not.
typedef struct _FAT_ARCH
{
  LONG cputype;
  LONG cpusubtype;
  DWORD offset;
  DWORD size;
  DWORD align;
} FAT_ARCH, *PFAT_ARCH;

typedef struct _MACHO_HEADER32
{
  DWORD magic;
  LONG cputype;
  LONG cpusubtype;
  DWORD filetype;
  DWORD ncmds;
  DWORD sizeofcmds;
  DWORD flags;
} MACHO_HEADER32, *PMACHO_HEADER32;

// Identical to 32bit header, just an extra DWORD that is reserved.
typedef struct _MACHO_HEADER64
{
  DWORD magic;
  LONG cputype;
  LONG cpusubtype;
  DWORD filetype;
  DWORD ncmds;
  DWORD sizeofcmds;
  DWORD flags;
  DWORD reserved;
} MACHO_HEADER64, *PMACHO_HEADER64;

typedef struct _LOAD_COMMAND
{
  DWORD cmd;
  DWORD cmd_size;
} LOAD_COMMAND, *PLOAD_COMMAND;
