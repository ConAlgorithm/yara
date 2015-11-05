/*
Copyright (c) 2015. The YARA Authors. All Rights Reserved.

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


#include <yara/modules.h>
#include <yara/mem.h>

#include "yara/macho.h"

#define MODULE_NAME macho

// This is used internally to track load commands.
typedef struct _LC
{
  DWORD cmd;
  struct _LC *next;
} LC, *PLC;

typedef struct _MACHO
{
  YR_OBJECT* object;
  PLC load_commands;
  uint32_t resources;
} MACHO;

begin_declarations;

  // CPU types
  declare_integer("CPU_TYPE_X86");
  declare_integer("CPU_TYPE_X86_64");

  // File types
  declare_integer("MH_OBJECT");
  declare_integer("MH_EXECUTE");
  declare_integer("MH_FVMLIB");
  declare_integer("MH_CORE");
  declare_integer("MH_PRELOAD");
  declare_integer("MH_DYLIB");
  declare_integer("MH_DYLINKER");
  declare_integer("MH_BUNDLE");
  declare_integer("MH_DYLIB_STUB");
  declare_integer("MH_DSYM");
  declare_integer("MH_KEXT_BUNDLE");

  // Load commands
  declare_integer("LC_SEGMENT")
  declare_integer("LC_SYMTAB")
  declare_integer("LC_SYMSEG")
  declare_integer("LC_THREAD")
  declare_integer("LC_UNIXTHREAD")
  declare_integer("LC_LOADFVMLIB")
  declare_integer("LC_IDFVMLIB")
  declare_integer("LC_IDENT")
  declare_integer("LC_FVMFILE")
  declare_integer("LC_PREPAGE")
  declare_integer("LC_DYSYMTAB")
  declare_integer("LC_LOAD_DYLIB")
  declare_integer("LC_ID_DYLIB")
  declare_integer("LC_LOAD_DYLINKER")
  declare_integer("LC_ID_DYLINKER")
  declare_integer("LC_PREBOUND_DYLIB")
  declare_integer("LC_ROUTINES")
  declare_integer("LC_SUB_FRAMEWORK")
  declare_integer("LC_SUB_UMBRELLA")
  declare_integer("LC_SUB_CLIENT")
  declare_integer("LC_SUB_LIBRARY")
  declare_integer("LC_TWOLEVEL_HINTS")
  declare_integer("LC_PREBIND_CKSUM")
  declare_integer("LC_LOAD_WEAK_DYLIB")
  declare_integer("LC_SEGMENT_64")
  declare_integer("LC_ROUTINES_64")
  declare_integer("LC_UUID")
  declare_integer("LC_RPATH")
  declare_integer("LC_CODE_SIGNATURE")
  declare_integer("LC_SEGMENT_SPLIT_INFO")
  declare_integer("LC_REEXPORT_DYLIB")
  declare_integer("LC_LAZY_LOAD_DYLIB")
  declare_integer("LC_ENCRYPTION_INFO")
  declare_integer("LC_DYLD_INFO")
  declare_integer("LC_DYLD_INFO_ONLY")
  declare_integer("LC_LOAD_UPWARD_DYLIB")
  declare_integer("LC_VERSION_MIN_MACOSX")
  declare_integer("LC_VERSION_MIN_IPHONEOS")
  declare_integer("LC_FUNCTION_STARTS")
  declare_integer("LC_DYLD_ENVIRONMENT")
  declare_integer("LC_MAIN")
  declare_integer("LC_DATA_IN_CODE")
  declare_integer("LC_SOURCE_VERSION")
  declare_integer("LC_DYLIB_CODE_SIGN_DRS")
  declare_integer("LC_ENCRYPTION_INFO_64")
  declare_integer("LC_LINKER_OPTION")
  declare_integer("LC_LINKER_OPTIMIZATION_HINT")

  // Magic will be either "64bit", "32bit" or "universal"
  // Internally we use the word "fat" in place of universal. That is
  // what the documentation uses everywhere.
  //
  // This could be removed, but it's conventient to be able to write a
  // rule that says:
  //
  //   condition:
  //     macho.magic == "32bit"
  //
  // instead of:
  //
  //   condition:
  //     macho.number_of_archs == 1 and macho.archs[0].magic == "32bit"
  //
  // The former is an easier way of finding a 32bit non-universal file
  // compared to the latter.
  //
  // If you don't care if it is universal or not, but just care that it
  // contains a 32bit binary you can use:
  //
  //   condition:
  //     for any i in (0..macho.number_of_archs):
  //       (macho.archs[i].magic == "32bit")
  declare_string("magic");

  // This is the number of architectures within the binary. All entries are
  // stored in an array of structs, even for non-fat binaries.
  declare_integer("number_of_archs");
  begin_struct_array("archs");
    declare_string("magic");
    declare_integer("cpu_type");
    declare_integer("cpu_subtype");
    declare_integer("filetype");
    declare_integer("number_of_commands");
    declare_integer("flags");
  end_struct_array("archs");

  // Every load command, even for universal binaries, is stored in here.
  begin_struct_array("load_commands");
    declare_integer("command");
  end_struct_array("load_commands");

end_declarations;


int module_initialize(
    YR_MODULE* module)
{
  return ERROR_SUCCESS;
}


int module_finalize(
    YR_MODULE* module)
{
  return ERROR_SUCCESS;
}


// Except for the reserved DWORD on the end the 32bit and 64bit version
// of the headers are identical.
void macho_parse_header32(
    PMACHO_HEADER32 header,
    YR_OBJECT* module_object,
    uint32_t entry)
{
  set_string("32bit", module_object, "archs[%i].magic", entry);
  set_integer(header->cputype, module_object, "archs[%i].cpu_type", entry);
  set_integer(header->cpusubtype, module_object, "archs[%i].cpu_subtype", entry);
  set_integer(header->filetype, module_object, "archs[%i].filetype", entry);
  set_integer(header->ncmds, module_object, "archs[%i].number_of_commands", entry);
  set_integer(header->flags, module_object, "archs[%i].flags", entry);
}


void macho_parse_header64(
    PMACHO_HEADER64 header,
    YR_OBJECT* module_object,
    uint32_t entry)
{
  set_string("64bit", module_object, "archs[%i].magic", entry);
  set_integer(header->cputype, module_object, "archs[%i].cpu_type", entry);
  set_integer(header->cpusubtype, module_object, "archs[%i].cpu_subtype", entry);
  set_integer(header->filetype, module_object, "archs[%i].filetype", entry);
  set_integer(header->ncmds, module_object, "archs[%i].number_of_commands", entry);
  set_integer(header->flags, module_object, "archs[%i].flags", entry);
}


void macho_set_constants(
    YR_OBJECT* module_object)
{
  // XXX: Finish cputype, cpusubtype and other header fields.
  set_integer(CPU_TYPE_X86, module_object, "CPU_TYPE_X86");
  set_integer(CPU_TYPE_X86_64, module_object, "CPU_TYPE_X86_64");

  // Filetypes
  set_integer(MH_OBJECT, module_object, "MH_OBJECT");
  set_integer(MH_EXECUTE, module_object, "MH_EXECUTE");
  set_integer(MH_FVMLIB, module_object, "MH_FVMLIB");
  set_integer(MH_CORE, module_object, "MH_CORE");
  set_integer(MH_PRELOAD, module_object, "MH_PRELOAD");
  set_integer(MH_DYLIB, module_object, "MH_DYLIB");
  set_integer(MH_DYLINKER, module_object, "MH_DYLINKER");
  set_integer(MH_BUNDLE, module_object, "MH_BUNDLE");
  set_integer(MH_DYLIB_STUB, module_object, "MH_DYLIB_STUB");
  set_integer(MH_DSYM, module_object, "MH_DSYM");
  set_integer(MH_KEXT_BUNDLE, module_object, "MH_KEXT_BUNDLE");

  // Load commands
  set_integer(LC_SEGMENT, module_object, "LC_SEGMENT");
  set_integer(LC_SYMTAB, module_object, "LC_SYMTAB");
  set_integer(LC_SYMSEG, module_object, "LC_SYMSEG");
  set_integer(LC_THREAD, module_object, "LC_THREAD");
  set_integer(LC_UNIXTHREAD, module_object, "LC_UNIXTHREAD");
  set_integer(LC_LOADFVMLIB, module_object, "LC_LOADFVMLIB");
  set_integer(LC_IDFVMLIB, module_object, "LC_IDFVMLIB");
  set_integer(LC_IDENT, module_object, "LC_IDENT");
  set_integer(LC_FVMFILE, module_object, "LC_FVMFILE");
  set_integer(LC_PREPAGE, module_object, "LC_PREPAGE");
  set_integer(LC_DYSYMTAB, module_object, "LC_DYSYMTAB");
  set_integer(LC_LOAD_DYLIB, module_object, "LC_LOAD_DYLIB");
  set_integer(LC_ID_DYLIB, module_object, "LC_ID_DYLIB");
  set_integer(LC_LOAD_DYLINKER, module_object, "LC_LOAD_DYLINKER");
  set_integer(LC_ID_DYLINKER, module_object, "LC_ID_DYLINKER");
  set_integer(LC_PREBOUND_DYLIB, module_object, "LC_PREBOUND_DYLIB");
  set_integer(LC_ROUTINES, module_object, "LC_ROUTINES");
  set_integer(LC_SUB_FRAMEWORK, module_object, "LC_SUB_FRAMEWORK");
  set_integer(LC_SUB_UMBRELLA, module_object, "LC_SUB_UMBRELLA");
  set_integer(LC_SUB_CLIENT, module_object, "LC_SUB_CLIENT");
  set_integer(LC_SUB_LIBRARY, module_object, "LC_SUB_LIBRARY");
  set_integer(LC_TWOLEVEL_HINTS, module_object, "LC_TWOLEVEL_HINTS");
  set_integer(LC_PREBIND_CKSUM, module_object, "LC_PREBIND_CKSUM");
  set_integer(LC_LOAD_WEAK_DYLIB, module_object, "LC_LOAD_WEAK_DYLIB");
  set_integer(LC_SEGMENT_64, module_object, "LC_SEGMENT_64");
  set_integer(LC_ROUTINES_64, module_object, "LC_ROUTINES_64");
  set_integer(LC_UUID, module_object, "LC_UUID");
  set_integer(LC_RPATH, module_object, "LC_RPATH");
  set_integer(LC_CODE_SIGNATURE, module_object, "LC_CODE_SIGNATURE");
  set_integer(LC_SEGMENT_SPLIT_INFO, module_object, "LC_SEGMENT_SPLIT_INFO");
  set_integer(LC_REEXPORT_DYLIB, module_object, "LC_REEXPORT_DYLIB");
  set_integer(LC_LAZY_LOAD_DYLIB, module_object, "LC_LAZY_LOAD_DYLIB");
  set_integer(LC_ENCRYPTION_INFO, module_object, "LC_ENCRYPTION_INFO");
  set_integer(LC_DYLD_INFO, module_object, "LC_DYLD_INFO");
  set_integer(LC_DYLD_INFO_ONLY, module_object, "LC_DYLD_INFO_ONLY");
  set_integer(LC_LOAD_UPWARD_DYLIB, module_object, "LC_LOAD_UPWARD_DYLIB");
  set_integer(LC_VERSION_MIN_MACOSX, module_object, "LC_VERSION_MIN_MACOSX");
  set_integer(LC_VERSION_MIN_IPHONEOS, module_object, "LC_VERSION_MIN_IPHONEOS");
  set_integer(LC_FUNCTION_STARTS, module_object, "LC_FUNCTION_STARTS");
  set_integer(LC_DYLD_ENVIRONMENT, module_object, "LC_DYLD_ENVIRONMENT");
  set_integer(LC_MAIN, module_object, "LC_MAIN");
  set_integer(LC_DATA_IN_CODE, module_object, "LC_DATA_IN_CODE");
  set_integer(LC_SOURCE_VERSION, module_object, "LC_SOURCE_VERSION");
  set_integer(LC_DYLIB_CODE_SIGN_DRS, module_object, "LC_DYLIB_CODE_SIGN_DRS");
  set_integer(LC_ENCRYPTION_INFO_64, module_object, "LC_ENCRYPTION_INFO_64");
  set_integer(LC_LINKER_OPTION, module_object, "LC_LINKER_OPTION");
  set_integer(LC_LINKER_OPTIMIZATION_HINT, module_object, "LC_LINKER_OPTIMIZATION_HINT");
}

PLC load_command_parser(PLOAD_COMMAND lc)
{
  switch(lc->cmd)
  {
    case LC_REQ_DYLD:
      break;
    case LC_SEGMENT:
      printf("LC_SEGMENT (%d)\n", lc->cmd_size);
      break;
    case LC_SYMTAB:
      break;
    case LC_SYMSEG:
      break;
    case LC_THREAD:
      break;
    case LC_UNIXTHREAD:
      break;
    case LC_LOADFVMLIB:
      break;
    case LC_IDFVMLIB:
      break;
    case LC_IDENT:
      break;
    case LC_FVMFILE:
      break;
    case LC_PREPAGE:
      break;
    case LC_DYSYMTAB:
      break;
    case LC_LOAD_DYLIB:
      break;
    case LC_ID_DYLIB:
      break;
    case LC_LOAD_DYLINKER:
      break;
    case LC_ID_DYLINKER:
      break;
    case LC_PREBOUND_DYLIB:
      break;
    case LC_ROUTINES:
      break;
    case LC_SUB_FRAMEWORK:
      break;
    case LC_SUB_UMBRELLA:
      break;
    case LC_SUB_CLIENT:
      break;
    case LC_SUB_LIBRARY:
      break;
    case LC_TWOLEVEL_HINTS:
      break;
    case LC_PREBIND_CKSUM:
      break;
    case LC_LOAD_WEAK_DYLIB:
      break;
    case LC_SEGMENT_64:
      printf("LC_SEGMENT_64 (%d)\n", lc->cmd_size);
      break;
    case LC_ROUTINES_64:
      break;
    case LC_UUID:
      break;
    case LC_RPATH:
      break;
    case LC_CODE_SIGNATURE:
      break;
    case LC_SEGMENT_SPLIT_INFO:
      break;
    case LC_REEXPORT_DYLIB:
      break;
    case LC_LAZY_LOAD_DYLIB:
      break;
    case LC_ENCRYPTION_INFO:
      break;
    case LC_DYLD_INFO:
      break;
    case LC_DYLD_INFO_ONLY:
      break;
    case LC_LOAD_UPWARD_DYLIB:
      break;
    case LC_VERSION_MIN_MACOSX:
      break;
    case LC_VERSION_MIN_IPHONEOS:
      break;
    case LC_FUNCTION_STARTS:
      break;
    case LC_DYLD_ENVIRONMENT:
      break;
    case LC_MAIN:
      break;
    case LC_DATA_IN_CODE:
      break;
    case LC_SOURCE_VERSION:
      break;
    case LC_DYLIB_CODE_SIGN_DRS:
      break;
    case LC_ENCRYPTION_INFO_64:
      break;
    case LC_LINKER_OPTION:
      break;
    case LC_LINKER_OPTIMIZATION_HINT:
      break;
    default:
      return NULL;
  }

  return NULL;
}

void macho_parse_load_commands(
    uint8_t* data,
    size_t size,
    DWORD ncmds,
    YR_OBJECT* module_object)
{
  uint8_t* offset;
  //MACHO* macho = module_object->data;
  PLC head = NULL;

  // Make sure we have enough data.
  if (size < sizeof(LOAD_COMMAND) * ncmds)
    return;

  offset = data;
  for (uint32_t i = 1; i <= ncmds; i++)
  {
    PLOAD_COMMAND lc = (PLOAD_COMMAND) offset;
    set_integer(lc->cmd, module_object, "load_commands[%i].command", i);

    PLC lc_node = load_command_parser(lc);
    if (lc_node == NULL)
    {
      // Move forward by cmd_size
      offset += lc->cmd_size;
      if (offset + lc->cmd_size + sizeof(LOAD_COMMAND) > data + size)
        return;
      continue;
    }

    if (head == NULL)
      head = lc_node;

    // Move forward by cmd_size
    offset += lc->cmd_size;
    if (offset + lc->cmd_size + sizeof(LOAD_COMMAND) > data + size)
      return;
  }
}


// Parse the data for each block. In the case of universal binaries this
// function is called recursively with each arch offset and size.
void macho_parse_block(
    uint8_t* data,
    size_t size,
    YR_OBJECT* module_object,
    uint32_t entry)
{
  // Read the first 4 bytes, to determine what kind of header this is.
  // 32bit and 64bit headers are parsed with macho_parse_header() while
  // fat headers are parsed here.
  if (size < sizeof(DWORD))
    return;

  DWORD magic = *(DWORD*) data;
  if (magic == MH_MAGIC || magic == MH_CIGAM)
  {
    if (size < sizeof(MACHO_HEADER32))
      return;

    if (entry == 0)
    {
      set_string("32bit", module_object, "magic");
      set_integer(1, module_object, "number_of_archs");
      set_string("32bit", module_object, "archs[%i].magic", entry);
    }
    else
    {
      set_string("32bit", module_object, "archs[%i].magic", entry - 1);
    }
    PMACHO_HEADER32 header = (PMACHO_HEADER32) data;
    macho_parse_header32(header, module_object, entry);
    DWORD ncmds = header->ncmds;
    // Move to load commands
    header += 1;
    macho_parse_load_commands((uint8_t*) header,
                              size,
                              ncmds,
                              module_object);
  }
  else if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64)
  {
    if (size < sizeof(MACHO_HEADER64))
      return;

    if (entry == 0)
    {
      set_string("64bit", module_object, "magic");
      set_integer(1, module_object, "number_of_archs");
      set_string("64bit", module_object, "archs[%i].magic", entry);
    }
    else
    {
      set_string("64bit", module_object, "archs[%i].magic", entry - 1);
    }
    PMACHO_HEADER64 header = (PMACHO_HEADER64) data;
    macho_parse_header64(header, module_object, entry);
    DWORD ncmds = header->ncmds;
    // Move to load commands
    header += 1;
    macho_parse_load_commands((uint8_t*) header,
                              size,
                              ncmds,
                              module_object);
  }
  else if (magic == FAT_MAGIC || magic == FAT_CIGAM)
  {
    // Make sure we don't recurse with multiple fat entries (fat-ception!)
    if (entry > 0)
      return;

    if (size < sizeof(FAT_HEADER))
      return;

    set_string("universal", module_object, "magic");
    PFAT_HEADER header = (PFAT_HEADER) data;
    // This value is always in big endian format.
    // If we are running on a little endian system, swap it.
    DWORD nfat_arch;
    if (header->magic == FAT_CIGAM)
      nfat_arch = endianswap(header->nfat_arch);
    else
      nfat_arch = header->nfat_arch;
    set_integer(nfat_arch, module_object, "number_of_archs");
    // After this header is an array of FAT_ARCH structures.
    PFAT_ARCH fat_arch = (PFAT_ARCH) (data + sizeof(FAT_HEADER));
    // Counter starts at one because if it is 32bit or 64bit it will
    // decrement and store in the appropriate spot in the array.
    for (uint32_t i = 1; i <= nfat_arch; i++)
    {
      if ((uint8_t*) (fat_arch) + sizeof(FAT_ARCH) <= data)
        break;

      // Get offset and size for this arch.
      uint32_t offset;
      uint32_t new_size;
      if (header->magic == FAT_CIGAM)
      {
        offset = endianswap(fat_arch->offset);
        new_size = endianswap(fat_arch->size);
      }
      else
      {
        offset = fat_arch->offset;
        new_size = fat_arch->size;
      }

      // Make sure offset and new_size are within bounds and parse it.
      if (data + offset > data + size ||
          data + offset + new_size > data + size)
        break;

      macho_parse_block(data + offset, new_size, module_object, i);
      fat_arch += 1;
    }
  }
}


int module_load(
    YR_SCAN_CONTEXT* context,
    YR_OBJECT* module_object,
    void* module_data,
    size_t module_data_size)
{
  YR_MEMORY_BLOCK* block;

  macho_set_constants(module_object);

  MACHO* macho = (MACHO*) yr_malloc(sizeof(MACHO));
  if (macho == NULL)
    return ERROR_INSUFICIENT_MEMORY;

  module_object->data = macho;

  foreach_memory_block(context, block)
  {
    macho_parse_block(block->data, block->size, module_object, 0);
    break;
  }
  return ERROR_SUCCESS;
}


int module_unload(
    YR_OBJECT* module_object)
{
  yr_free(module_object->data);
  return ERROR_SUCCESS;
}
