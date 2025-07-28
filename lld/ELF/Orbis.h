// ----- Start OpenOrbis changes -----

#ifndef ORBIS_H
#define ORBIS_H

#include "lld/Common/LLVM.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace lld::elf {
struct PhdrEntry;
}

constexpr auto SELF_ENTRY_PROPERTY_BIT_SIGNED = 2;
constexpr auto SELF_ENTRY_PROPERTY_BIT_HASBLOCKS = 11;
constexpr auto SELF_ENTRY_PROPERTY_BIT_BLOCKSIZE = 12;
constexpr auto SELF_ENTRY_PROPERTY_BIT_HASDIGESTS = 16;
constexpr auto SELF_ENTRY_PROPERTY_BIT_SEGMENT_INDEX = 20;
constexpr auto BLOCK_SIZE = 0x4000;
constexpr auto SELF_META_DATA_BLOCK_SIZE = 0x20;
constexpr auto ORBIS_SIGNATURE_SIZE = 0x100;

constexpr auto SELF_HEADER_SIZE = 0x20;
constexpr auto SELF_ELF_HEADER_SIZE = 0x40;
constexpr auto SELF_EXTENDED_HEADER_SIZE = 0x40;
constexpr auto SELF_NPDRM_BLOCK_SIZE = 0x30;

constexpr auto SELF_ENTRY_SIZE = 0x50;
constexpr auto SELF_META_FOOTER_SIZE = 0x50;
constexpr auto SELF_META_BLOCK_SIZE = 0x50;
constexpr auto SELF_SIGNATURE_SIZE = 0x100;

constexpr auto SELF_MODE_SPECIFICUSER = 0x1;
constexpr auto SELF_DATA_LSB = 0x1;
constexpr auto SELF_MAGIC_SELF = 0x1D3D154F;
constexpr auto SELF_CONTROL_BLOCK_TYPE_NPDRM = 0x3;
constexpr auto SELF_ELF_PROGHEADER_SIZE = 0x38;

constexpr auto SELF_PTYPE_FAKE = 0x1;
constexpr auto  SELF_PTYPE_NPDRM_EXEC = 0x4;
constexpr auto  SELF_PTYPE_NPDRM_DYNLIB = 0x5;
constexpr auto  SELF_PTYPE_SYSTEM_EXEC = 0x8;
constexpr auto  SELF_PTYPE_SYSTEM_DYNLIB = 0x9;
constexpr auto  SELF_PTYPE_HOST_KERNEL = 0xC;
constexpr auto  SELF_PTYPE_SECURE_MODULE = 0xE;
constexpr auto  SELF_PTYPE_SECURE_KERNEL = 0xF;

inline std::map<std::string, int> OrbisProgramTypeMap =
{
  {"npdrm_exec", SELF_PTYPE_NPDRM_EXEC},
  {"npdrm_dynlib", SELF_PTYPE_NPDRM_DYNLIB},
  {"system_exec", SELF_PTYPE_SYSTEM_EXEC},
  {"system_dynlib", SELF_PTYPE_SYSTEM_DYNLIB},
  {"host_kernel", SELF_PTYPE_HOST_KERNEL},
  {"secure_module", SELF_PTYPE_SECURE_MODULE},
  {"secure_kernel", SELF_PTYPE_SECURE_KERNEL}
};

typedef struct self_entry_t {
  uint32_t props;
  uint32_t reserved;
  uint64_t offset;
  uint64_t filesz;
  uint64_t memsz;
} self_entry_t, SelfEntry;
static_assert(offsetof(struct self_entry_t, props) == 0x00);
static_assert(offsetof(struct self_entry_t, offset) == 0x08);
static_assert(offsetof(struct self_entry_t, filesz) == 0x10);
static_assert(offsetof(struct self_entry_t, memsz) == 0x18);
static_assert(sizeof(struct self_entry_t) == 0x20);

typedef struct self_header_t {
  uint32_t magic;
  uint8_t version;
  uint8_t mode;
  uint8_t endian;
  uint8_t attr;
  uint32_t key_type;
  uint16_t header_size;
  uint16_t meta_size;
  uint64_t file_size;
  uint16_t num_entries;
  uint16_t flags;
  uint32_t reserved;
  self_entry_t entries[0];
} self_header_t, SelfHeader;

typedef struct self_auth_info_t {
  uint64_t paid;
  uint64_t caps[4];
  uint64_t attrs[4];
  uint8_t unk[0x40];
} self_auth_info_t, SelfAuthInfo;
static_assert(offsetof(struct self_auth_info_t, paid) == 0x00);
static_assert(offsetof(struct self_auth_info_t, caps) == 0x08);
static_assert(offsetof(struct self_auth_info_t, attrs) == 0x28);
static_assert(offsetof(struct self_auth_info_t, unk) == 0x48);
static_assert(sizeof(struct self_auth_info_t) == 0x88);

typedef struct self_ex_info_t {
  uint64_t paid;
  uint64_t ptype;
  uint64_t app_version;
  uint64_t firmware_version;
  uint8_t digest[0x20];
} self_ex_info_t, SelfExInfo;
static_assert(offsetof(struct self_ex_info_t, paid) == 0x00);
static_assert(offsetof(struct self_ex_info_t, ptype) == 0x08);
static_assert(offsetof(struct self_ex_info_t, app_version) == 0x10);
static_assert(offsetof(struct self_ex_info_t, firmware_version) == 0x18);
static_assert(offsetof(struct self_ex_info_t, digest) == 0x20);
static_assert(sizeof(struct self_ex_info_t) == 0x40);

typedef struct self_npdrm_control_block_t {
  uint16_t type;
  uint8_t unknown[0xE];
  uint8_t content_id[0x13];
  uint8_t random_pad[0xD];
} self_npdrm_control_block_t, SelfNpdrmControlBlock;
static_assert(offsetof(struct self_npdrm_control_block_t, type) == 0x00);
static_assert(offsetof(struct self_npdrm_control_block_t, unknown) == 0x2);
static_assert(offsetof(struct self_npdrm_control_block_t, content_id) == 0x10);
static_assert(offsetof(struct self_npdrm_control_block_t, random_pad) == 0x23);
static_assert(sizeof(struct self_npdrm_control_block_t) == 0x30);

typedef struct self_entry_info_t {
  uint8_t* data;
  uint64_t properties;
  uint64_t offset;
  uint64_t fileSize;
  uint64_t memorySize;
} self_entry_info_t, SelfEntryInfo;

std::vector<uint8_t> orbis_createSignature(const lld::StringRef authInfo,
                                                 const uint64_t paid);

/**
 * Creates a new self_entry_info_t for each program header, as well
 * as for the metadata entry for each program header.
 *
 * @param headerEntries Incoming program headers
 * @param outEntries Output self_entry_info_t's
 * @return Total size of all output self_entry_info_t's
 */
uint64_t orbis_createSelfEntries(std::vector<lld::elf::PhdrEntry *>& headerEntries,
  std::vector<self_entry_info_t>& outEntries);

uint64_t orbis_writeSelfHeader(llvm::raw_svector_ostream& writer,
  const uint8_t version, const uint8_t mode,
  const uint8_t endian, const uint8_t attr, const uint16_t headerSize,
  const uint64_t fileSize, const uint16_t flags, const uint16_t metaSize,
  const uint16_t numSelfEntries);

uint64_t orbis_writeSelfEntries(llvm::raw_svector_ostream& writer,
  const std::vector<self_entry_info_t>& entries);

uint64_t orbis_writeELFHeaders(llvm::raw_svector_ostream& writer,
  const llvm::ArrayRef<uint8_t>& inputElfData);

uint64_t orbis_writeExtendedInfo(llvm::raw_svector_ostream& writer,
  const std::string pType, const uint64_t paid, const uint64_t appVersion,
  const uint64_t firmwareVersion, const std::array<uint8_t, 32>& digest);

uint64_t orbis_writeNpdrmControlBlock(llvm::raw_svector_ostream& writer);

/**
 * writeMetaBlocks takes a given file and writes a list of MetaBlocks for each
 * SelfEntry to it. Currently, these blocks contain null data
 * @param writer Writer
 * @param numSelfEntries Number of selfEntries
 * @return Size of bytes written
 */
uint64_t orbis_writeMetaBlocks(llvm::raw_svector_ostream& writer,
  const uint64_t numSelfEntries);

uint64_t orbis_writeMetaFooter(llvm::raw_svector_ostream& writer,
  const uint32_t value);

uint64_t orbis_writeSignature(llvm::raw_svector_ostream& writer,
  const std::vector<uint8_t>& signature);

uint64_t orbis_writeSegments(llvm::raw_svector_ostream& writer,
  const std::vector<self_entry_info_t>& entries);

/**
 * Write's aligned null bytes to the writer, it takes the input size
 * finds the number of bytes to write to align in the input size to the
 * alignment
 *
 * @param writer Opened llvm::raw_svector_ostream
 * @param size Input size
 * @param alignment Input Alignment
 * @return Total amount of bytes written
 */
uint64_t orbis_writeNullPadding(llvm::raw_svector_ostream & writer,
  const uint64_t size, const uint32_t alignment);

constexpr uint64_t orbis_setProperty(const uint64_t property,
  const uint64_t bit, const uint64_t mask, const uint64_t val);

void orbis_create_self();

#endif //ORBIS_H

// ----- End OpenOrbis changes -----