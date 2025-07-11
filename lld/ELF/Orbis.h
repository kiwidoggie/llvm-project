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

typedef struct self_entry_info_t {
  uint64_t properties;
  uint64_t offset;
  uint64_t fileSize;
  uint64_t memorySize;
} self_entry_info_t, SelfEntryInfo;

std::vector<uint8_t> orbisCreateSignature(const lld::StringRef authInfo,
                                                 const uint64_t paid);

void createSelfEntries(std::vector<lld::elf::PhdrEntry *>& headerEntries,
  std::vector<self_entry_info_t>& outEntries,
  uint64_t& totalSize);

#endif //ORBIS_H

// ----- End OpenOrbis changes -----