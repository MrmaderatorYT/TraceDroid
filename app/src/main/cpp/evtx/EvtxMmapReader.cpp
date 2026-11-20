// TraceDroid - offline DFIR / SOC triage for Android.
// Copyright (C) CyberCraft Studio. GNU GPL v3.0 or later.
#include "evtx/EvtxMmapReader.hpp"

#include <array>
#include <cerrno>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

namespace td::evtx {

namespace {

constexpr char kFileMagic[8] = {'E', 'l', 'f', 'F', 'i', 'l', 'e', '\0'};
constexpr char kChunkMagic[8] = {'E', 'l', 'f', 'C', 'h', 'n', 'k', '\0'};
constexpr uint32_t kRecordMagic = 0x00002A2A;  // "**\0\0"

constexpr std::array<uint32_t, 256> makeCrcTable() {
    std::array<uint32_t, 256> t{};
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t c = i;
        for (int k = 0; k < 8; ++k) c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        t[i] = c;
    }
    return t;
}
constexpr auto kCrcTable = makeCrcTable();

}  // namespace

uint32_t crc32(const uint8_t* data, size_t size, uint32_t seed) {
    uint32_t c = ~seed;
    for (size_t i = 0; i < size; ++i) c = kCrcTable[(c ^ data[i]) & 0xFF] ^ (c >> 8);
    return ~c;
}

// ---------------------------------------------------------------- MappedFile

MappedFile::MappedFile(const std::string& path) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) throw ParseError("cannot open " + path + ": " + std::strerror(errno));
    mapFd(fd);
}

MappedFile MappedFile::fromFd(int fd) {
    MappedFile f;
    f.mapFd(fd);
    return f;
}

void MappedFile::mapFd(int fd) {
    struct stat st {};
    if (::fstat(fd, &st) != 0) {
        const int e = errno;
        ::close(fd);
        throw ParseError(std::string("fstat failed: ") + std::strerror(e));
    }
    if (st.st_size <= 0) {
        ::close(fd);
        throw ParseError("file is empty or not a regular file");
    }
    void* p = ::mmap(nullptr, static_cast<size_t>(st.st_size), PROT_READ, MAP_PRIVATE, fd, 0);
    const int e = errno;
    ::close(fd);  // the mapping keeps its own reference
    if (p == MAP_FAILED) throw ParseError(std::string("mmap failed: ") + std::strerror(e));
    data_ = static_cast<const uint8_t*>(p);
    size_ = static_cast<size_t>(st.st_size);
    ::madvise(p, size_, MADV_SEQUENTIAL);
}

void MappedFile::reset() noexcept {
    if (data_) ::munmap(const_cast<uint8_t*>(data_), size_);
    data_ = nullptr;
    size_ = 0;
}

MappedFile::~MappedFile() { reset(); }

MappedFile::MappedFile(MappedFile&& o) noexcept : data_(o.data_), size_(o.size_) {
    o.data_ = nullptr;
    o.size_ = 0;
}

MappedFile& MappedFile::operator=(MappedFile&& o) noexcept {
    if (this != &o) {
        reset();
        data_ = o.data_;
        size_ = o.size_;
        o.data_ = nullptr;
        o.size_ = 0;
    }
    return *this;
}

void MappedFile::release(size_t offset, size_t len) const noexcept {
    if (!data_ || offset >= size_) return;
    if (len > size_ - offset) len = size_ - offset;
    const auto page = static_cast<size_t>(::sysconf(_SC_PAGESIZE));
    const size_t start = (offset + page - 1) / page * page;
    const size_t end = (offset + len) / page * page;
    if (end > start) ::madvise(const_cast<uint8_t*>(data_) + start, end - start, MADV_DONTNEED);
}

// ---------------------------------------------------------------- EvtxMmapReader

EvtxMmapReader::EvtxMmapReader(const std::string& path) : file_(path) { parseHeader(); }
EvtxMmapReader::EvtxMmapReader(MappedFile file) : file_(std::move(file)) { parseHeader(); }

void EvtxMmapReader::parseHeader() {
    const uint8_t* p = file_.data();
    if (file_.size() < kFileHeaderBlockSize || std::memcmp(p, kFileMagic, sizeof kFileMagic) != 0)
        throw ParseError("not an EVTX file (missing ElfFile signature)");

    header_.firstChunkNumber = loadLe<uint64_t>(p + 8);
    header_.lastChunkNumber = loadLe<uint64_t>(p + 16);
    header_.nextRecordId = loadLe<uint64_t>(p + 24);
    header_.headerSize = loadLe<uint32_t>(p + 32);
    header_.minorVersion = loadLe<uint16_t>(p + 36);
    header_.majorVersion = loadLe<uint16_t>(p + 38);
    header_.headerBlockSize = loadLe<uint16_t>(p + 40);
    header_.chunkCount = loadLe<uint16_t>(p + 42);
    header_.flags = loadLe<uint32_t>(p + 120);
    header_.checksum = loadLe<uint32_t>(p + 124);
    header_.checksumValid = crc32(p, 120) == header_.checksum;

    if (header_.majorVersion != 3) throw ParseError("unsupported EVTX major version");
    // The header block is 4096 bytes in every known version, but honour the field when it is sane.
    chunkBase_ = (header_.headerBlockSize >= 128 && header_.headerBlockSize <= file_.size())
                     ? header_.headerBlockSize
                     : kFileHeaderBlockSize;
    chunkCount_ = (file_.size() - chunkBase_) / kChunkSize;
}

std::span<const uint8_t> EvtxMmapReader::chunkBytes(size_t index) const {
    if (index >= chunkCount_) throw ParseError("chunk index out of range");
    return {file_.data() + chunkBase_ + index * kChunkSize, kChunkSize};
}

std::optional<ChunkHeader> EvtxMmapReader::chunkHeader(size_t index) const {
    if (index >= chunkCount_) return std::nullopt;
    const uint8_t* p = file_.data() + chunkBase_ + index * kChunkSize;
    if (std::memcmp(p, kChunkMagic, sizeof kChunkMagic) != 0) return std::nullopt;

    ChunkHeader h;
    h.firstRecordNumber = loadLe<uint64_t>(p + 8);
    h.lastRecordNumber = loadLe<uint64_t>(p + 16);
    h.firstRecordId = loadLe<uint64_t>(p + 24);
    h.lastRecordId = loadLe<uint64_t>(p + 32);
    h.headerSize = loadLe<uint32_t>(p + 40);
    h.lastRecordOffset = loadLe<uint32_t>(p + 44);
    h.freeSpaceOffset = loadLe<uint32_t>(p + 48);
    h.recordsChecksum = loadLe<uint32_t>(p + 52);
    h.flags = loadLe<uint32_t>(p + 120);
    h.checksum = loadLe<uint32_t>(p + 124);

    // Header checksum covers bytes [0,120) and [128,512).
    uint32_t c = crc32(p, 120);
    c = crc32(p + 128, 384, c);
    h.headerChecksumValid = c == h.checksum;
    if (h.freeSpaceOffset >= kChunkHeaderSize && h.freeSpaceOffset <= kChunkSize)
        h.dataChecksumValid = crc32(p + kChunkHeaderSize, h.freeSpaceOffset - kChunkHeaderSize) == h.recordsChecksum;
    return h;
}

uint32_t EvtxMmapReader::recordAreaEnd(const ChunkHeader& h) noexcept {
    // On dirty logs the free-space offset may be stale; in that case scan the whole chunk and
    // rely on the per-record signature/size validation to stop.
    if (h.freeSpaceOffset > kChunkHeaderSize && h.freeSpaceOffset <= kChunkSize && h.dataChecksumValid)
        return h.freeSpaceOffset;
    return kChunkSize;
}

bool EvtxMmapReader::readRecordAt(size_t chunkIndex, std::span<const uint8_t> chunk, uint32_t pos, uint32_t limit,
                                  RecordView& out) const noexcept {
    if (pos + kRecordHeaderSize + 4 > limit) return false;
    const uint8_t* p = chunk.data() + pos;
    if (loadLe<uint32_t>(p) != kRecordMagic) return false;
    const uint32_t size = loadLe<uint32_t>(p + 4);
    if (size < kRecordHeaderSize + 4 || size > kChunkSize - pos) return false;
    if (loadLe<uint32_t>(p + size - 4) != size) return false;  // trailing size copy must agree

    out.chunk = chunk;
    out.fileOffset = chunkBase_ + chunkIndex * kChunkSize + pos;
    out.offsetInChunk = pos;
    out.size = size;
    out.recordId = loadLe<uint64_t>(p + 8);
    out.writtenFiletime = loadLe<uint64_t>(p + 16);
    out.binXmlOffset = pos + static_cast<uint32_t>(kRecordHeaderSize);
    out.binXmlSize = size - static_cast<uint32_t>(kRecordHeaderSize) - 4;
    return true;
}

std::optional<RecordView> EvtxMmapReader::recordAtFileOffset(uint64_t fileOffset) const {
    if (fileOffset < chunkBase_) return std::nullopt;
    const size_t index = static_cast<size_t>((fileOffset - chunkBase_) / kChunkSize);
    if (index >= chunkCount_ || !chunkHeader(index)) return std::nullopt;
    const auto pos = static_cast<uint32_t>((fileOffset - chunkBase_) % kChunkSize);
    RecordView rv;
    if (pos < kChunkHeaderSize || !readRecordAt(index, chunkBytes(index), pos, kChunkSize, rv)) return std::nullopt;
    return rv;
}

void EvtxMmapReader::releaseChunk(size_t index) const noexcept {
    if (index < chunkCount_) file_.release(chunkBase_ + index * kChunkSize, kChunkSize);
}

}  // namespace td::evtx
