// TraceDroid - offline DFIR / SOC triage for Android.
// Copyright (C) CyberCraft Studio. GNU GPL v3.0 or later.
//
// Zero-copy reader for the Windows XML Event Log (EVTX) container format:
//   file  = 4096-byte "ElfFile" header + N * 65536-byte "ElfChnk" chunks
//   chunk = 512-byte header (string/template hash tables) + event records
//   record= 24-byte header + BinXML fragment + trailing size copy
// Everything is addressed directly inside a read-only mmap; no record data is copied.
#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>

#include "common/Util.hpp"

namespace td::evtx {

inline constexpr size_t kFileHeaderBlockSize = 4096;
inline constexpr size_t kChunkSize = 65536;
inline constexpr size_t kChunkHeaderSize = 512;
inline constexpr size_t kRecordHeaderSize = 24;

uint32_t crc32(const uint8_t* data, size_t size, uint32_t seed = 0);

/// RAII read-only memory mapping.
class MappedFile {
public:
    MappedFile() = default;
    /// Maps the file at `path`. Throws ParseError on failure.
    explicit MappedFile(const std::string& path);
    /// Maps an already-open descriptor. Ownership of `fd` is taken (it is closed after mapping).
    static MappedFile fromFd(int fd);
    ~MappedFile();
    MappedFile(MappedFile&& o) noexcept;
    MappedFile& operator=(MappedFile&& o) noexcept;
    MappedFile(const MappedFile&) = delete;
    MappedFile& operator=(const MappedFile&) = delete;

    const uint8_t* data() const noexcept { return data_; }
    size_t size() const noexcept { return size_; }
    std::span<const uint8_t> bytes() const noexcept { return {data_, size_}; }
    /// Hints the kernel that pages in [offset, offset+len) are no longer needed (keeps RSS low).
    void release(size_t offset, size_t len) const noexcept;

private:
    void mapFd(int fd);
    void reset() noexcept;
    const uint8_t* data_ = nullptr;
    size_t size_ = 0;
};

struct FileHeader {
    uint64_t firstChunkNumber = 0;
    uint64_t lastChunkNumber = 0;
    uint64_t nextRecordId = 0;
    uint32_t headerSize = 0;
    uint16_t minorVersion = 0;
    uint16_t majorVersion = 0;
    uint16_t headerBlockSize = 0;
    uint16_t chunkCount = 0;
    uint32_t flags = 0;  // 0x1 = dirty, 0x2 = full
    uint32_t checksum = 0;
    bool checksumValid = false;
};

struct ChunkHeader {
    uint64_t firstRecordNumber = 0;
    uint64_t lastRecordNumber = 0;
    uint64_t firstRecordId = 0;
    uint64_t lastRecordId = 0;
    uint32_t headerSize = 0;
    uint32_t lastRecordOffset = 0;
    uint32_t freeSpaceOffset = 0;
    uint32_t recordsChecksum = 0;
    uint32_t flags = 0;
    uint32_t checksum = 0;
    bool headerChecksumValid = false;
    bool dataChecksumValid = false;
};

/// A record located inside a mapped chunk. All offsets are relative to the chunk start,
/// which is the addressing scheme BinXML itself uses for string and template references.
struct RecordView {
    std::span<const uint8_t> chunk;  // the full 64 KiB chunk
    uint64_t fileOffset = 0;         // absolute offset of the record header in the file
    uint32_t offsetInChunk = 0;
    uint32_t size = 0;
    uint64_t recordId = 0;
    uint64_t writtenFiletime = 0;
    uint32_t binXmlOffset = 0;  // chunk-relative
    uint32_t binXmlSize = 0;
};

class EvtxMmapReader {
public:
    explicit EvtxMmapReader(const std::string& path);
    explicit EvtxMmapReader(MappedFile file);

    const FileHeader& header() const noexcept { return header_; }
    size_t fileSize() const noexcept { return file_.size(); }
    /// Number of chunk slots physically present in the file (the header count is 16-bit and
    /// frequently stale on dirty logs, so the file size is authoritative).
    size_t chunkCount() const noexcept { return chunkCount_; }

    /// Returns the parsed header when slot `index` holds a valid ElfChnk; nullopt for unused or damaged slots.
    std::optional<ChunkHeader> chunkHeader(size_t index) const;
    std::span<const uint8_t> chunkBytes(size_t index) const;

    /// Walks every structurally valid record in a chunk. `fn(const RecordView&)` returns nothing.
    /// Returns the number of records visited; stops at the first malformed record header.
    template <typename Fn>
    size_t forEachRecord(size_t chunkIndex, Fn&& fn) const {
        const auto hdr = chunkHeader(chunkIndex);
        if (!hdr) return 0;
        const auto chunk = chunkBytes(chunkIndex);
        size_t count = 0;
        uint32_t pos = kChunkHeaderSize;
        const uint32_t limit = recordAreaEnd(*hdr);
        RecordView rv;
        while (readRecordAt(chunkIndex, chunk, pos, limit, rv)) {
            fn(static_cast<const RecordView&>(rv));
            ++count;
            pos += rv.size;
        }
        return count;
    }

    /// Re-locates a single record by absolute file offset (used to render raw XML on demand).
    std::optional<RecordView> recordAtFileOffset(uint64_t fileOffset) const;

    void releaseChunk(size_t index) const noexcept;

private:
    void parseHeader();
    static uint32_t recordAreaEnd(const ChunkHeader& h) noexcept;
    bool readRecordAt(size_t chunkIndex, std::span<const uint8_t> chunk, uint32_t pos, uint32_t limit,
                      RecordView& out) const noexcept;

    MappedFile file_;
    FileHeader header_;
    size_t chunkCount_ = 0;
    size_t chunkBase_ = kFileHeaderBlockSize;
};

}  // namespace td::evtx
