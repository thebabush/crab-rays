#pragma once
#include <loader.hpp>
#include <diskio.hpp>
#include <segment.hpp>
#include <entry.hpp>
#include <name.hpp>
#include <idp.hpp>
#include <cstdint>

// ---------------------------------------------------------------------------
// All IDA opaque types (linput_t, qstring) are passed as void* so autocxx
// never needs to generate bindings for incomplete C++ classes.
// ---------------------------------------------------------------------------

// ----- linput_t I/O --------------------------------------------------------
inline int64_t  ldr_read(void *li, uint8_t *buf, uint64_t size)
{
    return qlread(reinterpret_cast<linput_t *>(li), buf, (size_t)size);
}
inline void     ldr_seek(void *li, int64_t pos)
{
    qlseek(reinterpret_cast<linput_t *>(li), (qoff64_t)pos);
}
inline int64_t  ldr_size(void *li)
{
    return (int64_t)qlsize(reinterpret_cast<linput_t *>(li));
}

// ----- qstring assignment --------------------------------------------------
inline void     ldr_qstr_set(void *s, const char *v)
{
    *reinterpret_cast<qstring *>(s) = v;
}

// ----- IDA database setup --------------------------------------------------
inline bool     ldr_set_proc()
{
    return set_processor_type("SBF", SETPROC_LOADER);
}
inline bool     ldr_add_seg(uint64_t start, uint64_t end,
                             const char *name, const char *sclass)
{
    return add_segm(0, (ea_t)start, (ea_t)end, name, sclass, ADDSEG_NOSREG);
}
inline bool     ldr_file_to_base(void *li, int64_t foff,
                                  uint64_t ea1, uint64_t ea2)
{
    return file2base(reinterpret_cast<linput_t *>(li),
                     (qoff64_t)foff, (ea_t)ea1, (ea_t)ea2,
                     FILEREG_PATCHABLE) != 0;
}
inline bool     ldr_add_entry(uint64_t ea, const char *name)
{
    return add_entry(0, (ea_t)ea, name, true);
}
inline bool     ldr_set_name(uint64_t ea, const char *name)
{
    return set_name((ea_t)ea, name, 0);
}
inline void     ldr_filename_cmt()
{
    create_filename_cmt();
}
inline void     ldr_patch_qword(uint64_t ea, uint64_t val)
{
    patch_qword((ea_t)ea, val);
}
