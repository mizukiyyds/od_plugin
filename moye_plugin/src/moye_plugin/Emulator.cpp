#include <cassert>
#include <format>
#include <string>
#include <shlwapi.h>
#include <iostream>
#include "Emulator.h"

#pragma comment(lib, "shlwapi.lib")

using namespace std;

Emulator::Emulator()
{
    regs = {};
    uc_error = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    uc_error = uc_context_alloc(uc,&uc_ctx);
}

Emulator::~Emulator()
{
    seg_map.clear();
    callbacks.clear();
    uc_error = uc_context_free(uc_ctx);
    uc_error = uc_close(uc);
}

Emulator::Emulator(const Emulator& emu)
{
    uc_error = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    regs = emu.regs;
    for (DWORD i = 0; i < emu.seg_map.size(); i++)
    {
        seg_map.push_back(emu.seg_map[i]);
    }
    for (auto& seg : seg_map)
    {
        uc_mem_map(uc, seg.base, seg.size, UC_PROT_ALL);
        BYTE* buf = new BYTE[seg.size];
        uc_mem_read(emu.uc, seg.base, buf, seg.size);
        uc_mem_write(uc, seg.base, buf, seg.size);
        delete[] buf;
    }
    callbacks = emu.callbacks;
}


void Emulator::Dump(const std::string& path)
{
    char current[MAX_PATH];
    BYTE* buf;
    FILE* fp;
    string save_path;
    GetModuleFileNameA(NULL, current, MAX_PATH);
    PathRemoveFileSpecA(current);
    if (!CreateDirectoryA(format("{}\\{}\\", current, path).c_str(), NULL))
    {
        if (GetLastError() != ERROR_ALREADY_EXISTS)
        {
            printf("创建文件夹失败，路径：%s\n", format("{}\\{}\\", current, path).c_str());
            return;
        }
    }
    for (auto& seg : seg_map)
    {
        buf = new BYTE[seg.size];
        uc_mem_read(uc, seg.base, buf, seg.size);
        save_path = format("{}\\{}\\{}", current, path, seg.file_name);
        fopen_s(&fp, save_path.c_str(), "wb");
        if (fp == nullptr)
        {
            printf("保存失败，路径：%s\n", save_path.c_str());
            continue;
        }
        fwrite(buf, seg.size, 1, fp);
        fclose(fp);
        delete[] buf;
    }
    buf = new BYTE[1024];
    sprintf_s((char*)buf, 1024, "emu.regs.eax = 0x%08x;\nemu.regs.ecx = 0x%08x;\nemu.regs.edx = 0x%08x;\nemu.regs.ebx = 0x%08x;\n"
        "emu.regs.esp = 0x%08x;\nemu.regs.ebp = 0x%08x;\nemu.regs.esi = 0x%08x;\nemu.regs.edi = 0x%08x;\nemu.regs.eip = 0x%08x;\nemu.regs.efl = 0x%08x;\n",
        regs.eax, regs.ecx, regs.edx, regs.ebx, regs.esp, regs.ebp, regs.esi, regs.edi, regs.eip, regs.efl);
    save_path = format("{}\\{}\\regs.txt", current, path);
    fopen_s(&fp, save_path.c_str(), "wb");
    fwrite(buf, 1024, 1, fp);
    fclose(fp);
    delete[] buf;
}

bool Emulator::MapFromFile(const DWORD& base, const DWORD& size, const char* file_name)
{
    FILE* fp;
    if (fopen_s(&fp, file_name, "rb") != 0)
    {
        return false;
    }
    BYTE* buf = new BYTE[size];
    fread(buf, size, 1, fp);
    fclose(fp);
    uc_error = uc_mem_map(uc, base, size, UC_PROT_ALL);
    if (uc_error != UC_ERR_OK)
    {
        delete[] buf;
        return false;
    }
    uc_error = uc_mem_write(uc, base, buf, size);
    if (uc_error != UC_ERR_OK)
    {
        delete[] buf;
        return false;
    }
    delete[] buf;
    seg_map.push_back({ base,size,format("{:08X}_{:08X}.bin",base,base + size),0 });
    return true;
}

bool Emulator::MapFromMemory(const DWORD& base, const DWORD& size, void* buf)
{
    uc_error = uc_mem_map(uc, base, size, UC_PROT_ALL);
    if (uc_error != UC_ERR_OK)
    {
        return false;
    }
    uc_error = uc_mem_write(uc, base, buf, size);
    if (uc_error != UC_ERR_OK)
    {
        return false;
    }
    seg_map.push_back({ base,size,format("{:08X}_{:08X}.bin",base,base + size),0 });
    return true;
}

void Emulator::ReadUCRegs()
{
    uc_error = uc_reg_read(uc, UC_X86_REG_EAX, &regs.eax);
    uc_error = uc_reg_read(uc, UC_X86_REG_ECX, &regs.ecx);
    uc_error = uc_reg_read(uc, UC_X86_REG_EDX, &regs.edx);
    uc_error = uc_reg_read(uc, UC_X86_REG_EBX, &regs.ebx);
    uc_error = uc_reg_read(uc, UC_X86_REG_ESP, &regs.esp);
    uc_error = uc_reg_read(uc, UC_X86_REG_EBP, &regs.ebp);
    uc_error = uc_reg_read(uc, UC_X86_REG_ESI, &regs.esi);
    uc_error = uc_reg_read(uc, UC_X86_REG_EDI, &regs.edi);
    uc_error = uc_reg_read(uc, UC_X86_REG_EIP, &regs.eip);
    uc_error = uc_reg_read(uc, UC_X86_REG_EFLAGS, &regs.efl);
}

void Emulator::WriteUCRegs()
{
    uc_error = uc_reg_write(uc, UC_X86_REG_EAX, &regs.eax);
    uc_error = uc_reg_write(uc, UC_X86_REG_ECX, &regs.ecx);
    uc_error = uc_reg_write(uc, UC_X86_REG_EDX, &regs.edx);
    uc_error = uc_reg_write(uc, UC_X86_REG_EBX, &regs.ebx);
    uc_error = uc_reg_write(uc, UC_X86_REG_ESP, &regs.esp);
    uc_error = uc_reg_write(uc, UC_X86_REG_EBP, &regs.ebp);
    uc_error = uc_reg_write(uc, UC_X86_REG_ESI, &regs.esi);
    uc_error = uc_reg_write(uc, UC_X86_REG_EDI, &regs.edi);
    uc_error = uc_reg_write(uc, UC_X86_REG_EIP, &regs.eip);
    uc_error = uc_reg_write(uc, UC_X86_REG_EFLAGS, &regs.efl);
}

void Emulator::RegisterCallback(EMULATOR_CALLBACK func, void* user_data)
{
    for (DWORD i = 0; i < callbacks.size(); i++)
    {
        if (callbacks[i].first == func)
        {
            return;
        }
    }
    callbacks.emplace_back(func, user_data);
}

void Emulator::UnRegisterCallback(EMULATOR_CALLBACK func)
{
    for (auto iter = callbacks.begin(); iter != callbacks.end(); iter++)
    {
        if (iter->first == func)
        {
            callbacks.erase(iter);
            return;
        }
    }
}

DWORD Emulator::Run(const DWORD& max)
{
    run_state = true;
    run_cnt = 0;
    for (DWORD i = 1; i <= max; i++) {
        //执行回调函数
        for (auto& iter : callbacks)
        {
            if (!iter.first(this, iter.second)) break;
        }
        if (!run_state) break;
        WriteUCRegs();
        uc_error = uc_emu_start(uc, regs.eip, 0xffffffff, 0, 1);
        if (uc_error != UC_ERR_OK) break;
        ReadUCRegs();
        ++run_cnt;
    }
    return run_cnt;
}

void Emulator::Stop()
{
    run_state = false;
}

void Emulator::PrintEnvironment()
{
    printf("EAX=%08X ECX=%08X EDX=%08X EBX=%08X\n", regs.eax, regs.ecx, regs.edx, regs.ebx);
    printf("ESP=%08X EBP=%08X ESI=%08X EDI=%08X\n", regs.esp, regs.ebp, regs.esi, regs.edi);
    printf("EIP=%08X EFLAGS=%08X\n", regs.eip, regs.efl);
    DWORD value;
    ReadMemory(regs.esp, 4, &value);
    printf("$-4\t|%08X|\n", value);
    ReadMemory(regs.esp, 4, &value);
    printf("ESP  ->\t|%08X|\n", value);
    for (DWORD i = 1; i <= 8; i++)
    {
        ReadMemory(regs.esp + 4 * i, 4, &value);
        printf("$+%d\t|%08X|\n", 4 * i, value);
    }
}

void Emulator::PrintError()
{
    printf("Exception with error returned %u: %s\n", uc_error, uc_strerror(uc_error));
}

void Emulator::LogEnvironment()
{
    _Addtolist(0, -1, "EAX=%08X ECX=%08X EDX=%08X EBX=%08X", regs.eax, regs.ecx, regs.edx, regs.ebx);
    _Addtolist(0, -1, "ESP=%08X EBP=%08X ESI=%08X EDI=%08X", regs.esp, regs.ebp, regs.esi, regs.edi);
    _Addtolist(0, -1, "EIP=%08X EFLAGS=%08X", regs.eip, regs.efl);
    DWORD value;
    ReadMemory(regs.esp - 4, 4, &value);
    _Addtolist(0, -1, "       |%08X|", value);
    ReadMemory(regs.esp, 4, &value);
    _Addtolist(0, -1, "ESP -> |%08X|", value);
    for (DWORD i = 1; i <= 8; i++)
    {
        ReadMemory(regs.esp + 4 * i, 4, &value);
        _Addtolist(0, -1, "       |%08X|", value);
    }
}

void Emulator::LogError()
{
    _Addtolist(0, -1, "Exception with error returned %u: %s", uc_error, uc_strerror(uc_error));
}

bool Emulator::ReadMemory(const DWORD& addr, const DWORD& size, void* buf)
{
    uc_error = uc_mem_read(uc, addr, buf, size);
    if (uc_error != UC_ERR_OK) return false;
    return true;
}

bool Emulator::WriteMemory(const DWORD& addr, const DWORD& size, const void* buf)
{
    uc_error = uc_mem_write(uc, addr, buf, size);
    if (uc_error != UC_ERR_OK) return false;
    return true;
}

DWORD Emulator::GetReg(const x86_reg& reg)
{
    switch (reg)
    {
        case X86_REG_EAX:return regs.eax;
        case X86_REG_ECX:return regs.ecx;
        case X86_REG_EDX:return regs.edx;
        case X86_REG_EBX:return regs.ebx;
        case X86_REG_ESP:return regs.esp;
        case X86_REG_EBP:return regs.ebp;
        case X86_REG_ESI:return regs.esi;
        case X86_REG_EDI:return regs.edi;
        case X86_REG_EIP:return regs.eip;
        case X86_REG_EFLAGS:return regs.efl;
        case X86_REG_AX:return regs.ax;
        case X86_REG_CX:return regs.cx;
        case X86_REG_DX:return regs.dx;
        case X86_REG_BX:return regs.bx;
        case X86_REG_SP:return regs.sp;
        case X86_REG_BP:return regs.bp;
        case X86_REG_SI:return regs.si;
        case X86_REG_DI:return regs.di;
        case X86_REG_AL:return regs.al;
        case X86_REG_CL:return regs.cl;
        case X86_REG_DL:return regs.dl;
        case X86_REG_BL:return regs.bl;
        case X86_REG_AH:return regs.ah;
        case X86_REG_CH:return regs.ch;
        case X86_REG_DH:return regs.dh;
        case X86_REG_BH:return regs.bh;
        default:
            assert(0);
            return 0;
    }
}

void Emulator::SetReg(const x86_reg& reg, const DWORD& value)
{
    switch (reg)
    {
        case X86_REG_EAX:regs.eax = value; break;
        case X86_REG_ECX:regs.ecx = value; break;
        case X86_REG_EDX:regs.edx = value; break;
        case X86_REG_EBX:regs.ebx = value; break;
        case X86_REG_ESP:regs.esp = value; break;
        case X86_REG_EBP:regs.ebp = value; break;
        case X86_REG_ESI:regs.esi = value; break;
        case X86_REG_EDI:regs.edi = value; break;
        case X86_REG_EIP:regs.eip = value; break;
        case X86_REG_EFLAGS:regs.efl = value; break;
        case X86_REG_AX:regs.ax = (WORD)value; break;
        case X86_REG_CX:regs.cx = (WORD)value; break;
        case X86_REG_DX:regs.dx = (WORD)value; break;
        case X86_REG_BX:regs.bx = (WORD)value; break;
        case X86_REG_SP:regs.sp = (WORD)value; break;
        case X86_REG_BP:regs.bp = (WORD)value; break;
        case X86_REG_SI:regs.si = (WORD)value; break;
        case X86_REG_DI:regs.di = (WORD)value; break;
        case X86_REG_AH:regs.ah = (BYTE)value; break;
        case X86_REG_CH:regs.ch = (BYTE)value; break;
        case X86_REG_DH:regs.dh = (BYTE)value; break;
        case X86_REG_BH:regs.bh = (BYTE)value; break;
        case X86_REG_AL:regs.al = (BYTE)value; break;
        case X86_REG_CL:regs.cl = (BYTE)value; break;
        case X86_REG_DL:regs.dl = (BYTE)value; break;
        case X86_REG_BL:regs.bl = (BYTE)value; break;
        default:
            assert(0);
            return;
    }
}

DWORD Emulator::GetMemAddr(const x86_op_mem& mem)
{
    DWORD addr = 0;
    if (mem.base != X86_REG_INVALID)
    {
        addr += GetReg(mem.base);
    }
    if (mem.index != X86_REG_INVALID)
    {
        addr += GetReg(mem.index) * mem.scale;
    }
    addr += mem.disp;
    return addr;
}

DWORD Emulator::GetRunCount()
{
    return run_cnt;
}

void Emulator::MapMemoryFromOD()
{
    t_table* memory_table = (t_table*)_Plugingetvalue(VAL_MEMORY);
    t_sorted memory_data = memory_table->data;
    for (DWORD i = 0; i < memory_data.n; i++)
    {
        t_memory* memory = (t_memory*)_Getsortedbyselection(&memory_data, i);
        BYTE* buf = new BYTE[memory->size];
        DWORD ret = _Readmemory(buf, memory->base, memory->size, MM_SILENT);
        if (ret != memory->size)
        {
            _Addtolist(0, 1, "读取内存 0x%08x-0x%08x 失败 实际读取%08x", memory->base, memory->base + memory->size, ret);
        }
        if (!MapFromMemory(memory->base, memory->size, buf))
        {
            _Addtolist(0, 1, "映射内存 0x%08x-0x%08x 失败", memory->base, memory->base + memory->size);
        }
        delete[] buf;
        _Progress((i + 1) * 1000 / memory_data.n, "正在映射内存 0x%08x-0x%08x 进度", memory->base, memory->base + memory->size);
    }
    _Progress(0, 0);
}

/**
 * \brief 初始化段描述符
 * \param desc 段描述符
 * \param base 段基址
 * \param limit 段界限
 * \param is_code 是否为代码
 */
static void InitDescriptor(SegmentDescriptor* desc, uint32_t base, uint32_t limit, uint8_t is_code)
{
    desc->desc = 0; // clear the descriptor
    desc->base0 = base & 0xffff;
    desc->base1 = (base >> 16) & 0xff;
    desc->base2 = base >> 24;
    if (limit > 0xfffff) {
        // need Giant granularity
        limit >>= 12;
        desc->granularity = 1;
    }
    desc->limit0 = limit & 0xffff;
    desc->limit1 = limit >> 16;
    // some sane defaults
    desc->dpl = 3;
    desc->present = 1;
    desc->db = 1; // 32 bit
    desc->type = is_code ? 0xb : 3;
    desc->system = 1; // code or data
}

void Emulator::SetRegFromOD()
{
    t_thread* thread = _Findthread(_Getcputhreadid());
    const t_reg& treg = thread->reg;
    regs.eax = treg.r[REG_EAX];
    regs.ecx = treg.r[REG_ECX];
    regs.edx = treg.r[REG_EDX];
    regs.ebx = treg.r[REG_EBX];
    regs.esp = treg.r[REG_ESP];
    regs.ebp = treg.r[REG_EBP];
    regs.esi = treg.r[REG_ESI];
    regs.edi = treg.r[REG_EDI];
    regs.eip = treg.ip;
    regs.efl = treg.flags;
    regs.fs_base = treg.base[SEG_FS];
    const uint64_t gdt_address = 0x80000000;
    SegmentDescriptor* gdt = new SegmentDescriptor[32];
    uc_x86_mmr gdtr;
    gdtr.base = gdt_address;
    gdtr.limit = 32 * sizeof(SegmentDescriptor) - 1;
    SegmentSelector r_es = treg.s[SEG_ES];
    SegmentSelector r_cs = treg.s[SEG_CS];
    SegmentSelector r_ss = treg.s[SEG_SS];
    SegmentSelector r_ds = treg.s[SEG_DS];
    SegmentSelector r_fs = treg.s[SEG_FS];
    SegmentSelector r_gs = treg.s[SEG_GS];
    r_cs.rpl = 0;
    r_ss.rpl = 0;
    r_es.index = 1;
    r_cs.index = 2;
    r_ss.index = 3;
    r_ds.index = 4;
    r_fs.index = 5;
    r_gs.index = 6;
    InitDescriptor(&gdt[r_es.index], treg.base[SEG_ES], treg.limit[SEG_ES], 0);
    InitDescriptor(&gdt[r_cs.index], treg.base[SEG_CS], treg.limit[SEG_CS], 1);
    InitDescriptor(&gdt[r_ss.index], treg.base[SEG_SS], treg.limit[SEG_SS], 0);
    InitDescriptor(&gdt[r_ds.index], treg.base[SEG_DS], treg.limit[SEG_DS], 0);
    InitDescriptor(&gdt[r_fs.index], treg.base[SEG_FS], treg.limit[SEG_FS], 0);
    InitDescriptor(&gdt[r_gs.index], treg.base[SEG_GS], treg.limit[SEG_GS], 0);
    gdt[r_ss.index].dpl = 0;
    uc_error = uc_reg_write(uc, UC_X86_REG_GDTR, &gdtr);
    uc_error = uc_mem_map(uc, gdt_address, 0x1000, UC_PROT_WRITE | UC_PROT_READ);
    uc_error = uc_mem_write(uc, gdt_address, gdt, 32 * sizeof(SegmentDescriptor));
    uc_error = uc_reg_write(uc, UC_X86_REG_ES, &r_es.val);
    uc_error = uc_reg_write(uc, UC_X86_REG_CS, &r_cs.val);
    uc_error = uc_reg_write(uc, UC_X86_REG_SS, &r_ss.val);
    uc_error = uc_reg_write(uc, UC_X86_REG_DS, &r_ds.val);
    uc_error = uc_reg_write(uc, UC_X86_REG_FS, &r_fs.val);
    uc_error = uc_reg_write(uc, UC_X86_REG_GS, &r_gs.val);
    delete[] gdt;
}

void Emulator::SaveContext()
{
    uc_error = uc_context_save(uc,uc_ctx);
}

void Emulator::RestoreContext()
{
    uc_error = uc_context_restore(uc,uc_ctx);
}