#include <algorithm>
#include <iostream>
#include <vector>
#include <stack>
#include <windows.h>
#include <shlwapi.h>
#include <psapi.h>
#include "ollydbg-sdk/Plugin.h"
#include "Emulator.h"
#include "Analyzer.h"

#pragma comment(lib,"Shlwapi.lib")

using namespace std;

HWND g_hOllyDbg;			//OD主界面句柄
bool is_tracing;            //是否正在跟踪api调用
bool emu_control;           //控制模拟器是否暂停，可用于选项（模拟至api/内存访问分析）
Analyzer a;                 //分析器，用于反汇编指令
DWORD hash_data_addr;       //记录SP对hash数据写入的地址
DWORD hash_data_size;       //hash数据的长度（1，2，4字节）

DWORD cpuid_eax=0;            //模拟器中hook这些值
DWORD cpuid_ecx=0;
DWORD cpuid_edx=0;
DWORD cpuid_ebx=0;
DWORD rdtsc_eax=0;
DWORD rdtsc_edx=0;
bool special_ins_solver_control=0; //控制是否hook模拟器cpuid和rdtsc指令的值(是否注册处理回调)

/**
 * \brief 用于修复IAT表
 */
struct api_info
{
    //重载运算符用于排序
    bool operator<(const api_info& v)
    {
        if (dll_name == v.dll_name) return api_name < v.api_name;
        else return dll_name < v.dll_name;
    }
    std::string dll_name;   //api属于哪个dll（dll完整路径）
    std::string api_name;   //api函数的名字
    DWORD fix_addr;         //在此地址修复iat调用
    DWORD api_addr;         //调用的api的地址
    DWORD type;             //1-call 2-jmp 3-mov eax 4-mov ecx 5-mov edx 6-mov ebx 7-mov ebp 8-mov esi 9-mov edi
};

/**
 * \brief 返回GetLastError错误信息
 */
string GetLastErrorStr()
{
    DWORD err_code = GetLastError();
    if (err_code == 0)
    {
        puts("没有错误信息\n");
        return "";
    }
    char* buffer = nullptr;
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, err_code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&buffer, 0, NULL);
    string str = buffer;
    str.resize(str.size() - 2); //去掉末尾的换行符\r\n
    LocalFree(buffer);
    return str;
}

/**
 * \brief 给指定地址增加标签(ctrl cv自nck)
 * \param dump 转储数据
 */
DWORD __stdcall RenameCall(LPVOID lpThreadParameter)
{
    t_dump* dump = (t_dump*)lpThreadParameter;
    ulong select_addr = dump->sel0;
    if (select_addr == 0) return -1;
    uchar buf[MAXCMDSIZE];
    _Readmemory(buf, select_addr, MAXCMDSIZE, MM_SILENT);
    if (buf[0] != 0xE8) return -1;
    t_disasm td;
    if (strncmp(td.result, "call", 4)) return -1;
    char old_label[TEXTLEN] = { 0 };
    char new_label[TEXTLEN] = { 0 };
    _Findlabel(td.jmpaddr, old_label);
    if (_Gettext("请输入标签名", new_label, 0, NM_NONAME, 0) != -1) {
        _Addtolist(td.jmpaddr, 0, "[moye]地址：%#08x    标签：%s    原始：%s", td.jmpaddr, new_label, old_label);
        _Insertname(td.jmpaddr, NM_LABEL, new_label);
    }
    return 0;
}

/**
 * \brief 在当前被调试进程空间中分配一片内存
 * \param lpThreadParameter 未使用此参数
 * \return
 */
DWORD __stdcall AllocMemory(LPVOID lpThreadParameter)
{
    DWORD size = 0;
    if (_Getlong("内存大小(十六进制)", &size, 4, '0', DIA_HEXONLY) != 0)
    {
        return -1;
    }
    HANDLE hprocess = (HANDLE)_Plugingetvalue(VAL_HPROCESS);
    DWORD addr = (DWORD)VirtualAllocEx(hprocess, 0, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!addr)
    {
        _Addtolist(0, 1, "分配内存失败：%s", GetLastErrorStr().c_str());
        return -1;
    }
    _Listmemory();  //让OD刷新内存列表，不然会查找不到刚才分配的内存
    t_memory* memory = _Findmemory(addr);
    if (!memory)
    {
        _Addtolist(0, 1, "查找分配的内存失败：%s", GetLastErrorStr().c_str());
        VirtualFreeEx(hprocess, (LPVOID)addr, 0, MEM_RELEASE);
        return -1;
    }
    _Addtolist(addr, 0, "分配内存成功 地址：%08X 大小：%08x", addr, memory->size);
    _Setcpu(0, 0, addr, 0, CPU_DUMPFIRST);
    return 0;
}


/**
 * \brief 合并内存段式dump，保存文件至被调试程序目录下
 * \param lpThreadParameter 未使用此参数
 */
DWORD __stdcall MergeDump(LPVOID lpThreadParameter)
{
    DWORD start_addr = 0;
    DWORD end_addr = 0;
    if (_Getlong("Dump内存的起始位置", &start_addr, 4, '0', DIA_HEXONLY) != 0)
    {
        return -1;
    }
    if (_Getlong("Dump内存的结束位置", &end_addr, 4, '0', DIA_HEXONLY) != 0)
    {
        return -1;
    }
    const DWORD size = end_addr - start_addr;
    BYTE* buf = new BYTE[size];
    memset(buf, 0, size);
    t_table* memory_table = (t_table*)_Plugingetvalue(VAL_MEMORY);
    t_sorted memory_data = memory_table->data;
    for (int i = 0; i < memory_data.n; i++)
    {
        t_memory* memory = (t_memory*)_Getsortedbyselection(&memory_data, i);
        if (memory->base >= start_addr && memory->base < end_addr)
        {
            _Readmemory(buf + memory->base - start_addr, memory->base, memory->size, MM_SILENT);
        }
    }
    char current_dir[MAX_PATH];
    HANDLE hProcess = (HANDLE)_Plugingetvalue(VAL_HPROCESS);
    GetModuleFileNameExA(hProcess, NULL, current_dir, MAX_PATH);
    PathRemoveFileSpecA(current_dir);
    //bug: OD api错误，无法获取当前目录
    //char* current_dir = (char*)_Plugingetvalue(VAL_CURRENTDIR);
    char file_path[MAX_PATH] = { 0 };
    sprintf_s(file_path, 256, "%s\\Dump_%08X_%08X.bin", current_dir, start_addr, end_addr);
    HANDLE hfile = CreateFileA(file_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hfile == INVALID_HANDLE_VALUE)
    {
        _Addtolist(0, 1, "创建Dump文件 %s 失败：%s", file_path, GetLastErrorStr().c_str());
    }
    DWORD lpNumberOfBytesWritten = 0;
    if (!WriteFile(hfile, buf, size, &lpNumberOfBytesWritten, NULL))
    {
        _Addtolist(0, 1, "写入Dump文件 %s 失败：%s", file_path, GetLastErrorStr().c_str());
    }
    CloseHandle(hfile);
    _Addtolist(0, -1, "Dump完成 文件路径：%s", file_path);
    delete[] buf;
    return 0;
}

extc int ODBG_Pausedex(int reason, int extdata, t_reg* reg, DEBUG_EVENT* debugevent)
{
    if (is_tracing)
    {
        if (reason == PP_SINGLESTEP || reason == PP_EVENT)
        {
            _Animate(ANIMATE_OFF);
            is_tracing = false;
            char name[TEXTLEN];
            if (_Findsymbolicname(reg->ip, name) > 1)
            {
                //返回0表示没找到，返回1表示为空，返回其他表示名称长度
                _Flash("[moye] 跟踪api -> %#08x %s", reg->ip, name);
                _Addtolist(reg->ip, 1, "[moye] 跟踪api -> %#08x %s", reg->ip, name);
            }
            else
            {
                _Flash("[moye] 跟踪至节外 -> %#08x", reg->ip);
                _Addtolist(reg->ip, 1, "[moye] 跟踪至节外 -> %#08x", reg->ip);
            }
            return 0;
        }
    }
    return 0;
}


/**
 * \brief 使用trace的方式跟踪至api或者区段外
 */
void TraceToApi()
{
    _Deleteruntrace();
    is_tracing = true;
    ulong threadid = _Getcputhreadid();
    t_thread* thread = _Findthread(threadid);
    t_reg* reg = &thread->reg;
    t_memory* section = _Findmemory(reg->ip);
    //OD默认选项会导致跟踪步过系统Dll
    //枚举所有模块，并且将他们标记为非系统Dll
    t_table* module_table = (t_table*)_Plugingetvalue(VAL_MODULES);
    t_sorted module_data = module_table->data;
    for (int i = 0; i < module_data.n; ++i)
    {
        t_module* module = (t_module*)_Getsortedbyselection(&module_data, i);
        module->issystemdll = false;
    }
    _Animate(ANIMATE_TRIN);
    //_Settracepauseoncommands((char*)"call CONST");
    //_Settracecount();
    _Settracecondition((char*)"0", 0, 0, 0, section->base, section->base + section->size);
    _Startruntrace(reg);
    _Go(threadid, 0, STEP_RUN, 1, 0);
}

/**
 * \brief 处理模拟器中访问了fs寄存器的指令（unicorn有bug）
 * \param emu
 * \param user_data
 * \return
 */
 // bool EmuFsSolver(Emulator* emu, void* user_data)
 // {
 //     BYTE code[16] = {};
 //     DWORD addr = 0;
 //     DWORD value = 0;
 //     _Readmemory(code, emu->regs.eip, 16, MM_SILENT);
 //     a.Disasm(emu->regs.eip,code,sizeof(code));
 //     switch(a.vec_insn[0]->id)
 //     {
 //         case X86_INS_PUSH:
 //             if (a.vec_insn[0]->detail->x86.operands[0].mem.segment == X86_REG_FS)
 //             {
 //                 emu->regs.esp -= a.vec_insn[0]->detail->x86.operands[0].size;
 //                 addr = emu->regs.fs_base + emu->GetMemAddr(a.vec_insn[0]->detail->x86.operands[0].mem);
 //                 emu->ReadMemory(addr, a.vec_insn[0]->detail->x86.operands[0].size, &value);
 //                 emu->WriteMemory(emu->regs.esp, a.vec_insn[0]->detail->x86.operands[0].size, &value);
 //                 emu->regs.eip += a.vec_insn[0]->size;
 //             }
 //             break;
 //         case X86_INS_POP:
 //             if(a.vec_insn[0]->detail->x86.operands[0].type==X86_OP_MEM)
 //             {
 //                 if(a.vec_insn[0]->detail->x86.operands[0].mem.segment==X86_REG_FS)
 //                 {
 //                     addr = emu->regs.fs_base + emu->GetMemAddr(a.vec_insn[0]->detail->x86.operands[0].mem);
 //                     emu->ReadMemory(emu->regs.esp,a.vec_insn[0]->detail->x86.operands[0].size,&value);
 //                     emu->WriteMemory(addr,a.vec_insn[0]->detail->x86.operands[0].size,&value);
 //                     emu->regs.esp+=a.vec_insn[0]->detail->x86.operands[0].size;
 //                     emu->regs.eip+=a.vec_insn[0]->size;
 //                 }
 //             }
 //             break;
 //         case X86_INS_MOV:
 //             if(a.vec_insn[0]->detail->x86.operands[0].type==X86_OP_MEM)
 //             {
 //                 if(a.vec_insn[0]->detail->x86.operands[0].mem.segment==X86_REG_FS)
 //                 {
 //                     if(a.vec_insn[0]->detail->x86.operands[1].type==X86_OP_IMM)
 //                     {
 //                         addr = emu->regs.fs_base + emu->GetMemAddr(a.vec_insn[0]->detail->x86.operands[0].mem);
 //                         emu->WriteMemory(addr, a.vec_insn[0]->detail->x86.operands[1].size, &a.vec_insn[0]->detail->x86.operands[1].imm);
 //                         emu->regs.eip += a.vec_insn[0]->size;
 //                     }
 //                     else if(a.vec_insn[0]->detail->x86.operands[1].type==X86_OP_REG)
 //                     {
 //                         addr = emu->regs.fs_base + emu->GetMemAddr(a.vec_insn[0]->detail->x86.operands[0].mem);
 //                         value = emu->GetReg(a.vec_insn[0]->detail->x86.operands[1].reg);
 //                         emu->WriteMemory(addr, a.vec_insn[0]->detail->x86.operands[1].size, &value);
 //                         emu->regs.eip += a.vec_insn[0]->size;
 //                     }
 //                     else
 //                     {
 //                         _Addtolist(emu->regs.eip,1,"%#08x 无法处理的fs段寄存器访问",emu->regs.eip);
 //                     }
 //                 }
 //             }
 //             else if(a.vec_insn[0]->detail->x86.operands[1].type==X86_OP_MEM)
 //             {
 //                 if(a.vec_insn[0]->detail->x86.operands[1].mem.segment==X86_REG_FS)
 //                 {
 //                     if(a.vec_insn[0]->detail->x86.operands[0].type==X86_OP_REG)
 //                     {
 //                         addr = emu->regs.fs_base + emu->GetMemAddr(a.vec_insn[0]->detail->x86.operands[1].mem);
 //                         emu->ReadMemory(addr, a.vec_insn[0]->detail->x86.operands[1].size, &value);
 //                         emu->SetReg(a.vec_insn[0]->detail->x86.operands[0].reg,value);
 //                         emu->regs.eip += a.vec_insn[0]->size;
 //                     }
 //                     else
 //                     {
 //                         _Addtolist(emu->regs.eip,1,"%#08x 无法处理的fs段寄存器访问",emu->regs.eip);
 //                     }
 //                 }
 //             }
 //             break;
 //         default:
 //             for (DWORD i = 0; i < a.vec_insn[0]->detail->x86.op_count; i++)
 //             {
 //                 if (a.vec_insn[0]->detail->x86.operands[i].type == X86_OP_MEM&&
 //                     a.vec_insn[0]->detail->x86.operands[i].mem.segment == X86_REG_FS)
 //                 {
 //                     _Addtolist(emu->regs.eip,1,"%#08x 无法处理的fs段寄存器访问",emu->regs.eip);
 //                     break;
 //                 }
 //             }
 //             break;
 //     }
 //     return true;
 // }

/**
 * \brief 处理模拟器中的jmp指令（unicorn有bug）
 * \param emu
 * \param user_data
 * \return
 */
bool EmuJmpImmSolver(Emulator* emu, void* user_data)
{
    BYTE code[16];
    emu->ReadMemory(emu->regs.eip, sizeof(code), code);
    if(code[0]==0xE9)
    {
        DWORD addr = emu->regs.eip + 5 + *(DWORD*)(code + 1);
        emu->regs.eip = addr;
    }
    return true;
}

/**
 * \brief 处理模拟器中遇到的cpuid和rdtsc指令
 * \param emu 
 * \param user_data 
 * \return 
 */
bool EmuSpecialInsSolverCallback(Emulator* emu, void* user_data)
{
    BYTE code[16];
    emu->ReadMemory(emu->regs.eip, sizeof(code), code);
    a.Clear();
    a.Disasm(emu->regs.eip, code, sizeof(code));
    if (a.count != 1) return true;
    if(a.vec_insn[0]->id==X86_INS_CPUID)
    {
        _Addtolist(emu->regs.eip,0,"%#08x hook cpuid",emu->regs.eip);
        emu->regs.eax = cpuid_eax;
        emu->regs.ecx = cpuid_ecx;
        emu->regs.edx = cpuid_edx;
        emu->regs.ebx = cpuid_ebx;
        emu->regs.eip+=a.vec_insn[0]->size;
    }
    // else if(a.vec_insn[0]->id==X86_INS_RDTSC)
    // {
    //     _Addtolist(emu->regs.eip,0,"%#08x hook rdtsc",emu->regs.eip);
    //     ++rdtsc_eax;
    //     if(rdtsc_eax==0)
    //     {
    //         ++rdtsc_edx;
    //     }
    //     emu->regs.eax = rdtsc_eax;
    //     emu->regs.edx = rdtsc_edx;
    //     emu->regs.eip+=a.vec_insn[0]->size;
    // }
    return true;
}

 /**
  * \brief EmuToApi函数使用的回调函数
  * \param emu 模拟器this指针
  * \param user_data 最初eip所在的内存块
  * \return 返回真，不阻止后续回调函数执行
  */
bool EmuToApiCallback(Emulator* emu, void* user_data)
{
    t_memory* mem_code = (t_memory*)user_data;
    if (!emu_control)
    {
        _Addtolist(0, 1, "手动中断模拟");
        emu->Stop();
        return true;
    }
    if (emu->regs.eip < mem_code->base || emu->regs.eip >= mem_code->base + mem_code->size)
    {
        char name[TEXTLEN] = {};
        if (_Findsymbolicname(emu->regs.eip, name) > 1)
        {
            //返回0表示没找到，返回1表示为空，返回其他表示名称长度
            _Flash("[moye] 模拟至api -> 0x%08x %s", emu->regs.eip, name);
            _Addtolist(emu->regs.eip, 1, "[moye] 模拟至api -> 0x%08x %s", emu->regs.eip, name);
        }
        else
        {
            _Flash("[moye] 模拟至区段外 -> 0x%08x", emu->regs.eip);
            _Addtolist(emu->regs.eip, 1, "[moye] 模拟至区段外 -> 0x%08x", emu->regs.eip);
        }
        emu->Stop();
    }
    return true;
}



/**
 * \brief 模拟至api
 * \param lpThreadParameter 未使用此参数
 * \return 0
 */
DWORD __stdcall EmuToApi(LPVOID lpThreadParameter)
{
    emu_control = true;
    Emulator emu;
    _Infoline("模拟执行中...");
    emu.MapMemoryFromOD();
    emu.SetRegFromOD();
    if (special_ins_solver_control)
    {
        emu.RegisterCallback(EmuSpecialInsSolverCallback, NULL);
    }
    //emu.RegisterCallback(EmuJmpImmSolver, NULL);       //bug unicorn有bug导致jmp指令可能会崩溃
    emu.RegisterCallback(EmuToApiCallback, _Findmemory(emu.regs.eip));
    DWORD count = emu.Run();
    _Flash("模拟已终止");
    emu.LogError();
    emu.LogEnvironment();
    _Addtolist(0, -1, "共模拟了%lu条指令", count);
    _Setcpu(0, emu.regs.eip, 0, 0, CPU_NOFOCUS);
    return 0;
}


/*
 *\brief FixSpIAT使用的回调
 */
bool FixSpIATCallback(Emulator* emu, void* user_data)
{
    t_memory* mem_svmp1 = (t_memory*)user_data;
    if (emu->regs.eip < mem_svmp1->base || emu->regs.eip >= mem_svmp1->base + mem_svmp1->size)
    {
        emu->Stop();
    }
    return true;
}

/*
 *\brief 在svmp1段搜索特征，修复IAT
 */
DWORD __stdcall FixSpIAT(LPVOID lpThreadParameter)
{
    //----------------------初始化数据，寻找代码节和.svmp1 混淆节---------------------
    HANDLE hprocess = (HANDLE)_Plugingetvalue(VAL_HPROCESS);
    t_thread* thread = _Findthread(_Getcputhreadid());
    t_memory* mem_code = _Findmemory(0x00401000);
    if (mem_code == nullptr)
    {
        MessageBoxA(0, "未能在0x401000处搜索到代码", "警告", MB_TOPMOST | MB_ICONWARNING | MB_OK);
        return 0;
    }
    t_memory* mem_svmp1 = {};
    t_table memory_table = *(t_table*)_Plugingetvalue(VAL_MEMORY);
    t_sorted memory_data = memory_table.data;
    for (int i = 0; i < memory_data.n; i++)
    {
        t_memory* memory = (t_memory*)_Getsortedbyselection(&memory_data, i);
        if (strcmp(memory->sect, ".svmp1") == 0)
        {
            mem_svmp1 = memory;
            goto next;
        }
    }
    MessageBoxA(0, "未能搜索到区段.svmp1", "警告", MB_TOPMOST | MB_ICONWARNING | MB_OK);
    return 0;
next:
    DWORD tmp_iat_begin;
    if (_Getlong("临时数据起始位置", &tmp_iat_begin, 4, '0', DIA_HEXONLY) != 0)
    {
        return -1;
    }
    //-------------------------读取代码-------------------------------------
    SEG_MAP seg_map[2];
    //读取.text和.svmp1的代码
    seg_map[0] = { mem_code->base,mem_code->size,"",new uchar[mem_code->size] };
    _Readmemory(seg_map[0].buf, mem_code->base, mem_code->size, MM_RESILENT);
    seg_map[1] = { mem_svmp1->base,mem_svmp1->size,"",new uchar[mem_svmp1->size] };
    _Readmemory(seg_map[1].buf, mem_svmp1->base, mem_svmp1->size, MM_RESILENT);
    //---------------------------初始化模拟器--------------------------------
    emu_control = true;
    Emulator emu;
    emu.MapMemoryFromOD();
    emu.SetRegFromOD();
    emu.RegisterCallback(EmuJmpImmSolver, NULL);       //bug unicorn有bug导致jmp指令可能会崩溃
    emu.RegisterCallback(FixSpIATCallback, mem_svmp1);
    //---------------------在svmp1段搜索特征---------------------------------
    DWORD cnt_common_calljmp = 0;
    DWORD cnt_common_mov = 0;
    DWORD cnt_virtual_calljmp = 0;
    DWORD cnt_virtual_mov = 0;
    vector<api_info> vec_iat_data;	                     //存放等待重建的IAT数据
    vector<pair<DWORD32, DWORD32>> vec_err_call;         //第一个数据为entry，第二个数据为实际调用api的地址（未知或者异常）。这些地址需要手动处理
    char dll_path[MAX_PATH] = {};
    char api_name[TEXTLEN] = {};
    t_module* module;
    //entry=4cf731
    //eip=0x00d6cd7a
    for (DWORD i = mem_svmp1->base; i < mem_svmp1->base + mem_svmp1->size - 100; i++)
    {
        //常规iat加密特征
        if ((seg_map[1].buf[i - mem_svmp1->base] == 0x9C || seg_map[1].buf[i - mem_svmp1->base + 1] == 0x9C))
        {
            a.Clear();
            a.Disasm(i, seg_map[1].buf + i - mem_svmp1->base, 48, 3);
            if (a.count != 3) continue;
            if (a.vec_insn[0]->id!=X86_INS_PUSHFD&&a.vec_insn[0]->id!=X86_INS_PUSH) continue;
            if (a.vec_insn[1]->id!=X86_INS_PUSHFD&&a.vec_insn[1]->id!=X86_INS_PUSH) continue;
            if (a.vec_insn[2]->id!=X86_INS_JMP) continue;
            const DWORD jmp_to = (DWORD)a.vec_insn[2]->detail->x86.operands[0].imm;       //跳转的目标地址
            if (jmp_to < mem_svmp1->base || jmp_to >= mem_svmp1->base + mem_svmp1->size) continue;
            a.Clear();
            a.Disasm(jmp_to, seg_map[1].buf + jmp_to - mem_svmp1->base, 5, 1);
            if (a.count != 1) continue;
            if (a.vec_insn[0]->id != X86_INS_MOV) continue;
            if (a.vec_insn[0]->detail->x86.operands[0].type != X86_OP_REG) continue;
            if (a.vec_insn[0]->detail->x86.operands[1].type != X86_OP_IMM) continue;
            if (a.vec_insn[0]->detail->x86.operands[1].imm != 0) continue;

            //开始模拟直至eip不在svmp1区段
            //[esp]置0x00400000是为了判断是否是mov类型
            //(各个寄存器置0是为了判断mov类型时修改的是哪个寄存器)
            DWORD v = 0x00400000;
            emu.WriteMemory(emu.regs.esp, 4, &v);
            emu.regs.eax = 0;
            emu.regs.ecx = 0;
            emu.regs.edx = 0;
            emu.regs.ebx = 0;
            emu.regs.esp = thread->reg.r[REG_ESP];
            emu.regs.ebp = 0;
            emu.regs.esi = 0;
            emu.regs.edi = 0;
            emu.regs.eip = i;
            emu.regs.efl = 0x246;
            emu.Run();
            //判断eip是否为0x00401000，如果是则为mov reg，[mem]形式。否则为call或jmp类型
            if (emu.regs.eip == 0x00400000)
            {
                //mov reg, dword ptr [mem]
                if (emu.regs.eax != 0 && _Findsymbolicname(emu.regs.eax, api_name) > 1)
                {
                    module = _Findmodule(emu.regs.eax);
                    if (module == NULL)
                    {
                        _Addtolist(i, 1, "[moye] 无法定位到模块 entry = %#08x api -> %#08x", i, emu.regs.eax);
                        vec_err_call.emplace_back(i, emu.regs.eax);
                        continue;
                    }
                    strcpy_s(dll_path, module->name);
                    vec_iat_data.push_back({ dll_path, api_name, i, emu.regs.eax, 3 });
                    _Addtolist(i, 0, "[moye] |一般|类型为 mov entry = %#08x api -> %#08x %s", i, emu.regs.eax, api_name);
                    ++cnt_common_mov;
                }
                else if (emu.regs.ecx != 0 && _Findsymbolicname(emu.regs.ecx, api_name) > 1)
                {
                    module = _Findmodule(emu.regs.ecx);
                    if (module == NULL)
                    {
                        _Addtolist(i, 1, "[moye] 无法定位到模块 entry = %#08x api -> %#08x", i, emu.regs.ecx);
                        vec_err_call.emplace_back(i, emu.regs.ecx);
                        continue;
                    }
                    strcpy_s(dll_path, module->name);
                    vec_iat_data.push_back({ dll_path, api_name, i, emu.regs.ecx, 4 });
                    _Addtolist(i, 0, "[moye] |一般|类型为 mov entry = %#08x api -> %#08x %s", i, emu.regs.ecx, api_name);
                    ++cnt_common_mov;
                }
                else if (emu.regs.edx != 0 && _Findsymbolicname(emu.regs.edx, api_name) > 1)
                {
                    module = _Findmodule(emu.regs.edx);
                    if (module == NULL)
                    {
                        _Addtolist(i, 1, "[moye] 无法定位到模块 entry = %#08x api -> %#08x", i, emu.regs.edx);
                        vec_err_call.emplace_back(i, emu.regs.edx);
                        continue;
                    }
                    strcpy_s(dll_path, module->name);
                    vec_iat_data.push_back({ dll_path, api_name, i, emu.regs.edx, 5 });
                    _Addtolist(i, 0, "[moye] |一般|类型为 mov entry = %#08x api -> %#08x %s", i, emu.regs.edx, api_name);
                    ++cnt_common_mov;
                }
                else if (emu.regs.ebx != 0 && _Findsymbolicname(emu.regs.ebx, api_name) > 1)
                {
                    module = _Findmodule(emu.regs.ebx);
                    if (module == NULL)
                    {
                        _Addtolist(i, 1, "[moye] 无法定位到模块 entry = %#08x api -> %#08x", i, emu.regs.ebx);
                        vec_err_call.emplace_back(i, emu.regs.ebx);
                        continue;
                    }
                    strcpy_s(dll_path, module->name);
                    vec_iat_data.push_back({ dll_path, api_name, i, emu.regs.ebx, 6 });
                    _Addtolist(i, 0, "[moye] |一般|类型为 mov entry = %#08x api -> %#08x %s", i, emu.regs.ebx, api_name);
                    ++cnt_common_mov;
                }
                else if (emu.regs.ebp != 0 && _Findsymbolicname(emu.regs.ebp, api_name) > 1)
                {
                    module = _Findmodule(emu.regs.ebp);
                    if (module == NULL)
                    {
                        _Addtolist(i, 1, "[moye] 无法定位到模块 entry = %#08x api -> %#08x", i, emu.regs.ebp);
                        vec_err_call.emplace_back(i, emu.regs.ebp);
                        continue;
                    }
                    strcpy_s(dll_path, module->name);
                    vec_iat_data.push_back({ dll_path, api_name, i, emu.regs.ebp, 7 });
                    _Addtolist(i, 0, "[moye] |一般|类型为 mov entry = %#08x api -> %#08x %s", i, emu.regs.ebp, api_name);
                    ++cnt_common_mov;
                }
                else if (emu.regs.esi != 0 && _Findsymbolicname(emu.regs.esi, api_name) > 1)
                {
                    module = _Findmodule(emu.regs.esi);
                    if (module == NULL)
                    {
                        _Addtolist(i, 1, "[moye] 无法定位到模块 entry = %#08x api -> %#08x", i, emu.regs.esi);
                        vec_err_call.emplace_back(i, emu.regs.esi);
                        continue;
                    }
                    strcpy_s(dll_path, module->name);
                    vec_iat_data.push_back({ dll_path, api_name, i, emu.regs.esi, 8 });
                    _Addtolist(i, 0, "[moye] |一般|类型为 mov entry = %#08x api -> %#08x %s", i, emu.regs.esi, api_name);
                    ++cnt_common_mov;
                }
                else if (emu.regs.edi != 0 && _Findsymbolicname(emu.regs.edi, api_name) > 1)
                {
                    module = _Findmodule(emu.regs.edi);
                    if (module == NULL)
                    {
                        _Addtolist(i, 1, "[moye] 无法定位到模块 entry = %#08x api -> %#08x", i, emu.regs.edi);
                        vec_err_call.emplace_back(i, emu.regs.edi);
                        continue;
                    }
                    strcpy_s(dll_path, module->name);
                    vec_iat_data.push_back({ dll_path, api_name, i, emu.regs.edi, 9 });
                    _Addtolist(i, 0, "[moye] |一般|类型为 mov entry = %#08x api -> %#08x %s", i, emu.regs.edi, api_name);
                    ++cnt_common_mov;
                }
                else
                {
                    _Addtolist(i, 1, "[moye] 未知的加密方式 entry = %#08x api -> %#08x", i, emu.regs.eip);
                    vec_err_call.emplace_back(i, emu.regs.eip);
                    continue;
                }
            }
            else if (_Findsymbolicname(emu.regs.eip, api_name) > 1)
            {
                //保存api所在模块名
                module = _Findmodule(emu.regs.eip);
                if (module == NULL)
                {
                    _Addtolist(i, 1, "[moye] 无法定位到模块 entry = %#08x api -> %#08x", i, emu.regs.eip);
                    vec_err_call.emplace_back(i, emu.regs.eip);
                    continue;
                }
                strcpy_s(dll_path, module->name);
                //jmp加密比call加密只多一个lea esp, [esp + 4]，不需要在判断是call还是jmp
                if (thread->reg.r[REG_ESP] == emu.regs.esp)
                {
                    //jmp dword ptr [mem]
                    ++cnt_common_calljmp;
                    vec_iat_data.push_back({ dll_path, api_name, i, emu.regs.eip, 1 });
                    _Addtolist(i, 0, "[moye] |一般|在此处修复 entry = %#08x api -> %#08x %s", i, emu.regs.eip, api_name);
                }
                else
                {
                    _Addtolist(i, 1, "[moye] 未知的加密方式 entry = %#08x api -> %#08x", i, emu.regs.eip);
                    vec_err_call.emplace_back(i, emu.regs.eip);
                    continue;
                }
            }
            else
            {
                _Addtolist(i, 1, "[moye] 未知的加密方式 entry = %#08x api -> %#08x", i, emu.regs.eip);
                vec_err_call.emplace_back(i, emu.regs.eip);
                continue;
            }
            _Infoline("[moye] |一般|解析完成：entry -> %#08X api -> %-20s", i, api_name);
            //_Setcpu(0, i, 0, 0, CPU_NOFOCUS);
            continue;
        }
        //虚拟化iat加密特征
        else if (seg_map[1].buf[i - mem_svmp1->base + 2] == 0x9C && seg_map[1].buf[i - mem_svmp1->base + 4] == 0 &&
            seg_map[1].buf[i - mem_svmp1->base + 5] == 0 && seg_map[1].buf[i - mem_svmp1->base + 6] == 0 && seg_map[1].buf[i - mem_svmp1->base + 7] == 0)
        {
            a.Clear();
            a.Disasm(i, seg_map[1].buf + i - mem_svmp1->base, 26, 7);
            if (a.count != 7) continue;
            if (a.vec_insn[0]->id != X86_INS_PUSH) continue;
            if (a.vec_insn[1]->id != X86_INS_PUSH) continue;
            if (a.vec_insn[2]->id != X86_INS_PUSHFD) continue;
            if (a.vec_insn[3]->id != X86_INS_MOV) continue;
            if (a.vec_insn[3]->detail->x86.operands[0].type != X86_OP_REG) continue;
            if (a.vec_insn[3]->detail->x86.operands[1].type != X86_OP_IMM) continue;
            if (a.vec_insn[3]->detail->x86.operands[1].imm != 0) continue;
            if (a.vec_insn[4]->id != X86_INS_LEA) continue;
            if (a.vec_insn[5]->id != X86_INS_LEA) continue;
            if (a.vec_insn[6]->id != X86_INS_LEA) continue;

            //开始模拟直至eip不在svmp1区段
            //[esp]置0x00400000是为了判断是否是mov类型
            //(各个寄存器置0是为了判断mov类型时修改的是哪个寄存器)
            DWORD v = 0x00400000;
            emu.WriteMemory(emu.regs.esp, 4, &v);
            emu.regs.eax = 0;
            emu.regs.ecx = 0;
            emu.regs.edx = 0;
            emu.regs.ebx = 0;
            emu.regs.esp = thread->reg.r[REG_ESP];
            emu.regs.ebp = 0;
            emu.regs.esi = 0;
            emu.regs.edi = 0;
            emu.regs.eip = i;
            emu.regs.efl = 0x246;
            emu.Run();
            //判断eip是否为0x00401000，如果是则为mov reg，[mem]形式。否则为call或jmp类型
            if (emu.regs.eip == 0x00400000)
            {
                //mov reg, dword ptr [mem]
                if (emu.regs.eax != 0 && _Findsymbolicname(emu.regs.eax, api_name) > 1)
                {
                    module = _Findmodule(emu.regs.eax);
                    if (module == NULL)
                    {
                        _Addtolist(i, 1, "[moye] 无法定位到模块 entry = %#08x api -> %#08x", i, emu.regs.eax);
                        vec_err_call.emplace_back(i, emu.regs.eax);
                        continue;
                    }
                    strcpy_s(dll_path, module->name);
                    vec_iat_data.push_back({ dll_path, api_name, i, emu.regs.eax, 3 });
                    _Addtolist(i, 0, "[moye] |虚拟|类型为 mov entry = %#08x api -> %#08x %s", i, emu.regs.eax, api_name);
                    ++cnt_virtual_mov;
                }
                else if (emu.regs.ecx != 0 && _Findsymbolicname(emu.regs.ecx, api_name) > 1)
                {
                    module = _Findmodule(emu.regs.ecx);
                    if (module == NULL)
                    {
                        _Addtolist(i, 1, "[moye] 无法定位到模块 entry = %#08x api -> %#08x", i, emu.regs.ecx);
                        vec_err_call.emplace_back(i, emu.regs.ecx);
                        continue;
                    }
                    strcpy_s(dll_path, module->name);
                    vec_iat_data.push_back({ dll_path, api_name, i, emu.regs.ecx, 4 });
                    _Addtolist(i, 0, "[moye] |虚拟|类型为 mov entry = %#08x api -> %#08x %s", i, emu.regs.ecx, api_name);
                    ++cnt_virtual_mov;
                }
                else if (emu.regs.edx != 0 && _Findsymbolicname(emu.regs.edx, api_name) > 1)
                {
                    module = _Findmodule(emu.regs.edx);
                    if (module == NULL)
                    {
                        _Addtolist(i, 1, "[moye] 无法定位到模块 entry = %#08x api -> %#08x", i, emu.regs.edx);
                        vec_err_call.emplace_back(i, emu.regs.edx);
                        continue;
                    }
                    strcpy_s(dll_path, module->name);
                    vec_iat_data.push_back({ dll_path, api_name, i, emu.regs.edx, 5 });
                    _Addtolist(i, 0, "[moye] |虚拟|类型为 mov entry = %#08x api -> %#08x %s", i, emu.regs.edx, api_name);
                    ++cnt_virtual_mov;
                }
                else if (emu.regs.ebx != 0 && _Findsymbolicname(emu.regs.ebx, api_name) > 1)
                {
                    module = _Findmodule(emu.regs.ebx);
                    if (module == NULL)
                    {
                        _Addtolist(i, 1, "[moye] 无法定位到模块 entry = %#08x api -> %#08x", i, emu.regs.ebx);
                        vec_err_call.emplace_back(i, emu.regs.ebx);
                        continue;
                    }
                    strcpy_s(dll_path, module->name);
                    vec_iat_data.push_back({ dll_path, api_name, i, emu.regs.ebx, 6 });
                    _Addtolist(i, 0, "[moye] |虚拟|类型为 mov entry = %#08x api -> %#08x %s", i, emu.regs.ebx, api_name);
                    ++cnt_virtual_mov;
                }
                else if (emu.regs.ebp != 0 && _Findsymbolicname(emu.regs.ebp, api_name) > 1)
                {
                    module = _Findmodule(emu.regs.ebp);
                    if (module == NULL)
                    {
                        _Addtolist(i, 1, "[moye] 无法定位到模块 entry = %#08x api -> %#08x", i, emu.regs.ebp);
                        vec_err_call.emplace_back(i, emu.regs.ebp);
                        continue;
                    }
                    strcpy_s(dll_path, module->name);
                    vec_iat_data.push_back({ dll_path, api_name, i, emu.regs.ebp, 7 });
                    _Addtolist(i, 0, "[moye] |虚拟|类型为 mov entry = %#08x api -> %#08x %s", i, emu.regs.ebp, api_name);
                    ++cnt_virtual_mov;
                }
                else if (emu.regs.esi != 0 && _Findsymbolicname(emu.regs.esi, api_name) > 1)
                {
                    module = _Findmodule(emu.regs.esi);
                    if (module == NULL)
                    {
                        _Addtolist(i, 1, "[moye] 无法定位到模块 entry = %#08x api -> %#08x", i, emu.regs.esi);
                        vec_err_call.emplace_back(i, emu.regs.esi);
                        continue;
                    }
                    strcpy_s(dll_path, module->name);
                    vec_iat_data.push_back({ dll_path, api_name, i, emu.regs.esi, 8 });
                    _Addtolist(i, 0, "[moye] |虚拟|类型为 mov entry = %#08x api -> %#08x %s", i, emu.regs.esi, api_name);
                    ++cnt_virtual_mov;
                }
                else if (emu.regs.edi != 0 && _Findsymbolicname(emu.regs.edi, api_name) > 1)
                {
                    module = _Findmodule(emu.regs.edi);
                    if (module == NULL)
                    {
                        _Addtolist(i, 1, "[moye] 无法定位到模块 entry = %#08x api -> %#08x", i, emu.regs.edi);
                        vec_err_call.emplace_back(i, emu.regs.edi);
                        continue;
                    }
                    strcpy_s(dll_path, module->name);
                    vec_iat_data.push_back({ dll_path, api_name, i, emu.regs.edi, 9 });
                    _Addtolist(i, 0, "[moye] |虚拟|类型为 mov entry = %#08x api -> %#08x %s", i, emu.regs.edi, api_name);
                    ++cnt_virtual_mov;
                }
                else
                {
                    _Addtolist(i, 1, "[moye] 未知的加密方式 entry = %#08x api -> %#08x", i, emu.regs.eip);
                    vec_err_call.emplace_back(i, emu.regs.eip);
                    continue;
                }
            }
            else if (_Findsymbolicname(emu.regs.eip, api_name) > 1)
            {
                //保存api所在模块名
                module = _Findmodule(emu.regs.eip);
                if (module == NULL)
                {
                    _Addtolist(i, 1, "[moye] 无法定位到模块 entry = %#08x api -> %#08x", i, emu.regs.eip);
                    vec_err_call.emplace_back(i, emu.regs.eip);
                    continue;
                }
                strcpy_s(dll_path, module->name);
                //jmp加密比call加密只多一个lea esp, [esp + 4]，不需要在判断是call还是jmp
                if (thread->reg.r[REG_ESP] == emu.regs.esp)
                {
                    //jmp dword ptr [mem]
                    ++cnt_virtual_calljmp;
                    vec_iat_data.push_back({ dll_path, api_name, i, emu.regs.eip, 1 });
                    _Addtolist(i, 0, "[moye] |虚拟|在此处修复 entry = %#08x api -> %#08x %s", i, emu.regs.eip, api_name);
                }
                else
                {
                    _Addtolist(i, 1, "[moye] 未知的加密方式 entry = %#08x api -> %#08x", i, emu.regs.eip);
                    vec_err_call.emplace_back(i, emu.regs.eip);
                    continue;
                }
            }
            else
            {
                _Addtolist(i, 1, "[moye] 未知的加密方式 entry = %#08x api -> %#08x", i, emu.regs.eip);
                vec_err_call.emplace_back(i, emu.regs.eip);
                continue;
            }
            _Infoline("[moye] |虚拟|解析完成：entry -> %#08X api -> %-20s", i, api_name);
            //_Setcpu(0, i, 0, 0, CPU_NOFOCUS);
            continue;
        }
    }

    delete[] seg_map[0].buf;
    delete[] seg_map[1].buf;
    //-----------------------重建iat表------------------------
    if (vec_iat_data.empty())
    {
        MessageBoxA(0, "未查找到需要修复的地方", "提示", MB_TOPMOST | MB_ICONWARNING | MB_OK);
        return 0;
    }
    sort(vec_iat_data.begin(), vec_iat_data.end());     //排序

    DWORD tmp_addr = tmp_iat_begin;    //当前api存放的地址
    char tmp[50] = {};                 //汇编字符串缓冲区
    char errtext[TEXTLEN];
    t_asmmodel asmmodel;
    vec_iat_data.push_back({});   //末尾标记，并且防越界
    for (DWORD i = 0; i < vec_iat_data.size() - 1; i++)
    {
        _Progress(i * 1000 / (vec_iat_data.size() - 1), (char*)"重建IAT表中...进度");
        switch (vec_iat_data[i].type)
        {
            case 1:
                _Writememory(&vec_iat_data[i].api_addr, tmp_addr, 4, MM_SILENT);
                _Writememory((char*)"\xFF\x25", vec_iat_data[i].fix_addr, 2, MM_SILENT);
                _Writememory(&tmp_addr, vec_iat_data[i].fix_addr + 2, 4, MM_SILENT);
                break;
                //在这种修复方式下，不需要call类型的修复
                // case 2:
                //     _Writememory(&vec_iat_data[i].api_addr, tmp_addr, 4, MM_SILENT);
                //     _Writememory((char*)"\x58\xFF\x25", vec_iat_data[i].fix_addr, 3, MM_SILENT);
                //     _Writememory(&tmp_addr, vec_iat_data[i].fix_addr + 3, 4, MM_SILENT);
                //     break;
            case 3:
                _Writememory(&vec_iat_data[i].api_addr, tmp_addr, 4, MM_SILENT);
                sprintf_s(tmp, "mov eax, dword ptr [%08X]", tmp_addr);
                _Assemble(tmp, vec_iat_data[i].fix_addr, &asmmodel, 0, 0, errtext);
                _Writememory(asmmodel.code, vec_iat_data[i].fix_addr, asmmodel.length, MM_SILENT);
                _Writememory((void*)"\xC3", vec_iat_data[i].fix_addr + 6, 1, MM_SILENT);
                break;
            case 4:
                _Writememory(&vec_iat_data[i].api_addr, tmp_addr, 4, MM_SILENT);
                sprintf_s(tmp, "mov ecx, dword ptr [%08X]", tmp_addr);
                _Assemble(tmp, vec_iat_data[i].fix_addr, &asmmodel, 0, 0, errtext);
                _Writememory(asmmodel.code, vec_iat_data[i].fix_addr, asmmodel.length, MM_SILENT);
                _Writememory((void*)"\xC3", vec_iat_data[i].fix_addr + 6, 1, MM_SILENT);
                break;
            case 5:
                _Writememory(&vec_iat_data[i].api_addr, tmp_addr, 4, MM_SILENT);
                sprintf_s(tmp, "mov edx, dword ptr [%08X]", tmp_addr);
                _Assemble(tmp, vec_iat_data[i].fix_addr, &asmmodel, 0, 0, errtext);
                _Writememory(asmmodel.code, vec_iat_data[i].fix_addr, asmmodel.length, MM_SILENT);
                _Writememory((void*)"\xC3", vec_iat_data[i].fix_addr + 6, 1, MM_SILENT);
                break;
            case 6:
                _Writememory(&vec_iat_data[i].api_addr, tmp_addr, 4, MM_SILENT);
                sprintf_s(tmp, "mov ebx, dword ptr [%08X]", tmp_addr);
                _Assemble(tmp, vec_iat_data[i].fix_addr, &asmmodel, 0, 0, errtext);
                _Writememory(asmmodel.code, vec_iat_data[i].fix_addr, asmmodel.length, MM_SILENT);
                _Writememory((void*)"\xC3", vec_iat_data[i].fix_addr + 6, 1, MM_SILENT);
                break;
            case 7:
                _Writememory(&vec_iat_data[i].api_addr, tmp_addr, 4, MM_SILENT);
                sprintf_s(tmp, "mov ebp, dword ptr [%08X]", tmp_addr);
                _Assemble(tmp, vec_iat_data[i].fix_addr, &asmmodel, 0, 0, errtext);
                _Writememory(asmmodel.code, vec_iat_data[i].fix_addr, asmmodel.length, MM_SILENT);
                _Writememory((void*)"\xC3", vec_iat_data[i].fix_addr + 6, 1, MM_SILENT);
                break;
            case 8:
                _Writememory(&vec_iat_data[i].api_addr, tmp_addr, 4, MM_SILENT);
                sprintf_s(tmp, "mov esi, dword ptr [%08X]", tmp_addr);
                _Assemble(tmp, vec_iat_data[i].fix_addr, &asmmodel, 0, 0, errtext);
                _Writememory(asmmodel.code, vec_iat_data[i].fix_addr, asmmodel.length, MM_SILENT);
                _Writememory((void*)"\xC3", vec_iat_data[i].fix_addr + 6, 1, MM_SILENT);
                break;
            case 9:
                _Writememory(&vec_iat_data[i].api_addr, tmp_addr, 4, MM_SILENT);
                sprintf_s(tmp, "mov edi, dword ptr [%08X]", tmp_addr);
                _Assemble(tmp, vec_iat_data[i].fix_addr, &asmmodel, 0, 0, errtext);
                _Writememory(asmmodel.code, vec_iat_data[i].fix_addr, asmmodel.length, MM_SILENT);
                _Writememory((void*)"\xC3", vec_iat_data[i].fix_addr + 6, 1, MM_SILENT);
                break;
            default:
                MessageBoxA(0, "重建IAT表时异常：不正确的类型", "错误", MB_TOPMOST | MB_ICONERROR | MB_OK);
                break;
        }

        if (vec_iat_data[i].dll_name != vec_iat_data[i + 1].dll_name)
        {
            //不同dll的函数集合，用0隔开
            DWORD data = 0;
            tmp_addr += 4;
            _Writememory(&data, tmp_addr, 4, MM_SILENT);
            tmp_addr += 4;
        }
        else if (vec_iat_data[i].api_name != vec_iat_data[i + 1].api_name)
        {
            //如果不是相同的函数名，代表碰到了新的函数，需要扩大4字节放它的地址
            tmp_addr += 4;
        }
    }
    _Progress(0, 0);
    _Addtolist(0, 0, "[moye] --------------修复完毕--------------");
    _Addtolist(0, 0, "[moye] 一般类型call/jmp的数量：%lu", cnt_common_calljmp);
    _Addtolist(0, 0, "[moye] 一般类型mov的数量：%lu", cnt_common_mov);
    _Addtolist(0, 0, "[moye] 虚拟类型call/jmp的数量：%lu", cnt_virtual_calljmp);
    _Addtolist(0, 0, "[moye] 虚拟类型mov的数量：%lu", cnt_virtual_mov);
    _Addtolist(0, 0, "[moye] 临时数据地址：0x%08x", tmp_iat_begin);
    _Addtolist(0, 0, "[moye] 临时数据大小：0x%08x", tmp_addr - tmp_iat_begin);
    _Addtolist(0, 0, "[moye] ------------------------------------");
    if (!vec_err_call.empty())
    {
        _Addtolist(0, 1, "[moye] --------以下数据需要手动处理--------");
        for (auto& i : vec_err_call)
        {
            _Addtolist(0, 1, "[moye] entry->0x%08x api->0x%08x", i.first, i.second);
        }
        _Addtolist(0, 1, "[moye] ------------------------------------");
    }
    _Flash("修复完毕");
    return 0;
}


bool MemAccessAnalysisCallback(Emulator* emu, void* user_data)
{
    hash_data_addr = 0;
    hash_data_size = 0;
    BYTE code[16];
    emu->ReadMemory(emu->regs.eip, sizeof(code), code);
    a.Clear();
    a.Disasm(emu->regs.eip, code, sizeof(code));
    if (a.vec_insn[0]->id == X86_INS_CPUID)
    {
        _Message(emu->regs.eip, "[Special Insn] cpuid | 0x%08x %s %s", emu->regs.eip, a.vec_insn[0]->mnemonic, a.vec_insn[0]->op_str);
        a.Clear();
        return true;
    }
    if (a.vec_insn[0]->id == X86_INS_RDTSC)
    {
        _Message(emu->regs.eip, "[Special Insn] rdtsc | 0x%08x %s %s", emu->regs.eip, a.vec_insn[0]->mnemonic, a.vec_insn[0]->op_str);
        return true;
    }
    if (a.vec_insn[0]->id == X86_INS_IN)
    {
        _Message(emu->regs.eip, "[Special Insn] in | 0x%08x %s %s", emu->regs.eip, a.vec_insn[0]->mnemonic, a.vec_insn[0]->op_str);
        return true;
    }
    if (a.vec_insn[0]->id == X86_INS_OUT)
    {
        _Message(emu->regs.eip, "[Special Insn] out | 0x%08x %s %s", emu->regs.eip, a.vec_insn[0]->mnemonic, a.vec_insn[0]->op_str);
        return true;
    }
    if (a.vec_insn[0]->id == X86_INS_SGDT)
    {
        _Message(emu->regs.eip, "[Special Insn] sgdt | 0x%08x %s %s", emu->regs.eip, a.vec_insn[0]->mnemonic, a.vec_insn[0]->op_str);
        return true;
    }
    if (a.vec_insn[0]->id == X86_INS_SLDT)
    {
        _Message(emu->regs.eip, "[Special Insn] sldt | 0x%08x %s %s", emu->regs.eip, a.vec_insn[0]->mnemonic, a.vec_insn[0]->op_str);
        return true;
    }
    if (a.vec_insn[0]->id != X86_INS_LEA)
    {
        for (DWORD i = 0; i < a.vec_insn[0]->detail->x86.op_count; i++)
        {
            if (a.vec_insn[0]->detail->x86.operands[i].type == X86_OP_MEM)
            {
                DWORD mem_addr = emu->GetMemAddr(a.vec_insn[0]->detail->x86.operands[i].mem);
                DWORD value = 0;
                if (a.vec_insn[0]->detail->x86.operands[i].mem.segment == X86_REG_FS)
                {
                    DWORD offset = mem_addr;
                    mem_addr = emu->regs.fs_base + mem_addr;
                    emu->ReadMemory(mem_addr, 4, &value);
                    _Message(emu->regs.eip, "[ FS->[0x%02x] ] mem_addr = 0x%08x value = 0x%08x | 0x%08x %s %s", offset, mem_addr, value, emu->regs.eip, a.vec_insn[0]->mnemonic, a.vec_insn[0]->op_str);
                    break;
                }
                t_memory* memory = _Findmemory(mem_addr);
                if (memory == nullptr)
                {
                    _Addtolist(emu->regs.eip, 0, "无法查找到指定内存 mem_addr = 0x%08x 0x%08x %s %s", mem_addr, emu->regs.eip, a.vec_insn[0]->mnemonic, a.vec_insn[0]->op_str);
                    break;
                }
                //过滤不需要关注的内存信息
                if ((memory->type & TY_STACK) != 0) continue;
                if (memory->base < 0x200000) continue;
                emu->ReadMemory(mem_addr, a.vec_insn[0]->detail->x86.operands[i].size, &value);

                //记录对内存的写入，可能是表示虚拟机是否按顺序执行过的hash数据
                if (strstr(memory->sect, ".svmp") != NULL)
                {
                    if (i == 0)
                    {
                        if (a.vec_insn[0]->id == X86_INS_POP)
                        {
                            _Message(emu->regs.eip, "[Write %s] mem_addr = 0x%08x value = 0x%08x | 0x%08x %s %s", memory->sect, mem_addr, value, emu->regs.eip, a.vec_insn[0]->mnemonic, a.vec_insn[0]->op_str);
                            hash_data_addr = mem_addr;
                            hash_data_size = a.vec_insn[0]->detail->x86.operands[i].size;
                            break;
                        }
                        if (a.vec_insn[0]->id == X86_INS_MOV)
                        {
                            _Message(emu->regs.eip, "[Write %s] mem_addr = 0x%08x value = 0x%08x | 0x%08x %s %s", memory->sect, mem_addr, value, emu->regs.eip, a.vec_insn[0]->mnemonic, a.vec_insn[0]->op_str);
                            hash_data_addr = mem_addr;
                            hash_data_size = a.vec_insn[0]->detail->x86.operands[i].size;
                            break;
                        }
                        if (a.vec_insn[0]->id == X86_INS_XCHG)
                        {
                            _Message(emu->regs.eip, "[Write %s] mem_addr = 0x%08x value = 0x%08x | 0x%08x %s %s", memory->sect, mem_addr, value, emu->regs.eip, a.vec_insn[0]->mnemonic, a.vec_insn[0]->op_str);
                            hash_data_addr = mem_addr;
                            hash_data_size = a.vec_insn[0]->detail->x86.operands[i].size;
                            break;
                        }
                    }
                    else if (i == 1)
                    {
                        if (a.vec_insn[0]->id == X86_INS_XCHG)
                        {
                            _Message(emu->regs.eip, "[Write %s] mem_addr = 0x%08x value = 0x%08x | 0x%08x %s %s", memory->sect, mem_addr, value, emu->regs.eip, a.vec_insn[0]->mnemonic, a.vec_insn[0]->op_str);
                            hash_data_addr = mem_addr;
                            hash_data_size = a.vec_insn[0]->detail->x86.operands[i].size;
                            break;
                        }
                    }
                    //if(strstr(memory->sect, ".svmp1") == NULL)
                    //_Message(emu->regs.eip, "[Read  %s] mem_addr = 0x%08x value = 0x%08x | 0x%08x %s %s", memory->sect, mem_addr, value, emu->regs.eip, a.vec_insn[0]->mnemonic, a.vec_insn[0]->op_str);
                }
                else if ((memory->type & TY_HEADER) != 0)
                {
                    _Message(emu->regs.eip, "[ PE  Header ] mem_addr = 0x%08x value = 0x%08x | 0x%08x %s %s", mem_addr, value, emu->regs.eip, a.vec_insn[0]->mnemonic, a.vec_insn[0]->op_str);
                }
                else if ((memory->type & TY_EXPDATA) != 0)
                {
                    _Message(emu->regs.eip, "[Export  Data] mem_addr = 0x%08x value = 0x%08x | 0x%08x %s %s", mem_addr, value, emu->regs.eip, a.vec_insn[0]->mnemonic, a.vec_insn[0]->op_str);
                }
                else if ((memory->type & TY_IMPDATA) != 0)
                {
                    _Message(emu->regs.eip, "[Import  Data] mem_addr = 0x%08x value = 0x%08x | 0x%08x %s %s", mem_addr, value, emu->regs.eip, a.vec_insn[0]->mnemonic, a.vec_insn[0]->op_str);
                }
                else if ((memory->type & TY_CODE) != 0)
                {
                    _Message(emu->regs.eip, "[Code section] mem_addr = 0x%08x value = 0x%08x | 0x%08x %s %s", mem_addr, value, emu->regs.eip, a.vec_insn[0]->mnemonic, a.vec_insn[0]->op_str);
                }
                else if ((memory->type & TY_RSRC) != 0)
                {
                    _Message(emu->regs.eip, "[Rsrc section] mem_addr = 0x%08x value = 0x%08x | 0x%08x %s %s", mem_addr, value, emu->regs.eip, a.vec_insn[0]->mnemonic, a.vec_insn[0]->op_str);
                }
                else if ((memory->type & TY_THREAD) != 0)
                {
                    _Message(emu->regs.eip, "[Thread  Data] mem_addr = 0x%08x value = 0x%08x | 0x%08x %s %s", mem_addr, value, emu->regs.eip, a.vec_insn[0]->mnemonic, a.vec_insn[0]->op_str);
                }
                else
                {
                    _Message(emu->regs.eip, "      -        mem_addr = 0x%08x value = 0x%08x | 0x%08x %s %s", mem_addr, value, emu->regs.eip, a.vec_insn[0]->mnemonic, a.vec_insn[0]->op_str);
                }
            }
        }
    }
    a.Clear();
    return true;
}

/**
 * \brief 生成patch SP虚拟机Hash数据的回调，SP虚拟机生成了Hash数据以防止虚拟机执行流程被篡改
 * \param emu 模拟器this指针
 * \param user_data 此回调不使用此额外参数
 * \return 真
 */
bool GetPatchSPWriteHashDataCallback(Emulator* emu, void* user_data)
{
    if (hash_data_addr)
    {
        DWORD hash_value = 0;
        char patch_asm[200];
        switch (hash_data_size)
        {
            case 1:
                emu->ReadMemory(hash_data_addr, 1, &hash_value);
                sprintf_s(patch_asm, "mov byte ptr [0x%08x], 0x%08x\n", hash_data_addr, hash_value);
                break;
            case 2:
                emu->ReadMemory(hash_data_addr, 2, &hash_value);
                sprintf_s(patch_asm, "mov word ptr [0x%08x], 0x%08x\n", hash_data_addr, hash_value);
                break;
            case 4:
                emu->ReadMemory(hash_data_addr, 4, &hash_value);
                sprintf_s(patch_asm, "mov dword ptr [0x%08x], 0x%08x\n", hash_data_addr, hash_value);
                break;
            default:
                _Addtolist(emu->regs.eip, 1, "Invalid hash_data_size %lu", hash_data_size);
                emu->Stop();
                return true;
        }
        OutputDebugStringA(patch_asm);
        hash_data_addr = 0;
        hash_data_size = 0;
    }
    return true;
}

/**
 * \brief 寻找SP虚拟机出口的回调
 * \param emu 模拟器this指针
 * \param user_data 此回调不使用此额外参数
 * \return 真
 */
bool FindSPVMExitCallback(Emulator* emu, void* user_data)
{
    BYTE code[32];
    emu->ReadMemory(emu->regs.eip, sizeof(code), code);
    a.Clear();
    a.Disasm(emu->regs.eip, code, sizeof(code), 2);
    if (a.count != 2) {
        a.Clear();
        return true;
    }
    if (a.vec_insn[0]->id == X86_INS_POP && a.vec_insn[0]->detail->x86.operands[0].reg == X86_REG_ESP && a.vec_insn[1]->id == X86_INS_RET)
    {
        _Message(emu->regs.eip, "VM exit type 1");
    }
    else if (a.vec_insn[0]->id == X86_INS_MOV && a.vec_insn[0]->detail->x86.operands[0].reg == X86_REG_ESP && a.vec_insn[1]->id == X86_INS_RET)
    {
        _Message(emu->regs.eip, "VM exit type 2");
    }
    else if (a.vec_insn[0]->id == X86_INS_MOV && a.vec_insn[0]->detail->x86.operands[0].reg == X86_REG_ESP && a.vec_insn[0]->detail->x86.operands[1].type==X86_OP_MEM)
    {
        _Message(emu->regs.eip, "VM exit type 3");
    }
    return true;
}

/**
 * \brief 内存访问分析，并且具备AntiDump分析功能
 * \param lpThreadParameter 未使用此参数
 * \return
 */
DWORD __stdcall MemAccessAnalysis(LPVOID lpThreadParameter)
{
    emu_control = true;
    _Addtolist(0, 0, "----------------内存访问分析[AntiDump]开始----------------");
    Emulator emu;
    t_thread* thread = _Findthread(_Getcputhreadid());
    emu.MapMemoryFromOD();
    emu.SetRegFromOD();
    if (special_ins_solver_control)
    {
        emu.RegisterCallback(EmuSpecialInsSolverCallback, NULL);
    }
    emu.RegisterCallback(EmuJmpImmSolver, NULL);       //bug unicorn有bug导致jmp指令可能会崩溃
    emu.RegisterCallback(GetPatchSPWriteHashDataCallback, NULL);
    emu.RegisterCallback(FindSPVMExitCallback, NULL);
    emu.RegisterCallback(MemAccessAnalysisCallback, NULL);
    emu.RegisterCallback(EmuToApiCallback, _Findmemory(emu.regs.eip));
    DWORD count = emu.Run();
    _Flash("分析已终止");
    emu.LogError();
    emu.LogEnvironment();
    _Addtolist(0, 0, "分析完毕，共模拟了%lu条指令", count);
    _Addtolist(0, 0, "----------------内存访问分析[AntiDump]结束----------------");
    _Setcpu(0, emu.regs.eip, 0, 0, CPU_NOFOCUS);
    return 0;
}

DWORD __stdcall EmuSpecialInsSolver(LPVOID lpThreadParameter)
{
    special_ins_solver_control = 1;
    DWORD data = 0;
    if (_Getlong("cpuid_eax", &data, 4, '0', DIA_HEXONLY) == 0)
    {
        cpuid_eax = data;
    }
    if (_Getlong("cpuid_ecx", &data, 4, '0', DIA_HEXONLY) == 0)
    {
        cpuid_ecx = data;
    }
    if (_Getlong("cpuid_edx", &data, 4, '0', DIA_HEXONLY) == 0)
    {
        cpuid_edx = data;
    }
    if (_Getlong("cpuid_ebx", &data, 4, '0', DIA_HEXONLY) == 0)
    {
        cpuid_ebx = data;
    }
    return 0;
}



/*
 *\brief FixSpIAT使用的回调
 */
bool UniversalTextIATFixCallback(Emulator* emu, void* user_data)
{
    char api_name[TEXTLEN]={};
    DWORD i = (DWORD)(DWORD*)user_data;
    if(_Findsymbolicname(emu->regs.eip, api_name) > 1)
    {
        emu->Stop();
    }
    else if(emu->regs.eip == i+5 || emu->regs.eip == i+6)
    {
        emu->Stop();
    }
    return true;
}

/**
 * \brief 通用IAT修复（已测试vmp3.8）此函数并不完善（视具体情况），并且无法处理apphelp.dll
 * \param lpThreadParameter 未使用此参数
 * \return 
 */
DWORD __stdcall UniversalTextIATFix(LPVOID lpThreadParameter)
{
    //----------------------初始化数据，寻找代码节和混淆节---------------------
    t_dump* item = (t_dump*)lpThreadParameter;
    HANDLE hprocess = (HANDLE)_Plugingetvalue(VAL_HPROCESS);
    t_thread* thread = _Findthread(_Getcputhreadid());
    t_memory* mem_code = _Findmemory(item->base);
    if (mem_code == nullptr)
    {
        MessageBoxA(0, "未能在0x401000处搜索到代码", "警告", MB_TOPMOST | MB_ICONWARNING | MB_OK);
        return 0;
    }
    t_memory* mem_vmp0 = {};
    t_table memory_table = *(t_table*)_Plugingetvalue(VAL_MEMORY);
    t_sorted memory_data = memory_table.data;
    for (int i = 0; i < memory_data.n; i++)
    {
        t_memory* memory = (t_memory*)_Getsortedbyselection(&memory_data, i);
        if (strcmp(memory->sect, ".vmp0") == 0)
        {
            mem_vmp0 = memory;
            goto next;
        }
    }
    DWORD shellcode_addr;
    //未能自动搜索到.vmp0段，手动指定混淆代码段地址
    if (_Getlong("请指定混淆代码段地址", &shellcode_addr, 4, '0', DIA_HEXONLY) != 0)
    {
        return -1;
    }
    mem_vmp0 = _Findmemory(shellcode_addr);
    if(mem_vmp0==nullptr)
    {
        MessageBoxA(0, "未能在指定地址搜索到内存，请检查输入\n任何一个属于混淆代码内存块的地址均可", "警告", MB_TOPMOST | MB_ICONWARNING | MB_OK);
        return -1;
    }
next:
    //-------------------------读取代码段二进制数据-------------------------------------
    SEG_MAP seg_map[2];
    //读取.text和.svmp1的代码
    seg_map[0] = { mem_code->base,mem_code->size,"",new uchar[mem_code->size] };
    _Readmemory(seg_map[0].buf, mem_code->base, mem_code->size, MM_RESILENT);
    seg_map[1] = { mem_vmp0->base,mem_vmp0->size,"",new uchar[mem_vmp0->size] };
    _Readmemory(seg_map[1].buf, mem_vmp0->base, mem_vmp0->size, MM_RESILENT);
    //---------------------------初始化模拟器---------------------------------------
    emu_control = true;
    Emulator emu;
    emu.MapMemoryFromOD();
    emu.SetRegFromOD();
    emu.RegisterCallback(EmuJmpImmSolver, NULL);
    //-----------------------初始化统计数据与修复数据--------------------------------
    DWORD tmp_iat_begin;
    if (_Getlong("临时数据起始位置", &tmp_iat_begin, 4, '0', DIA_HEXONLY) != 0)
    {
        return -1;
    }
    DWORD cnt_call = 0;
    DWORD cnt_jmp = 0;
    DWORD cnt_mov = 0;
    vector<api_info> vec_iat_data;	                     //存放等待重建的IAT数据
    vector<pair<DWORD32, DWORD32>> vec_err_call;         //第一个数据为entry，第二个数据为实际调用api的地址（未知或者异常）。这些地址需要手动处理
    char dll_path[MAX_PATH] = {};
    char api_name[TEXTLEN] = {};
    t_module* module;
    for (DWORD i = mem_code->base; i < mem_code->base + mem_code->size - 100; i++)
    {
        //常规iat加密特征
        if (seg_map[0].buf[i - mem_code->base] == 0xE8)
        {
            a.Clear();
            a.Disasm(i, seg_map[0].buf + i - mem_code->base, 5, 1);
            DWORD jmp_to = 0;
            if (a.count != 1) continue;
            jmp_to = (DWORD)a.vec_insn[0]->detail->x86.operands[0].imm;
            if (jmp_to < mem_vmp0->base || jmp_to >= mem_vmp0->base + mem_vmp0->size) continue;
            emu.regs.eax = 0;
            emu.regs.ecx = 0;
            emu.regs.edx = 0;
            emu.regs.ebx = 0;
            emu.regs.esp = thread->reg.r[REG_ESP];
            emu.regs.ebp = 0;
            emu.regs.esi = 0;
            emu.regs.edi = 0;
            emu.regs.eip = i;
            emu.regs.efl = 0x246;
            DWORD v=0x0;
            //mov类型时防止将寄存器恢复成不为0的值，将esp置0
            emu.WriteMemory(emu.regs.esp,4,&v);
            emu.WriteMemory(emu.regs.esp+4,4,&v);
            emu.Run(1);
            emu.RegisterCallback(UniversalTextIATFixCallback, (void*)i);
            emu.Run();
            emu.UnRegisterCallback(UniversalTextIATFixCallback);
            DWORD ret;
            emu.ReadMemory(emu.regs.esp,4,&ret);
            //先通过eip筛选mov类型
            if(emu.regs.eip == i+5||emu.regs.eip==i+6)
            {
                //mov
                if (emu.regs.eax != 0 && _Findsymbolicname(emu.regs.eax, api_name) > 1)
                {
                    module = _Findmodule(emu.regs.eax);
                    strcpy_s(dll_path, module->name);
                    if(emu.regs.eip == i+5)
                    {
                        vec_iat_data.push_back({ dll_path, api_name, i-1, emu.regs.eax, 3 });
                        _Addtolist(i-1, 0, "[moye] |push call -> mov | entry = %#08x api -> %#08x %s", i-1, emu.regs.eax, api_name);
                    }
                    else if(emu.regs.eip == i+6)
                    {
                         vec_iat_data.push_back({ dll_path, api_name, i, emu.regs.eax, 3 });
                        _Addtolist(i, 0, "[moye] |call retn -> mov | entry = %#08x api -> %#08x %s", i, emu.regs.eax, api_name);
                    }
                    ++cnt_mov;
                }
                else if (emu.regs.ecx != 0 && _Findsymbolicname(emu.regs.ecx, api_name) > 1)
                {
                    module = _Findmodule(emu.regs.ecx);
                    strcpy_s(dll_path, module->name);
                    if(emu.regs.eip == i+5)
                    {
                        vec_iat_data.push_back({ dll_path, api_name, i-1, emu.regs.ecx, 3 });
                        _Addtolist(i-1, 0, "[moye] |push call -> mov | entry = %#08x api -> %#08x %s", i-1, emu.regs.ecx, api_name);
                    }
                    else if(emu.regs.eip == i+6)
                    {
                         vec_iat_data.push_back({ dll_path, api_name, i, emu.regs.ecx, 3 });
                        _Addtolist(i, 0, "[moye] |call retn -> mov | entry = %#08x api -> %#08x %s", i, emu.regs.ecx, api_name);
                    }
                    ++cnt_mov;
                }
                else if (emu.regs.edx != 0 && _Findsymbolicname(emu.regs.edx, api_name) > 1)
                {
                    module = _Findmodule(emu.regs.edx);
                    strcpy_s(dll_path, module->name);
                    if(emu.regs.eip == i+5)
                    {
                        vec_iat_data.push_back({ dll_path, api_name, i-1, emu.regs.edx, 3 });
                        _Addtolist(i-1, 0, "[moye] |push call -> mov | entry = %#08x api -> %#08x %s", i-1, emu.regs.edx, api_name);
                    }
                    else if(emu.regs.eip == i+6)
                    {
                         vec_iat_data.push_back({ dll_path, api_name, i, emu.regs.edx, 3 });
                        _Addtolist(i, 0, "[moye] |call retn -> mov | entry = %#08x api -> %#08x %s", i, emu.regs.edx, api_name);
                    }
                    ++cnt_mov;
                }
                else if (emu.regs.ebx != 0 && _Findsymbolicname(emu.regs.ebx, api_name) > 1)
                {
                    module = _Findmodule(emu.regs.ebx);
                    strcpy_s(dll_path, module->name);
                    if(emu.regs.eip == i+5)
                    {
                        vec_iat_data.push_back({ dll_path, api_name, i-1, emu.regs.ebx, 3 });
                        _Addtolist(i-1, 0, "[moye] |push call -> mov | entry = %#08x api -> %#08x %s", i-1, emu.regs.ebx, api_name);
                    }
                    else if(emu.regs.eip == i+6)
                    {
                         vec_iat_data.push_back({ dll_path, api_name, i, emu.regs.ebx, 3 });
                        _Addtolist(i, 0, "[moye] |call retn -> mov | entry = %#08x api -> %#08x %s", i, emu.regs.ebx, api_name);
                    }
                    ++cnt_mov;
                }
                else if (emu.regs.ebp != 0 && _Findsymbolicname(emu.regs.ebp, api_name) > 1)
                {
                    module = _Findmodule(emu.regs.ebp);
                    strcpy_s(dll_path, module->name);
                    if(emu.regs.eip == i+5)
                    {
                        vec_iat_data.push_back({ dll_path, api_name, i-1, emu.regs.ebp, 3 });
                        _Addtolist(i-1, 0, "[moye] |push call -> mov | entry = %#08x api -> %#08x %s", i-1, emu.regs.ebp, api_name);
                    }
                    else if(emu.regs.eip == i+6)
                    {
                         vec_iat_data.push_back({ dll_path, api_name, i, emu.regs.ebp, 3 });
                        _Addtolist(i, 0, "[moye] |call retn -> mov | entry = %#08x api -> %#08x %s", i, emu.regs.ebp, api_name);
                    }
                    ++cnt_mov;
                }
                else if (emu.regs.esi != 0 && _Findsymbolicname(emu.regs.esi, api_name) > 1)
                {
                    module = _Findmodule(emu.regs.esi);
                    strcpy_s(dll_path, module->name);
                    if(emu.regs.eip == i+5)
                    {
                        vec_iat_data.push_back({ dll_path, api_name, i-1, emu.regs.esi, 3 });
                        _Addtolist(i-1, 0, "[moye] |push call -> mov | entry = %#08x api -> %#08x %s", i-1, emu.regs.esi, api_name);
                    }
                    else if(emu.regs.eip == i+6)
                    {
                         vec_iat_data.push_back({ dll_path, api_name, i, emu.regs.esi, 3 });
                        _Addtolist(i, 0, "[moye] |call retn -> mov | entry = %#08x api -> %#08x %s", i, emu.regs.esi, api_name);
                    }
                    ++cnt_mov;
                }
                else if (emu.regs.edi != 0 && _Findsymbolicname(emu.regs.edi, api_name) > 1)
                {
                    module = _Findmodule(emu.regs.edi);
                    strcpy_s(dll_path, module->name);
                    if(emu.regs.eip == i+5)
                    {
                        vec_iat_data.push_back({ dll_path, api_name, i-1, emu.regs.edi, 3 });
                        _Addtolist(i-1, 0, "[moye] |push call -> mov | entry = %#08x api -> %#08x %s", i-1, emu.regs.edi, api_name);
                    }
                    else if(emu.regs.eip == i+6)
                    {
                         vec_iat_data.push_back({ dll_path, api_name, i, emu.regs.edi, 3 });
                        _Addtolist(i, 0, "[moye] |call retn -> mov | entry = %#08x api -> %#08x %s", i, emu.regs.edi, api_name);
                    }
                    ++cnt_mov;
                }
                else
                {
                    _Addtolist(i, 1, "[moye] 未知的加密方式 entry = %#08x api -> %#08x", i, emu.regs.eip);
                    vec_err_call.emplace_back(i, emu.regs.eip);
                    continue;
                }
            }
            else if (ret==i+5||ret==i+6)
            {
                //call
                module = _Findmodule(emu.regs.eip);
                strcpy_s(dll_path, module->name);
                if(_Findsymbolicname(emu.regs.eip, api_name) > 1)
                {
                    if(ret==i+5)
                    {
                        vec_iat_data.push_back({ dll_path, api_name, i-1, emu.regs.eip, 2 });
                        _Addtolist(i-1, 0, "[moye] |push call -> call| entry = %#08x api -> %#08x %s", i-1, emu.regs.eip, api_name);
                    }
                    else
                    {
                        vec_iat_data.push_back({ dll_path, api_name, i, emu.regs.eip, 2 });
                        _Addtolist(i, 0, "[moye] |call retn -> call| entry = %#08x api -> %#08x %s", i, emu.regs.eip, api_name);
                    }
                    ++cnt_call;
                }
                else
                {
                    _Addtolist(i, 1, "[moye] 未知的加密方式 entry = %#08x api -> %#08x", i, emu.regs.eip);
                    vec_err_call.emplace_back(i, emu.regs.eip);
                    continue;
                }
            }
            else
            {
                DWORD v = 0;
                emu.ReadMemory(emu.regs.esp,4,&v);
                if(v==0)
                {
                    //jmp
                    module = _Findmodule(emu.regs.eip);
                    if(module == NULL)
                    {
                        _Addtolist(i, 1, "[moye] 未知的加密方式 entry = %#08x api -> %#08x", i, emu.regs.eip);
                        vec_err_call.emplace_back(i, emu.regs.eip);
                        continue;
                    }
                    strcpy_s(dll_path, module->name);
                    if (_Findsymbolicname(emu.regs.eip, api_name) > 1)
                    {
                        if (emu.regs.esp == thread->reg.r[REG_ESP]+8)
                        {
                            vec_iat_data.push_back({ dll_path, api_name, i - 1, emu.regs.eip, 1 });
                            _Addtolist(i-1, 0, "[moye] |push call -> jmp | entry = %#08x api -> %#08x %s", i - 1, emu.regs.eip, api_name);
                        }
                        else if (emu.regs.esp == thread->reg.r[REG_ESP]+4)
                        {
                            vec_iat_data.push_back({ dll_path, api_name, i, emu.regs.eip, 1 });
                            _Addtolist(i, 0, "[moye] |call retn -> jmp | entry = %#08x api -> %#08x %s", i, emu.regs.eip, api_name);
                        }
                        else
                        {
                            _Addtolist(i, 1, "[moye] 未知的加密方式 entry = %#08x api -> %#08x", i, emu.regs.eip);
                            vec_err_call.emplace_back(i, emu.regs.eip);
                            continue;
                        }
                        ++cnt_jmp;
                    }
                    else
                    {
                        _Addtolist(i, 1, "[moye] 未知的加密方式 entry = %#08x api -> %#08x", i, emu.regs.eip);
                        vec_err_call.emplace_back(i, emu.regs.eip);
                        continue;
                    }
                }
                else
                {
                    _Addtolist(i, 1, "[moye] 未知的加密方式 entry = %#08x api -> %#08x", i, emu.regs.eip);
                    vec_err_call.emplace_back(i, emu.regs.eip);
                    continue;
                }
            }
            _Infoline("[moye] 解析完成：entry -> %#08X api -> %-20s", i, api_name);
            i+=4;
        }
    }

    delete[] seg_map[0].buf;
    delete[] seg_map[1].buf;
    //-----------------------重建iat表------------------------
    if (vec_iat_data.empty())
    {
        MessageBoxA(0, "未查找到需要修复的地方", "提示", MB_TOPMOST | MB_ICONWARNING | MB_OK);
        return 0;
    }
    sort(vec_iat_data.begin(), vec_iat_data.end());     //排序

    DWORD tmp_addr = tmp_iat_begin;    //当前api存放的地址
    char tmp[50] = {};                 //汇编字符串缓冲区
    char errtext[TEXTLEN];
    t_asmmodel asmmodel;
    vec_iat_data.push_back({});   //末尾标记，并且防越界
    for (DWORD i = 0; i < vec_iat_data.size() - 1; i++)
    {
        _Progress(i * 1000 / (vec_iat_data.size() - 1), (char*)"重建IAT表中...进度");
        switch (vec_iat_data[i].type)
        {
            case 1:
                //jmp
                _Writememory(&vec_iat_data[i].api_addr, tmp_addr, 4, MM_SILENT);
                _Writememory((BYTE*)"\xFF\x25", vec_iat_data[i].fix_addr, 2, MM_SILENT);
                _Writememory(&tmp_addr, vec_iat_data[i].fix_addr + 2, 4, MM_SILENT);
                break;
            case 2:
                //call
                _Writememory(&vec_iat_data[i].api_addr, tmp_addr, 4, MM_SILENT);
                _Writememory((BYTE*)"\xFF\x15", vec_iat_data[i].fix_addr, 2, MM_SILENT);
                _Writememory(&tmp_addr, vec_iat_data[i].fix_addr + 2, 4, MM_SILENT);

                break;
            case 3:
                _Writememory(&vec_iat_data[i].api_addr, tmp_addr, 4, MM_SILENT);
                sprintf_s(tmp, "mov eax, dword ptr [%08X]", tmp_addr);
                _Assemble(tmp, vec_iat_data[i].fix_addr, &asmmodel, 0, 0, errtext);
                _Writememory(asmmodel.code, vec_iat_data[i].fix_addr, asmmodel.length, MM_SILENT);
                break;
            case 4:
                _Writememory(&vec_iat_data[i].api_addr, tmp_addr, 4, MM_SILENT);
                sprintf_s(tmp, "mov ecx, dword ptr [%08X]", tmp_addr);
                _Assemble(tmp, vec_iat_data[i].fix_addr, &asmmodel, 0, 0, errtext);
                _Writememory(asmmodel.code, vec_iat_data[i].fix_addr, asmmodel.length, MM_SILENT);
                break;
            case 5:
                _Writememory(&vec_iat_data[i].api_addr, tmp_addr, 4, MM_SILENT);
                sprintf_s(tmp, "mov edx, dword ptr [%08X]", tmp_addr);
                _Assemble(tmp, vec_iat_data[i].fix_addr, &asmmodel, 0, 0, errtext);
                _Writememory(asmmodel.code, vec_iat_data[i].fix_addr, asmmodel.length, MM_SILENT);
                break;
            case 6:
                _Writememory(&vec_iat_data[i].api_addr, tmp_addr, 4, MM_SILENT);
                sprintf_s(tmp, "mov ebx, dword ptr [%08X]", tmp_addr);
                _Assemble(tmp, vec_iat_data[i].fix_addr, &asmmodel, 0, 0, errtext);
                _Writememory(asmmodel.code, vec_iat_data[i].fix_addr, asmmodel.length, MM_SILENT);
                break;
            case 7:
                _Writememory(&vec_iat_data[i].api_addr, tmp_addr, 4, MM_SILENT);
                sprintf_s(tmp, "mov ebp, dword ptr [%08X]", tmp_addr);
                _Assemble(tmp, vec_iat_data[i].fix_addr, &asmmodel, 0, 0, errtext);
                _Writememory(asmmodel.code, vec_iat_data[i].fix_addr, asmmodel.length, MM_SILENT);
                break;
            case 8:
                _Writememory(&vec_iat_data[i].api_addr, tmp_addr, 4, MM_SILENT);
                sprintf_s(tmp, "mov esi, dword ptr [%08X]", tmp_addr);
                _Assemble(tmp, vec_iat_data[i].fix_addr, &asmmodel, 0, 0, errtext);
                _Writememory(asmmodel.code, vec_iat_data[i].fix_addr, asmmodel.length, MM_SILENT);
                break;
            case 9:
                _Writememory(&vec_iat_data[i].api_addr, tmp_addr, 4, MM_SILENT);
                sprintf_s(tmp, "mov edi, dword ptr [%08X]", tmp_addr);
                _Assemble(tmp, vec_iat_data[i].fix_addr, &asmmodel, 0, 0, errtext);
                _Writememory(asmmodel.code, vec_iat_data[i].fix_addr, asmmodel.length, MM_SILENT);
                break;
            default:
                MessageBoxA(0, "重建IAT表时异常：不正确的类型", "错误", MB_TOPMOST | MB_ICONERROR | MB_OK);
                break;
        }

        if (vec_iat_data[i].dll_name != vec_iat_data[i + 1].dll_name)
        {
            //不同dll的函数集合，用0隔开
            DWORD data = 0;
            tmp_addr += 4;
            _Writememory(&data, tmp_addr, 4, MM_SILENT);
            tmp_addr += 4;
        }
        else if (vec_iat_data[i].api_name != vec_iat_data[i + 1].api_name)
        {
            //如果不是相同的函数名，代表碰到了新的函数，需要扩大4字节放它的地址
            tmp_addr += 4;
        }
    }
    _Progress(0, 0);
    _Addtolist(0, 0, "[moye] --------------修复完毕--------------");
    _Addtolist(0, 0, "[moye] 修复为call的数量：%lu", cnt_call);
    _Addtolist(0, 0, "[moye] 修复为jmp的数量：%lu", cnt_jmp);
    _Addtolist(0, 0, "[moye] 修复为mov的数量：%lu", cnt_mov);
    _Addtolist(0, 0, "[moye] 临时数据地址：0x%08x", tmp_iat_begin);
    _Addtolist(0, 0, "[moye] 临时数据大小：0x%08x", tmp_addr - tmp_iat_begin);
    _Addtolist(0, 0, "[moye] ------------------------------------");
    if (!vec_err_call.empty())
    {
        _Addtolist(0, 1, "[moye] --------以下数据需要手动处理--------");
        for (auto& i : vec_err_call)
        {
            _Addtolist(i.first, 1, "[moye] entry->0x%08x api->0x%08x", i.first, i.second);
        }
        _Addtolist(0, 1, "[moye] ------------------------------------");
    }
    _Flash("修复完毕");
    return 0;
}


//
//
// void SpTestPatch()
// {
//     t_thread* thread = _Findthread(_Getcputhreadid());
//     fs_base=thread->reg.base[SEG_FS];
//     _Writememory(PEHeader,0x00400000,0x400,MM_SILENT);
//     WORD pid=0x57b8;
//     _Writememory(&pid,fs_base+0x20,0x2,MM_SILENT);
//     _Writememory(&pid,fs_base+0x6b4,0x2,MM_SILENT);
//     DWORD peb_addr=0;
//     _Readmemory(&peb_addr,fs_base+0x30,4,MM_SILENT);
//     DWORD ldr_addr=0;
//     _Readmemory(&ldr_addr,peb_addr+0xc,4,MM_SILENT);
//     DWORD InMemoryOrderModuleList_addr;
//     _Readmemory(&InMemoryOrderModuleList_addr,ldr_addr+0x14,4,MM_SILENT);
//     DWORD dll_base=0;
//     _Readmemory(&dll_base,InMemoryOrderModuleList_addr+0x10,4,MM_SILENT);
//     WORD len=0x48;
//     _Writememory(&len,InMemoryOrderModuleList_addr+0x1c,2,MM_SILENT);
//     DWORD path_addr=0;
//     _Readmemory(&path_addr,InMemoryOrderModuleList_addr+0x20,4,MM_SILENT);
//     _Writememory(ProcessFullPath,path_addr,sizeof(ProcessFullPath),MM_SILENT);
//
//     
// }
//
//

/**
 * \brief 复制内存窗口中的字符串到剪切板
 * \param dump
 */
void GetString(t_dump* dump)
{
    if (dump == NULL)
    {
        return;
    }
    const DWORD size = dump->sel1 - dump->sel0;
    char* str = new char[size + 1];
    memset(str, 0, size + 1);
    _Readmemory(str, dump->sel0, size, MM_SILENT);
    if (OpenClipboard(0))
    {
        EmptyClipboard();
        HGLOBAL hClip;
        hClip = GlobalAlloc(GMEM_MOVEABLE, size + 1);
        char* pBuf;
        pBuf = (char*)GlobalLock(hClip);
        strcpy_s(pBuf, size + 1, str);
        GlobalUnlock(hClip);
        SetClipboardData(CF_TEXT, hClip);
        CloseClipboard();
        _Message(0, "[moye] 复制完成  长度：%lu字节", size);
    }
    else
    {
        _Addtolist(0, 1, "[moye] 打开剪切板失败");
        _Flash("打开剪切板失败");
    }
    delete[] str;
}

void GetBinArray(t_dump* dump)
{
    if (dump == NULL)
    {
        return;
    }
    const DWORD len = dump->sel1 - dump->sel0;
    BYTE* str = new BYTE[len + 1];
    memset(str, 0, len + 1);
    _Readmemory(str, dump->sel0, len, MM_SILENT);
    std::string str_arr = "BYTE array[] = {";
    for (DWORD i = 0; i < len; i++)
    {
        if (i % 20 == 0) str_arr += "\n\t";
        char temp[8];
        sprintf_s(temp, "0x%02X,", str[i]);
        str_arr += temp;
    }
    str_arr[str_arr.size() - 1] = '}';
    str_arr += ";\n";
    const DWORD str_size = str_arr.size();
    if (OpenClipboard(0))
    {
        EmptyClipboard();
        HGLOBAL hClip;
        hClip = GlobalAlloc(GMEM_MOVEABLE, str_size + 1);
        char* pBuf;
        pBuf = (char*)GlobalLock(hClip);
        strcpy_s(pBuf, str_size + 1, str_arr.c_str());
        GlobalUnlock(hClip);
        SetClipboardData(CF_TEXT, hClip);
        CloseClipboard();
        _Message(0, "[moye] 复制完成  数组长度：%lu字节  数据长度：%lu字节", len, str_size);
    }
    else
    {
        _Addtolist(0, 1, "[moye] 打开剪切板失败");
        _Flash("打开剪切板失败");
    }
    delete[] str;
}


/**
 * \brief 注册的异常处理函数
 */
LONG __stdcall ExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo)
{
    char msg[256];
    sprintf_s(msg, "[moye] OD发生异常，错误代码：%08X", ExceptionInfo->ExceptionRecord->ExceptionCode);
    MessageBoxA(0, msg, "错误", MB_TOPMOST | MB_ICONERROR | MB_OK);
    return EXCEPTION_CONTINUE_SEARCH;
}


/**
 * \brief 必须的导出函数
 * \param shortname 菜单中显示的插件名
 * \return
 */
extern "C" __declspec(dllexport) int ODBG_Plugindata(char* shortname)
{
    // h_exp_handler = AddVectoredExceptionHandler(0, ExceptionHandler);
    // if (h_exp_handler == NULL)
    // {
    //     _Addtolist(0, 1, "注册异常处理函数失败");
    // }
    const char* pluginName = "寞叶的OD插件v8.0";
    strcpy_s(shortname, strlen(pluginName) + 1, pluginName);
    return PLUGIN_VERSION;
}

/**
 * \brief 必须的导出函数 插件初始化，用于判断和插件所支持的版本是否一致
 * \param ollydbgversion    当前OD版本号
 * \param hw                OllyDbg 主窗口句柄
 * \param features          保留
 * \return
 */
extern "C" __declspec(dllexport) int ODBG_Plugininit(int ollydbgversion, HWND hw, ulong * features)
{
    char msg[200] = {};
    sprintf_s(msg, "  编译时间：%s %s", __DATE__, __TIME__);
    _Addtolist(0, 0, "寞叶的OD插件v8.0");
    _Addtolist(0, -1, msg);
    if (ollydbgversion < PLUGIN_VERSION)
    {
        MessageBoxA(hw, "本插件不支持当前版本OD!", "寞叶的OD插件v8.0", MB_TOPMOST | MB_ICONERROR | MB_OK);
        return -1;
    }
    //g_hOllyDbg = hw;
    return 0;
}


/**
 * \brief 重要的导出函数，显示菜单项
 * \param origin    调用 ODBG_Pluginmenu 函数的窗口代码
 * \param data      指向4K字节长的缓冲区，用于接收描述菜单的结构
 * \param item      指向已选择的元素，可以是已显示于当前窗口的，也可以是转储窗口中的，指向转储描述符。可为NULL
 * \return
 */
extern "C" __declspec(dllexport) cdecl int  ODBG_Pluginmenu(int origin, TCHAR data[4096], VOID * item)
{
    if (origin == PM_MAIN)
    {
        strcpy_s(data, 4096, "0&关于");
    }
    if (origin == PM_DISASM)
    {
        strcpy_s(data, 4096, "寞叶的OD插件{0&标签,1&分配内存,2&合并区段式dump,3&跟踪至api,4&模拟至api,5&通用IAT修复[请先转到代码段再使用],6&修复sp导入表(特征匹配),7&内存访问分析[AntiDump],8&中断模拟器,9&模拟时hook cpuid}");
    }
    if (origin == PM_CPUDUMP)
    {
        strcpy_s(data, 4096, "寞叶的OD插件{0&复制字符串,1&复制为二进制数组}");
    }
    return 1;
}

/**
 * \brief 菜单项被点击执行此函数，所有的菜单项被点击都会执行到这个函数
 * \param origin    允许调用 ODBG_Pluginaction 函数的窗口的代码
 * \param action    菜单项对应索引(0..63)，在ODBG_Pluginmenu 中设置
 * \param item      指向到已选择的数据，可以是已显示于当前窗口的，或是转储窗口中的，指向 dump结构，或为 NULL
 */
extern "C" __declspec(dllexport) cdecl void ODBG_Pluginaction(int origin, int action, VOID * item)
{
    //在主窗口点击
    if (origin == PM_MAIN)
    {
        if (action == 0)
        {
            char msg[256];
            sprintf_s(msg, "cpu窗口、数据窗口 右键可调用功能\n（注意）最好在关闭程序前停止模拟器\n不保证本程序以及使用的模块不存在bug，可能会存在崩溃现象\n仅供交流学习使用\n编译时间：%s %s", __DATE__, __TIME__);
            MessageBoxA(g_hOllyDbg, msg, "关于", MB_TOPMOST | MB_ICONINFORMATION | MB_OK);
        }
    }
    //在反汇编窗口点击
    if (origin == PM_DISASM)
    {
        if (action == 0)
        {
            CreateThread(0, 0, RenameCall, item, 0, 0);
        }
        else if (action == 1)
        {
            CreateThread(0, 0, AllocMemory, 0, 0, 0);
        }
        else if (action == 2)
        {
            CreateThread(0, 0, MergeDump, 0, 0, 0);
        }
        else if (action == 3)
        {
            TraceToApi();
        }
        else if (action == 4)
        {
            CreateThread(0, 0, EmuToApi, 0, 0, 0);
        }
        else if (action == 5)
        {
            CreateThread(0, 0, UniversalTextIATFix, (t_dump*)item, 0, 0);
        }
        else if (action == 6)
        {
            CreateThread(0, 0, FixSpIAT, 0, 0, 0);
        }
        else if (action == 7)
        {
            CreateThread(0, 0, MemAccessAnalysis, 0, 0, 0);
        }
        else if (action == 8)
        {
            emu_control = false;
        }
        else if (action == 9)
        {
            CreateThread(0, 0, EmuSpecialInsSolver, 0, 0, 0);
        }
    }
    //在数据窗口点击
    if (origin == PM_CPUDUMP)
    {
        if (action == 0)
        {
            GetString((t_dump*)item);
        }
        if (action == 1)
        {
            GetBinArray((t_dump*)item);
        }
    }
}

extern "C" __declspec(dllexport) cdecl void ODBG_Pluginreset()
{
    emu_control = false;
}

extern "C" __declspec(dllexport) cdecl void ODBG_Plugindestroy()
{
    emu_control = false;
}
