#pragma once
#include <string>
#include <vector>
#include "ollydbg-sdk/Plugin.h"
#include "unicorn-2.0.1-win32/include/unicorn/unicorn.h"
#include "capstone-5.0/include/capstone/capstone.h"


struct SEG_MAP {
    DWORD				base;
    unsigned int		size;
    std::string	file_name;
    BYTE* buf;
    SEG_MAP()
    {
        base = 0;
        size = 0;
        file_name = "";
        buf = nullptr;
    }
    SEG_MAP(DWORD base, unsigned int size, const std::string& file_name, BYTE* buf)
    {
        this->base = base;
        this->size = size;
        this->file_name = file_name;
        this->buf = buf;
    }
    SEG_MAP& operator=(const SEG_MAP& seg)
    {
        base = seg.base;
        size = seg.size;
        file_name = seg.file_name;
        buf = seg.buf;
        return *this;
    }
};

class Emulator
{
    struct REGS {
        union
        {
            DWORD eax;
            struct
            {
                union
                {
                    WORD ax;
                    struct
                    {
                        BYTE al;
                        BYTE ah;
                    };
                };
                WORD eax_h;
            };
        };
        union
        {
            DWORD ecx;
            struct
            {
                union
                {
                    WORD cx;
                    struct
                    {
                        BYTE cl;
                        BYTE ch;
                    };
                };
                WORD ecx_h;
            };
        };
        union
        {
            DWORD edx;
            struct
            {
                union
                {
                    WORD dx;
                    struct
                    {
                        BYTE dl;
                        BYTE dh;
                    };
                };
                WORD edx_h;
            };
        };
        union
        {
            DWORD ebx;
            struct
            {
                union
                {
                    WORD bx;
                    struct
                    {
                        BYTE bl;
                        BYTE bh;
                    };
                };
                WORD ebx_h;
            };
        };
        union
        {
            DWORD esp;
            struct
            {
                union
                {
                    WORD sp;
                    struct
                    {
                        BYTE sp_l;
                        BYTE sp_h;
                    };
                };
                WORD esp_h;
            };
        };
        union
        {
            DWORD ebp;
            struct
            {
                union
                {
                    WORD bp;
                    struct
                    {
                        BYTE bp_l;
                        BYTE bp_h;
                    };
                };
                WORD ebp_h;
            };
        };
        union
        {
            DWORD esi;
            struct
            {
                union
                {
                    WORD si;
                    struct
                    {
                        BYTE si_l;
                        BYTE si_h;
                    };
                };
                WORD esi_h;
            };
        };
        union
        {
            DWORD edi;
            struct
            {
                union
                {
                    WORD di;
                    struct
                    {
                        BYTE di_l;
                        BYTE di_h;
                    };
                };
                WORD edi_h;
            };
        };
        DWORD eip;
        union
        {
            DWORD efl;
            struct {
                unsigned CF : 1;
                unsigned reserved1 : 1;
                unsigned PF : 1;
                unsigned reserved2 : 1;
                unsigned AF : 1;
                unsigned reserved3 : 1;
                unsigned ZF : 1;
                unsigned SF : 1;
                unsigned TF : 1;
                unsigned IF : 1;
                unsigned DF : 1;
                unsigned OF : 1;
                unsigned IOPL : 2;
                unsigned NT : 1;
                unsigned reserved4 : 1;
                unsigned RF : 1;
                unsigned VM : 1;
                unsigned AC : 1;
                unsigned VIF : 1;
                unsigned VIP : 1;
                unsigned ID : 1;
                unsigned reserved5 : 10;
            };
        };
        DWORD fs_base;
    };
    
    /**
     * \brief 回调函数定义，第一个参数为指向自身的this指针，user_data为注册回调时传递的参数
     * \return 返回真时，将继续执行后面的回调函数。否则在本条指令，剩下的回调函数都不会执行
     */
    typedef bool(*EMULATOR_CALLBACK)(Emulator* emu, void* user_data);

    uc_engine* uc;	                                                //unicorn句柄
    uc_err uc_error;												//unicorn错误信息
    
    std::vector<SEG_MAP> seg_map;									//内存布局信息 
    std::vector<std::pair<EMULATOR_CALLBACK, void*>> callbacks;		//存放回调函数
    DWORD run_cnt;													//模拟器执行完成的指令数
    bool run_state;													//模拟器状态，为1则继续运行，为0则停止

    /**
     * \brief 用成员变量regs设置unicorn的寄存器的值
     */
    void WriteUCRegs();

    /**
     * \brief 从unicorn读取寄存器的值，存放到成员变量regs
     */
    void ReadUCRegs();

    //-----------------------------以下为Public接口-------------------------------------
public:
    REGS regs;
    uc_context* uc_ctx;												//unicorn上下文
    Emulator();

    ~Emulator();

    Emulator(const Emulator& emu);

    /**
     * \brief dump模拟器所有内存和寄存器状态，dump的数据将被保存在当前程序目录下的自定义名字文件夹
     * （如果写的是OD插件，就会保存在OD目录下的path文件夹）           \n
     * 使用示例：emu.Dump("save"); emu.Dump("folder1/folder2/save");
     * \param path [in] 保存dump文件的文件夹名称(或相对路径)
     */
    void Dump(const std::string& path);

    /**
     * \brief 从文件中读取数据，映射到模拟器内存中
     * \param base		[in]内存块的起始地址(Virtual Address)
     * \param size		[in]文件的大小，必须为0x1000的倍数
     * \param file_name [in]文件名
     * \return			如果映射成功，返回真。否则返回假
     */
    bool MapFromFile(const DWORD& base, const DWORD& size, const char* file_name);

    /**
     * \brief 从缓冲区中读取数据，映射到模拟器内存中
     * \param base   [in]内存块的起始地址(Virtual Address)
     * \param size   [in]内存块大小，可以小于缓冲区的大小，但必须为0x1000的倍数
     * \param buf    [in]缓冲区指针
     * \return       如果映射成功，返回真。否则返回假
     */
    bool MapFromMemory(const DWORD& base, const DWORD& size, void* buf);

    /**
     * \brief 注册一个回调函数，模拟器执行每条指令之前，都会按注册时的顺序调用
     * \param function	[in]自定义的回调函数
     * \param user_data [in]给回调函数传递的额外参数。
     * \warning 函数相同将被视为同一个回调函数,无论额外参数是否相同。重复注册回调函数不会有任何效果
     */
    void RegisterCallback(EMULATOR_CALLBACK func, void* user_data);

    /**
     * \brief 删除一个回调函数
     * \param func [in]自定义的回调函数
     * \warning 如果回调不存在，不会有任何效果
     */
    void UnRegisterCallback(EMULATOR_CALLBACK func);

    /**
     * \brief 开始模拟执行
     * \param max [in]最大执行的指令数。可以不填，默认不限制
     * \return 执行的指令数
     * \warning 如果在回调中手动处理了某些指令，比如修改eip实现模拟hook，会导致返回的count值小于真正的值
     */
    DWORD Run(const DWORD& max = 0xFFFFFFFF);

    /**
     * \brief 停止模拟执行
     */
    void Stop();

    /**
     * \brief 输出模拟器的寄存器和堆栈情况
     */
    void PrintEnvironment();

    /**
     * \brief 输出模拟器错误信息
     */
    void PrintError();

    /**
     * \brief 从模拟器中读取一片内存
     * \param addr  [in]内存的虚拟地址
     * \param size  [in]要读取的大小
     * \param buf   [out]存放数据的缓冲区
     * \return 如果成功返回真，否则返回假
     */
    bool ReadMemory(const DWORD& addr, const DWORD& size, void* buf);

    /**
     * \brief 修改模拟器中的一片内存
     * \param addr [in]内存的虚拟地址
     * \param size [in]要写入的大小
     * \param buf  [in]存放数据的缓冲区
     * \return 如果成功返回真，否则返回假
     */
    bool WriteMemory(const DWORD& addr, const DWORD& size, const void* buf);

    /* \brief 通过capstone reg类型获取模拟器中寄存器的值
     * \param reg [in]capstone reg
     * \return 寄存器的值
     */
    DWORD GetReg(const x86_reg& reg);

    /* \brief 通过capstone reg类型设置模拟器中寄存器的值
     * \param reg [in]capstone reg
     * \param value [in]数值
     */
    void SetReg(const x86_reg& reg, const DWORD& value);

    /* \brief 通过capstone mem类型获取模拟器中内存的地址
     * \param reg [in]capstone mem
     * \return 内存的虚拟地址
     */
    DWORD GetMemAddr(const x86_op_mem& mem);

    /**
     * \brief 返回模拟器当前执行过的指令数
     * \return run_cnt
     */
    DWORD GetRunCount();

    /**
     * \brief 在od日志窗口输出模拟器的寄存器和堆栈情况
     */
    void LogEnvironment();

    /**
     * \brief 在od日志窗口输出模拟器的寄存器和堆栈情况
     */
    void LogError();

    /**
     * \brief 映射OD所有内存到模拟器
     */
    void MapMemoryFromOD();

    /**
     * \brief 用OD寄存器设置模拟器的寄存器
     */
    void SetRegFromOD();

    /**
     * \brief 保存模拟器上下文，用于快速还原模拟器环境
     */
    void SaveContext();

    /**
     * \brief 快速还原模拟器环境
     */
    void RestoreContext();
};

struct SegmentDescriptor {
    union {
        struct {
            unsigned short limit0;
            unsigned short base0;
            unsigned char base1;
            unsigned char type : 4;
            unsigned char system : 1; /* S flag */
            unsigned char dpl : 2;
            unsigned char present : 1; /* P flag */
            unsigned char limit1 : 4;
            unsigned char avail : 1;
            unsigned char is_64_code : 1;  /* L flag */
            unsigned char db : 1;          /* DB flag */
            unsigned char granularity : 1; /* G flag */
            unsigned char base2;
        };
        uint64_t desc;
    };
};


#define SEGBASE(d)                                                             \
    ((uint32_t)((((d).desc >> 16) & 0xffffff) |                                \
                (((d).desc >> 32) & 0xff000000)))
#define SEGLIMIT(d) ((d).limit0 | (((unsigned int)(d).limit1) << 16))


class SegmentSelector {
public:
    union
    {
        DWORD val = 0;
        struct
        {
            unsigned rpl : 2;
            unsigned ti : 1;
            unsigned index : 13;
        };
    };
    SegmentSelector& operator =(const ulong& v)
    {
        val = v;
    }
    SegmentSelector(const ulong& v)
    {
        val = v;
    }
};
