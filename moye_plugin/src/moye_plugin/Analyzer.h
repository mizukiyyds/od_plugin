#pragma once
#include <vector>
#include <Windows.h>
#include "capstone-5.0/include/capstone/capstone.h"

class Analyzer
{
public:
    csh csh;							    //capstone句柄（用户不应该修改它）
    cs_err cs_error;			            //capstone错误码（用户不应该修改它）
    std::vector<cs_insn*> vec_insn;		    //capstone反汇编的指令集（用户应该通过成员函数修改它）
    DWORD count;						    //指令数（用户不应该直接修改它）

    Analyzer();

    ~Analyzer();

    /**
     * \brief 反汇编指定代码
     * \param base [in]第一条指令的VirtualAddress
     * \param code [in]二进制代码缓冲区
     * \param size [in]缓冲区大小
     * \param max_count [in]最大反汇编指令数, 为0则不限制
     */
    void Disasm(const DWORD& base, BYTE* code, const DWORD& code_size, const DWORD& max_count = 1);

    /**
     * \brief 清空反汇编结果
     */
    void Clear();
};
