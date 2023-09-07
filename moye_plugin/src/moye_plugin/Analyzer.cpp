#include "Analyzer.h"

Analyzer::Analyzer()
{
    cs_error = cs_open(CS_ARCH_X86, CS_MODE_32, &csh);
    cs_error = cs_option(csh, CS_OPT_DETAIL, CS_OPT_ON);
    count = 0;
}

Analyzer::~Analyzer()
{
    Clear();
    cs_error = cs_close(&csh);
}

void Analyzer::Disasm(const DWORD& base, BYTE* code, const DWORD& code_size, const DWORD& max_count)
{
    DWORD offset = 0;
    cs_insn* insn = nullptr;
    for(DWORD i=1;i<=max_count;i++)
    {
        if (offset >= code_size) break;
        DWORD add_count = cs_disasm(csh, code + offset, code_size - offset, base + offset, 1, &insn);
        if (add_count == 1)
        {
            vec_insn.push_back(insn);
            count += 1;
            offset += insn->size;
        }
        else break;
    }
}

void Analyzer::Clear()
{
    for (DWORD i = 0; i < count; i++) cs_free(vec_insn[i], 1);
    vec_insn.clear();
    count = 0;
}
