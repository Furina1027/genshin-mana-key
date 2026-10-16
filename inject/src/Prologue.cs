namespace GenshinSniffer;

/// <summary>
/// 「这段字节像不像 x64 函数入口」的判据。
///
/// 为什么单独抽出来：它是**安全关键**的一道门 —— 判错方向只有两种后果，
/// 放过去 = MinHook 改掉别的函数的机器码（游戏行为变得无法解释），
/// 拦下来 = 少挂一个钩子并打日志。所以它必须能被单元测试直接覆盖，
/// 因此这里只吃一段字节（不碰地址、不碰 Native），测试工程可以链接同一份源码。
///
/// 为什么不能只看第一个字节（旧实现）：拿真实 exe 实测 —— 把国际服那 5 个 RVA
/// 丢进国服 exe 核对，它们**同样落在 il2cpp 可执行节内**，而且首字节就是 0x48：
///   `48 B8 01 00 00 00 02 00`（mov rax, imm64）是一个"看着合法"的中段指令。
/// 只看首字节会放它过去。
///
/// 现在的判据：在窗口内找到「分配栈帧 / 保存入参 / 建立帧指针」的典型序列，
/// 并且它之前**只允许**出现序言前缀字节（push、REX 前缀、endbr64）。
/// 中段指令要同时凑齐这两条的概率极低。
///
/// 刻意偏严：现网 7.1 国服 14 个钩子的序言全部通过（已用真实 exe 逐个验证，见单测）；
/// 将来版本变了若误判，表现是**打日志跳过**而不是改错代码。
/// </summary>
internal static class Prologue {

    /// <summary>判断窗口至少需要的字节数。</summary>
    public const int WindowSize = 16;

    /// <summary>模式最多允许出现的起始位置（保证 b[j+3] 不越界）。</summary>
    private const int MaxPatternOffset = WindowSize - 4;

    public static bool LooksLikeFunctionEntry(ReadOnlySpan<byte> bytes) {
        if (bytes.Length < WindowSize) {
            return false;
        }
        // CET 的间接跳转目标标记 `F3 0F 1E FA`：它是序言的一部分，但不是 push/REX，
        // 所以先整体跳过，再在剩下的字节里找帧建立序列。
        var start = 0;
        if (bytes[0] == 0xF3 && bytes[1] == 0x0F && bytes[2] == 0x1E && bytes[3] == 0xFA) {
            start = 4;
        }
        for (var j = start; j <= MaxPatternOffset; j++) {
            if (!IsFrameSetup(bytes, j)) {
                continue;
            }
            // 帧建立序列之前只能是序言前缀；否则就是"中段指令里的巧合"
            var cleanPrefix = true;
            for (var k = start; k < j; k++) {
                if (!IsProloguePrefixByte(bytes[k])) {
                    cleanPrefix = false;
                    break;
                }
            }
            if (cleanPrefix) {
                return true;
            }
        }
        return false;
    }

    /// <summary>帧建立序列：sub rsp / 保存入参到栈 / 建立帧指针。</summary>
    private static bool IsFrameSetup(ReadOnlySpan<byte> b, int j) =>
        // sub rsp, imm8 / imm32
        (b[j] == 0x48 && b[j + 1] is 0x83 or 0x81 && b[j + 2] == 0xEC)
        // mov [rsp+disp8], rcx/rdx/rbx/rbp/rdi —— MSVC 把入参 home 到栈上
        || (b[j] == 0x48 && b[j + 1] == 0x89 && b[j + 3] == 0x24
            && b[j + 2] is 0x4C or 0x54 or 0x5C or 0x6C or 0x7C)
        // mov rax, rsp
        || (b[j] == 0x48 && b[j + 1] == 0x8B && b[j + 2] == 0xC4)
        // mov rbp, rsp —— 经典 `push rbp; mov rbp, rsp; sub rsp, N` 帧指针序言
        || (b[j] == 0x48 && b[j + 1] == 0x89 && b[j + 2] == 0xE5);

    /// <summary>序言允许出现的前缀字节：push（含 41 5x 的 r8-r15）与 REX 前缀。</summary>
    private static bool IsProloguePrefixByte(byte value) =>
        value is 0x41 or 0x48 or 0x40 or 0x44 or 0x4C      // REX.B/R/W/X 前缀
            or 0x53 or 0x55 or 0x56 or 0x57                 // push rbx/rbp/rsi/rdi
            or (>= 0x50 and <= 0x57);                       // push rax..rdi（配合 41 前缀即 push r8..r15）

}
