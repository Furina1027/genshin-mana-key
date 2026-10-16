namespace GenshinSniffer;

/// <summary>
/// 日志级别 —— **只影响前台遮罩上的三字母前缀**（照 BetterGI 的 `{Level:u3}`）。
///
/// 为什么不照搬 Serilog 那套六级：遮罩只有左下角一小块，用户要能一眼分出的就是
/// 「正常 / 要注意 / 出错了」三档，级别再多只会让前缀互相挤、反而看不清。
///
/// **后台 dumper.log 完全不受级别影响**：它仍然是 `[MM-dd HH:mm:ss] 消息`，
/// 既没有级别字段也没有任何其它变化（这是本次改动的硬约束）。
/// </summary>
internal enum LogLevel {

    /// <summary>正常流程。遮罩前缀 `INF`。</summary>
    Info = 0,

    /// <summary>降级但仍能继续：未采纳、未配对、转储失败、被忽略的异常等。遮罩前缀 `WRN`。</summary>
    Warn = 1,

    /// <summary>致命或主链路已经断掉：注入失败、管道不可用、结果写不进去。遮罩前缀 `ERR`。</summary>
    Error = 2,
}
