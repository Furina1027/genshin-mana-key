using System.Diagnostics;

namespace GenshinSniffer.Utilities;

/// <summary>
/// 定位原神国服主程序 YuanShen.exe：命令行参数 → 常见安装路径 → 运行中的游戏进程。
/// （本项目只针对国服；国际服 GenshinImpact.exe 不处理。）
/// </summary>
internal static class AppConfig {

    private static readonly string[] ExeNames = ["YuanShen.exe"];

    private static readonly string[] Candidates = [
        @"E:\Genshin Impact bilibili\games\Genshin Impact Game\YuanShen.exe",
        @"E:\米家游戏\切换器\米家三合一切换器\资源替换包\原神\原神官服\YuanShen.exe",
        @"C:\Program Files\Genshin Impact\Genshin Impact Game\YuanShen.exe",
        @"D:\Genshin Impact\Genshin Impact Game\YuanShen.exe",
    ];

    public static string? GetGamePath(string? argPath) {
        if (argPath != null && File.Exists(argPath)) {
            return argPath;
        }
        foreach (var p in Candidates) {
            if (File.Exists(p)) {
                return p;
            }
        }
        foreach (var name in ExeNames) {
            var baseName = Path.GetFileNameWithoutExtension(name);
            var proc = Process.GetProcessesByName(baseName).FirstOrDefault();
            if (proc != null) {
                return proc.GetFileName();
            }
        }
        return null;
    }

    /// <summary>游戏是否在运行（用它自己的进程名判断，避免误判别的程序）。</summary>
    public static bool IsGameRunning() {
        foreach (var name in ExeNames) {
            var baseName = Path.GetFileNameWithoutExtension(name);
            if (Process.GetProcessesByName(baseName).Length > 0) {
                return true;
            }
        }
        return false;
    }

}
