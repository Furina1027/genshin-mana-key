namespace GenshinSniffer;

internal static class Log {
    private static readonly object LockObj = new();
    public static void Write(string message) {
        var line = $"[{DateTime.Now:HH:mm:ss}] {message}";
        lock (LockObj) {
            Console.WriteLine(line);
            try {
                File.AppendAllText("dumper.log", line + Environment.NewLine);
            } catch { }
        }
    }
}
