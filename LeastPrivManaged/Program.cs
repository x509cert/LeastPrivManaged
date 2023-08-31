using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;

public class ProcessPrivilegesManager
{
    #region Native Windows Calls and Constants
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, int BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern bool LookupPrivilegeValue(string? lpSystemName, string lpName, ref LUID lpLuid);

    private const uint TOKEN_ADJUST_PRIVILEGES = 0x20;
    private const uint SE_PRIVILEGE_REMOVED = 0x04;

    private struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    private struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public uint Attributes;
    }

    private struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public LUID_AND_ATTRIBUTES Privilege;
    }
    #endregion

    public List<string> RemovePrivileges(Process? process = null, params string[] privilegeNames)
    {
        var errors = new List<string>();

        if (privilegeNames == null || privilegeNames.Length == 0)
        {
            errors.Add("No privileges provided to reduce.");
            return errors;
        }

        if (process == null)
        {
            process = Process.GetCurrentProcess();
        }

        if (OpenProcessToken(process.Handle, TOKEN_ADJUST_PRIVILEGES, out IntPtr tokenHandle))
        {
            foreach (string privilegeName in privilegeNames)
            {
                var luid = new LUID();
                if (LookupPrivilegeValue(null, privilegeName, ref luid))
                {
                    TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES
                    {
                        PrivilegeCount = 1,
                        Privilege = new LUID_AND_ATTRIBUTES
                        {
                            Luid = luid,
                            Attributes = SE_PRIVILEGE_REMOVED
                        }
                    };

                    if (!AdjustTokenPrivileges(tokenHandle, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
                    {
                        errors.Add($"Failed to adjust privilege {privilegeName}. Error code: {Marshal.GetLastWin32Error()}");
                    }
                }
                else
                {
                    errors.Add($"Failed to lookup privilege value {privilegeName}. Error code: {Marshal.GetLastWin32Error()}");
                }
            }
        }
        else
        {
            errors.Add($"Failed to open process token. Error code: {Marshal.GetLastWin32Error()}");
        }

        return errors;
    }
}

public class Program
{
    public static void Main(string[] args)
    {
        var manager = new ProcessPrivilegesManager();
        var errors = manager.RemovePrivileges(null, "SeUndockPrivilege", "SeShutdownPrivilege");
        if (errors.Count > 0)
        {
            Console.WriteLine("Errors encountered while reducing privileges:");
            foreach (string error in errors)
            {
                Console.WriteLine(error);
            }
        }
        else
        {
            Console.WriteLine("Privileges adjusted successfully.");
        }

        // Pause to see the result
        Console.WriteLine("Press any key to exit...");
        Console.ReadKey();
    }
}
